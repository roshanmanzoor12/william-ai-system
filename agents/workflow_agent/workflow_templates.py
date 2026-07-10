"""
agents/workflow_agent/workflow_templates.py

Reusable automation templates for the William / Jarvis Workflow Agent.

Purpose:
    Provides production-safe reusable workflow templates for:
    - Lead capture and follow-up automation
    - Scheduled reports and dashboard summaries
    - Support ticket intake and escalation
    - Reminder and notification workflows

Architecture Compatibility:
    - Master Agent routing
    - Workflow Agent orchestration
    - Security Agent approval checks
    - Verification Agent payload preparation
    - Memory Agent compatible context payloads
    - Dashboard/API/FastAPI structured responses
    - Agent Registry / Agent Loader import safety

Safety:
    This module does not execute external actions directly.
    It creates, validates, clones, renders, imports, exports, and lists workflow
    templates. Execution must be handled by workflow_builder, trigger_engine,
    scheduler, action_router, approval_gate, and related Workflow Agent files.

SaaS Isolation:
    Every user-specific operation validates user_id and workspace_id.
    No template runtime data is mixed between users/workspaces.
"""

from __future__ import annotations

import copy
import dataclasses
import enum
import hashlib
import json
import logging
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Import-safe BaseAgent fallback
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for isolated imports
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps the file import-safe before the full William/Jarvis
        framework is loaded. In production, agents.base_agent.BaseAgent
        should be used by the Agent Loader / Registry.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())
            self.logger = logging.getLogger(self.agent_name)

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback emit_event: %s | %s", event_name, payload)

        def log_audit(self, payload: Dict[str, Any]) -> None:
            self.logger.info("Fallback audit: %s", payload)


# ---------------------------------------------------------------------------
# Constants and enums
# ---------------------------------------------------------------------------

MODULE_NAME = "workflow_agent"
FILE_NAME = "workflow_templates.py"
AGENT_NAME = "WorkflowTemplates"
DEFAULT_TEMPLATE_VERSION = "1.0.0"
MAX_TEMPLATE_NAME_LENGTH = 120
MAX_DESCRIPTION_LENGTH = 1500
MAX_TAGS = 30
MAX_STEPS = 100
MAX_VARIABLES = 100
SUPPORTED_EXPORT_FORMATS = {"dict", "json"}
PLACEHOLDER_PATTERN = re.compile(r"\{\{\s*([a-zA-Z_][a-zA-Z0-9_.-]*)\s*\}\}")


class TemplateCategory(str, enum.Enum):
    """Supported reusable workflow template categories."""

    LEADS = "leads"
    REPORTS = "reports"
    SUPPORT = "support"
    REMINDERS = "reminders"


class StepType(str, enum.Enum):
    """Supported declarative step types.

    These are intentionally generic so action_router.py can later map them
    to connectors, agents, queues, approval gates, or dashboard actions.
    """

    TRIGGER = "trigger"
    VALIDATION = "validation"
    CONDITION = "condition"
    ACTION = "action"
    APPROVAL = "approval"
    NOTIFICATION = "notification"
    WAIT = "wait"
    MEMORY = "memory"
    VERIFICATION = "verification"
    REPORT = "report"


class RiskLevel(str, enum.Enum):
    """Risk level used for security and approval routing."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TemplateStatus(str, enum.Enum):
    """Template lifecycle status."""

    ACTIVE = "active"
    DRAFT = "draft"
    DEPRECATED = "deprecated"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class WorkflowVariable:
    """
    Template variable definition.

    Variables are rendered from runtime data through render_template().
    They do not store secrets. Sensitive values should be referenced by key
    and resolved by app_connector / approval_gate / Security Agent.
    """

    name: str
    label: str
    var_type: str = "string"
    required: bool = False
    default: Any = None
    description: str = ""
    choices: Optional[List[Any]] = None
    sensitive: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class WorkflowStep:
    """
    Declarative workflow template step.

    The step does not execute anything. It describes what the Workflow Agent
    should later build or route through workflow_builder/action_router.
    """

    step_id: str
    name: str
    step_type: str
    agent: Optional[str] = None
    connector: Optional[str] = None
    action: Optional[str] = None
    config: Optional[Dict[str, Any]] = None
    depends_on: Optional[List[str]] = None
    condition: Optional[Dict[str, Any]] = None
    requires_approval: bool = False
    risk_level: str = RiskLevel.LOW.value
    timeout_seconds: Optional[int] = None
    retry_policy: Optional[Dict[str, Any]] = None
    output_key: Optional[str] = None
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class WorkflowTemplate:
    """
    Reusable workflow template.

    Templates may be global/system templates or user/workspace-scoped custom
    templates. User/workspace fields must be present for custom templates.
    """

    template_id: str
    name: str
    category: str
    description: str
    version: str
    status: str
    variables: List[WorkflowVariable]
    steps: List[WorkflowStep]
    tags: List[str]
    created_by: str = "system"
    user_id: Optional[str] = None
    workspace_id: Optional[str] = None
    is_system_template: bool = True
    risk_level: str = RiskLevel.LOW.value
    requires_security_review: bool = False
    compatible_agents: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None
    created_at: str = dataclasses.field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    updated_at: str = dataclasses.field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        data = dataclasses.asdict(self)
        data["variables"] = [variable.to_dict() for variable in self.variables]
        data["steps"] = [step.to_dict() for step in self.steps]
        return data


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class WorkflowTemplates(BaseAgent):
    """
    Reusable workflow template manager for the William / Jarvis Workflow Agent.

    This class is intentionally action-safe:
    - It does not send emails, WhatsApp messages, calls, or external API writes.
    - It does not run workflows.
    - It only manages reusable template definitions and prepares structured
      payloads for other Workflow Agent components.

    Main public methods:
        - list_templates()
        - get_template()
        - create_custom_template()
        - update_custom_template()
        - delete_custom_template()
        - validate_template()
        - render_template()
        - instantiate_template()
        - export_template()
        - import_template()
        - search_templates()
        - get_template_catalog()
    """

    def __init__(
        self,
        *,
        agent_name: str = AGENT_NAME,
        agent_id: str = "workflow_templates",
        logger: Optional[logging.Logger] = None,
        event_emitter: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], None]] = None,
        security_client: Optional[Any] = None,
        memory_client: Optional[Any] = None,
        verification_client: Optional[Any] = None,
        template_store: Optional[Mapping[str, Dict[str, Any]]] = None,
        strict_context: bool = True,
    ) -> None:
        try:
            super().__init__(agent_name=agent_name, agent_id=agent_id)
        except TypeError:
            super().__init__()

        self.agent_name = agent_name
        self.agent_id = agent_id
        self.logger = logger or logging.getLogger(f"{MODULE_NAME}.{AGENT_NAME}")
        self.event_emitter = event_emitter
        self.audit_logger = audit_logger
        self.security_client = security_client
        self.memory_client = memory_client
        self.verification_client = verification_client
        self.strict_context = strict_context

        self._system_templates: Dict[str, Dict[str, Any]] = self._load_builtin_templates()
        self._custom_templates: Dict[str, Dict[str, Any]] = {}

        if template_store:
            for template_id, template_data in template_store.items():
                if isinstance(template_data, Mapping):
                    self._custom_templates[str(template_id)] = copy.deepcopy(dict(template_data))

        self._emit_agent_event(
            "workflow_templates.initialized",
            {
                "system_template_count": len(self._system_templates),
                "custom_template_count": len(self._custom_templates),
            },
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def list_templates(
        self,
        *,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        category: Optional[str] = None,
        include_system: bool = True,
        include_custom: bool = True,
        status: Optional[str] = TemplateStatus.ACTIVE.value,
        tags: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        """
        List templates visible to a user/workspace.

        System templates are globally visible.
        Custom templates are visible only when user_id and workspace_id match.
        """

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            require_context=include_custom and self.strict_context,
            operation="list_templates",
        )
        if not context_result["success"]:
            return context_result

        try:
            normalized_category = self._normalize_optional_enum(
                category,
                TemplateCategory,
                field_name="category",
            )
            normalized_status = self._normalize_optional_enum(
                status,
                TemplateStatus,
                field_name="status",
            )
            requested_tags = {self._normalize_tag(tag) for tag in (tags or []) if tag}

            templates: List[Dict[str, Any]] = []

            if include_system:
                templates.extend(copy.deepcopy(list(self._system_templates.values())))

            if include_custom:
                templates.extend(
                    copy.deepcopy(
                        [
                            template
                            for template in self._custom_templates.values()
                            if template.get("user_id") == user_id
                            and template.get("workspace_id") == workspace_id
                        ]
                    )
                )

            filtered: List[Dict[str, Any]] = []
            for template in templates:
                if normalized_category and template.get("category") != normalized_category:
                    continue
                if normalized_status and template.get("status") != normalized_status:
                    continue
                if requested_tags:
                    template_tags = {self._normalize_tag(tag) for tag in template.get("tags", [])}
                    if not requested_tags.issubset(template_tags):
                        continue
                filtered.append(self._public_template_summary(template))

            filtered.sort(key=lambda item: (item.get("category", ""), item.get("name", "")))

            self._log_audit_event(
                event_type="workflow_template.list",
                user_id=user_id,
                workspace_id=workspace_id,
                details={
                    "category": normalized_category,
                    "status": normalized_status,
                    "count": len(filtered),
                    "include_system": include_system,
                    "include_custom": include_custom,
                },
            )

            return self._safe_result(
                message="Workflow templates listed successfully.",
                data={
                    "templates": filtered,
                    "count": len(filtered),
                    "filters": {
                        "category": normalized_category,
                        "status": normalized_status,
                        "tags": sorted(requested_tags),
                        "include_system": include_system,
                        "include_custom": include_custom,
                    },
                },
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to list workflow templates.",
                error=exc,
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )

    def get_template(
        self,
        template_id: str,
        *,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        include_validation: bool = True,
    ) -> Dict[str, Any]:
        """Get a full workflow template by ID with SaaS visibility checks."""

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            require_context=self.strict_context,
            operation="get_template",
        )
        if not context_result["success"]:
            return context_result

        try:
            template = self._find_visible_template(
                template_id=template_id,
                user_id=user_id,
                workspace_id=workspace_id,
            )
            if not template:
                return self._error_result(
                    message="Workflow template not found or not accessible.",
                    error="template_not_found",
                    metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
                )

            result_data: Dict[str, Any] = {"template": copy.deepcopy(template)}
            if include_validation:
                validation_result = self.validate_template(
                    template,
                    user_id=user_id,
                    workspace_id=workspace_id,
                )
                result_data["validation"] = validation_result.get("data", {})

            self._log_audit_event(
                event_type="workflow_template.get",
                user_id=user_id,
                workspace_id=workspace_id,
                details={"template_id": template_id},
            )

            return self._safe_result(
                message="Workflow template loaded successfully.",
                data=result_data,
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to get workflow template.",
                error=exc,
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )

    def search_templates(
        self,
        query: str,
        *,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        category: Optional[str] = None,
        limit: int = 20,
    ) -> Dict[str, Any]:
        """Search visible templates by name, description, category, tags, or step actions."""

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            require_context=self.strict_context,
            operation="search_templates",
        )
        if not context_result["success"]:
            return context_result

        try:
            normalized_query = (query or "").strip().lower()
            if not normalized_query:
                return self._error_result(
                    message="Search query is required.",
                    error="missing_query",
                    metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
                )

            list_result = self.list_templates(
                user_id=user_id,
                workspace_id=workspace_id,
                category=category,
                include_system=True,
                include_custom=True,
                status=None,
            )
            if not list_result["success"]:
                return list_result

            summaries = list_result["data"]["templates"]
            scored: List[Tuple[int, Dict[str, Any]]] = []

            for summary in summaries:
                template = self._find_visible_template(
                    template_id=summary["template_id"],
                    user_id=user_id,
                    workspace_id=workspace_id,
                )
                if not template:
                    continue

                haystack_parts = [
                    template.get("name", ""),
                    template.get("description", ""),
                    template.get("category", ""),
                    " ".join(template.get("tags", [])),
                    " ".join(step.get("name", "") for step in template.get("steps", [])),
                    " ".join(step.get("action", "") or "" for step in template.get("steps", [])),
                    " ".join(step.get("connector", "") or "" for step in template.get("steps", [])),
                    " ".join(step.get("agent", "") or "" for step in template.get("steps", [])),
                ]
                haystack = " ".join(haystack_parts).lower()

                if normalized_query not in haystack:
                    continue

                score = 1
                if normalized_query in template.get("name", "").lower():
                    score += 10
                if normalized_query in template.get("category", "").lower():
                    score += 5
                if any(normalized_query in tag.lower() for tag in template.get("tags", [])):
                    score += 3

                scored.append((score, self._public_template_summary(template)))

            scored.sort(key=lambda item: item[0], reverse=True)
            results = [item for _, item in scored[: max(1, min(limit, 100))]]

            self._log_audit_event(
                event_type="workflow_template.search",
                user_id=user_id,
                workspace_id=workspace_id,
                details={"query": query, "count": len(results)},
            )

            return self._safe_result(
                message="Workflow template search completed successfully.",
                data={"templates": results, "count": len(results), "query": query},
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to search workflow templates.",
                error=exc,
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )

    def get_template_catalog(
        self,
        *,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Return dashboard/API-friendly grouped template catalog.

        Useful for the Workflow Builder UI when showing reusable automation
        blocks grouped by category.
        """

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            require_context=self.strict_context,
            operation="get_template_catalog",
        )
        if not context_result["success"]:
            return context_result

        try:
            templates_result = self.list_templates(
                user_id=user_id,
                workspace_id=workspace_id,
                include_system=True,
                include_custom=True,
                status=TemplateStatus.ACTIVE.value,
            )
            if not templates_result["success"]:
                return templates_result

            catalog: Dict[str, List[Dict[str, Any]]] = {
                category.value: [] for category in TemplateCategory
            }

            for template in templates_result["data"]["templates"]:
                category = template.get("category")
                catalog.setdefault(category, []).append(template)

            return self._safe_result(
                message="Workflow template catalog prepared successfully.",
                data={
                    "catalog": catalog,
                    "categories": [
                        {
                            "category": category.value,
                            "label": self._category_label(category.value),
                            "count": len(catalog.get(category.value, [])),
                        }
                        for category in TemplateCategory
                    ],
                },
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to prepare workflow template catalog.",
                error=exc,
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )

    def create_custom_template(
        self,
        template: Mapping[str, Any],
        *,
        user_id: str,
        workspace_id: str,
        created_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Create a user/workspace-scoped custom reusable workflow template.

        The custom template is stored in-memory by default. In production, the
        dashboard/API layer can persist the returned template into database
        storage and reload it through template_store.
        """

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            require_context=True,
            operation="create_custom_template",
        )
        if not context_result["success"]:
            return context_result

        try:
            template_data = copy.deepcopy(dict(template))
            template_id = str(template_data.get("template_id") or self._generate_template_id(template_data))
            template_data["template_id"] = template_id
            template_data["user_id"] = user_id
            template_data["workspace_id"] = workspace_id
            template_data["created_by"] = created_by or user_id
            template_data["is_system_template"] = False
            template_data.setdefault("version", DEFAULT_TEMPLATE_VERSION)
            template_data.setdefault("status", TemplateStatus.ACTIVE.value)
            template_data.setdefault("metadata", {})
            template_data.setdefault("created_at", datetime.now(timezone.utc).isoformat())
            template_data["updated_at"] = datetime.now(timezone.utc).isoformat()

            validation_result = self.validate_template(
                template_data,
                user_id=user_id,
                workspace_id=workspace_id,
            )
            if not validation_result["success"]:
                return validation_result

            if template_id in self._system_templates:
                return self._error_result(
                    message="Custom template ID conflicts with a system template.",
                    error="template_id_conflict",
                    metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
                )

            existing = self._custom_templates.get(template_id)
            if existing and (
                existing.get("user_id") != user_id
                or existing.get("workspace_id") != workspace_id
            ):
                return self._error_result(
                    message="Custom template ID belongs to a different user/workspace.",
                    error="template_scope_conflict",
                    metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
                )

            if self._requires_security_check(template_data):
                approval = self._request_security_approval(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    action="create_custom_template",
                    payload={
                        "template_id": template_id,
                        "risk_level": template_data.get("risk_level"),
                        "requires_security_review": template_data.get("requires_security_review"),
                    },
                )
                if not approval.get("approved", False):
                    return self._error_result(
                        message="Security approval required before creating this template.",
                        error="security_approval_required",
                        data={"approval": approval},
                        metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
                    )

            self._custom_templates[template_id] = template_data

            verification_payload = self._prepare_verification_payload(
                user_id=user_id,
                workspace_id=workspace_id,
                action="create_custom_template",
                data={"template_id": template_id, "template_name": template_data.get("name")},
            )
            memory_payload = self._prepare_memory_payload(
                user_id=user_id,
                workspace_id=workspace_id,
                memory_type="workflow_template_created",
                data={
                    "template_id": template_id,
                    "name": template_data.get("name"),
                    "category": template_data.get("category"),
                    "tags": template_data.get("tags", []),
                },
            )

            self._emit_agent_event(
                "workflow_template.created",
                {
                    "template_id": template_id,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "category": template_data.get("category"),
                },
            )
            self._log_audit_event(
                event_type="workflow_template.create",
                user_id=user_id,
                workspace_id=workspace_id,
                details={"template_id": template_id, "name": template_data.get("name")},
            )

            return self._safe_result(
                message="Custom workflow template created successfully.",
                data={
                    "template": copy.deepcopy(template_data),
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to create custom workflow template.",
                error=exc,
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )

    def update_custom_template(
        self,
        template_id: str,
        updates: Mapping[str, Any],
        *,
        user_id: str,
        workspace_id: str,
    ) -> Dict[str, Any]:
        """Update a custom template within the same user/workspace scope."""

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            require_context=True,
            operation="update_custom_template",
        )
        if not context_result["success"]:
            return context_result

        try:
            existing = self._custom_templates.get(template_id)
            if not existing:
                return self._error_result(
                    message="Custom workflow template not found.",
                    error="template_not_found",
                    metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
                )

            if existing.get("user_id") != user_id or existing.get("workspace_id") != workspace_id:
                return self._error_result(
                    message="Custom workflow template is not accessible in this workspace.",
                    error="template_scope_denied",
                    metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
                )

            protected_fields = {
                "template_id",
                "user_id",
                "workspace_id",
                "is_system_template",
                "created_at",
            }
            safe_updates = {
                key: copy.deepcopy(value)
                for key, value in dict(updates).items()
                if key not in protected_fields
            }

            updated = copy.deepcopy(existing)
            updated.update(safe_updates)
            updated["updated_at"] = datetime.now(timezone.utc).isoformat()

            validation_result = self.validate_template(
                updated,
                user_id=user_id,
                workspace_id=workspace_id,
            )
            if not validation_result["success"]:
                return validation_result

            if self._requires_security_check(updated):
                approval = self._request_security_approval(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    action="update_custom_template",
                    payload={"template_id": template_id, "updates": list(safe_updates.keys())},
                )
                if not approval.get("approved", False):
                    return self._error_result(
                        message="Security approval required before updating this template.",
                        error="security_approval_required",
                        data={"approval": approval},
                        metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
                    )

            self._custom_templates[template_id] = updated

            verification_payload = self._prepare_verification_payload(
                user_id=user_id,
                workspace_id=workspace_id,
                action="update_custom_template",
                data={"template_id": template_id, "updated_fields": list(safe_updates.keys())},
            )

            self._emit_agent_event(
                "workflow_template.updated",
                {"template_id": template_id, "user_id": user_id, "workspace_id": workspace_id},
            )
            self._log_audit_event(
                event_type="workflow_template.update",
                user_id=user_id,
                workspace_id=workspace_id,
                details={"template_id": template_id, "updated_fields": list(safe_updates.keys())},
            )

            return self._safe_result(
                message="Custom workflow template updated successfully.",
                data={
                    "template": copy.deepcopy(updated),
                    "verification_payload": verification_payload,
                },
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to update custom workflow template.",
                error=exc,
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )

    def delete_custom_template(
        self,
        template_id: str,
        *,
        user_id: str,
        workspace_id: str,
        soft_delete: bool = True,
    ) -> Dict[str, Any]:
        """
        Delete or deprecate a custom template.

        soft_delete=True marks the template as deprecated.
        soft_delete=False removes it from the in-memory custom registry.
        """

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            require_context=True,
            operation="delete_custom_template",
        )
        if not context_result["success"]:
            return context_result

        try:
            existing = self._custom_templates.get(template_id)
            if not existing:
                return self._error_result(
                    message="Custom workflow template not found.",
                    error="template_not_found",
                    metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
                )

            if existing.get("user_id") != user_id or existing.get("workspace_id") != workspace_id:
                return self._error_result(
                    message="Custom workflow template is not accessible in this workspace.",
                    error="template_scope_denied",
                    metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
                )

            approval = self._request_security_approval(
                user_id=user_id,
                workspace_id=workspace_id,
                action="delete_custom_template",
                payload={"template_id": template_id, "soft_delete": soft_delete},
            )
            if not approval.get("approved", False):
                return self._error_result(
                    message="Security approval required before deleting this template.",
                    error="security_approval_required",
                    data={"approval": approval},
                    metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
                )

            if soft_delete:
                updated = copy.deepcopy(existing)
                updated["status"] = TemplateStatus.DEPRECATED.value
                updated["updated_at"] = datetime.now(timezone.utc).isoformat()
                self._custom_templates[template_id] = updated
                deleted_data = updated
                message = "Custom workflow template deprecated successfully."
            else:
                deleted_data = self._custom_templates.pop(template_id)
                message = "Custom workflow template deleted successfully."

            verification_payload = self._prepare_verification_payload(
                user_id=user_id,
                workspace_id=workspace_id,
                action="delete_custom_template",
                data={"template_id": template_id, "soft_delete": soft_delete},
            )

            self._emit_agent_event(
                "workflow_template.deleted",
                {
                    "template_id": template_id,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "soft_delete": soft_delete,
                },
            )
            self._log_audit_event(
                event_type="workflow_template.delete",
                user_id=user_id,
                workspace_id=workspace_id,
                details={"template_id": template_id, "soft_delete": soft_delete},
            )

            return self._safe_result(
                message=message,
                data={
                    "template": copy.deepcopy(deleted_data),
                    "verification_payload": verification_payload,
                },
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to delete custom workflow template.",
                error=exc,
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )

    def validate_template(
        self,
        template: Union[Mapping[str, Any], WorkflowTemplate],
        *,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Validate a workflow template without executing it.

        This method is used by:
        - Dashboard template editor
        - Workflow Builder
        - Import/export process
        - Agent Registry health checks
        """

        try:
            template_data = (
                template.to_dict()
                if isinstance(template, WorkflowTemplate)
                else copy.deepcopy(dict(template))
            )

            errors: List[str] = []
            warnings: List[str] = []

            template_id = str(template_data.get("template_id") or "").strip()
            name = str(template_data.get("name") or "").strip()
            category = str(template_data.get("category") or "").strip()
            description = str(template_data.get("description") or "").strip()
            version = str(template_data.get("version") or "").strip()
            status = str(template_data.get("status") or "").strip()
            variables = template_data.get("variables", [])
            steps = template_data.get("steps", [])
            tags = template_data.get("tags", [])

            if not template_id:
                errors.append("template_id is required.")
            elif len(template_id) > 160:
                errors.append("template_id is too long.")

            if not name:
                errors.append("name is required.")
            elif len(name) > MAX_TEMPLATE_NAME_LENGTH:
                errors.append(f"name must be <= {MAX_TEMPLATE_NAME_LENGTH} characters.")

            if not description:
                warnings.append("description is recommended.")
            elif len(description) > MAX_DESCRIPTION_LENGTH:
                errors.append(f"description must be <= {MAX_DESCRIPTION_LENGTH} characters.")

            try:
                self._normalize_enum(category, TemplateCategory, "category")
            except ValueError as exc:
                errors.append(str(exc))

            if not version:
                errors.append("version is required.")

            try:
                self._normalize_enum(status, TemplateStatus, "status")
            except ValueError as exc:
                errors.append(str(exc))

            if not isinstance(variables, list):
                errors.append("variables must be a list.")
                variables = []
            elif len(variables) > MAX_VARIABLES:
                errors.append(f"variables must be <= {MAX_VARIABLES}.")

            if not isinstance(steps, list):
                errors.append("steps must be a list.")
                steps = []
            elif len(steps) > MAX_STEPS:
                errors.append(f"steps must be <= {MAX_STEPS}.")

            if not steps:
                errors.append("at least one workflow step is required.")

            if not isinstance(tags, list):
                errors.append("tags must be a list.")
                tags = []
            elif len(tags) > MAX_TAGS:
                errors.append(f"tags must be <= {MAX_TAGS}.")

            variable_names = self._validate_variables(variables, errors, warnings)
            step_ids = self._validate_steps(steps, errors, warnings)
            self._validate_step_dependencies(steps, step_ids, errors)

            placeholders = self._extract_placeholders(template_data)
            undefined_placeholders = sorted(
                placeholder for placeholder in placeholders if placeholder not in variable_names
            )
            if undefined_placeholders:
                warnings.append(
                    "Undefined placeholders found: "
                    + ", ".join(undefined_placeholders)
                    + ". They must be supplied at render/runtime."
                )

            if template_data.get("is_system_template") is False:
                if not template_data.get("user_id"):
                    errors.append("custom templates require user_id.")
                if not template_data.get("workspace_id"):
                    errors.append("custom templates require workspace_id.")

            if user_id and template_data.get("user_id") and template_data.get("user_id") != user_id:
                errors.append("template user_id does not match task context user_id.")
            if workspace_id and template_data.get("workspace_id") and template_data.get("workspace_id") != workspace_id:
                errors.append("template workspace_id does not match task context workspace_id.")

            risk_level = str(template_data.get("risk_level") or RiskLevel.LOW.value)
            try:
                self._normalize_enum(risk_level, RiskLevel, "risk_level")
            except ValueError as exc:
                errors.append(str(exc))

            requires_security_review = bool(template_data.get("requires_security_review", False))
            high_risk_steps = [
                step
                for step in steps
                if str(step.get("risk_level", RiskLevel.LOW.value)) in {
                    RiskLevel.HIGH.value,
                    RiskLevel.CRITICAL.value,
                }
                or bool(step.get("requires_approval", False))
            ]
            if high_risk_steps and not requires_security_review:
                warnings.append(
                    "Template contains high-risk or approval-required steps; "
                    "requires_security_review is recommended."
                )

            is_valid = not errors

            return self._safe_result(
                success=is_valid,
                message=(
                    "Workflow template validation passed."
                    if is_valid
                    else "Workflow template validation failed."
                ),
                data={
                    "is_valid": is_valid,
                    "errors": errors,
                    "warnings": warnings,
                    "placeholder_count": len(placeholders),
                    "placeholders": sorted(placeholders),
                    "variable_names": sorted(variable_names),
                    "step_ids": sorted(step_ids),
                },
                error=None if is_valid else {"validation_errors": errors},
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to validate workflow template.",
                error=exc,
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )

    def render_template(
        self,
        template_id: str,
        variables: Optional[Mapping[str, Any]] = None,
        *,
        user_id: str,
        workspace_id: str,
        strict_variables: bool = True,
    ) -> Dict[str, Any]:
        """
        Render placeholders in a template using supplied variables.

        Rendering does not execute the workflow. It prepares a ready-to-build
        workflow definition for workflow_builder.py.
        """

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            require_context=True,
            operation="render_template",
        )
        if not context_result["success"]:
            return context_result

        try:
            template = self._find_visible_template(
                template_id=template_id,
                user_id=user_id,
                workspace_id=workspace_id,
            )
            if not template:
                return self._error_result(
                    message="Workflow template not found or not accessible.",
                    error="template_not_found",
                    metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
                )

            runtime_variables = self._merge_template_variables(template, variables or {})
            missing_required = self._missing_required_variables(template, runtime_variables)
            if missing_required:
                return self._error_result(
                    message="Missing required template variables.",
                    error="missing_required_variables",
                    data={"missing_variables": missing_required},
                    metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
                )

            rendered = self._render_value(copy.deepcopy(template), runtime_variables, strict_variables)

            validation_result = self.validate_template(
                rendered,
                user_id=user_id,
                workspace_id=workspace_id,
            )
            if not validation_result["success"]:
                return validation_result

            self._log_audit_event(
                event_type="workflow_template.render",
                user_id=user_id,
                workspace_id=workspace_id,
                details={
                    "template_id": template_id,
                    "variable_keys": sorted(list(runtime_variables.keys())),
                },
            )

            return self._safe_result(
                message="Workflow template rendered successfully.",
                data={
                    "template": rendered,
                    "variables": self._redact_sensitive_variables(template, runtime_variables),
                    "validation": validation_result.get("data"),
                },
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to render workflow template.",
                error=exc,
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )

    def instantiate_template(
        self,
        template_id: str,
        variables: Optional[Mapping[str, Any]] = None,
        *,
        user_id: str,
        workspace_id: str,
        workflow_name: Optional[str] = None,
        created_by: Optional[str] = None,
        dry_run: bool = True,
    ) -> Dict[str, Any]:
        """
        Instantiate a template into a workflow definition.

        This does not schedule or execute the workflow. The returned payload is
        ready for workflow_builder.py or FastAPI/dashboard workflow creation.
        """

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            require_context=True,
            operation="instantiate_template",
        )
        if not context_result["success"]:
            return context_result

        try:
            rendered_result = self.render_template(
                template_id,
                variables or {},
                user_id=user_id,
                workspace_id=workspace_id,
                strict_variables=False,
            )
            if not rendered_result["success"]:
                return rendered_result

            template = rendered_result["data"]["template"]
            workflow_id = self._generate_workflow_id(template_id, user_id, workspace_id)
            now = datetime.now(timezone.utc).isoformat()

            workflow_definition = {
                "workflow_id": workflow_id,
                "template_id": template_id,
                "name": workflow_name or template.get("name"),
                "description": template.get("description"),
                "category": template.get("category"),
                "version": template.get("version"),
                "user_id": user_id,
                "workspace_id": workspace_id,
                "created_by": created_by or user_id,
                "status": "draft" if dry_run else "ready",
                "dry_run": dry_run,
                "steps": template.get("steps", []),
                "variables": rendered_result["data"]["variables"],
                "tags": template.get("tags", []),
                "risk_level": template.get("risk_level", RiskLevel.LOW.value),
                "requires_security_review": template.get("requires_security_review", False),
                "metadata": {
                    "source": FILE_NAME,
                    "module": MODULE_NAME,
                    "instantiated_at": now,
                    "template_name": template.get("name"),
                    "compatible_agents": template.get("compatible_agents", []),
                },
                "created_at": now,
                "updated_at": now,
            }

            if self._requires_security_check(template):
                approval = self._request_security_approval(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    action="instantiate_template",
                    payload={
                        "template_id": template_id,
                        "workflow_id": workflow_id,
                        "dry_run": dry_run,
                    },
                )
                if not approval.get("approved", False):
                    return self._error_result(
                        message="Security approval required before instantiating this workflow template.",
                        error="security_approval_required",
                        data={
                            "workflow_definition": workflow_definition,
                            "approval": approval,
                        },
                        metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
                    )

            verification_payload = self._prepare_verification_payload(
                user_id=user_id,
                workspace_id=workspace_id,
                action="instantiate_template",
                data={
                    "workflow_id": workflow_id,
                    "template_id": template_id,
                    "dry_run": dry_run,
                },
            )
            memory_payload = self._prepare_memory_payload(
                user_id=user_id,
                workspace_id=workspace_id,
                memory_type="workflow_template_instantiated",
                data={
                    "workflow_id": workflow_id,
                    "template_id": template_id,
                    "workflow_name": workflow_definition["name"],
                    "category": workflow_definition["category"],
                },
            )

            self._emit_agent_event(
                "workflow_template.instantiated",
                {
                    "workflow_id": workflow_id,
                    "template_id": template_id,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "dry_run": dry_run,
                },
            )
            self._log_audit_event(
                event_type="workflow_template.instantiate",
                user_id=user_id,
                workspace_id=workspace_id,
                details={
                    "workflow_id": workflow_id,
                    "template_id": template_id,
                    "dry_run": dry_run,
                },
            )

            return self._safe_result(
                message="Workflow template instantiated successfully.",
                data={
                    "workflow_definition": workflow_definition,
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to instantiate workflow template.",
                error=exc,
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )

    def export_template(
        self,
        template_id: str,
        *,
        user_id: str,
        workspace_id: str,
        export_format: str = "dict",
        include_scope: bool = False,
    ) -> Dict[str, Any]:
        """Export a visible template as dict or JSON."""

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            require_context=True,
            operation="export_template",
        )
        if not context_result["success"]:
            return context_result

        try:
            export_format = export_format.lower().strip()
            if export_format not in SUPPORTED_EXPORT_FORMATS:
                return self._error_result(
                    message="Unsupported workflow template export format.",
                    error="unsupported_export_format",
                    data={"supported_formats": sorted(SUPPORTED_EXPORT_FORMATS)},
                    metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
                )

            template = self._find_visible_template(
                template_id=template_id,
                user_id=user_id,
                workspace_id=workspace_id,
            )
            if not template:
                return self._error_result(
                    message="Workflow template not found or not accessible.",
                    error="template_not_found",
                    metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
                )

            exported = copy.deepcopy(template)
            if not include_scope:
                exported.pop("user_id", None)
                exported.pop("workspace_id", None)
                exported["is_system_template"] = False

            export_payload: Union[Dict[str, Any], str]
            if export_format == "json":
                export_payload = json.dumps(exported, indent=2, sort_keys=True)
            else:
                export_payload = exported

            self._log_audit_event(
                event_type="workflow_template.export",
                user_id=user_id,
                workspace_id=workspace_id,
                details={
                    "template_id": template_id,
                    "export_format": export_format,
                    "include_scope": include_scope,
                },
            )

            return self._safe_result(
                message="Workflow template exported successfully.",
                data={
                    "export_format": export_format,
                    "template_id": template_id,
                    "export": export_payload,
                },
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to export workflow template.",
                error=exc,
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )

    def import_template(
        self,
        template_payload: Union[str, Mapping[str, Any]],
        *,
        user_id: str,
        workspace_id: str,
        created_by: Optional[str] = None,
        overwrite: bool = False,
    ) -> Dict[str, Any]:
        """Import a template as a workspace-scoped custom template."""

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            require_context=True,
            operation="import_template",
        )
        if not context_result["success"]:
            return context_result

        try:
            if isinstance(template_payload, str):
                template_data = json.loads(template_payload)
            else:
                template_data = copy.deepcopy(dict(template_payload))

            if not isinstance(template_data, dict):
                return self._error_result(
                    message="Imported workflow template must be an object.",
                    error="invalid_import_payload",
                    metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
                )

            original_id = str(template_data.get("template_id") or "").strip()
            if not original_id:
                template_data["template_id"] = self._generate_template_id(template_data)
            elif original_id in self._system_templates:
                template_data["template_id"] = f"custom_{original_id}_{uuid.uuid4().hex[:8]}"

            template_id = str(template_data["template_id"])
            existing = self._custom_templates.get(template_id)

            if existing and not overwrite:
                return self._error_result(
                    message="A custom template with this ID already exists. Use overwrite=True to replace it.",
                    error="template_already_exists",
                    data={"template_id": template_id},
                    metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
                )

            create_result = self.create_custom_template(
                template_data,
                user_id=user_id,
                workspace_id=workspace_id,
                created_by=created_by or user_id,
            )
            if not create_result["success"]:
                return create_result

            self._log_audit_event(
                event_type="workflow_template.import",
                user_id=user_id,
                workspace_id=workspace_id,
                details={"template_id": create_result["data"]["template"]["template_id"]},
            )

            return self._safe_result(
                message="Workflow template imported successfully.",
                data=create_result["data"],
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )
        except json.JSONDecodeError as exc:
            return self._error_result(
                message="Failed to import workflow template because JSON is invalid.",
                error=exc,
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to import workflow template.",
                error=exc,
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )

    def clone_system_template(
        self,
        template_id: str,
        *,
        user_id: str,
        workspace_id: str,
        new_name: Optional[str] = None,
        created_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Clone a system template into a custom user/workspace template."""

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            require_context=True,
            operation="clone_system_template",
        )
        if not context_result["success"]:
            return context_result

        try:
            system_template = self._system_templates.get(template_id)
            if not system_template:
                return self._error_result(
                    message="System workflow template not found.",
                    error="system_template_not_found",
                    metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
                )

            cloned = copy.deepcopy(system_template)
            cloned["template_id"] = f"custom_{template_id}_{uuid.uuid4().hex[:8]}"
            cloned["name"] = new_name or f"{system_template.get('name')} Copy"
            cloned["is_system_template"] = False
            cloned["user_id"] = user_id
            cloned["workspace_id"] = workspace_id
            cloned["created_by"] = created_by or user_id
            cloned["created_at"] = datetime.now(timezone.utc).isoformat()
            cloned["updated_at"] = datetime.now(timezone.utc).isoformat()

            return self.create_custom_template(
                cloned,
                user_id=user_id,
                workspace_id=workspace_id,
                created_by=created_by or user_id,
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to clone system workflow template.",
                error=exc,
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )

    def health_check(self) -> Dict[str, Any]:
        """Agent Registry / Loader compatible health check."""

        try:
            validation_errors: Dict[str, Any] = {}
            for template_id, template in self._system_templates.items():
                validation = self.validate_template(template)
                if not validation["success"]:
                    validation_errors[template_id] = validation.get("data", {}).get("errors", [])

            healthy = not validation_errors

            return self._safe_result(
                success=healthy,
                message=(
                    "WorkflowTemplates health check passed."
                    if healthy
                    else "WorkflowTemplates health check found template validation errors."
                ),
                data={
                    "healthy": healthy,
                    "system_template_count": len(self._system_templates),
                    "custom_template_count": len(self._custom_templates),
                    "validation_errors": validation_errors,
                },
                error=None if healthy else validation_errors,
                metadata=self._base_metadata(),
            )
        except Exception as exc:
            return self._error_result(
                message="WorkflowTemplates health check failed.",
                error=exc,
                metadata=self._base_metadata(),
            )

    # ------------------------------------------------------------------
    # Required compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(
        self,
        *,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        require_context: bool = True,
        operation: str = "unknown",
    ) -> Dict[str, Any]:
        """
        Validate SaaS user/workspace isolation context.

        This hook is used by Master Agent / Agent Router compatible methods.
        """

        errors: List[str] = []

        if require_context:
            if not self._is_safe_identifier(user_id):
                errors.append("A valid user_id is required.")
            if not self._is_safe_identifier(workspace_id):
                errors.append("A valid workspace_id is required.")

        if errors:
            return self._error_result(
                message="Invalid workflow template task context.",
                error={"context_errors": errors},
                data={"operation": operation},
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )

        return self._safe_result(
            message="Workflow template task context validated.",
            data={
                "operation": operation,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "context_required": require_context,
            },
            metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
        )

    def _requires_security_check(self, payload: Mapping[str, Any]) -> bool:
        """
        Determine if Security Agent approval is required.

        Templates with high/critical risk, explicit security review, approval
        steps, outbound messaging actions, financial actions, destructive
        actions, or external browser/system actions should be security-gated.
        """

        risk_level = str(payload.get("risk_level") or RiskLevel.LOW.value)
        if risk_level in {RiskLevel.HIGH.value, RiskLevel.CRITICAL.value}:
            return True

        if bool(payload.get("requires_security_review", False)):
            return True

        sensitive_actions = {
            "send_email",
            "send_whatsapp",
            "send_sms",
            "make_call",
            "charge_customer",
            "issue_refund",
            "delete_record",
            "archive_record",
            "browser_submit",
            "system_command",
            "external_api_write",
            "crm_update_deal",
            "crm_create_contact",
        }

        for step in payload.get("steps", []) or []:
            if not isinstance(step, Mapping):
                continue
            if bool(step.get("requires_approval", False)):
                return True
            if str(step.get("risk_level") or RiskLevel.LOW.value) in {
                RiskLevel.HIGH.value,
                RiskLevel.CRITICAL.value,
            }:
                return True
            action = str(step.get("action") or "").strip()
            if action in sensitive_actions:
                return True

        return False

    def _request_security_approval(
        self,
        *,
        user_id: Optional[str],
        workspace_id: Optional[str],
        action: str,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        If a security_client is attached, the request is forwarded.
        Otherwise, safe low/medium operations are auto-approved and risky
        operations return approval_required.
        """

        approval_request = {
            "request_id": f"sec_{uuid.uuid4().hex}",
            "agent": self.agent_name,
            "module": MODULE_NAME,
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "payload": copy.deepcopy(dict(payload)),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        try:
            if self.security_client and hasattr(self.security_client, "request_approval"):
                response = self.security_client.request_approval(approval_request)
                if isinstance(response, Mapping):
                    return dict(response)

            risk_level = str(payload.get("risk_level") or RiskLevel.LOW.value)
            approval_required = risk_level in {RiskLevel.HIGH.value, RiskLevel.CRITICAL.value}

            return {
                "approved": not approval_required,
                "approval_required": approval_required,
                "request": approval_request,
                "mode": "fallback",
                "message": (
                    "Fallback security approval granted."
                    if not approval_required
                    else "Fallback security approval required."
                ),
            }
        except Exception as exc:
            self.logger.exception("Security approval request failed: %s", exc)
            return {
                "approved": False,
                "approval_required": True,
                "request": approval_request,
                "error": str(exc),
                "mode": "error",
            }

    def _prepare_verification_payload(
        self,
        *,
        user_id: Optional[str],
        workspace_id: Optional[str],
        action: str,
        data: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        Other Workflow Agent components can pass this payload to the
        Verification Agent after workflow/template operations.
        """

        payload = {
            "verification_id": f"ver_{uuid.uuid4().hex}",
            "source_agent": self.agent_name,
            "module": MODULE_NAME,
            "file": FILE_NAME,
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "data": copy.deepcopy(dict(data)),
            "checks": [
                "saas_context_present",
                "template_schema_valid",
                "security_gate_considered",
                "no_direct_external_execution",
            ],
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        try:
            if self.verification_client and hasattr(self.verification_client, "prepare"):
                prepared = self.verification_client.prepare(payload)
                if isinstance(prepared, Mapping):
                    return dict(prepared)
        except Exception as exc:
            self.logger.warning("Verification payload client failed: %s", exc)

        return payload

    def _prepare_memory_payload(
        self,
        *,
        user_id: Optional[str],
        workspace_id: Optional[str],
        memory_type: str,
        data: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        This does not write memory directly unless an injected memory_client
        supports a safe prepare_memory method.
        """

        payload = {
            "memory_id": f"mem_{uuid.uuid4().hex}",
            "source_agent": self.agent_name,
            "module": MODULE_NAME,
            "memory_type": memory_type,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "data": copy.deepcopy(dict(data)),
            "privacy_scope": "workspace",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        try:
            if self.memory_client and hasattr(self.memory_client, "prepare_memory"):
                prepared = self.memory_client.prepare_memory(payload)
                if isinstance(prepared, Mapping):
                    return dict(prepared)
        except Exception as exc:
            self.logger.warning("Memory payload client failed: %s", exc)

        return payload

    def _emit_agent_event(self, event_name: str, payload: Mapping[str, Any]) -> None:
        """
        Emit an Agent Registry / dashboard compatible event.

        This hook is intentionally non-fatal.
        """

        event_payload = {
            "event_id": f"evt_{uuid.uuid4().hex}",
            "event_name": event_name,
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "module": MODULE_NAME,
            "file": FILE_NAME,
            "payload": copy.deepcopy(dict(payload)),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        try:
            if self.event_emitter:
                self.event_emitter(event_name, event_payload)
                return
            if hasattr(super(), "emit_event"):
                try:
                    super().emit_event(event_name, event_payload)  # type: ignore[misc]
                    return
                except Exception:
                    pass
            self.logger.debug("Agent event emitted: %s | %s", event_name, event_payload)
        except Exception as exc:
            self.logger.warning("Agent event emission failed: %s", exc)

    def _log_audit_event(
        self,
        *,
        event_type: str,
        user_id: Optional[str],
        workspace_id: Optional[str],
        details: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Log audit event for SaaS traceability.

        This hook is intentionally non-fatal and does not expose secrets.
        """

        audit_payload = {
            "audit_id": f"aud_{uuid.uuid4().hex}",
            "event_type": event_type,
            "agent": self.agent_name,
            "module": MODULE_NAME,
            "file": FILE_NAME,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "details": self._redact_value(copy.deepcopy(dict(details or {}))),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        try:
            if self.audit_logger:
                self.audit_logger(audit_payload)
                return
            if hasattr(super(), "log_audit"):
                try:
                    super().log_audit(audit_payload)  # type: ignore[misc]
                    return
                except Exception:
                    pass
            self.logger.info("Audit event: %s", audit_payload)
        except Exception as exc:
            self.logger.warning("Audit logging failed: %s", exc)

    def _safe_result(
        self,
        *,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        error: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        success: bool = True,
    ) -> Dict[str, Any]:
        """Return a structured dict/JSON-style success result."""

        return {
            "success": bool(success),
            "message": message,
            "data": copy.deepcopy(dict(data or {})),
            "error": error,
            "metadata": copy.deepcopy(dict(metadata or self._base_metadata())),
        }

    def _error_result(
        self,
        *,
        message: str,
        error: Any,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return a structured dict/JSON-style error result."""

        error_payload: Any
        if isinstance(error, Exception):
            error_payload = {
                "type": error.__class__.__name__,
                "message": str(error),
            }
        else:
            error_payload = error

        return {
            "success": False,
            "message": message,
            "data": copy.deepcopy(dict(data or {})),
            "error": error_payload,
            "metadata": copy.deepcopy(dict(metadata or self._base_metadata())),
        }

    # ------------------------------------------------------------------
    # Built-in workflow templates
    # ------------------------------------------------------------------

    def _load_builtin_templates(self) -> Dict[str, Dict[str, Any]]:
        """Load production-ready built-in reusable templates."""

        templates = [
            self._lead_capture_to_crm_template(),
            self._lead_followup_sequence_template(),
            self._weekly_performance_report_template(),
            self._daily_sales_report_template(),
            self._support_ticket_intake_template(),
            self._support_escalation_template(),
            self._appointment_reminder_template(),
            self._task_due_reminder_template(),
        ]

        return {template["template_id"]: template for template in templates}

    def _lead_capture_to_crm_template(self) -> Dict[str, Any]:
        return WorkflowTemplate(
            template_id="tpl_leads_capture_validate_crm_notify",
            name="Lead Capture → Validate → CRM → Notify",
            category=TemplateCategory.LEADS.value,
            description=(
                "Captures an inbound lead from a form or webhook, validates required "
                "fields, checks duplicates, prepares CRM contact/deal creation, sends "
                "an internal notification, and prepares verification and memory payloads."
            ),
            version=DEFAULT_TEMPLATE_VERSION,
            status=TemplateStatus.ACTIVE.value,
            tags=["lead", "form", "crm", "notification", "duplicate-check"],
            risk_level=RiskLevel.MEDIUM.value,
            requires_security_review=True,
            compatible_agents=[
                "WorkflowAgent",
                "SecurityAgent",
                "VerificationAgent",
                "MemoryAgent",
                "BusinessAgent",
            ],
            variables=[
                WorkflowVariable(
                    name="lead_source",
                    label="Lead Source",
                    required=True,
                    default="website_form",
                    description="Source channel such as website_form, webhook, landing_page, or manual.",
                ),
                WorkflowVariable(
                    name="notification_channel",
                    label="Internal Notification Channel",
                    required=True,
                    default="dashboard",
                    choices=["dashboard", "email", "whatsapp", "slack"],
                    description="Where internal team notification should be routed.",
                ),
                WorkflowVariable(
                    name="crm_pipeline",
                    label="CRM Pipeline",
                    required=False,
                    default="new_leads",
                    description="CRM pipeline or board key.",
                ),
            ],
            steps=[
                WorkflowStep(
                    step_id="trigger_lead_received",
                    name="Lead Received",
                    step_type=StepType.TRIGGER.value,
                    agent="WorkflowAgent",
                    action="receive_trigger",
                    config={"source": "{{lead_source}}"},
                    output_key="raw_lead",
                    description="Accepts lead payload from Trigger Engine.",
                ),
                WorkflowStep(
                    step_id="validate_lead",
                    name="Validate Lead Fields",
                    step_type=StepType.VALIDATION.value,
                    agent="WorkflowAgent",
                    action="validate_payload",
                    depends_on=["trigger_lead_received"],
                    config={
                        "required_fields": ["full_name", "phone"],
                        "optional_fields": ["email", "company", "message", "service_interest"],
                        "normalize_phone": True,
                    },
                    output_key="validated_lead",
                    description="Validates lead fields while preserving SaaS isolation.",
                ),
                WorkflowStep(
                    step_id="duplicate_check",
                    name="Check Duplicate Lead",
                    step_type=StepType.CONDITION.value,
                    agent="WorkflowAgent",
                    action="check_duplicate",
                    depends_on=["validate_lead"],
                    config={
                        "match_fields": ["phone", "email"],
                        "scope": "workspace",
                        "on_duplicate": "route_to_existing_record",
                    },
                    output_key="duplicate_status",
                    description="Checks duplicate leads within the same workspace only.",
                ),
                WorkflowStep(
                    step_id="prepare_crm_contact",
                    name="Prepare CRM Contact",
                    step_type=StepType.ACTION.value,
                    connector="crm_connector",
                    action="crm_create_contact",
                    depends_on=["duplicate_check"],
                    requires_approval=True,
                    risk_level=RiskLevel.HIGH.value,
                    config={
                        "pipeline": "{{crm_pipeline}}",
                        "dedupe_key": "phone",
                        "mode": "prepare_only",
                    },
                    output_key="crm_contact_payload",
                    description="Prepares CRM contact creation; execution requires approval.",
                ),
                WorkflowStep(
                    step_id="notify_team",
                    name="Notify Internal Team",
                    step_type=StepType.NOTIFICATION.value,
                    connector="notification_engine",
                    action="send_internal_alert",
                    depends_on=["prepare_crm_contact"],
                    requires_approval=True,
                    risk_level=RiskLevel.MEDIUM.value,
                    config={
                        "channel": "{{notification_channel}}",
                        "template": "new_lead_alert",
                        "mode": "prepare_only",
                    },
                    output_key="notification_payload",
                    description="Prepares internal alert for a new lead.",
                ),
                WorkflowStep(
                    step_id="prepare_memory",
                    name="Prepare Lead Memory",
                    step_type=StepType.MEMORY.value,
                    agent="MemoryAgent",
                    action="prepare_memory_payload",
                    depends_on=["notify_team"],
                    config={"memory_type": "lead_intake_summary", "scope": "workspace"},
                    output_key="memory_payload",
                ),
                WorkflowStep(
                    step_id="prepare_verification",
                    name="Prepare Verification",
                    step_type=StepType.VERIFICATION.value,
                    agent="VerificationAgent",
                    action="prepare_verification_payload",
                    depends_on=["prepare_memory"],
                    config={"checks": ["lead_validated", "crm_payload_prepared", "notification_prepared"]},
                    output_key="verification_payload",
                ),
            ],
            metadata={
                "dashboard_icon": "user-plus",
                "recommended_for": ["website forms", "landing pages", "lead generation"],
                "execution_note": "External actions must be routed through approval_gate/action_router.",
            },
        ).to_dict()

    def _lead_followup_sequence_template(self) -> Dict[str, Any]:
        return WorkflowTemplate(
            template_id="tpl_leads_followup_sequence",
            name="Lead Follow-Up Sequence",
            category=TemplateCategory.LEADS.value,
            description=(
                "Creates a safe staged follow-up workflow for new leads. It prepares "
                "email/WhatsApp follow-ups, waits between steps, records touchpoints, "
                "and stops when a response or manual close condition is detected."
            ),
            version=DEFAULT_TEMPLATE_VERSION,
            status=TemplateStatus.ACTIVE.value,
            tags=["lead", "follow-up", "email", "whatsapp", "sequence"],
            risk_level=RiskLevel.HIGH.value,
            requires_security_review=True,
            compatible_agents=[
                "WorkflowAgent",
                "SecurityAgent",
                "VerificationAgent",
                "MemoryAgent",
                "BusinessAgent",
            ],
            variables=[
                WorkflowVariable(
                    name="first_wait_hours",
                    label="First Wait Hours",
                    var_type="integer",
                    required=True,
                    default=24,
                ),
                WorkflowVariable(
                    name="second_wait_hours",
                    label="Second Wait Hours",
                    var_type="integer",
                    required=True,
                    default=72,
                ),
                WorkflowVariable(
                    name="followup_channel",
                    label="Follow-Up Channel",
                    required=True,
                    default="email",
                    choices=["email", "whatsapp", "dashboard_task"],
                ),
                WorkflowVariable(
                    name="offer_name",
                    label="Offer Name",
                    required=False,
                    default="consultation",
                ),
            ],
            steps=[
                WorkflowStep(
                    step_id="trigger_new_lead_ready",
                    name="New Lead Ready for Follow-Up",
                    step_type=StepType.TRIGGER.value,
                    agent="WorkflowAgent",
                    action="manual_or_crm_trigger",
                    config={"allowed_statuses": ["new", "qualified"]},
                    output_key="lead_record",
                ),
                WorkflowStep(
                    step_id="security_precheck",
                    name="Security Precheck",
                    step_type=StepType.APPROVAL.value,
                    agent="SecurityAgent",
                    action="request_approval",
                    depends_on=["trigger_new_lead_ready"],
                    requires_approval=True,
                    risk_level=RiskLevel.HIGH.value,
                    config={"reason": "Outbound lead follow-up sequence"},
                    output_key="approval_status",
                ),
                WorkflowStep(
                    step_id="first_followup",
                    name="Prepare First Follow-Up",
                    step_type=StepType.ACTION.value,
                    connector="email_connector",
                    action="send_email",
                    depends_on=["security_precheck"],
                    requires_approval=True,
                    risk_level=RiskLevel.HIGH.value,
                    config={
                        "channel": "{{followup_channel}}",
                        "template": "lead_first_followup",
                        "offer_name": "{{offer_name}}",
                        "mode": "prepare_only",
                    },
                    output_key="first_followup_payload",
                ),
                WorkflowStep(
                    step_id="wait_after_first",
                    name="Wait After First Follow-Up",
                    step_type=StepType.WAIT.value,
                    connector="scheduler",
                    action="delay",
                    depends_on=["first_followup"],
                    config={"hours": "{{first_wait_hours}}"},
                    output_key="first_wait_status",
                ),
                WorkflowStep(
                    step_id="check_response",
                    name="Check Lead Response",
                    step_type=StepType.CONDITION.value,
                    agent="WorkflowAgent",
                    action="check_condition",
                    depends_on=["wait_after_first"],
                    config={
                        "condition": "lead_has_replied_or_status_changed",
                        "if_true": "stop_sequence",
                        "if_false": "continue_sequence",
                    },
                    output_key="response_status",
                ),
                WorkflowStep(
                    step_id="second_followup",
                    name="Prepare Second Follow-Up",
                    step_type=StepType.ACTION.value,
                    connector="email_connector",
                    action="send_email",
                    depends_on=["check_response"],
                    requires_approval=True,
                    risk_level=RiskLevel.HIGH.value,
                    config={
                        "channel": "{{followup_channel}}",
                        "template": "lead_second_followup",
                        "mode": "prepare_only",
                    },
                    output_key="second_followup_payload",
                ),
                WorkflowStep(
                    step_id="wait_after_second",
                    name="Wait After Second Follow-Up",
                    step_type=StepType.WAIT.value,
                    connector="scheduler",
                    action="delay",
                    depends_on=["second_followup"],
                    config={"hours": "{{second_wait_hours}}"},
                    output_key="second_wait_status",
                ),
                WorkflowStep(
                    step_id="create_manual_task",
                    name="Create Manual Sales Task",
                    step_type=StepType.ACTION.value,
                    connector="crm_connector",
                    action="crm_create_task",
                    depends_on=["wait_after_second"],
                    requires_approval=False,
                    risk_level=RiskLevel.MEDIUM.value,
                    config={"task_type": "manual_followup", "priority": "normal"},
                    output_key="sales_task_payload",
                ),
                WorkflowStep(
                    step_id="verification",
                    name="Prepare Verification",
                    step_type=StepType.VERIFICATION.value,
                    agent="VerificationAgent",
                    action="prepare_verification_payload",
                    depends_on=["create_manual_task"],
                    config={"checks": ["approval_checked", "followups_prepared", "manual_task_prepared"]},
                    output_key="verification_payload",
                ),
            ],
            metadata={
                "dashboard_icon": "send",
                "recommended_for": ["sales teams", "lead nurturing", "agency pipelines"],
            },
        ).to_dict()

    def _weekly_performance_report_template(self) -> Dict[str, Any]:
        return WorkflowTemplate(
            template_id="tpl_reports_weekly_performance",
            name="Weekly Performance Report",
            category=TemplateCategory.REPORTS.value,
            description=(
                "Collects workspace metrics, builds a weekly report payload, prepares "
                "dashboard/email delivery, stores report memory, and generates "
                "verification payload."
            ),
            version=DEFAULT_TEMPLATE_VERSION,
            status=TemplateStatus.ACTIVE.value,
            tags=["report", "weekly", "analytics", "dashboard", "email"],
            risk_level=RiskLevel.MEDIUM.value,
            requires_security_review=True,
            compatible_agents=[
                "WorkflowAgent",
                "BusinessAgent",
                "FinanceAgent",
                "VerificationAgent",
                "MemoryAgent",
            ],
            variables=[
                WorkflowVariable(
                    name="report_day",
                    label="Report Day",
                    required=True,
                    default="monday",
                    choices=["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"],
                ),
                WorkflowVariable(
                    name="delivery_channel",
                    label="Delivery Channel",
                    required=True,
                    default="dashboard",
                    choices=["dashboard", "email", "slack"],
                ),
                WorkflowVariable(
                    name="include_finance",
                    label="Include Finance Metrics",
                    var_type="boolean",
                    required=True,
                    default=False,
                ),
            ],
            steps=[
                WorkflowStep(
                    step_id="schedule_weekly_report",
                    name="Scheduled Weekly Report Trigger",
                    step_type=StepType.TRIGGER.value,
                    connector="scheduler",
                    action="schedule_recurring",
                    config={"frequency": "weekly", "day": "{{report_day}}"},
                    output_key="schedule_trigger",
                ),
                WorkflowStep(
                    step_id="collect_workflow_metrics",
                    name="Collect Workflow Metrics",
                    step_type=StepType.REPORT.value,
                    connector="workflow_monitor",
                    action="collect_metrics",
                    depends_on=["schedule_weekly_report"],
                    config={
                        "period": "last_7_days",
                        "metrics": ["runs", "success_rate", "failures", "retries", "average_duration"],
                    },
                    output_key="workflow_metrics",
                ),
                WorkflowStep(
                    step_id="collect_business_metrics",
                    name="Collect Business Metrics",
                    step_type=StepType.REPORT.value,
                    agent="BusinessAgent",
                    action="prepare_business_summary",
                    depends_on=["collect_workflow_metrics"],
                    config={"period": "last_7_days"},
                    output_key="business_metrics",
                ),
                WorkflowStep(
                    step_id="collect_finance_metrics",
                    name="Collect Finance Metrics",
                    step_type=StepType.CONDITION.value,
                    agent="FinanceAgent",
                    action="prepare_finance_summary",
                    depends_on=["collect_business_metrics"],
                    requires_approval=True,
                    risk_level=RiskLevel.HIGH.value,
                    config={
                        "enabled": "{{include_finance}}",
                        "period": "last_7_days",
                        "mode": "prepare_only",
                    },
                    output_key="finance_metrics",
                ),
                WorkflowStep(
                    step_id="build_report",
                    name="Build Report Payload",
                    step_type=StepType.REPORT.value,
                    agent="WorkflowAgent",
                    action="build_report_payload",
                    depends_on=["collect_finance_metrics"],
                    config={"format": "dashboard_card_and_email_summary"},
                    output_key="report_payload",
                ),
                WorkflowStep(
                    step_id="deliver_report",
                    name="Prepare Report Delivery",
                    step_type=StepType.NOTIFICATION.value,
                    connector="notification_engine",
                    action="send_internal_alert",
                    depends_on=["build_report"],
                    requires_approval=True,
                    risk_level=RiskLevel.MEDIUM.value,
                    config={
                        "channel": "{{delivery_channel}}",
                        "template": "weekly_performance_report",
                        "mode": "prepare_only",
                    },
                    output_key="delivery_payload",
                ),
                WorkflowStep(
                    step_id="memory",
                    name="Prepare Report Memory",
                    step_type=StepType.MEMORY.value,
                    agent="MemoryAgent",
                    action="prepare_memory_payload",
                    depends_on=["deliver_report"],
                    config={"memory_type": "weekly_performance_report", "scope": "workspace"},
                    output_key="memory_payload",
                ),
                WorkflowStep(
                    step_id="verification",
                    name="Prepare Verification",
                    step_type=StepType.VERIFICATION.value,
                    agent="VerificationAgent",
                    action="prepare_verification_payload",
                    depends_on=["memory"],
                    config={"checks": ["metrics_collected", "report_built", "delivery_prepared"]},
                    output_key="verification_payload",
                ),
            ],
            metadata={
                "dashboard_icon": "bar-chart-3",
                "recommended_for": ["agency reporting", "workspace dashboards", "weekly reviews"],
            },
        ).to_dict()

    def _daily_sales_report_template(self) -> Dict[str, Any]:
        return WorkflowTemplate(
            template_id="tpl_reports_daily_sales",
            name="Daily Sales Report",
            category=TemplateCategory.REPORTS.value,
            description=(
                "Prepares daily sales activity summary including leads, qualified "
                "opportunities, CRM stage changes, follow-ups due, and dashboard summary."
            ),
            version=DEFAULT_TEMPLATE_VERSION,
            status=TemplateStatus.ACTIVE.value,
            tags=["report", "daily", "sales", "crm", "leads"],
            risk_level=RiskLevel.MEDIUM.value,
            requires_security_review=False,
            compatible_agents=["WorkflowAgent", "BusinessAgent", "VerificationAgent", "MemoryAgent"],
            variables=[
                WorkflowVariable(
                    name="report_time",
                    label="Report Time",
                    required=True,
                    default="18:00",
                    description="Local workspace report time in HH:MM format.",
                ),
                WorkflowVariable(
                    name="delivery_channel",
                    label="Delivery Channel",
                    required=True,
                    default="dashboard",
                    choices=["dashboard", "email", "slack"],
                ),
            ],
            steps=[
                WorkflowStep(
                    step_id="schedule_daily_sales_report",
                    name="Scheduled Daily Sales Report Trigger",
                    step_type=StepType.TRIGGER.value,
                    connector="scheduler",
                    action="schedule_recurring",
                    config={"frequency": "daily", "time": "{{report_time}}"},
                    output_key="schedule_trigger",
                ),
                WorkflowStep(
                    step_id="collect_sales_metrics",
                    name="Collect Sales Metrics",
                    step_type=StepType.REPORT.value,
                    connector="crm_connector",
                    action="crm_prepare_sales_summary",
                    depends_on=["schedule_daily_sales_report"],
                    config={
                        "period": "today",
                        "metrics": ["new_leads", "qualified_leads", "won_deals", "lost_deals", "followups_due"],
                        "mode": "read_only",
                    },
                    output_key="sales_metrics",
                ),
                WorkflowStep(
                    step_id="build_daily_summary",
                    name="Build Daily Sales Summary",
                    step_type=StepType.REPORT.value,
                    agent="BusinessAgent",
                    action="prepare_daily_sales_summary",
                    depends_on=["collect_sales_metrics"],
                    config={"format": "short_executive_summary"},
                    output_key="sales_summary",
                ),
                WorkflowStep(
                    step_id="deliver_summary",
                    name="Prepare Summary Delivery",
                    step_type=StepType.NOTIFICATION.value,
                    connector="notification_engine",
                    action="send_internal_alert",
                    depends_on=["build_daily_summary"],
                    requires_approval=False,
                    risk_level=RiskLevel.MEDIUM.value,
                    config={
                        "channel": "{{delivery_channel}}",
                        "template": "daily_sales_report",
                        "mode": "prepare_only",
                    },
                    output_key="delivery_payload",
                ),
                WorkflowStep(
                    step_id="verification",
                    name="Prepare Verification",
                    step_type=StepType.VERIFICATION.value,
                    agent="VerificationAgent",
                    action="prepare_verification_payload",
                    depends_on=["deliver_summary"],
                    config={"checks": ["sales_metrics_collected", "summary_prepared"]},
                    output_key="verification_payload",
                ),
            ],
            metadata={
                "dashboard_icon": "line-chart",
                "recommended_for": ["sales dashboards", "daily agency reporting"],
            },
        ).to_dict()

    def _support_ticket_intake_template(self) -> Dict[str, Any]:
        return WorkflowTemplate(
            template_id="tpl_support_ticket_intake",
            name="Support Ticket Intake",
            category=TemplateCategory.SUPPORT.value,
            description=(
                "Receives a support request, validates ticket data, classifies priority, "
                "creates a workspace-scoped ticket payload, notifies the support team, "
                "and prepares memory/verification records."
            ),
            version=DEFAULT_TEMPLATE_VERSION,
            status=TemplateStatus.ACTIVE.value,
            tags=["support", "ticket", "classification", "notification"],
            risk_level=RiskLevel.MEDIUM.value,
            requires_security_review=False,
            compatible_agents=["WorkflowAgent", "BusinessAgent", "VerificationAgent", "MemoryAgent"],
            variables=[
                WorkflowVariable(
                    name="support_channel",
                    label="Support Channel",
                    required=True,
                    default="website_form",
                    choices=["website_form", "email", "dashboard", "webhook"],
                ),
                WorkflowVariable(
                    name="default_priority",
                    label="Default Priority",
                    required=True,
                    default="normal",
                    choices=["low", "normal", "high", "urgent"],
                ),
                WorkflowVariable(
                    name="notify_channel",
                    label="Notify Channel",
                    required=True,
                    default="dashboard",
                    choices=["dashboard", "email", "slack"],
                ),
            ],
            steps=[
                WorkflowStep(
                    step_id="trigger_support_request",
                    name="Support Request Received",
                    step_type=StepType.TRIGGER.value,
                    agent="WorkflowAgent",
                    action="receive_trigger",
                    config={"source": "{{support_channel}}"},
                    output_key="support_request",
                ),
                WorkflowStep(
                    step_id="validate_ticket",
                    name="Validate Ticket Fields",
                    step_type=StepType.VALIDATION.value,
                    agent="WorkflowAgent",
                    action="validate_payload",
                    depends_on=["trigger_support_request"],
                    config={
                        "required_fields": ["customer_name", "message"],
                        "optional_fields": ["email", "phone", "account_id", "attachments", "product"],
                    },
                    output_key="validated_ticket",
                ),
                WorkflowStep(
                    step_id="classify_ticket",
                    name="Classify Ticket",
                    step_type=StepType.ACTION.value,
                    agent="BusinessAgent",
                    action="classify_support_ticket",
                    depends_on=["validate_ticket"],
                    config={
                        "default_priority": "{{default_priority}}",
                        "classification_labels": ["billing", "technical", "sales", "account", "other"],
                    },
                    output_key="ticket_classification",
                ),
                WorkflowStep(
                    step_id="prepare_ticket_record",
                    name="Prepare Ticket Record",
                    step_type=StepType.ACTION.value,
                    connector="crm_connector",
                    action="crm_create_task",
                    depends_on=["classify_ticket"],
                    requires_approval=False,
                    risk_level=RiskLevel.MEDIUM.value,
                    config={
                        "record_type": "support_ticket",
                        "mode": "prepare_only",
                        "scope": "workspace",
                    },
                    output_key="ticket_payload",
                ),
                WorkflowStep(
                    step_id="notify_support",
                    name="Notify Support Team",
                    step_type=StepType.NOTIFICATION.value,
                    connector="notification_engine",
                    action="send_internal_alert",
                    depends_on=["prepare_ticket_record"],
                    requires_approval=False,
                    risk_level=RiskLevel.MEDIUM.value,
                    config={
                        "channel": "{{notify_channel}}",
                        "template": "new_support_ticket",
                        "mode": "prepare_only",
                    },
                    output_key="support_notification",
                ),
                WorkflowStep(
                    step_id="memory",
                    name="Prepare Ticket Memory",
                    step_type=StepType.MEMORY.value,
                    agent="MemoryAgent",
                    action="prepare_memory_payload",
                    depends_on=["notify_support"],
                    config={"memory_type": "support_ticket_intake", "scope": "workspace"},
                    output_key="memory_payload",
                ),
                WorkflowStep(
                    step_id="verification",
                    name="Prepare Verification",
                    step_type=StepType.VERIFICATION.value,
                    agent="VerificationAgent",
                    action="prepare_verification_payload",
                    depends_on=["memory"],
                    config={"checks": ["ticket_validated", "ticket_classified", "team_notified"]},
                    output_key="verification_payload",
                ),
            ],
            metadata={
                "dashboard_icon": "life-buoy",
                "recommended_for": ["support desks", "client portals", "service teams"],
            },
        ).to_dict()

    def _support_escalation_template(self) -> Dict[str, Any]:
        return WorkflowTemplate(
            template_id="tpl_support_escalation",
            name="Support Escalation",
            category=TemplateCategory.SUPPORT.value,
            description=(
                "Escalates high-priority or overdue support tickets to the right team, "
                "prepares notifications, creates escalation audit data, and prepares "
                "verification payload."
            ),
            version=DEFAULT_TEMPLATE_VERSION,
            status=TemplateStatus.ACTIVE.value,
            tags=["support", "escalation", "sla", "urgent"],
            risk_level=RiskLevel.MEDIUM.value,
            requires_security_review=False,
            compatible_agents=["WorkflowAgent", "BusinessAgent", "VerificationAgent"],
            variables=[
                WorkflowVariable(
                    name="sla_hours",
                    label="SLA Hours",
                    var_type="integer",
                    required=True,
                    default=24,
                ),
                WorkflowVariable(
                    name="escalation_channel",
                    label="Escalation Channel",
                    required=True,
                    default="dashboard",
                    choices=["dashboard", "email", "slack"],
                ),
                WorkflowVariable(
                    name="escalation_priority",
                    label="Escalation Priority",
                    required=True,
                    default="high",
                    choices=["high", "urgent"],
                ),
            ],
            steps=[
                WorkflowStep(
                    step_id="trigger_sla_check",
                    name="SLA Check Trigger",
                    step_type=StepType.TRIGGER.value,
                    connector="scheduler",
                    action="schedule_recurring",
                    config={"frequency": "hourly", "lookback_hours": "{{sla_hours}}"},
                    output_key="sla_trigger",
                ),
                WorkflowStep(
                    step_id="find_overdue_tickets",
                    name="Find Overdue Tickets",
                    step_type=StepType.CONDITION.value,
                    connector="crm_connector",
                    action="crm_search_tasks",
                    depends_on=["trigger_sla_check"],
                    config={
                        "record_type": "support_ticket",
                        "status_not_in": ["closed", "resolved"],
                        "older_than_hours": "{{sla_hours}}",
                        "mode": "read_only",
                    },
                    output_key="overdue_tickets",
                ),
                WorkflowStep(
                    step_id="prepare_escalation",
                    name="Prepare Escalation Payload",
                    step_type=StepType.ACTION.value,
                    agent="BusinessAgent",
                    action="prepare_support_escalation",
                    depends_on=["find_overdue_tickets"],
                    config={"priority": "{{escalation_priority}}"},
                    output_key="escalation_payload",
                ),
                WorkflowStep(
                    step_id="notify_escalation",
                    name="Notify Escalation Team",
                    step_type=StepType.NOTIFICATION.value,
                    connector="notification_engine",
                    action="send_internal_alert",
                    depends_on=["prepare_escalation"],
                    requires_approval=False,
                    risk_level=RiskLevel.MEDIUM.value,
                    config={
                        "channel": "{{escalation_channel}}",
                        "template": "support_escalation",
                        "mode": "prepare_only",
                    },
                    output_key="notification_payload",
                ),
                WorkflowStep(
                    step_id="verification",
                    name="Prepare Verification",
                    step_type=StepType.VERIFICATION.value,
                    agent="VerificationAgent",
                    action="prepare_verification_payload",
                    depends_on=["notify_escalation"],
                    config={"checks": ["sla_checked", "escalation_prepared", "notification_prepared"]},
                    output_key="verification_payload",
                ),
            ],
            metadata={
                "dashboard_icon": "alert-triangle",
                "recommended_for": ["SLA monitoring", "support operations"],
            },
        ).to_dict()

    def _appointment_reminder_template(self) -> Dict[str, Any]:
        return WorkflowTemplate(
            template_id="tpl_reminders_appointment",
            name="Appointment Reminder",
            category=TemplateCategory.REMINDERS.value,
            description=(
                "Prepares appointment reminders before a scheduled meeting, checks "
                "required consent/approval, sends internal or customer-facing reminder "
                "payloads through approved connectors, and prepares verification."
            ),
            version=DEFAULT_TEMPLATE_VERSION,
            status=TemplateStatus.ACTIVE.value,
            tags=["reminder", "appointment", "calendar", "notification"],
            risk_level=RiskLevel.HIGH.value,
            requires_security_review=True,
            compatible_agents=["WorkflowAgent", "SecurityAgent", "VerificationAgent", "MemoryAgent"],
            variables=[
                WorkflowVariable(
                    name="reminder_minutes_before",
                    label="Reminder Minutes Before",
                    var_type="integer",
                    required=True,
                    default=60,
                ),
                WorkflowVariable(
                    name="reminder_channel",
                    label="Reminder Channel",
                    required=True,
                    default="email",
                    choices=["email", "whatsapp", "dashboard"],
                ),
                WorkflowVariable(
                    name="recipient_type",
                    label="Recipient Type",
                    required=True,
                    default="internal",
                    choices=["internal", "customer"],
                ),
            ],
            steps=[
                WorkflowStep(
                    step_id="trigger_appointment",
                    name="Appointment Scheduled",
                    step_type=StepType.TRIGGER.value,
                    connector="scheduler",
                    action="schedule_relative",
                    config={"minutes_before": "{{reminder_minutes_before}}"},
                    output_key="appointment_trigger",
                ),
                WorkflowStep(
                    step_id="security_check",
                    name="Reminder Permission Check",
                    step_type=StepType.APPROVAL.value,
                    agent="SecurityAgent",
                    action="request_approval",
                    depends_on=["trigger_appointment"],
                    requires_approval=True,
                    risk_level=RiskLevel.HIGH.value,
                    config={
                        "reason": "Appointment reminder may contact external recipient.",
                        "recipient_type": "{{recipient_type}}",
                    },
                    output_key="approval_status",
                ),
                WorkflowStep(
                    step_id="prepare_reminder",
                    name="Prepare Appointment Reminder",
                    step_type=StepType.NOTIFICATION.value,
                    connector="notification_engine",
                    action="send_internal_alert",
                    depends_on=["security_check"],
                    requires_approval=True,
                    risk_level=RiskLevel.HIGH.value,
                    config={
                        "channel": "{{reminder_channel}}",
                        "recipient_type": "{{recipient_type}}",
                        "template": "appointment_reminder",
                        "mode": "prepare_only",
                    },
                    output_key="reminder_payload",
                ),
                WorkflowStep(
                    step_id="memory",
                    name="Prepare Reminder Memory",
                    step_type=StepType.MEMORY.value,
                    agent="MemoryAgent",
                    action="prepare_memory_payload",
                    depends_on=["prepare_reminder"],
                    config={"memory_type": "appointment_reminder", "scope": "workspace"},
                    output_key="memory_payload",
                ),
                WorkflowStep(
                    step_id="verification",
                    name="Prepare Verification",
                    step_type=StepType.VERIFICATION.value,
                    agent="VerificationAgent",
                    action="prepare_verification_payload",
                    depends_on=["memory"],
                    config={"checks": ["permission_checked", "reminder_prepared"]},
                    output_key="verification_payload",
                ),
            ],
            metadata={
                "dashboard_icon": "calendar-clock",
                "recommended_for": ["appointments", "consultation reminders", "meeting reminders"],
            },
        ).to_dict()

    def _task_due_reminder_template(self) -> Dict[str, Any]:
        return WorkflowTemplate(
            template_id="tpl_reminders_task_due",
            name="Task Due Reminder",
            category=TemplateCategory.REMINDERS.value,
            description=(
                "Finds due tasks in the workspace, prepares reminder notifications, "
                "updates dashboard reminders safely, and prepares verification payload."
            ),
            version=DEFAULT_TEMPLATE_VERSION,
            status=TemplateStatus.ACTIVE.value,
            tags=["reminder", "task", "dashboard", "productivity"],
            risk_level=RiskLevel.MEDIUM.value,
            requires_security_review=False,
            compatible_agents=["WorkflowAgent", "VerificationAgent", "MemoryAgent"],
            variables=[
                WorkflowVariable(
                    name="due_window_hours",
                    label="Due Window Hours",
                    var_type="integer",
                    required=True,
                    default=24,
                ),
                WorkflowVariable(
                    name="reminder_channel",
                    label="Reminder Channel",
                    required=True,
                    default="dashboard",
                    choices=["dashboard", "email", "slack"],
                ),
                WorkflowVariable(
                    name="priority_filter",
                    label="Priority Filter",
                    required=False,
                    default="all",
                    choices=["all", "normal", "high", "urgent"],
                ),
            ],
            steps=[
                WorkflowStep(
                    step_id="schedule_due_task_scan",
                    name="Scheduled Due Task Scan",
                    step_type=StepType.TRIGGER.value,
                    connector="scheduler",
                    action="schedule_recurring",
                    config={"frequency": "daily"},
                    output_key="scan_trigger",
                ),
                WorkflowStep(
                    step_id="find_due_tasks",
                    name="Find Due Tasks",
                    step_type=StepType.CONDITION.value,
                    connector="crm_connector",
                    action="crm_search_tasks",
                    depends_on=["schedule_due_task_scan"],
                    config={
                        "due_within_hours": "{{due_window_hours}}",
                        "priority": "{{priority_filter}}",
                        "mode": "read_only",
                    },
                    output_key="due_tasks",
                ),
                WorkflowStep(
                    step_id="prepare_task_reminders",
                    name="Prepare Task Reminders",
                    step_type=StepType.NOTIFICATION.value,
                    connector="notification_engine",
                    action="send_internal_alert",
                    depends_on=["find_due_tasks"],
                    requires_approval=False,
                    risk_level=RiskLevel.MEDIUM.value,
                    config={
                        "channel": "{{reminder_channel}}",
                        "template": "task_due_reminder",
                        "mode": "prepare_only",
                    },
                    output_key="reminder_payload",
                ),
                WorkflowStep(
                    step_id="verification",
                    name="Prepare Verification",
                    step_type=StepType.VERIFICATION.value,
                    agent="VerificationAgent",
                    action="prepare_verification_payload",
                    depends_on=["prepare_task_reminders"],
                    config={"checks": ["due_tasks_checked", "reminders_prepared"]},
                    output_key="verification_payload",
                ),
            ],
            metadata={
                "dashboard_icon": "bell",
                "recommended_for": ["team productivity", "task management", "dashboard reminders"],
            },
        ).to_dict()

    # ------------------------------------------------------------------
    # Validation helpers
    # ------------------------------------------------------------------

    def _validate_variables(
        self,
        variables: Sequence[Any],
        errors: List[str],
        warnings: List[str],
    ) -> set:
        """Validate template variables and return variable names."""

        names: set = set()

        for index, variable in enumerate(variables):
            if isinstance(variable, WorkflowVariable):
                variable = variable.to_dict()

            if not isinstance(variable, Mapping):
                errors.append(f"variables[{index}] must be an object.")
                continue

            name = str(variable.get("name") or "").strip()
            label = str(variable.get("label") or "").strip()
            var_type = str(variable.get("var_type") or "string").strip()

            if not name:
                errors.append(f"variables[{index}].name is required.")
                continue

            if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_.-]*$", name):
                errors.append(f"variables[{index}].name has invalid format: {name}")

            if name in names:
                errors.append(f"Duplicate variable name: {name}")
            names.add(name)

            if not label:
                warnings.append(f"variables[{index}].label is recommended.")

            if var_type not in {
                "string",
                "integer",
                "float",
                "boolean",
                "date",
                "datetime",
                "list",
                "dict",
                "choice",
            }:
                warnings.append(f"variables[{index}].var_type is uncommon: {var_type}")

            choices = variable.get("choices")
            if choices is not None and not isinstance(choices, list):
                errors.append(f"variables[{index}].choices must be a list when provided.")

        return names

    def _validate_steps(
        self,
        steps: Sequence[Any],
        errors: List[str],
        warnings: List[str],
    ) -> set:
        """Validate template steps and return step IDs."""

        step_ids: set = set()

        for index, step in enumerate(steps):
            if isinstance(step, WorkflowStep):
                step = step.to_dict()

            if not isinstance(step, Mapping):
                errors.append(f"steps[{index}] must be an object.")
                continue

            step_id = str(step.get("step_id") or "").strip()
            name = str(step.get("name") or "").strip()
            step_type = str(step.get("step_type") or "").strip()

            if not step_id:
                errors.append(f"steps[{index}].step_id is required.")
                continue

            if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_-]*$", step_id):
                errors.append(f"steps[{index}].step_id has invalid format: {step_id}")

            if step_id in step_ids:
                errors.append(f"Duplicate step_id: {step_id}")
            step_ids.add(step_id)

            if not name:
                warnings.append(f"steps[{index}].name is recommended.")

            try:
                self._normalize_enum(step_type, StepType, "step_type")
            except ValueError as exc:
                errors.append(f"steps[{index}]: {exc}")

            risk_level = str(step.get("risk_level") or RiskLevel.LOW.value)
            try:
                self._normalize_enum(risk_level, RiskLevel, "risk_level")
            except ValueError as exc:
                errors.append(f"steps[{index}]: {exc}")

            config = step.get("config")
            if config is not None and not isinstance(config, Mapping):
                errors.append(f"steps[{index}].config must be an object when provided.")

            condition = step.get("condition")
            if condition is not None and not isinstance(condition, Mapping):
                errors.append(f"steps[{index}].condition must be an object when provided.")

            depends_on = step.get("depends_on")
            if depends_on is not None and not isinstance(depends_on, list):
                errors.append(f"steps[{index}].depends_on must be a list when provided.")

            if not step.get("agent") and not step.get("connector"):
                warnings.append(
                    f"steps[{index}] has no agent or connector. Router must infer destination."
                )

        return step_ids

    def _validate_step_dependencies(
        self,
        steps: Sequence[Any],
        step_ids: set,
        errors: List[str],
    ) -> None:
        """Validate step dependency references."""

        for index, step in enumerate(steps):
            if isinstance(step, WorkflowStep):
                step = step.to_dict()
            if not isinstance(step, Mapping):
                continue

            step_id = str(step.get("step_id") or "")
            depends_on = step.get("depends_on") or []
            if not isinstance(depends_on, list):
                continue

            for dependency in depends_on:
                dependency_id = str(dependency)
                if dependency_id not in step_ids:
                    errors.append(
                        f"steps[{index}] dependency '{dependency_id}' does not exist."
                    )
                if dependency_id == step_id:
                    errors.append(f"steps[{index}] cannot depend on itself.")

    # ------------------------------------------------------------------
    # Template rendering helpers
    # ------------------------------------------------------------------

    def _merge_template_variables(
        self,
        template: Mapping[str, Any],
        variables: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Merge variable defaults with runtime variables."""

        merged: Dict[str, Any] = {}

        for variable in template.get("variables", []) or []:
            if isinstance(variable, WorkflowVariable):
                variable = variable.to_dict()
            if not isinstance(variable, Mapping):
                continue
            name = str(variable.get("name") or "").strip()
            if not name:
                continue
            if "default" in variable:
                merged[name] = copy.deepcopy(variable.get("default"))

        for key, value in variables.items():
            merged[str(key)] = copy.deepcopy(value)

        return merged

    def _missing_required_variables(
        self,
        template: Mapping[str, Any],
        variables: Mapping[str, Any],
    ) -> List[str]:
        """Return missing required variable names."""

        missing: List[str] = []

        for variable in template.get("variables", []) or []:
            if isinstance(variable, WorkflowVariable):
                variable = variable.to_dict()
            if not isinstance(variable, Mapping):
                continue

            name = str(variable.get("name") or "").strip()
            required = bool(variable.get("required", False))
            if not required:
                continue

            value = variables.get(name)
            if value is None or value == "":
                missing.append(name)

        return missing

    def _render_value(
        self,
        value: Any,
        variables: Mapping[str, Any],
        strict: bool,
    ) -> Any:
        """Recursively render placeholder variables inside any JSON-like value."""

        if isinstance(value, str):
            return self._render_string(value, variables, strict)

        if isinstance(value, list):
            return [self._render_value(item, variables, strict) for item in value]

        if isinstance(value, tuple):
            return tuple(self._render_value(item, variables, strict) for item in value)

        if isinstance(value, dict):
            return {
                key: self._render_value(item, variables, strict)
                for key, item in value.items()
            }

        return value

    def _render_string(
        self,
        text: str,
        variables: Mapping[str, Any],
        strict: bool,
    ) -> Any:
        """Render placeholders inside a string."""

        matches = list(PLACEHOLDER_PATTERN.finditer(text))
        if not matches:
            return text

        if len(matches) == 1 and matches[0].span() == (0, len(text)):
            key = matches[0].group(1)
            if key in variables:
                return copy.deepcopy(variables[key])
            if strict:
                raise KeyError(f"Missing template variable: {key}")
            return text

        def replace(match: re.Match[str]) -> str:
            key = match.group(1)
            if key not in variables:
                if strict:
                    raise KeyError(f"Missing template variable: {key}")
                return match.group(0)
            return str(variables[key])

        return PLACEHOLDER_PATTERN.sub(replace, text)

    def _extract_placeholders(self, value: Any) -> set:
        """Extract all placeholder variable names from a template."""

        placeholders: set = set()

        def walk(item: Any) -> None:
            if isinstance(item, str):
                for match in PLACEHOLDER_PATTERN.finditer(item):
                    placeholders.add(match.group(1))
            elif isinstance(item, Mapping):
                for child in item.values():
                    walk(child)
            elif isinstance(item, Iterable) and not isinstance(item, (str, bytes)):
                for child in item:
                    walk(child)

        walk(value)
        return placeholders

    # ------------------------------------------------------------------
    # Internal lookup and formatting helpers
    # ------------------------------------------------------------------

    def _find_visible_template(
        self,
        *,
        template_id: str,
        user_id: Optional[str],
        workspace_id: Optional[str],
    ) -> Optional[Dict[str, Any]]:
        """Find a system template or user/workspace-scoped custom template."""

        safe_template_id = str(template_id or "").strip()
        if not safe_template_id:
            return None

        if safe_template_id in self._system_templates:
            return copy.deepcopy(self._system_templates[safe_template_id])

        template = self._custom_templates.get(safe_template_id)
        if not template:
            return None

        if template.get("user_id") != user_id or template.get("workspace_id") != workspace_id:
            return None

        return copy.deepcopy(template)

    def _public_template_summary(self, template: Mapping[str, Any]) -> Dict[str, Any]:
        """Return a dashboard-safe summary of a template."""

        return {
            "template_id": template.get("template_id"),
            "name": template.get("name"),
            "category": template.get("category"),
            "category_label": self._category_label(str(template.get("category") or "")),
            "description": template.get("description"),
            "version": template.get("version"),
            "status": template.get("status"),
            "tags": copy.deepcopy(template.get("tags", [])),
            "is_system_template": bool(template.get("is_system_template", False)),
            "risk_level": template.get("risk_level", RiskLevel.LOW.value),
            "requires_security_review": bool(template.get("requires_security_review", False)),
            "step_count": len(template.get("steps", []) or []),
            "variable_count": len(template.get("variables", []) or []),
            "compatible_agents": copy.deepcopy(template.get("compatible_agents", []) or []),
            "metadata": copy.deepcopy(template.get("metadata", {}) or {}),
            "updated_at": template.get("updated_at"),
        }

    def _category_label(self, category: str) -> str:
        labels = {
            TemplateCategory.LEADS.value: "Leads",
            TemplateCategory.REPORTS.value: "Reports",
            TemplateCategory.SUPPORT.value: "Support",
            TemplateCategory.REMINDERS.value: "Reminders",
        }
        return labels.get(category, category.replace("_", " ").title())

    def _generate_template_id(self, template_data: Mapping[str, Any]) -> str:
        """Generate stable custom template ID from content and uuid suffix."""

        name = str(template_data.get("name") or "workflow_template").lower()
        category = str(template_data.get("category") or "custom").lower()
        slug = re.sub(r"[^a-z0-9]+", "_", f"{category}_{name}").strip("_")
        digest = hashlib.sha256(
            json.dumps(dict(template_data), sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()[:8]
        return f"tpl_custom_{slug[:80]}_{digest}"

    def _generate_workflow_id(self, template_id: str, user_id: str, workspace_id: str) -> str:
        """Generate a runtime workflow ID."""

        seed = f"{template_id}:{user_id}:{workspace_id}:{time.time()}:{uuid.uuid4().hex}"
        digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]
        return f"wf_{digest}"

    def _normalize_enum(
        self,
        value: str,
        enum_cls: Any,
        field_name: str,
    ) -> str:
        """Normalize enum string and raise ValueError on invalid values."""

        normalized = str(value or "").strip().lower()
        allowed = {item.value for item in enum_cls}
        if normalized not in allowed:
            raise ValueError(f"{field_name} must be one of: {', '.join(sorted(allowed))}.")
        return normalized

    def _normalize_optional_enum(
        self,
        value: Optional[str],
        enum_cls: Any,
        *,
        field_name: str,
    ) -> Optional[str]:
        """Normalize optional enum value."""

        if value is None:
            return None
        return self._normalize_enum(value, enum_cls, field_name)

    def _normalize_tag(self, tag: Any) -> str:
        """Normalize dashboard/search tags."""

        return re.sub(r"\s+", "-", str(tag).strip().lower())

    def _is_safe_identifier(self, value: Optional[str]) -> bool:
        """Validate user/workspace identifier shape without enforcing format vendor lock-in."""

        if not value or not isinstance(value, str):
            return False
        if len(value) > 160:
            return False
        return bool(re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_.:@-]*$", value))

    def _base_metadata(
        self,
        *,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return standard result metadata."""

        return {
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "module": MODULE_NAME,
            "file": FILE_NAME,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # ------------------------------------------------------------------
    # Redaction helpers
    # ------------------------------------------------------------------

    def _redact_sensitive_variables(
        self,
        template: Mapping[str, Any],
        variables: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Redact sensitive variable values before returning to UI/API."""

        sensitive_names = {
            str(variable.get("name"))
            for variable in template.get("variables", []) or []
            if isinstance(variable, Mapping) and bool(variable.get("sensitive", False))
        }

        redacted: Dict[str, Any] = {}
        for key, value in variables.items():
            if key in sensitive_names or self._looks_sensitive_key(key):
                redacted[key] = "***REDACTED***"
            else:
                redacted[key] = copy.deepcopy(value)
        return redacted

    def _redact_value(self, value: Any) -> Any:
        """Recursively redact sensitive-looking keys."""

        if isinstance(value, Mapping):
            redacted: Dict[str, Any] = {}
            for key, item in value.items():
                if self._looks_sensitive_key(str(key)):
                    redacted[str(key)] = "***REDACTED***"
                else:
                    redacted[str(key)] = self._redact_value(item)
            return redacted

        if isinstance(value, list):
            return [self._redact_value(item) for item in value]

        return value

    def _looks_sensitive_key(self, key: str) -> bool:
        """Detect sensitive key names."""

        lowered = key.lower()
        sensitive_fragments = [
            "secret",
            "token",
            "password",
            "api_key",
            "apikey",
            "private_key",
            "auth",
            "credential",
            "access_key",
            "refresh",
        ]
        return any(fragment in lowered for fragment in sensitive_fragments)


# ---------------------------------------------------------------------------
# Module-level factory and metadata hooks
# ---------------------------------------------------------------------------

def get_agent() -> WorkflowTemplates:
    """
    Agent Loader compatible factory.

    The William/Jarvis Agent Loader can call this to instantiate the module
    without knowing constructor details.
    """

    return WorkflowTemplates()


def get_module_metadata() -> Dict[str, Any]:
    """
    Agent Registry compatible metadata.

    Useful for dashboard module discovery, health checks, and Master Agent
    routing maps.
    """

    return {
        "module": MODULE_NAME,
        "file": FILE_NAME,
        "class_name": AGENT_NAME,
        "agent_id": "workflow_templates",
        "purpose": "Reusable automation templates for leads, reports, support, reminders.",
        "categories": [category.value for category in TemplateCategory],
        "safe_to_import": True,
        "executes_external_actions": False,
        "requires_user_workspace_context": True,
        "compatible_with": [
            "BaseAgent",
            "AgentRegistry",
            "AgentLoader",
            "AgentRouter",
            "MasterAgent",
            "SecurityAgent",
            "VerificationAgent",
            "MemoryAgent",
            "DashboardAPI",
            "FastAPI",
        ],
        "public_methods": [
            "list_templates",
            "get_template",
            "search_templates",
            "get_template_catalog",
            "create_custom_template",
            "update_custom_template",
            "delete_custom_template",
            "validate_template",
            "render_template",
            "instantiate_template",
            "export_template",
            "import_template",
            "clone_system_template",
            "health_check",
        ],
        "completion": {
            "agent_module": "Workflow Agent",
            "file_completed": "workflow_templates.py",
            "completion_percent": 85.7,
        },
    }


__all__ = [
    "WorkflowTemplates",
    "WorkflowTemplate",
    "WorkflowStep",
    "WorkflowVariable",
    "TemplateCategory",
    "TemplateStatus",
    "StepType",
    "RiskLevel",
    "get_agent",
    "get_module_metadata",
]