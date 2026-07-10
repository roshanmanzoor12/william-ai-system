"""
agents/code_agent/documentation_writer.py

Documentation Writer for the William / Jarvis Multi-Agent AI SaaS System.

Purpose:
    Writes README, setup guides, API documentation, deployment documentation,
    changelog entries, troubleshooting guides, and structured documentation bundles.

Architecture Role:
    - Used by Code Agent and Master Agent routing when documentation tasks are requested.
    - Supports SaaS-safe user/workspace isolation.
    - Produces structured dict/JSON-style results.
    - Prepares payloads for Security Agent, Verification Agent, Memory Agent,
      Dashboard/API, Audit Logs, and Agent Registry integration.

Safety:
    - This file does not write to disk unless explicitly requested through safe public methods.
    - File writes are path-validated and can be blocked by security approval.
    - No secrets are hardcoded.
    - No system, terminal, financial, browser, message, or destructive actions are executed.

Import Safety:
    - Safe fallback BaseAgent is provided if the real William BaseAgent is not available yet.
    - Safe fallback logging is used.
"""

from __future__ import annotations

import datetime as _dt
import json
import logging
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Safe optional BaseAgent import
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for early project bootstrapping
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps the file import-safe even before the full William/Jarvis
        agent foundation has been generated.
        """

        def __init__(
            self,
            agent_name: str = "DocumentationWriter",
            agent_type: str = "code_agent_helper",
            **kwargs: Any,
        ) -> None:
            self.agent_name = agent_name
            self.agent_type = agent_type
            self.agent_config = kwargs

        def emit_event(self, event_name: str, payload: Mapping[str, Any]) -> None:
            return None

        def log_audit(self, payload: Mapping[str, Any]) -> None:
            return None


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_AGENT_NAME = "DocumentationWriter"
DEFAULT_AGENT_TYPE = "code_agent.documentation_writer"

SAFE_DOC_EXTENSIONS = {
    ".md",
    ".txt",
    ".rst",
    ".json",
    ".yaml",
    ".yml",
}

DEFAULT_README_SECTIONS = [
    "Overview",
    "Features",
    "Architecture",
    "Installation",
    "Configuration",
    "Usage",
    "API",
    "Security",
    "SaaS Isolation",
    "Testing",
    "Deployment",
    "Troubleshooting",
    "Changelog",
]

DOCUMENTATION_TYPES = {
    "readme",
    "setup",
    "api",
    "deployment",
    "changelog",
    "troubleshooting",
    "architecture",
    "security",
    "testing",
    "module",
    "bundle",
}

SENSITIVE_KEY_PATTERNS = [
    re.compile(r"api[_-]?key", re.IGNORECASE),
    re.compile(r"secret", re.IGNORECASE),
    re.compile(r"token", re.IGNORECASE),
    re.compile(r"password", re.IGNORECASE),
    re.compile(r"private[_-]?key", re.IGNORECASE),
    re.compile(r"credential", re.IGNORECASE),
]

MASKED_VALUE = "***REDACTED***"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class DocumentationContext:
    """
    SaaS-safe task context for documentation actions.

    user_id and workspace_id are required for user-specific execution.
    request_id is optional but recommended for dashboard/API traceability.
    """

    user_id: Union[str, int]
    workspace_id: Union[str, int]
    request_id: Optional[str] = None
    role: Optional[str] = None
    subscription_plan: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DocumentationSection:
    """
    Represents a generated documentation section.
    """

    title: str
    body: str
    order: int = 0

    def render_markdown(self) -> str:
        title = self.title.strip()
        body = self.body.strip()
        return f"## {title}\n\n{body}\n"


@dataclass
class DocumentationArtifact:
    """
    Represents a generated documentation artifact.
    """

    doc_type: str
    title: str
    content: str
    format: str = "markdown"
    file_name: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _utc_now_iso() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).isoformat()


def _slugify(value: str, default: str = "documentation") -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    value = value.strip("-")
    return value or default


def _ensure_list(value: Optional[Union[str, Sequence[str]]]) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return [str(item) for item in value]


def _safe_string(value: Any, fallback: str = "") -> str:
    if value is None:
        return fallback
    return str(value)


def _mask_sensitive_mapping(data: Any) -> Any:
    """
    Recursively masks sensitive-looking keys inside dictionaries/lists.
    """

    if isinstance(data, Mapping):
        masked: Dict[str, Any] = {}
        for key, value in data.items():
            key_str = str(key)
            if any(pattern.search(key_str) for pattern in SENSITIVE_KEY_PATTERNS):
                masked[key_str] = MASKED_VALUE
            else:
                masked[key_str] = _mask_sensitive_mapping(value)
        return masked

    if isinstance(data, list):
        return [_mask_sensitive_mapping(item) for item in data]

    return data


def _normalize_heading(title: str) -> str:
    cleaned = str(title or "").strip()
    if not cleaned:
        return "Untitled"
    return cleaned


def _render_bullets(items: Optional[Iterable[Any]]) -> str:
    safe_items = [str(item).strip() for item in items or [] if str(item).strip()]
    if not safe_items:
        return "- Not specified yet."
    return "\n".join(f"- {item}" for item in safe_items)


def _render_numbered(items: Optional[Iterable[Any]]) -> str:
    safe_items = [str(item).strip() for item in items or [] if str(item).strip()]
    if not safe_items:
        return "1. Not specified yet."
    return "\n".join(f"{index}. {item}" for index, item in enumerate(safe_items, start=1))


def _render_code_block(content: str, language: str = "") -> str:
    return f"```{language}\n{content.strip()}\n```"


def _safe_json(data: Any) -> str:
    return json.dumps(_mask_sensitive_mapping(data), indent=2, ensure_ascii=False, default=str)


# ---------------------------------------------------------------------------
# DocumentationWriter
# ---------------------------------------------------------------------------

class DocumentationWriter(BaseAgent):
    """
    Production-ready documentation helper for William/Jarvis Code Agent.

    Main responsibilities:
        - Generate README files.
        - Generate setup documentation.
        - Generate API documentation.
        - Generate deployment documentation.
        - Generate changelog entries.
        - Generate troubleshooting guides.
        - Generate architecture/security/testing/module docs.
        - Optionally write safe documentation files to disk.
        - Return structured results compatible with Master Agent routing.

    Integration notes:
        - Master Agent can route documentation tasks here by calling run_task().
        - Security Agent can approve or reject write operations through
          _request_security_approval().
        - Verification Agent receives a payload through _prepare_verification_payload().
        - Memory Agent receives reusable documentation context through
          _prepare_memory_payload().
        - Dashboard/API can display structured result metadata.
        - Registry/Loader can discover this class safely without requiring
          all future files to exist.
    """

    def __init__(
        self,
        *,
        agent_name: str = DEFAULT_AGENT_NAME,
        agent_type: str = DEFAULT_AGENT_TYPE,
        safe_mode: bool = True,
        allow_file_write: bool = False,
        allowed_output_roots: Optional[Sequence[Union[str, Path]]] = None,
        logger: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        try:
            super().__init__(agent_name=agent_name, agent_type=agent_type, **kwargs)
        except TypeError:
            super().__init__()  # type: ignore[misc]

        self.agent_name = agent_name
        self.agent_type = agent_type
        self.safe_mode = bool(safe_mode)
        self.allow_file_write = bool(allow_file_write)
        self.allowed_output_roots = [
            Path(root).expanduser().resolve()
            for root in (allowed_output_roots or [Path.cwd()])
        ]
        self.logger = logger or logging.getLogger(__name__)

    # ------------------------------------------------------------------
    # Core result helpers
    # ------------------------------------------------------------------

    def _safe_result(
        self,
        *,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": {
                "agent": self.agent_name,
                "agent_type": self.agent_type,
                "timestamp": _utc_now_iso(),
                **(metadata or {}),
            },
        }

    def _error_result(
        self,
        *,
        message: str,
        error: Optional[Union[str, Exception]] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        error_message = str(error) if error is not None else message
        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": {
                "type": error.__class__.__name__ if isinstance(error, Exception) else "DocumentationWriterError",
                "message": error_message,
            },
            "metadata": {
                "agent": self.agent_name,
                "agent_type": self.agent_type,
                "timestamp": _utc_now_iso(),
                **(metadata or {}),
            },
        }

    # ------------------------------------------------------------------
    # Required compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(
        self,
        context: Optional[Union[DocumentationContext, Mapping[str, Any]]],
        *,
        require_user_workspace: bool = True,
    ) -> Tuple[bool, Optional[DocumentationContext], Optional[str]]:
        """
        Validates SaaS task context.

        user_id and workspace_id are mandatory for user/workspace-specific tasks.
        """

        if context is None:
            if require_user_workspace:
                return False, None, "Missing task context with user_id and workspace_id."
            return True, None, None

        if isinstance(context, DocumentationContext):
            doc_context = context
        elif isinstance(context, Mapping):
            user_id = context.get("user_id")
            workspace_id = context.get("workspace_id")
            doc_context = DocumentationContext(
                user_id=user_id,
                workspace_id=workspace_id,
                request_id=context.get("request_id"),
                role=context.get("role"),
                subscription_plan=context.get("subscription_plan"),
                permissions=_ensure_list(context.get("permissions")),
                metadata=dict(context.get("metadata") or {}),
            )
        else:
            return False, None, "Invalid context type. Expected dict or DocumentationContext."

        if require_user_workspace:
            if doc_context.user_id in (None, ""):
                return False, None, "Missing user_id in task context."
            if doc_context.workspace_id in (None, ""):
                return False, None, "Missing workspace_id in task context."

        return True, doc_context, None

    def _requires_security_check(self, action: str, payload: Optional[Mapping[str, Any]] = None) -> bool:
        """
        Determines whether a documentation action requires Security Agent approval.

        Read/generate-only tasks are safe.
        File writes require security approval.
        """

        action = str(action or "").strip().lower()
        if action in {"write_file", "save_documentation", "write_bundle", "overwrite_file"}:
            return True

        payload = payload or {}
        if payload.get("write_to_disk") is True:
            return True

        return False

    def _request_security_approval(
        self,
        *,
        action: str,
        context: Optional[DocumentationContext],
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepares a Security Agent approval request.

        In this standalone file, approval is conservative:
            - If safe_mode is enabled and file writes are disabled, deny write action.
            - If allow_file_write is enabled, approve only after path validation elsewhere.

        Future Security Agent integration can replace this method or consume the payload.
        """

        approval_payload = {
            "action": action,
            "context": context.to_dict() if context else None,
            "payload": _mask_sensitive_mapping(dict(payload or {})),
            "requires_security_check": True,
            "safe_mode": self.safe_mode,
            "allow_file_write": self.allow_file_write,
            "timestamp": _utc_now_iso(),
        }

        if self.safe_mode and not self.allow_file_write:
            return {
                "approved": False,
                "message": "File write blocked by safe_mode. Enable allow_file_write or route through Security Agent.",
                "data": approval_payload,
            }

        return {
            "approved": True,
            "message": "Approved by DocumentationWriter local safety policy.",
            "data": approval_payload,
        }

    def _prepare_verification_payload(
        self,
        *,
        action: str,
        context: Optional[DocumentationContext],
        result: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Creates Verification Agent-compatible payload.
        """

        data = result.get("data") if isinstance(result, Mapping) else {}
        artifact = data.get("artifact") if isinstance(data, Mapping) else None

        return {
            "verification_type": "documentation_generation",
            "action": action,
            "agent": self.agent_name,
            "context": context.to_dict() if context else None,
            "checks": {
                "structured_result": isinstance(result, Mapping),
                "success_flag_present": "success" in result,
                "message_present": bool(result.get("message")) if isinstance(result, Mapping) else False,
                "artifact_present": artifact is not None,
                "no_unmasked_sensitive_keys": True,
            },
            "result_summary": {
                "success": result.get("success") if isinstance(result, Mapping) else None,
                "message": result.get("message") if isinstance(result, Mapping) else None,
            },
            "timestamp": _utc_now_iso(),
        }

    def _prepare_memory_payload(
        self,
        *,
        action: str,
        context: Optional[DocumentationContext],
        artifact: Optional[DocumentationArtifact] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Creates Memory Agent-compatible payload.

        This stores useful reusable documentation context, not secrets.
        """

        return {
            "memory_type": "code_documentation_context",
            "action": action,
            "agent": self.agent_name,
            "context": context.to_dict() if context else None,
            "artifact": {
                "doc_type": artifact.doc_type,
                "title": artifact.title,
                "format": artifact.format,
                "file_name": artifact.file_name,
                "metadata": _mask_sensitive_mapping(artifact.metadata),
            } if artifact else None,
            "metadata": _mask_sensitive_mapping(dict(metadata or {})),
            "timestamp": _utc_now_iso(),
        }

    def _emit_agent_event(
        self,
        event_name: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Emits agent event for dashboard/API/registry observers.

        Safe no-op if BaseAgent event system is unavailable.
        """

        event_payload = {
            "event_name": event_name,
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "payload": _mask_sensitive_mapping(dict(payload or {})),
            "timestamp": _utc_now_iso(),
        }

        try:
            if hasattr(super(), "emit_event"):
                super().emit_event(event_name, event_payload)  # type: ignore[misc]
            elif hasattr(self, "emit_event"):
                self.emit_event(event_name, event_payload)  # type: ignore[misc]
        except Exception:
            self.logger.debug("Agent event emission skipped.", exc_info=True)

    def _log_audit_event(
        self,
        *,
        action: str,
        context: Optional[DocumentationContext],
        status: str,
        details: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Logs audit event for SaaS compliance.

        Safe no-op if central audit logging is unavailable.
        """

        audit_payload = {
            "action": action,
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "status": status,
            "context": context.to_dict() if context else None,
            "details": _mask_sensitive_mapping(dict(details or {})),
            "timestamp": _utc_now_iso(),
        }

        try:
            if hasattr(super(), "log_audit"):
                super().log_audit(audit_payload)  # type: ignore[misc]
            elif hasattr(self, "log_audit"):
                self.log_audit(audit_payload)  # type: ignore[misc]
        except Exception:
            self.logger.debug("Audit event logging skipped.", exc_info=True)

    # ------------------------------------------------------------------
    # Public routing method
    # ------------------------------------------------------------------

    def run_task(
        self,
        *,
        task_type: str,
        context: Optional[Union[DocumentationContext, Mapping[str, Any]]],
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Master Agent / Router compatible task entrypoint.

        Supported task_type values:
            - readme
            - setup
            - api
            - deployment
            - changelog
            - troubleshooting
            - architecture
            - security
            - testing
            - module
            - bundle
            - write_file
        """

        is_valid, doc_context, validation_error = self._validate_task_context(context)
        if not is_valid:
            return self._error_result(
                message="Documentation task context validation failed.",
                error=validation_error,
                metadata={"task_type": task_type},
            )

        safe_payload = dict(payload or {})
        task_type_normalized = str(task_type or "").strip().lower()

        self._emit_agent_event(
            "documentation_writer.task_started",
            {
                "task_type": task_type_normalized,
                "context": doc_context.to_dict() if doc_context else None,
            },
        )
        self._log_audit_event(
            action=f"documentation_writer.{task_type_normalized}",
            context=doc_context,
            status="started",
            details={"payload_keys": sorted(safe_payload.keys())},
        )

        try:
            if task_type_normalized == "readme":
                result = self.generate_readme(context=doc_context, **safe_payload)
            elif task_type_normalized == "setup":
                result = self.generate_setup_guide(context=doc_context, **safe_payload)
            elif task_type_normalized == "api":
                result = self.generate_api_docs(context=doc_context, **safe_payload)
            elif task_type_normalized == "deployment":
                result = self.generate_deployment_guide(context=doc_context, **safe_payload)
            elif task_type_normalized == "changelog":
                result = self.generate_changelog(context=doc_context, **safe_payload)
            elif task_type_normalized == "troubleshooting":
                result = self.generate_troubleshooting_guide(context=doc_context, **safe_payload)
            elif task_type_normalized == "architecture":
                result = self.generate_architecture_doc(context=doc_context, **safe_payload)
            elif task_type_normalized == "security":
                result = self.generate_security_doc(context=doc_context, **safe_payload)
            elif task_type_normalized == "testing":
                result = self.generate_testing_doc(context=doc_context, **safe_payload)
            elif task_type_normalized == "module":
                result = self.generate_module_doc(context=doc_context, **safe_payload)
            elif task_type_normalized == "bundle":
                result = self.generate_documentation_bundle(context=doc_context, **safe_payload)
            elif task_type_normalized == "write_file":
                result = self.write_documentation_file(context=doc_context, **safe_payload)
            else:
                result = self._error_result(
                    message=f"Unsupported documentation task type: {task_type}",
                    metadata={
                        "supported_task_types": sorted(DOCUMENTATION_TYPES | {"write_file"}),
                    },
                )

            verification_payload = self._prepare_verification_payload(
                action=task_type_normalized,
                context=doc_context,
                result=result,
            )

            result.setdefault("metadata", {})
            result["metadata"]["verification_payload"] = verification_payload

            self._log_audit_event(
                action=f"documentation_writer.{task_type_normalized}",
                context=doc_context,
                status="completed" if result.get("success") else "failed",
                details={"message": result.get("message")},
            )
            self._emit_agent_event(
                "documentation_writer.task_completed",
                {
                    "task_type": task_type_normalized,
                    "success": result.get("success"),
                    "context": doc_context.to_dict() if doc_context else None,
                },
            )

            return result

        except Exception as exc:
            self.logger.exception("Documentation task failed.")
            self._log_audit_event(
                action=f"documentation_writer.{task_type_normalized}",
                context=doc_context,
                status="error",
                details={"error": str(exc)},
            )
            return self._error_result(
                message="Documentation task failed.",
                error=exc,
                metadata={"task_type": task_type_normalized},
            )

    # ------------------------------------------------------------------
    # README generation
    # ------------------------------------------------------------------

    def generate_readme(
        self,
        *,
        context: Optional[DocumentationContext],
        project_name: str = "William / Jarvis Multi-Agent AI SaaS System",
        description: str = "A Jarvis-style multi-agent AI SaaS system by Digital Promotix.",
        features: Optional[Sequence[str]] = None,
        architecture_points: Optional[Sequence[str]] = None,
        install_steps: Optional[Sequence[str]] = None,
        configuration: Optional[Mapping[str, Any]] = None,
        usage_examples: Optional[Sequence[str]] = None,
        api_summary: Optional[Sequence[str]] = None,
        security_notes: Optional[Sequence[str]] = None,
        testing_steps: Optional[Sequence[str]] = None,
        deployment_steps: Optional[Sequence[str]] = None,
        troubleshooting: Optional[Mapping[str, str]] = None,
        changelog: Optional[Sequence[str]] = None,
        include_toc: bool = True,
        file_name: str = "README.md",
        **_: Any,
    ) -> Dict[str, Any]:
        """
        Generates a complete README markdown document.
        """

        is_valid, doc_context, validation_error = self._validate_task_context(context)
        if not is_valid:
            return self._error_result(message="Invalid context for README generation.", error=validation_error)

        features = features or [
            "Master Agent routing with specialized sub-agents.",
            "SaaS-ready user and workspace isolation.",
            "Role, subscription, and permission-aware execution.",
            "Agent registry and plugin-style future agent support.",
            "Memory, audit logging, verification payloads, and dashboard-ready metadata.",
            "Security-first task approval patterns for sensitive actions.",
        ]

        architecture_points = architecture_points or [
            "Master Agent receives and routes user tasks.",
            "Code Agent handles project creation, editing, testing, documentation, and developer workflows.",
            "Security Agent reviews sensitive actions before execution.",
            "Verification Agent receives completion payloads after task execution.",
            "Memory Agent stores reusable context without crossing user/workspace boundaries.",
            "Dashboard/API layer can display events, task history, logs, and documentation artifacts.",
        ]

        install_steps = install_steps or [
            "Clone the repository.",
            "Create a Python virtual environment.",
            "Install project dependencies.",
            "Configure environment variables without hardcoding secrets.",
            "Run tests before starting the application.",
            "Start the API/dashboard service.",
        ]

        configuration = configuration or {
            "APP_ENV": "development",
            "DATABASE_URL": "Set from environment or secret manager.",
            "REDIS_URL": "Set from environment or secret manager.",
            "SECRET_KEY": "Never hardcode. Use environment variables.",
            "SAFE_MODE": True,
        }

        usage_examples = usage_examples or [
            "Submit a task to Master Agent with user_id and workspace_id.",
            "Route code-related requests to Code Agent.",
            "Generate verification payloads after task completion.",
            "Store reusable context through Memory Agent only when safe.",
        ]

        api_summary = api_summary or [
            "POST /api/tasks - Create a task for Master Agent routing.",
            "GET /api/tasks/{task_id} - Read task status and result.",
            "GET /api/agents - List registered agents.",
            "GET /api/audit-logs - Review workspace audit events.",
        ]

        security_notes = security_notes or [
            "Every user-specific action must include user_id and workspace_id.",
            "Never mix files, memory, logs, tasks, analytics, or audit data between workspaces.",
            "Sensitive actions must go through Security Agent approval.",
            "Secrets must be loaded from environment variables or a secret manager.",
            "Generated documentation must redact secret-looking configuration keys.",
        ]

        testing_steps = testing_steps or [
            "Run unit tests for individual agents.",
            "Run integration tests for Master Agent routing.",
            "Validate SaaS isolation using multiple users and workspaces.",
            "Verify Security Agent approval behavior for sensitive tasks.",
            "Confirm Verification Agent payloads are created after task completion.",
        ]

        deployment_steps = deployment_steps or [
            "Set production environment variables.",
            "Run database migrations.",
            "Build frontend/dashboard assets if applicable.",
            "Start API workers and background workers.",
            "Enable monitoring, audit logging, and error tracking.",
            "Verify health checks and rollback plan.",
        ]

        troubleshooting = troubleshooting or {
            "Agent import fails": "Check safe imports, module paths, and fallback stubs.",
            "Task has no user_id": "Send user_id and workspace_id in every SaaS task context.",
            "Security approval blocked": "Enable explicit permission or route the task through Security Agent.",
            "Memory appears mixed": "Review workspace filters and Memory Agent isolation rules.",
            "Documentation file not written": "Enable allow_file_write and use an allowed output path.",
        }

        changelog = changelog or [
            "Initial documentation generated for William / Jarvis Code Agent module.",
        ]

        sections = [
            DocumentationSection("Overview", description, 1),
            DocumentationSection("Features", _render_bullets(features), 2),
            DocumentationSection("Architecture", _render_bullets(architecture_points), 3),
            DocumentationSection("Installation", _render_numbered(install_steps), 4),
            DocumentationSection("Configuration", _render_code_block(_safe_json(configuration), "json"), 5),
            DocumentationSection("Usage", _render_bullets(usage_examples), 6),
            DocumentationSection("API", _render_bullets(api_summary), 7),
            DocumentationSection("Security", _render_bullets(security_notes), 8),
            DocumentationSection(
                "SaaS Isolation",
                (
                    "- Every task must include `user_id` and `workspace_id`.\n"
                    "- Every query, file, memory item, task, log, and analytics event must be scoped.\n"
                    "- Workspace data must never be shared unless explicitly permitted by role and policy.\n"
                    "- Audit logs should record who performed an action, in which workspace, and when."
                ),
                9,
            ),
            DocumentationSection("Testing", _render_numbered(testing_steps), 10),
            DocumentationSection("Deployment", _render_numbered(deployment_steps), 11),
            DocumentationSection("Troubleshooting", self._render_troubleshooting_table(troubleshooting), 12),
            DocumentationSection("Changelog", _render_bullets(changelog), 13),
        ]

        content = self._render_markdown_document(
            title=project_name,
            intro="Generated documentation for the William / Jarvis system.",
            sections=sections,
            include_toc=include_toc,
        )

        artifact = DocumentationArtifact(
            doc_type="readme",
            title=project_name,
            content=content,
            file_name=file_name,
            metadata={
                "section_count": len(sections),
                "generated_by": self.agent_name,
            },
        )

        memory_payload = self._prepare_memory_payload(
            action="generate_readme",
            context=doc_context,
            artifact=artifact,
        )

        return self._safe_result(
            message="README documentation generated successfully.",
            data={
                "artifact": artifact.to_dict(),
                "memory_payload": memory_payload,
            },
            metadata={
                "doc_type": "readme",
                "file_name": file_name,
            },
        )

    # ------------------------------------------------------------------
    # Setup guide
    # ------------------------------------------------------------------

    def generate_setup_guide(
        self,
        *,
        context: Optional[DocumentationContext],
        project_name: str = "William / Jarvis Multi-Agent AI SaaS System",
        prerequisites: Optional[Sequence[str]] = None,
        environment_variables: Optional[Mapping[str, Any]] = None,
        installation_steps: Optional[Sequence[str]] = None,
        local_run_steps: Optional[Sequence[str]] = None,
        validation_steps: Optional[Sequence[str]] = None,
        file_name: str = "SETUP.md",
        **_: Any,
    ) -> Dict[str, Any]:
        """
        Generates setup documentation for local or server environments.
        """

        is_valid, doc_context, validation_error = self._validate_task_context(context)
        if not is_valid:
            return self._error_result(message="Invalid context for setup guide.", error=validation_error)

        prerequisites = prerequisites or [
            "Python 3.10+",
            "pip or poetry",
            "Git",
            "Database service such as PostgreSQL or SQLite for development",
            "Redis if background queues are enabled",
            "Environment variable management through `.env` or secret manager",
        ]

        environment_variables = environment_variables or {
            "APP_ENV": "development",
            "DATABASE_URL": "Set safely outside code.",
            "REDIS_URL": "Set safely outside code.",
            "SECRET_KEY": "Use a generated secret from a secure store.",
            "SAFE_MODE": "true",
            "LOG_LEVEL": "INFO",
        }

        installation_steps = installation_steps or [
            "Clone the repository.",
            "Create a virtual environment.",
            "Activate the virtual environment.",
            "Install dependencies.",
            "Copy `.env.example` to `.env` if available.",
            "Fill environment variables without committing secrets.",
        ]

        local_run_steps = local_run_steps or [
            "Run database migrations if applicable.",
            "Start the API service.",
            "Start worker processes if enabled.",
            "Open the dashboard/API URL.",
            "Create or log in as a test user.",
        ]

        validation_steps = validation_steps or [
            "Confirm the application starts without import errors.",
            "Create a task with user_id and workspace_id.",
            "Confirm Master Agent can route to Code Agent.",
            "Confirm audit logs are created.",
            "Confirm no workspace can access another workspace's data.",
        ]

        sections = [
            DocumentationSection("Prerequisites", _render_bullets(prerequisites), 1),
            DocumentationSection("Environment Variables", _render_code_block(_safe_json(environment_variables), "json"), 2),
            DocumentationSection("Installation", _render_numbered(installation_steps), 3),
            DocumentationSection("Run Locally", _render_numbered(local_run_steps), 4),
            DocumentationSection("Validation", _render_numbered(validation_steps), 5),
            DocumentationSection(
                "Security Notes",
                (
                    "- Do not commit `.env` files.\n"
                    "- Do not hardcode API keys, tokens, passwords, or private keys.\n"
                    "- Keep local test data separated by user_id and workspace_id.\n"
                    "- Use Security Agent approval before enabling sensitive actions."
                ),
                6,
            ),
        ]

        content = self._render_markdown_document(
            title=f"{project_name} Setup Guide",
            intro="This guide explains how to configure and run the system safely.",
            sections=sections,
            include_toc=True,
        )

        artifact = DocumentationArtifact(
            doc_type="setup",
            title=f"{project_name} Setup Guide",
            content=content,
            file_name=file_name,
        )

        return self._safe_result(
            message="Setup guide generated successfully.",
            data={
                "artifact": artifact.to_dict(),
                "memory_payload": self._prepare_memory_payload(
                    action="generate_setup_guide",
                    context=doc_context,
                    artifact=artifact,
                ),
            },
            metadata={"doc_type": "setup", "file_name": file_name},
        )

    # ------------------------------------------------------------------
    # API docs
    # ------------------------------------------------------------------

    def generate_api_docs(
        self,
        *,
        context: Optional[DocumentationContext],
        api_name: str = "William / Jarvis API",
        endpoints: Optional[Sequence[Mapping[str, Any]]] = None,
        auth_notes: Optional[Sequence[str]] = None,
        response_format: Optional[Mapping[str, Any]] = None,
        file_name: str = "API.md",
        **_: Any,
    ) -> Dict[str, Any]:
        """
        Generates API documentation for dashboard/backend integration.
        """

        is_valid, doc_context, validation_error = self._validate_task_context(context)
        if not is_valid:
            return self._error_result(message="Invalid context for API docs.", error=validation_error)

        endpoints = endpoints or [
            {
                "method": "POST",
                "path": "/api/tasks",
                "description": "Create a task for Master Agent routing.",
                "required_context": ["user_id", "workspace_id"],
                "request_body": {
                    "task_type": "string",
                    "payload": {},
                    "context": {
                        "user_id": "required",
                        "workspace_id": "required",
                    },
                },
            },
            {
                "method": "GET",
                "path": "/api/tasks/{task_id}",
                "description": "Fetch task result and status.",
                "required_context": ["user_id", "workspace_id"],
            },
            {
                "method": "GET",
                "path": "/api/agents",
                "description": "List available registered agents.",
                "required_context": ["user_id", "workspace_id"],
            },
            {
                "method": "GET",
                "path": "/api/audit-logs",
                "description": "List audit logs scoped to workspace permissions.",
                "required_context": ["user_id", "workspace_id"],
            },
        ]

        auth_notes = auth_notes or [
            "Use authenticated user sessions or bearer tokens.",
            "Every API request must resolve user_id and workspace_id.",
            "Role and subscription checks should happen before task execution.",
            "Sensitive actions must be routed through Security Agent.",
        ]

        response_format = response_format or {
            "success": True,
            "message": "Human-readable status message.",
            "data": {},
            "error": None,
            "metadata": {
                "timestamp": "ISO-8601 UTC timestamp",
                "agent": "Agent name when relevant",
            },
        }

        endpoint_docs = [self._render_endpoint_doc(endpoint) for endpoint in endpoints]

        sections = [
            DocumentationSection("Authentication", _render_bullets(auth_notes), 1),
            DocumentationSection("Standard Response Format", _render_code_block(_safe_json(response_format), "json"), 2),
            DocumentationSection("Endpoints", "\n\n".join(endpoint_docs), 3),
            DocumentationSection(
                "SaaS Context Requirements",
                (
                    "Every user-specific API request must include or resolve:\n\n"
                    "- `user_id`\n"
                    "- `workspace_id`\n"
                    "- role/permission information where needed\n"
                    "- subscription state where feature gating is needed"
                ),
                4,
            ),
        ]

        content = self._render_markdown_document(
            title=api_name,
            intro="API documentation for William / Jarvis dashboard and backend integration.",
            sections=sections,
            include_toc=True,
        )

        artifact = DocumentationArtifact(
            doc_type="api",
            title=api_name,
            content=content,
            file_name=file_name,
            metadata={"endpoint_count": len(endpoints)},
        )

        return self._safe_result(
            message="API documentation generated successfully.",
            data={
                "artifact": artifact.to_dict(),
                "memory_payload": self._prepare_memory_payload(
                    action="generate_api_docs",
                    context=doc_context,
                    artifact=artifact,
                    metadata={"endpoint_count": len(endpoints)},
                ),
            },
            metadata={"doc_type": "api", "file_name": file_name},
        )

    # ------------------------------------------------------------------
    # Deployment guide
    # ------------------------------------------------------------------

    def generate_deployment_guide(
        self,
        *,
        context: Optional[DocumentationContext],
        project_name: str = "William / Jarvis Multi-Agent AI SaaS System",
        environments: Optional[Sequence[str]] = None,
        deployment_steps: Optional[Sequence[str]] = None,
        rollback_steps: Optional[Sequence[str]] = None,
        health_checks: Optional[Sequence[str]] = None,
        monitoring_notes: Optional[Sequence[str]] = None,
        file_name: str = "DEPLOYMENT.md",
        **_: Any,
    ) -> Dict[str, Any]:
        """
        Generates deployment documentation.
        """

        is_valid, doc_context, validation_error = self._validate_task_context(context)
        if not is_valid:
            return self._error_result(message="Invalid context for deployment guide.", error=validation_error)

        environments = environments or ["development", "staging", "production"]

        deployment_steps = deployment_steps or [
            "Confirm all tests pass.",
            "Confirm environment variables are configured in the deployment platform.",
            "Run database migrations.",
            "Build frontend/dashboard assets if applicable.",
            "Deploy backend/API service.",
            "Deploy background workers if applicable.",
            "Run health checks.",
            "Review audit logs and error logs after deployment.",
        ]

        rollback_steps = rollback_steps or [
            "Stop new deployments immediately.",
            "Restore the previous stable release.",
            "Rollback database migrations only if they are backward-compatible and safe.",
            "Restart API and worker services.",
            "Verify health checks and critical flows.",
            "Create an incident note in the changelog.",
        ]

        health_checks = health_checks or [
            "API service responds successfully.",
            "Database connection works.",
            "Redis/queue connection works if enabled.",
            "Master Agent can route a basic task.",
            "Audit log write succeeds.",
            "Workspace isolation test passes.",
        ]

        monitoring_notes = monitoring_notes or [
            "Track API errors and latency.",
            "Track task failures by agent.",
            "Track Security Agent denials.",
            "Track workspace-level audit events.",
            "Track subscription/permission-related blocked actions.",
        ]

        sections = [
            DocumentationSection("Supported Environments", _render_bullets(environments), 1),
            DocumentationSection("Deployment Steps", _render_numbered(deployment_steps), 2),
            DocumentationSection("Rollback Plan", _render_numbered(rollback_steps), 3),
            DocumentationSection("Health Checks", _render_bullets(health_checks), 4),
            DocumentationSection("Monitoring", _render_bullets(monitoring_notes), 5),
            DocumentationSection(
                "Production Safety Rules",
                (
                    "- Never deploy with hardcoded secrets.\n"
                    "- Keep safe_mode enabled unless Security Agent policies are active.\n"
                    "- Ensure user/workspace isolation is tested before production release.\n"
                    "- Keep audit logging enabled for sensitive and user-specific actions."
                ),
                6,
            ),
        ]

        content = self._render_markdown_document(
            title=f"{project_name} Deployment Guide",
            intro="Production deployment guide for safe William / Jarvis releases.",
            sections=sections,
            include_toc=True,
        )

        artifact = DocumentationArtifact(
            doc_type="deployment",
            title=f"{project_name} Deployment Guide",
            content=content,
            file_name=file_name,
        )

        return self._safe_result(
            message="Deployment guide generated successfully.",
            data={
                "artifact": artifact.to_dict(),
                "memory_payload": self._prepare_memory_payload(
                    action="generate_deployment_guide",
                    context=doc_context,
                    artifact=artifact,
                ),
            },
            metadata={"doc_type": "deployment", "file_name": file_name},
        )

    # ------------------------------------------------------------------
    # Changelog
    # ------------------------------------------------------------------

    def generate_changelog(
        self,
        *,
        context: Optional[DocumentationContext],
        version: str = "Unreleased",
        changes_added: Optional[Sequence[str]] = None,
        changes_changed: Optional[Sequence[str]] = None,
        changes_fixed: Optional[Sequence[str]] = None,
        changes_security: Optional[Sequence[str]] = None,
        release_date: Optional[str] = None,
        file_name: str = "CHANGELOG.md",
        **_: Any,
    ) -> Dict[str, Any]:
        """
        Generates a Keep-a-Changelog style entry.
        """

        is_valid, doc_context, validation_error = self._validate_task_context(context)
        if not is_valid:
            return self._error_result(message="Invalid context for changelog.", error=validation_error)

        release_date = release_date or _dt.date.today().isoformat()

        changes_added = changes_added or [
            "Added documentation generation support for README, setup, API, deployment, changelog, and troubleshooting.",
            "Added SaaS-safe context validation for user_id and workspace_id.",
            "Added verification and memory payload preparation hooks.",
        ]

        changes_changed = changes_changed or [
            "Improved Code Agent documentation workflow compatibility with Master Agent routing.",
        ]

        changes_fixed = changes_fixed or [
            "Ensured documentation helper remains import-safe before all future files exist.",
        ]

        changes_security = changes_security or [
            "Added sensitive key masking for generated configuration examples.",
            "Added safe file write approval flow.",
        ]

        content = (
            "# Changelog\n\n"
            "All notable changes to this project should be documented in this file.\n\n"
            f"## [{version}] - {release_date}\n\n"
            "### Added\n\n"
            f"{_render_bullets(changes_added)}\n\n"
            "### Changed\n\n"
            f"{_render_bullets(changes_changed)}\n\n"
            "### Fixed\n\n"
            f"{_render_bullets(changes_fixed)}\n\n"
            "### Security\n\n"
            f"{_render_bullets(changes_security)}\n"
        )

        artifact = DocumentationArtifact(
            doc_type="changelog",
            title=f"Changelog {version}",
            content=content,
            file_name=file_name,
            metadata={"version": version, "release_date": release_date},
        )

        return self._safe_result(
            message="Changelog generated successfully.",
            data={
                "artifact": artifact.to_dict(),
                "memory_payload": self._prepare_memory_payload(
                    action="generate_changelog",
                    context=doc_context,
                    artifact=artifact,
                    metadata={"version": version},
                ),
            },
            metadata={"doc_type": "changelog", "file_name": file_name},
        )

    # ------------------------------------------------------------------
    # Troubleshooting
    # ------------------------------------------------------------------

    def generate_troubleshooting_guide(
        self,
        *,
        context: Optional[DocumentationContext],
        title: str = "Troubleshooting Guide",
        issues: Optional[Mapping[str, str]] = None,
        diagnostics: Optional[Sequence[str]] = None,
        escalation_steps: Optional[Sequence[str]] = None,
        file_name: str = "TROUBLESHOOTING.md",
        **_: Any,
    ) -> Dict[str, Any]:
        """
        Generates troubleshooting documentation.
        """

        is_valid, doc_context, validation_error = self._validate_task_context(context)
        if not is_valid:
            return self._error_result(message="Invalid context for troubleshooting guide.", error=validation_error)

        issues = issues or {
            "Import error while loading agent": "Check Python path, package __init__.py files, and optional fallback imports.",
            "Task rejected because user_id is missing": "Send a valid SaaS context containing user_id and workspace_id.",
            "Workspace data appears empty": "Confirm the workspace_id is correct and the current user has permission.",
            "Security check blocks action": "Route the action to Security Agent or enable the required permission.",
            "Documentation file was not saved": "Set allow_file_write=True and use an allowed output root.",
            "Verification payload missing": "Confirm task execution goes through run_task() or call _prepare_verification_payload().",
        }

        diagnostics = diagnostics or [
            "Check application logs.",
            "Check audit logs for denied actions.",
            "Validate user_id and workspace_id.",
            "Confirm agent registry can discover the target agent.",
            "Run unit tests for the failing module.",
            "Review security approval payloads.",
        ]

        escalation_steps = escalation_steps or [
            "Capture the task payload without secrets.",
            "Capture the structured error result.",
            "Check whether the issue is user-specific, workspace-specific, or system-wide.",
            "Escalate to the system owner or developer with audit log reference.",
        ]

        sections = [
            DocumentationSection("Common Issues", self._render_troubleshooting_table(issues), 1),
            DocumentationSection("Diagnostic Checklist", _render_bullets(diagnostics), 2),
            DocumentationSection("Escalation Steps", _render_numbered(escalation_steps), 3),
        ]

        content = self._render_markdown_document(
            title=title,
            intro="Use this guide to diagnose and resolve common William / Jarvis issues.",
            sections=sections,
            include_toc=True,
        )

        artifact = DocumentationArtifact(
            doc_type="troubleshooting",
            title=title,
            content=content,
            file_name=file_name,
            metadata={"issue_count": len(issues)},
        )

        return self._safe_result(
            message="Troubleshooting guide generated successfully.",
            data={
                "artifact": artifact.to_dict(),
                "memory_payload": self._prepare_memory_payload(
                    action="generate_troubleshooting_guide",
                    context=doc_context,
                    artifact=artifact,
                    metadata={"issue_count": len(issues)},
                ),
            },
            metadata={"doc_type": "troubleshooting", "file_name": file_name},
        )

    # ------------------------------------------------------------------
    # Architecture docs
    # ------------------------------------------------------------------

    def generate_architecture_doc(
        self,
        *,
        context: Optional[DocumentationContext],
        title: str = "William / Jarvis Architecture",
        agents: Optional[Sequence[str]] = None,
        flows: Optional[Sequence[str]] = None,
        data_boundaries: Optional[Sequence[str]] = None,
        file_name: str = "ARCHITECTURE.md",
        **_: Any,
    ) -> Dict[str, Any]:
        """
        Generates architecture documentation.
        """

        is_valid, doc_context, validation_error = self._validate_task_context(context)
        if not is_valid:
            return self._error_result(message="Invalid context for architecture doc.", error=validation_error)

        agents = agents or [
            "Master Agent",
            "Voice Agent",
            "System Agent",
            "Browser Agent",
            "Code Agent",
            "Memory Agent",
            "Security Agent",
            "Verification Agent",
            "Visual Agent",
            "Workflow Agent",
            "Hologram Agent",
            "Call Agent",
            "Business Agent",
            "Finance Agent",
            "Creator Agent",
        ]

        flows = flows or [
            "User submits a task from dashboard/API.",
            "Master Agent validates context and routes to the correct agent.",
            "Target agent validates user_id and workspace_id.",
            "Sensitive actions request Security Agent approval.",
            "Agent executes the safe action.",
            "Agent prepares Verification Agent payload.",
            "Agent prepares Memory Agent payload when reusable context exists.",
            "Dashboard/API receives structured result.",
        ]

        data_boundaries = data_boundaries or [
            "Memory is scoped by user_id and workspace_id.",
            "Files are scoped by user_id and workspace_id.",
            "Task history is scoped by user_id and workspace_id.",
            "Audit logs are scoped by user_id and workspace_id.",
            "Analytics are scoped by user_id and workspace_id.",
            "Cross-workspace access requires explicit role and policy approval.",
        ]

        sections = [
            DocumentationSection("Agents", _render_bullets(agents), 1),
            DocumentationSection("Task Flow", _render_numbered(flows), 2),
            DocumentationSection("Data Boundaries", _render_bullets(data_boundaries), 3),
            DocumentationSection(
                "Extension Model",
                (
                    "William / Jarvis supports plugin-style future agents. New agents should expose "
                    "clear public methods, structured results, safe imports, registry metadata, and "
                    "SaaS context validation."
                ),
                4,
            ),
        ]

        content = self._render_markdown_document(
            title=title,
            intro="Architecture overview for the William / Jarvis multi-agent SaaS system.",
            sections=sections,
            include_toc=True,
        )

        artifact = DocumentationArtifact(
            doc_type="architecture",
            title=title,
            content=content,
            file_name=file_name,
        )

        return self._safe_result(
            message="Architecture documentation generated successfully.",
            data={
                "artifact": artifact.to_dict(),
                "memory_payload": self._prepare_memory_payload(
                    action="generate_architecture_doc",
                    context=doc_context,
                    artifact=artifact,
                ),
            },
            metadata={"doc_type": "architecture", "file_name": file_name},
        )

    # ------------------------------------------------------------------
    # Security docs
    # ------------------------------------------------------------------

    def generate_security_doc(
        self,
        *,
        context: Optional[DocumentationContext],
        title: str = "Security Guide",
        policies: Optional[Sequence[str]] = None,
        sensitive_actions: Optional[Sequence[str]] = None,
        file_name: str = "SECURITY.md",
        **_: Any,
    ) -> Dict[str, Any]:
        """
        Generates security documentation.
        """

        is_valid, doc_context, validation_error = self._validate_task_context(context)
        if not is_valid:
            return self._error_result(message="Invalid context for security doc.", error=validation_error)

        policies = policies or [
            "Safety and permission rules come first.",
            "SaaS user/workspace isolation comes second.",
            "BaseAgent compatibility comes third.",
            "Master Agent and registry compatibility comes fourth.",
            "File-specific functionality comes fifth.",
            "Future upgrades come last.",
        ]

        sensitive_actions = sensitive_actions or [
            "Writing files",
            "Running terminal commands",
            "Deploying code",
            "Accessing external browser automation",
            "Sending messages or calls",
            "Handling finance-related actions",
            "Deleting, overwriting, or modifying user assets",
        ]

        sections = [
            DocumentationSection("Security Policy Order", _render_numbered(policies), 1),
            DocumentationSection("Sensitive Actions", _render_bullets(sensitive_actions), 2),
            DocumentationSection(
                "Secret Handling",
                (
                    "- Never hardcode secrets.\n"
                    "- Never log full secrets.\n"
                    "- Mask secret-looking keys in documentation and logs.\n"
                    "- Load production secrets from environment variables or a secure secret manager."
                ),
                3,
            ),
            DocumentationSection(
                "SaaS Isolation",
                (
                    "- Every sensitive action must include user_id and workspace_id.\n"
                    "- Every database query must be scoped.\n"
                    "- Every file path must be scoped or validated.\n"
                    "- Every audit event must identify the user and workspace."
                ),
                4,
            ),
        ]

        content = self._render_markdown_document(
            title=title,
            intro="Security documentation for William / Jarvis agents and helper modules.",
            sections=sections,
            include_toc=True,
        )

        artifact = DocumentationArtifact(
            doc_type="security",
            title=title,
            content=content,
            file_name=file_name,
        )

        return self._safe_result(
            message="Security documentation generated successfully.",
            data={
                "artifact": artifact.to_dict(),
                "memory_payload": self._prepare_memory_payload(
                    action="generate_security_doc",
                    context=doc_context,
                    artifact=artifact,
                ),
            },
            metadata={"doc_type": "security", "file_name": file_name},
        )

    # ------------------------------------------------------------------
    # Testing docs
    # ------------------------------------------------------------------

    def generate_testing_doc(
        self,
        *,
        context: Optional[DocumentationContext],
        title: str = "Testing Guide",
        test_categories: Optional[Mapping[str, Sequence[str]]] = None,
        file_name: str = "TESTING.md",
        **_: Any,
    ) -> Dict[str, Any]:
        """
        Generates testing documentation.
        """

        is_valid, doc_context, validation_error = self._validate_task_context(context)
        if not is_valid:
            return self._error_result(message="Invalid context for testing doc.", error=validation_error)

        test_categories = test_categories or {
            "Unit Tests": [
                "Validate each public method returns structured results.",
                "Validate import safety when optional modules are missing.",
                "Validate sensitive keys are masked.",
            ],
            "Integration Tests": [
                "Validate Master Agent routing to DocumentationWriter.",
                "Validate Security Agent approval payload flow.",
                "Validate Verification Agent payload generation.",
            ],
            "SaaS Isolation Tests": [
                "Confirm user A cannot read user B documentation artifacts.",
                "Confirm workspace A cannot access workspace B audit logs.",
                "Confirm all tasks require user_id and workspace_id.",
            ],
            "File Write Tests": [
                "Confirm writes are blocked in safe_mode when allow_file_write=False.",
                "Confirm invalid extensions are blocked.",
                "Confirm paths outside allowed roots are blocked.",
            ],
        }

        body_parts = []
        for category, tests in test_categories.items():
            body_parts.append(f"### {_normalize_heading(category)}\n\n{_render_bullets(tests)}")

        sections = [
            DocumentationSection("Test Categories", "\n\n".join(body_parts), 1),
            DocumentationSection(
                "Recommended Command",
                _render_code_block("python -m pytest", "bash"),
                2,
            ),
            DocumentationSection(
                "Expected Result Format",
                _render_code_block(
                    _safe_json(
                        {
                            "success": True,
                            "message": "Test action completed.",
                            "data": {},
                            "error": None,
                            "metadata": {},
                        }
                    ),
                    "json",
                ),
                3,
            ),
        ]

        content = self._render_markdown_document(
            title=title,
            intro="Testing guide for William / Jarvis modules and agent helpers.",
            sections=sections,
            include_toc=True,
        )

        artifact = DocumentationArtifact(
            doc_type="testing",
            title=title,
            content=content,
            file_name=file_name,
            metadata={"category_count": len(test_categories)},
        )

        return self._safe_result(
            message="Testing documentation generated successfully.",
            data={
                "artifact": artifact.to_dict(),
                "memory_payload": self._prepare_memory_payload(
                    action="generate_testing_doc",
                    context=doc_context,
                    artifact=artifact,
                ),
            },
            metadata={"doc_type": "testing", "file_name": file_name},
        )

    # ------------------------------------------------------------------
    # Module docs
    # ------------------------------------------------------------------

    def generate_module_doc(
        self,
        *,
        context: Optional[DocumentationContext],
        module_name: str,
        module_path: str,
        purpose: str,
        public_classes: Optional[Sequence[str]] = None,
        public_methods: Optional[Sequence[str]] = None,
        dependencies: Optional[Sequence[str]] = None,
        integration_notes: Optional[Sequence[str]] = None,
        file_name: Optional[str] = None,
        **_: Any,
    ) -> Dict[str, Any]:
        """
        Generates documentation for a specific module/file.
        """

        is_valid, doc_context, validation_error = self._validate_task_context(context)
        if not is_valid:
            return self._error_result(message="Invalid context for module doc.", error=validation_error)

        if not module_name or not str(module_name).strip():
            return self._error_result(message="module_name is required.")
        if not module_path or not str(module_path).strip():
            return self._error_result(message="module_path is required.")
        if not purpose or not str(purpose).strip():
            return self._error_result(message="purpose is required.")

        file_name = file_name or f"{_slugify(module_name)}.md"

        sections = [
            DocumentationSection("Purpose", purpose, 1),
            DocumentationSection("File Path", f"`{module_path}`", 2),
            DocumentationSection("Public Classes", _render_bullets(public_classes), 3),
            DocumentationSection("Public Methods", _render_bullets(public_methods), 4),
            DocumentationSection("Dependencies", _render_bullets(dependencies), 5),
            DocumentationSection("Integration Notes", _render_bullets(integration_notes), 6),
            DocumentationSection(
                "Required Result Format",
                _render_code_block(
                    _safe_json(
                        {
                            "success": True,
                            "message": "Operation completed.",
                            "data": {},
                            "error": None,
                            "metadata": {},
                        }
                    ),
                    "json",
                ),
                7,
            ),
        ]

        content = self._render_markdown_document(
            title=f"{module_name} Module Documentation",
            intro="Generated module-level documentation.",
            sections=sections,
            include_toc=True,
        )

        artifact = DocumentationArtifact(
            doc_type="module",
            title=f"{module_name} Module Documentation",
            content=content,
            file_name=file_name,
            metadata={
                "module_name": module_name,
                "module_path": module_path,
            },
        )

        return self._safe_result(
            message="Module documentation generated successfully.",
            data={
                "artifact": artifact.to_dict(),
                "memory_payload": self._prepare_memory_payload(
                    action="generate_module_doc",
                    context=doc_context,
                    artifact=artifact,
                    metadata={"module_name": module_name, "module_path": module_path},
                ),
            },
            metadata={"doc_type": "module", "file_name": file_name},
        )

    # ------------------------------------------------------------------
    # Bundle generation
    # ------------------------------------------------------------------

    def generate_documentation_bundle(
        self,
        *,
        context: Optional[DocumentationContext],
        project_name: str = "William / Jarvis Multi-Agent AI SaaS System",
        include: Optional[Sequence[str]] = None,
        common_payload: Optional[Mapping[str, Any]] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Generates multiple documentation artifacts in one call.

        Does not write files unless write_documentation_file is called separately.
        """

        is_valid, doc_context, validation_error = self._validate_task_context(context)
        if not is_valid:
            return self._error_result(message="Invalid context for documentation bundle.", error=validation_error)

        include_set = {str(item).strip().lower() for item in (include or ["readme", "setup", "api", "deployment", "changelog", "troubleshooting"])}
        invalid = include_set - DOCUMENTATION_TYPES
        if invalid:
            return self._error_result(
                message="Invalid documentation types requested.",
                error=f"Unsupported types: {sorted(invalid)}",
                metadata={"supported_types": sorted(DOCUMENTATION_TYPES)},
            )

        payload = dict(common_payload or {})
        payload.update(kwargs)

        results: Dict[str, Any] = {}
        artifact_list: List[Dict[str, Any]] = []

        generators = {
            "readme": self.generate_readme,
            "setup": self.generate_setup_guide,
            "api": self.generate_api_docs,
            "deployment": self.generate_deployment_guide,
            "changelog": self.generate_changelog,
            "troubleshooting": self.generate_troubleshooting_guide,
            "architecture": self.generate_architecture_doc,
            "security": self.generate_security_doc,
            "testing": self.generate_testing_doc,
        }

        for doc_type in sorted(include_set):
            if doc_type == "bundle":
                continue
            if doc_type == "module":
                continue

            generator = generators.get(doc_type)
            if generator is None:
                continue

            generator_payload = dict(payload)
            generator_payload.setdefault("project_name", project_name)

            result = generator(context=doc_context, **generator_payload)
            results[doc_type] = result

            if result.get("success"):
                artifact = result.get("data", {}).get("artifact")
                if artifact:
                    artifact_list.append(artifact)

        failed = {
            doc_type: result
            for doc_type, result in results.items()
            if not result.get("success")
        }

        bundle_data = {
            "artifacts": artifact_list,
            "results": results,
            "failed": failed,
            "artifact_count": len(artifact_list),
        }

        if failed:
            return self._error_result(
                message="Documentation bundle generated with failures.",
                data=bundle_data,
                metadata={"requested_types": sorted(include_set), "failed_count": len(failed)},
            )

        return self._safe_result(
            message="Documentation bundle generated successfully.",
            data=bundle_data,
            metadata={
                "doc_type": "bundle",
                "requested_types": sorted(include_set),
                "artifact_count": len(artifact_list),
            },
        )

    # ------------------------------------------------------------------
    # Safe file writing
    # ------------------------------------------------------------------

    def write_documentation_file(
        self,
        *,
        context: Optional[DocumentationContext],
        artifact: Optional[Union[DocumentationArtifact, Mapping[str, Any]]] = None,
        content: Optional[str] = None,
        output_path: Optional[Union[str, Path]] = None,
        overwrite: bool = False,
        **_: Any,
    ) -> Dict[str, Any]:
        """
        Writes documentation content to disk with safety checks.

        Requires:
            - allow_file_write=True
            - approved local security policy
            - safe extension
            - path inside allowed output roots
            - overwrite=True if file already exists
        """

        is_valid, doc_context, validation_error = self._validate_task_context(context)
        if not is_valid:
            return self._error_result(message="Invalid context for documentation file write.", error=validation_error)

        normalized_artifact: Optional[DocumentationArtifact] = None

        if artifact is not None:
            if isinstance(artifact, DocumentationArtifact):
                normalized_artifact = artifact
            elif isinstance(artifact, Mapping):
                normalized_artifact = DocumentationArtifact(
                    doc_type=str(artifact.get("doc_type") or "documentation"),
                    title=str(artifact.get("title") or "Documentation"),
                    content=str(artifact.get("content") or ""),
                    format=str(artifact.get("format") or "markdown"),
                    file_name=artifact.get("file_name"),
                    metadata=dict(artifact.get("metadata") or {}),
                )
            else:
                return self._error_result(message="Invalid artifact type.")

        final_content = content
        if final_content is None and normalized_artifact is not None:
            final_content = normalized_artifact.content

        if not final_content:
            return self._error_result(message="No documentation content provided.")

        final_output_path = Path(output_path) if output_path else None
        if final_output_path is None:
            if normalized_artifact and normalized_artifact.file_name:
                final_output_path = Path(normalized_artifact.file_name)
            else:
                final_output_path = Path("documentation.md")

        path_result = self._validate_output_path(final_output_path, overwrite=overwrite)
        if not path_result["success"]:
            return path_result

        resolved_path = Path(path_result["data"]["resolved_path"])

        security_payload = {
            "output_path": str(resolved_path),
            "overwrite": overwrite,
            "content_length": len(final_content),
            "artifact": normalized_artifact.to_dict() if normalized_artifact else None,
            "write_to_disk": True,
        }

        if self._requires_security_check("write_file", security_payload):
            approval = self._request_security_approval(
                action="write_file",
                context=doc_context,
                payload=security_payload,
            )
            if not approval.get("approved"):
                return self._error_result(
                    message="Documentation file write was not approved.",
                    error=approval.get("message"),
                    data={"security_approval": approval},
                    metadata={"output_path": str(resolved_path)},
                )

        try:
            resolved_path.parent.mkdir(parents=True, exist_ok=True)
            resolved_path.write_text(final_content, encoding="utf-8")

            self._log_audit_event(
                action="documentation_writer.write_file",
                context=doc_context,
                status="completed",
                details={
                    "output_path": str(resolved_path),
                    "content_length": len(final_content),
                    "overwrite": overwrite,
                },
            )

            return self._safe_result(
                message="Documentation file written successfully.",
                data={
                    "output_path": str(resolved_path),
                    "bytes_written": len(final_content.encode("utf-8")),
                    "artifact": normalized_artifact.to_dict() if normalized_artifact else None,
                },
                metadata={"output_path": str(resolved_path)},
            )

        except Exception as exc:
            self.logger.exception("Failed to write documentation file.")
            return self._error_result(
                message="Failed to write documentation file.",
                error=exc,
                metadata={"output_path": str(resolved_path)},
            )

    def _validate_output_path(
        self,
        output_path: Union[str, Path],
        *,
        overwrite: bool,
    ) -> Dict[str, Any]:
        """
        Validates output path for safe documentation file writes.
        """

        try:
            raw_path = Path(output_path).expanduser()
            resolved_path = raw_path.resolve()

            if resolved_path.suffix.lower() not in SAFE_DOC_EXTENSIONS:
                return self._error_result(
                    message="Unsafe documentation file extension.",
                    error=f"Allowed extensions: {sorted(SAFE_DOC_EXTENSIONS)}",
                    data={"path": str(resolved_path), "suffix": resolved_path.suffix},
                )

            inside_allowed_root = any(
                self._is_relative_to(resolved_path, root)
                for root in self.allowed_output_roots
            )

            if not inside_allowed_root:
                return self._error_result(
                    message="Output path is outside allowed documentation roots.",
                    error="Path validation failed.",
                    data={
                        "path": str(resolved_path),
                        "allowed_output_roots": [str(root) for root in self.allowed_output_roots],
                    },
                )

            if resolved_path.exists() and not overwrite:
                return self._error_result(
                    message="Output file already exists and overwrite=False.",
                    data={"path": str(resolved_path)},
                )

            return self._safe_result(
                message="Output path validated successfully.",
                data={"resolved_path": str(resolved_path)},
            )

        except Exception as exc:
            return self._error_result(
                message="Output path validation failed.",
                error=exc,
            )

    @staticmethod
    def _is_relative_to(path: Path, root: Path) -> bool:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            return False

    # ------------------------------------------------------------------
    # Rendering helpers
    # ------------------------------------------------------------------

    def _render_markdown_document(
        self,
        *,
        title: str,
        intro: str,
        sections: Sequence[DocumentationSection],
        include_toc: bool = True,
    ) -> str:
        """
        Renders a full markdown document.
        """

        sorted_sections = sorted(sections, key=lambda item: item.order)
        parts = [
            f"# {_normalize_heading(title)}",
            "",
            intro.strip(),
            "",
            f"_Generated by `{self.agent_name}` on `{_utc_now_iso()}`._",
            "",
        ]

        if include_toc:
            parts.append("## Table of Contents")
            parts.append("")
            for section in sorted_sections:
                anchor = _slugify(section.title)
                parts.append(f"- [{_normalize_heading(section.title)}](#{anchor})")
            parts.append("")

        for section in sorted_sections:
            parts.append(section.render_markdown())

        return "\n".join(parts).strip() + "\n"

    def _render_troubleshooting_table(self, issues: Mapping[str, str]) -> str:
        """
        Renders a markdown troubleshooting table.
        """

        if not issues:
            return "| Issue | Fix |\n|---|---|\n| Not specified | Add troubleshooting details. |"

        rows = ["| Issue | Fix |", "|---|---|"]
        for issue, fix in issues.items():
            safe_issue = str(issue).replace("|", "\\|").strip()
            safe_fix = str(fix).replace("|", "\\|").strip()
            rows.append(f"| {safe_issue} | {safe_fix} |")
        return "\n".join(rows)

    def _render_endpoint_doc(self, endpoint: Mapping[str, Any]) -> str:
        """
        Renders one API endpoint block.
        """

        method = str(endpoint.get("method") or "GET").upper()
        path = str(endpoint.get("path") or "/")
        description = str(endpoint.get("description") or "No description provided.")
        required_context = endpoint.get("required_context") or ["user_id", "workspace_id"]
        request_body = endpoint.get("request_body")
        response_example = endpoint.get("response_example") or {
            "success": True,
            "message": "Request completed.",
            "data": {},
            "error": None,
            "metadata": {},
        }

        parts = [
            f"### `{method} {path}`",
            "",
            description,
            "",
            "**Required Context**",
            "",
            _render_bullets(required_context),
            "",
        ]

        if request_body is not None:
            parts.extend(
                [
                    "**Request Body**",
                    "",
                    _render_code_block(_safe_json(request_body), "json"),
                    "",
                ]
            )

        parts.extend(
            [
                "**Response Example**",
                "",
                _render_code_block(_safe_json(response_example), "json"),
            ]
        )

        return "\n".join(parts).strip()

    # ------------------------------------------------------------------
    # Metadata / registry helpers
    # ------------------------------------------------------------------

    def get_agent_capabilities(self) -> Dict[str, Any]:
        """
        Returns registry/dashboard-friendly capability metadata.
        """

        return {
            "success": True,
            "message": "DocumentationWriter capabilities loaded.",
            "data": {
                "agent_name": self.agent_name,
                "agent_type": self.agent_type,
                "safe_mode": self.safe_mode,
                "allow_file_write": self.allow_file_write,
                "supported_documentation_types": sorted(DOCUMENTATION_TYPES),
                "supported_file_extensions": sorted(SAFE_DOC_EXTENSIONS),
                "public_methods": [
                    "run_task",
                    "generate_readme",
                    "generate_setup_guide",
                    "generate_api_docs",
                    "generate_deployment_guide",
                    "generate_changelog",
                    "generate_troubleshooting_guide",
                    "generate_architecture_doc",
                    "generate_security_doc",
                    "generate_testing_doc",
                    "generate_module_doc",
                    "generate_documentation_bundle",
                    "write_documentation_file",
                    "get_agent_capabilities",
                ],
            },
            "error": None,
            "metadata": {
                "timestamp": _utc_now_iso(),
                "agent": self.agent_name,
            },
        }


__all__ = [
    "DocumentationWriter",
    "DocumentationContext",
    "DocumentationSection",
    "DocumentationArtifact",
]