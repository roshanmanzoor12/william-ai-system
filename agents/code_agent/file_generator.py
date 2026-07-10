"""
agents/code_agent/file_generator.py

FileGenerator for William / Jarvis Multi-Agent AI SaaS System by Digital Promotix.

Purpose:
    Creates files, templates, configs, components, and docs in a safe,
    SaaS-isolated, import-safe, testable way.

Architecture compatibility:
    - Master Agent routing compatible through run(task)
    - BaseAgent compatible with safe fallback import
    - Security Agent approval compatible
    - Verification Agent payload compatible
    - Memory Agent payload compatible
    - Dashboard/API structured dict/JSON responses
    - Agent Registry / Loader friendly metadata

Safety model:
    - Every user-specific write requires user_id and workspace_id.
    - Files are isolated under safe_root / user_id / workspace_id.
    - Path traversal and absolute paths are blocked.
    - Sensitive writes can require Security Agent approval.
    - No shell commands are executed.
    - No secrets are hardcoded.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from string import Template
from typing import Any, Dict, List, Mapping, Optional, Sequence, Union


try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """Import-safe fallback BaseAgent for early project generation."""

        agent_name = "base_agent_fallback"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_id = kwargs.get("agent_id", str(uuid.uuid4()))
            self.logger = logging.getLogger(self.__class__.__name__)

        def run(self, task: Mapping[str, Any]) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent does not implement run().",
                "data": {},
                "error": "BASE_AGENT_FALLBACK_RUN_NOT_IMPLEMENTED",
                "metadata": {"agent_id": self.agent_id},
            }


LOGGER = logging.getLogger(__name__)
if not LOGGER.handlers:
    logging.basicConfig(level=logging.INFO)


DEFAULT_SAFE_ROOT = Path(os.getenv("WILLIAM_PROJECTS_ROOT", "./william_workspaces")).resolve()
DEFAULT_FILE_ENCODING = "utf-8"
MAX_DEFAULT_FILE_SIZE_CHARS = 2_000_000
MAX_DEFAULT_FILES_PER_BATCH = 200

SAFE_FILENAME_PATTERN = re.compile(r"^[a-zA-Z0-9._\-\s]+$")
SAFE_RELATIVE_PATH_PATTERN = re.compile(r"^[a-zA-Z0-9._\-/\s]+$")

RESERVED_WINDOWS_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}

TEXT_EXTENSIONS = {
    ".py", ".txt", ".md", ".json", ".yaml", ".yml", ".toml", ".ini",
    ".cfg", ".env", ".example", ".html", ".css", ".js", ".ts", ".tsx",
    ".jsx", ".sql", ".sh", ".bat", ".ps1", ".xml", ".csv",
}

DEFAULT_TEMPLATE_REGISTRY: Dict[str, Dict[str, Any]] = {
    "python_agent": {
        "description": "Basic William/Jarvis compatible Python agent file.",
        "extension": ".py",
        "content": '''"""
${module_path}

${class_name} for William / Jarvis Multi-Agent AI SaaS System.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, Mapping


class ${class_name}:
    """${description}"""

    agent_name = "${agent_name}"
    agent_type = "${agent_type}"
    version = "1.0.0"

    def __init__(self, agent_id: str | None = None) -> None:
        self.agent_id = agent_id or str(uuid.uuid4())

    def run(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """Run a structured William/Jarvis task."""
        return {
            "success": True,
            "message": "${class_name} received task.",
            "data": {"task": dict(task or {})},
            "error": None,
            "metadata": {
                "agent_name": self.agent_name,
                "agent_type": self.agent_type,
                "agent_id": self.agent_id,
                "version": self.version,
            },
        }
''',
    },
    "fastapi_router": {
        "description": "FastAPI router module.",
        "extension": ".py",
        "content": '''"""
${module_path}

FastAPI router for William / Jarvis SaaS dashboard/API.
"""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="${route_prefix}", tags=["${tag}"])


@router.get("/health")
def health() -> dict:
    """Health check endpoint."""
    return {
        "success": True,
        "message": "${tag} router is healthy.",
        "data": {},
        "error": None,
        "metadata": {},
    }
''',
    },
    "readme": {
        "description": "README documentation file.",
        "extension": ".md",
        "content": '''# ${title}

${description}

## Purpose

${purpose}

## William / Jarvis Compatibility

- SaaS user/workspace isolation ready
- Master Agent routing ready
- Security Agent approval compatible
- Verification Agent payload compatible
- Memory Agent context compatible
- Dashboard/API integration ready

## Status

Generated by FileGenerator.
''',
    },
    "json_config": {
        "description": "Safe JSON configuration file.",
        "extension": ".json",
        "content": '''{
  "name": "${name}",
  "description": "${description}",
  "version": "1.0.0",
  "system": "William / Jarvis Multi-Agent AI SaaS System",
  "brand": "Digital Promotix",
  "enabled": true,
  "metadata": {}
}
''',
    },
    "env_example": {
        "description": "Environment example file without secrets.",
        "extension": ".example",
        "content": '''# William / Jarvis environment example
APP_ENV=development
APP_SECRET_KEY=change-me
DATABASE_URL=sqlite:///william.db
WILLIAM_PROJECTS_ROOT=./william_workspaces

# Do not place real secrets in committed files.
''',
    },
    "html_component": {
        "description": "Simple dashboard HTML component.",
        "extension": ".html",
        "content": '''<section class="${component_class}" data-component="${component_name}">
  <div class="${component_class}__inner">
    <h2>${title}</h2>
    <p>${description}</p>
  </div>
</section>
''',
    },
    "css_component": {
        "description": "Simple dashboard CSS component.",
        "extension": ".css",
        "content": '''.${component_class} {
  width: 100%;
  padding: 24px;
  border-radius: 16px;
  background: #101010;
  color: #ffffff;
}

.${component_class}__inner {
  max-width: 1200px;
  margin: 0 auto;
}
''',
    },
}


@dataclass
class GeneratedFileSpec:
    """A single generated file request."""

    path: str
    content: str = ""
    template_name: Optional[str] = None
    variables: Dict[str, Any] = field(default_factory=dict)
    overwrite: bool = False
    encoding: str = DEFAULT_FILE_ENCODING
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FileGenerationBatch:
    """A batch of file generation requests."""

    files: List[GeneratedFileSpec]
    project_path: Optional[str] = None
    overwrite_existing_files: bool = False
    dry_run: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FileGenerationReport:
    """Structured file generation report."""

    root_path: str
    generated_files: List[str] = field(default_factory=list)
    skipped_files: List[str] = field(default_factory=list)
    overwritten_files: List[str] = field(default_factory=list)
    preview_files: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[Dict[str, Any]] = field(default_factory=list)
    manifest_path: Optional[str] = None
    duration_seconds: float = 0.0


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_id(value: Any, field_name: str) -> str:
    if value is None:
        raise ValueError(f"{field_name} is required.")
    normalized = str(value).strip()
    if not normalized:
        raise ValueError(f"{field_name} cannot be empty.")
    if len(normalized) > 128:
        raise ValueError(f"{field_name} is too long.")
    if not re.match(r"^[a-zA-Z0-9_\-:.@]+$", normalized):
        raise ValueError(
            f"{field_name} contains unsafe characters. Allowed: letters, numbers, underscore, hyphen, colon, dot, @."
        )
    return normalized


def _is_reserved_name(path_part: str) -> bool:
    return path_part.split(".")[0].upper() in RESERVED_WINDOWS_NAMES


def _safe_text(value: Any, max_length: int = 5000) -> str:
    text = str(value)
    return text[:max_length] + "...[truncated]" if len(text) > max_length else text


def _sha256_text(content: str) -> str:
    return hashlib.sha256(content.encode(DEFAULT_FILE_ENCODING)).hexdigest()


def _safe_join(root: Path, relative_path: Union[str, Path]) -> Path:
    raw = str(relative_path).replace("\\", "/").strip()
    if not raw:
        raise ValueError("Path cannot be empty.")
    candidate = Path(raw)
    if candidate.is_absolute():
        raise ValueError(f"Absolute paths are not allowed: {raw}")
    for part in candidate.parts:
        if part in {"", ".."}:
            raise ValueError(f"Unsafe path traversal detected: {raw}")
        if _is_reserved_name(part):
            raise ValueError(f"Reserved path name is not allowed: {part}")
    resolved = (root / candidate).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(f"Path escapes safe root: {raw}") from exc
    return resolved


def _slugify_name(value: str, fallback: str = "generated_file") -> str:
    text = str(value or "").strip()
    text = re.sub(r"\s+", "-", text)
    text = re.sub(r"[^a-zA-Z0-9._\-]", "-", text)
    text = re.sub(r"-{2,}", "-", text).strip(".-")
    return text[:120] or fallback


def _guess_file_type(path: str) -> str:
    suffix = Path(path).suffix.lower()
    if suffix == ".py":
        return "python"
    if suffix in {".md", ".txt"}:
        return "document"
    if suffix in {".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".env", ".example"}:
        return "config"
    if suffix in {".html", ".css", ".js", ".ts", ".tsx", ".jsx"}:
        return "frontend_component"
    if suffix == ".sql":
        return "database"
    return "text" if suffix in TEXT_EXTENSIONS else "unknown"


class FileGenerator(BaseAgent):
    """
    Creates files, templates, configs, components, and docs.

    Public methods expose structured results suitable for FastAPI routes,
    dashboards, Master Agent routing, Registry discovery, Memory Agent storage,
    Verification Agent checks, and Security Agent approval flows.
    """

    agent_name = "code_file_generator"
    agent_type = "code_agent"
    version = "1.0.0"

    def __init__(
        self,
        *,
        safe_root: Union[str, Path, None] = None,
        security_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        event_sink: Optional[Any] = None,
        audit_sink: Optional[Any] = None,
        template_registry: Optional[Mapping[str, Mapping[str, Any]]] = None,
        require_security_approval: bool = False,
        allow_overwrite: bool = False,
        max_files_per_batch: int = MAX_DEFAULT_FILES_PER_BATCH,
        max_file_size_chars: int = MAX_DEFAULT_FILE_SIZE_CHARS,
        agent_id: Optional[str] = None,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        try:
            super().__init__(agent_id=agent_id or str(uuid.uuid4()))
        except TypeError:
            super().__init__()

        self.agent_id = getattr(self, "agent_id", agent_id or str(uuid.uuid4()))
        self.safe_root = Path(safe_root or DEFAULT_SAFE_ROOT).resolve()
        self.security_agent = security_agent
        self.memory_agent = memory_agent
        self.verification_agent = verification_agent
        self.event_sink = event_sink
        self.audit_sink = audit_sink
        self.require_security_approval = require_security_approval
        self.allow_overwrite = allow_overwrite
        self.max_files_per_batch = int(max_files_per_batch)
        self.max_file_size_chars = int(max_file_size_chars)
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        self.template_registry: Dict[str, Dict[str, Any]] = dict(DEFAULT_TEMPLATE_REGISTRY)

        if template_registry:
            for key, value in template_registry.items():
                self.template_registry[str(key)] = dict(value)

    def run(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        BaseAgent-compatible task router.

        Supported actions:
            create_file, create_files, preview_files, render_template,
            list_templates, validate_file, register_template
        """

        started = time.time()
        try:
            context = self._validate_task_context(task)
            action = str(task.get("action", "create_files")).strip().lower()

            self._emit_agent_event(
                event_type="task_started",
                user_id=context["user_id"],
                workspace_id=context["workspace_id"],
                payload={"action": action},
            )

            if action == "create_file":
                result = self.create_file(
                    user_id=context["user_id"],
                    workspace_id=context["workspace_id"],
                    path=str(task.get("path", "")),
                    content=str(task.get("content", "")),
                    template_name=task.get("template_name"),
                    variables=dict(task.get("variables") or {}),
                    project_path=task.get("project_path"),
                    overwrite=bool(task.get("overwrite", False)),
                    dry_run=bool(task.get("dry_run", False)),
                    metadata=dict(task.get("metadata") or {}),
                )
            elif action == "create_files":
                result = self.create_files(
                    user_id=context["user_id"],
                    workspace_id=context["workspace_id"],
                    batch=task.get("batch") or task,
                )
            elif action == "preview_files":
                batch_data = dict(task.get("batch") or task)
                batch_data["dry_run"] = True
                result = self.create_files(
                    user_id=context["user_id"],
                    workspace_id=context["workspace_id"],
                    batch=batch_data,
                )
            elif action == "render_template":
                result = self.render_template_result(
                    template_name=str(task.get("template_name", "")),
                    variables=dict(task.get("variables") or {}),
                )
            elif action == "list_templates":
                result = self.list_templates()
            elif action == "validate_file":
                result = self.validate_file_spec(self._coerce_file_spec(task.get("file") or task))
            elif action == "register_template":
                result = self.register_template(
                    template_name=str(task.get("template_name", "")),
                    content=str(task.get("content", "")),
                    description=str(task.get("description", "")),
                    extension=str(task.get("extension", "")),
                    metadata=dict(task.get("metadata") or {}),
                )
            else:
                result = self._error_result(
                    message=f"Unsupported FileGenerator action: {action}",
                    error="UNSUPPORTED_ACTION",
                    metadata={
                        "supported_actions": [
                            "create_file", "create_files", "preview_files", "render_template",
                            "list_templates", "validate_file", "register_template",
                        ]
                    },
                )

            self._emit_agent_event(
                event_type="task_completed" if result.get("success") else "task_failed",
                user_id=context["user_id"],
                workspace_id=context["workspace_id"],
                payload={
                    "action": action,
                    "success": result.get("success"),
                    "message": result.get("message"),
                    "duration_seconds": round(time.time() - started, 4),
                },
            )
            return result
        except Exception as exc:
            self.logger.exception("FileGenerator.run failed.")
            return self._error_result(
                message="FileGenerator task failed.",
                error=str(exc),
                metadata={"duration_seconds": round(time.time() - started, 4)},
            )

    def create_file(
        self,
        *,
        user_id: Any,
        workspace_id: Any,
        path: str,
        content: str = "",
        template_name: Optional[str] = None,
        variables: Optional[Mapping[str, Any]] = None,
        project_path: Optional[Union[str, Path]] = None,
        overwrite: bool = False,
        dry_run: bool = False,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create one file safely."""

        spec = GeneratedFileSpec(
            path=path,
            content=content,
            template_name=template_name,
            variables=dict(variables or {}),
            overwrite=overwrite,
            metadata=dict(metadata or {}),
        )
        batch = FileGenerationBatch(
            files=[spec],
            project_path=str(project_path) if project_path else None,
            overwrite_existing_files=overwrite,
            dry_run=dry_run,
            metadata=dict(metadata or {}),
        )
        return self.create_files(user_id=user_id, workspace_id=workspace_id, batch=batch)

    def create_files(
        self,
        *,
        user_id: Any,
        workspace_id: Any,
        batch: Union[FileGenerationBatch, Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """Create files from direct content or registered templates."""

        started = time.time()
        context = self._validate_task_context({"user_id": user_id, "workspace_id": workspace_id})

        try:
            generation_batch = self._coerce_batch(batch)
            validation = self.validate_batch(generation_batch)
            if not validation.get("success"):
                return validation

            root_path = self._resolve_generation_root(
                user_id=context["user_id"],
                workspace_id=context["workspace_id"],
                project_path=generation_batch.project_path,
            )

            sensitive = self._requires_security_check(
                action="create_files",
                user_id=context["user_id"],
                workspace_id=context["workspace_id"],
                target_path=str(root_path),
                payload={
                    "file_count": len(generation_batch.files),
                    "overwrite": generation_batch.overwrite_existing_files,
                    "dry_run": generation_batch.dry_run,
                    "metadata": generation_batch.metadata,
                },
            )

            if sensitive:
                approval = self._request_security_approval(
                    action="create_files",
                    user_id=context["user_id"],
                    workspace_id=context["workspace_id"],
                    target_path=str(root_path),
                    payload={
                        "file_count": len(generation_batch.files),
                        "overwrite": generation_batch.overwrite_existing_files,
                        "dry_run": generation_batch.dry_run,
                        "metadata": generation_batch.metadata,
                    },
                )
                if not approval.get("approved"):
                    return self._error_result(
                        message="File generation blocked by Security Agent policy.",
                        error="SECURITY_APPROVAL_DENIED",
                        data={"approval": approval},
                        metadata={
                            "user_id": context["user_id"],
                            "workspace_id": context["workspace_id"],
                            "root_path": str(root_path),
                        },
                    )

            report = FileGenerationReport(root_path=str(root_path))

            self._log_audit_event(
                user_id=context["user_id"],
                workspace_id=context["workspace_id"],
                action="file_generation_requested",
                resource=str(root_path),
                payload={
                    "file_count": len(generation_batch.files),
                    "dry_run": generation_batch.dry_run,
                    "overwrite": generation_batch.overwrite_existing_files,
                    "metadata": generation_batch.metadata,
                },
            )

            if generation_batch.dry_run:
                for file_spec in generation_batch.files:
                    rendered = self._render_file_content(file_spec)
                    target = _safe_join(root_path, file_spec.path)
                    report.preview_files.append({
                        "path": str(target),
                        "relative_path": file_spec.path,
                        "file_type": _guess_file_type(file_spec.path),
                        "content_length": len(rendered),
                        "sha256": _sha256_text(rendered),
                        "would_overwrite": target.exists(),
                        "template_name": file_spec.template_name,
                    })

                report.duration_seconds = round(time.time() - started, 4)
                verification_payload = self._prepare_verification_payload(
                    user_id=context["user_id"],
                    workspace_id=context["workspace_id"],
                    action="preview_files",
                    report=report,
                )
                memory_payload = self._prepare_memory_payload(
                    user_id=context["user_id"],
                    workspace_id=context["workspace_id"],
                    action="preview_files",
                    report=report,
                )
                return self._safe_result(
                    message="Dry run completed. No files were written.",
                    data={
                        "report": asdict(report),
                        "verification_payload": verification_payload,
                        "memory_payload": memory_payload,
                    },
                    metadata={
                        "user_id": context["user_id"],
                        "workspace_id": context["workspace_id"],
                        "root_path": str(root_path),
                        "dry_run": True,
                        "duration_seconds": report.duration_seconds,
                    },
                )

            root_path.mkdir(parents=True, exist_ok=True)
            for file_spec in generation_batch.files:
                self._write_single_file(
                    root_path=root_path,
                    file_spec=file_spec,
                    report=report,
                    batch_overwrite=generation_batch.overwrite_existing_files,
                )

            manifest_path = self._write_manifest(
                root_path=root_path,
                user_id=context["user_id"],
                workspace_id=context["workspace_id"],
                batch=generation_batch,
                report=report,
            )
            report.manifest_path = str(manifest_path)
            report.duration_seconds = round(time.time() - started, 4)

            verification_payload = self._prepare_verification_payload(
                user_id=context["user_id"],
                workspace_id=context["workspace_id"],
                action="create_files",
                report=report,
            )
            memory_payload = self._prepare_memory_payload(
                user_id=context["user_id"],
                workspace_id=context["workspace_id"],
                action="create_files",
                report=report,
            )

            self._log_audit_event(
                user_id=context["user_id"],
                workspace_id=context["workspace_id"],
                action="files_generated",
                resource=str(root_path),
                payload={
                    "generated_files": len(report.generated_files),
                    "skipped_files": len(report.skipped_files),
                    "overwritten_files": len(report.overwritten_files),
                    "errors": report.errors,
                },
            )

            if report.errors:
                return self._error_result(
                    message="Some files failed to generate.",
                    error="FILE_GENERATION_PARTIAL_FAILURE",
                    data={
                        "report": asdict(report),
                        "verification_payload": verification_payload,
                        "memory_payload": memory_payload,
                    },
                    metadata={
                        "user_id": context["user_id"],
                        "workspace_id": context["workspace_id"],
                        "root_path": str(root_path),
                        "duration_seconds": report.duration_seconds,
                    },
                )

            return self._safe_result(
                message="Files generated successfully.",
                data={
                    "report": asdict(report),
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                metadata={
                    "user_id": context["user_id"],
                    "workspace_id": context["workspace_id"],
                    "root_path": str(root_path),
                    "dry_run": False,
                    "duration_seconds": report.duration_seconds,
                },
            )

        except Exception as exc:
            self.logger.exception("File generation failed.")
            return self._error_result(
                message="File generation failed.",
                error=str(exc),
                metadata={
                    "user_id": context["user_id"],
                    "workspace_id": context["workspace_id"],
                    "duration_seconds": round(time.time() - started, 4),
                },
            )

    def render_template_result(self, *, template_name: str, variables: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        """Render a template and return a structured result."""

        try:
            content = self.render_template(template_name, dict(variables or {}))
            return self._safe_result(
                message="Template rendered successfully.",
                data={
                    "template_name": template_name,
                    "content": content,
                    "content_length": len(content),
                    "sha256": _sha256_text(content),
                },
                metadata={"template_name": template_name},
            )
        except Exception as exc:
            return self._error_result(
                message="Template rendering failed.",
                error=str(exc),
                metadata={"template_name": template_name},
            )

    def render_template(self, template_name: str, variables: Mapping[str, Any]) -> str:
        """Render a registered template using safe_substitute."""

        name = str(template_name).strip()
        if not name:
            raise ValueError("template_name is required.")
        if name not in self.template_registry:
            raise ValueError(f"Unknown template: {name}")
        raw_content = str(self.template_registry[name].get("content", ""))
        safe_variables = {str(k): self._sanitize_template_value(v) for k, v in dict(variables or {}).items()}
        return Template(raw_content).safe_substitute(safe_variables)

    def list_templates(self) -> Dict[str, Any]:
        """List all registered templates."""

        templates = {
            name: {
                "description": data.get("description", ""),
                "extension": data.get("extension", ""),
                "metadata": data.get("metadata", {}),
            }
            for name, data in sorted(self.template_registry.items())
        }
        return self._safe_result(
            message="Templates listed successfully.",
            data={"templates": templates, "count": len(templates)},
            metadata={"count": len(templates)},
        )

    def register_template(
        self,
        *,
        template_name: str,
        content: str,
        description: str = "",
        extension: str = "",
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Register a runtime in-memory template."""

        name = _slugify_name(template_name, fallback="")
        if not name:
            return self._error_result(message="template_name is required.", error="TEMPLATE_NAME_REQUIRED")
        if not isinstance(content, str) or not content.strip():
            return self._error_result(message="Template content is required.", error="TEMPLATE_CONTENT_REQUIRED")
        if len(content) > self.max_file_size_chars:
            return self._error_result(
                message="Template content exceeds maximum size.",
                error="TEMPLATE_TOO_LARGE",
                metadata={"max_file_size_chars": self.max_file_size_chars},
            )
        self.template_registry[name] = {
            "description": description or f"Runtime template: {name}",
            "extension": extension,
            "content": content,
            "metadata": dict(metadata or {}),
            "registered_at": _utc_now_iso(),
        }
        return self._safe_result(
            message="Template registered successfully.",
            data={"template_name": name, "description": self.template_registry[name]["description"], "extension": extension},
            metadata={"template_name": name},
        )

    def validate_file_spec(self, file_spec: GeneratedFileSpec) -> Dict[str, Any]:
        """Validate a single file spec."""

        errors: List[str] = []
        try:
            self._validate_relative_file_path(file_spec.path)
        except Exception as exc:
            errors.append(str(exc))
        if file_spec.template_name and file_spec.template_name not in self.template_registry:
            errors.append(f"Unknown template_name: {file_spec.template_name}")
        try:
            rendered = self._render_file_content(file_spec)
            if len(rendered) > self.max_file_size_chars:
                errors.append(f"File content exceeds max size of {self.max_file_size_chars} characters.")
        except Exception as exc:
            errors.append(f"Could not render file content: {exc}")
        if errors:
            return self._error_result(
                message="File spec validation failed.",
                error="FILE_SPEC_VALIDATION_FAILED",
                data={"errors": errors, "file": asdict(file_spec)},
            )
        return self._safe_result(
            message="File spec is valid.",
            data={
                "file": {
                    "path": file_spec.path,
                    "file_type": _guess_file_type(file_spec.path),
                    "template_name": file_spec.template_name,
                    "overwrite": file_spec.overwrite,
                    "metadata": file_spec.metadata,
                }
            },
        )

    def validate_batch(self, batch: FileGenerationBatch) -> Dict[str, Any]:
        """Validate a full generation batch."""

        errors: List[str] = []
        if not isinstance(batch, FileGenerationBatch):
            errors.append("Batch must be FileGenerationBatch.")
        if not batch.files:
            errors.append("At least one file is required.")
        if len(batch.files) > self.max_files_per_batch:
            errors.append(f"Too many files. Limit is {self.max_files_per_batch}; received {len(batch.files)}.")
        seen_paths = set()
        duplicate_paths = set()
        for index, file_spec in enumerate(batch.files):
            validation = self.validate_file_spec(file_spec)
            if not validation.get("success"):
                errors.append(f"File #{index + 1} invalid: {validation.get('data', {}).get('errors')}")
            normalized = file_spec.path.strip().replace("\\", "/").lower()
            if normalized in seen_paths:
                duplicate_paths.add(file_spec.path)
            seen_paths.add(normalized)
        if duplicate_paths:
            errors.append(f"Duplicate file paths detected: {sorted(duplicate_paths)}")
        if batch.project_path:
            try:
                self._validate_relative_directory_path(str(batch.project_path))
            except Exception as exc:
                errors.append(f"Invalid project_path: {exc}")
        if errors:
            return self._error_result(
                message="File generation batch validation failed.",
                error="BATCH_VALIDATION_FAILED",
                data={"errors": errors},
                metadata={"file_count": len(batch.files)},
            )
        return self._safe_result(
            message="File generation batch is valid.",
            data={"file_count": len(batch.files), "project_path": batch.project_path, "dry_run": batch.dry_run},
        )

    def _validate_task_context(self, task: Mapping[str, Any]) -> Dict[str, str]:
        """Validate user/workspace context for SaaS isolation."""

        return {
            "user_id": _normalize_id(task.get("user_id"), "user_id"),
            "workspace_id": _normalize_id(task.get("workspace_id"), "workspace_id"),
        }

    def _requires_security_check(
        self,
        *,
        action: str,
        user_id: str,
        workspace_id: str,
        target_path: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """Decide whether Security Agent approval is required."""

        payload = dict(payload or {})
        if self.require_security_approval:
            return True
        if bool(payload.get("overwrite")):
            return True
        if int(payload.get("file_count") or 0) > 50:
            return True
        normalized_path = str(target_path).replace("\\", "/")
        if "/../" in normalized_path or normalized_path.endswith("/.."):
            return True
        return False

    def _request_security_approval(
        self,
        *,
        action: str,
        user_id: str,
        workspace_id: str,
        target_path: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Request Security Agent approval with fallback-safe behavior."""

        approval_payload = {
            "action": action,
            "agent_name": self.agent_name,
            "agent_id": self.agent_id,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "target_path": target_path,
            "payload": dict(payload or {}),
            "requested_at": _utc_now_iso(),
        }
        try:
            if self.security_agent is None:
                if self.require_security_approval:
                    return {"approved": False, "reason": "Security approval required but no Security Agent is configured.", "payload": approval_payload}
                return {"approved": True, "reason": "No Security Agent configured; safe local file generation allowed.", "payload": approval_payload}
            if hasattr(self.security_agent, "approve_action"):
                response = self.security_agent.approve_action(approval_payload)
            elif hasattr(self.security_agent, "validate_action"):
                response = self.security_agent.validate_action(approval_payload)
            elif callable(self.security_agent):
                response = self.security_agent(approval_payload)
            else:
                return {"approved": False, "reason": "Configured Security Agent has no supported approval method.", "payload": approval_payload}
            if isinstance(response, Mapping):
                return {
                    "approved": bool(response.get("approved", response.get("success", False))),
                    "reason": response.get("reason") or response.get("message") or "",
                    "response": dict(response),
                    "payload": approval_payload,
                }
            return {"approved": bool(response), "reason": "Security Agent returned non-dict response.", "response": response, "payload": approval_payload}
        except Exception as exc:
            self.logger.exception("Security approval failed.")
            return {"approved": False, "reason": f"Security approval failed: {exc}", "payload": approval_payload}

    def _prepare_verification_payload(self, *, user_id: str, workspace_id: str, action: str, report: FileGenerationReport) -> Dict[str, Any]:
        """Prepare Verification Agent payload."""

        file_hashes = []
        for file_path in report.generated_files + report.overwritten_files:
            path = Path(file_path)
            if path.exists() and path.is_file():
                try:
                    content = path.read_text(encoding=DEFAULT_FILE_ENCODING)
                    file_hashes.append({"path": str(path), "sha256": _sha256_text(content), "size_chars": len(content)})
                except Exception:
                    file_hashes.append({"path": str(path), "sha256": None, "size_chars": None, "read_error": True})
        payload = {
            "verification_type": "file_generation_result",
            "agent_name": self.agent_name,
            "agent_id": self.agent_id,
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "root_path": report.root_path,
            "manifest_path": report.manifest_path,
            "generated_files_count": len(report.generated_files),
            "overwritten_files_count": len(report.overwritten_files),
            "skipped_files_count": len(report.skipped_files),
            "preview_files_count": len(report.preview_files),
            "errors_count": len(report.errors),
            "file_hashes": file_hashes,
            "errors": report.errors,
            "created_at": _utc_now_iso(),
        }
        self._send_to_optional_agent(agent=self.verification_agent, method_names=("prepare_payload", "receive_payload", "record"), payload=payload, label="verification_agent")
        return payload

    def _prepare_memory_payload(self, *, user_id: str, workspace_id: str, action: str, report: FileGenerationReport) -> Dict[str, Any]:
        """Prepare Memory Agent payload."""

        payload = {
            "memory_type": "file_generation_summary",
            "agent_name": self.agent_name,
            "agent_id": self.agent_id,
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "summary": f"Generated {len(report.generated_files)} files, overwrote {len(report.overwritten_files)}, skipped {len(report.skipped_files)} under {report.root_path}.",
            "file_generation": {
                "root_path": report.root_path,
                "generated_files_count": len(report.generated_files),
                "overwritten_files_count": len(report.overwritten_files),
                "skipped_files_count": len(report.skipped_files),
                "preview_files_count": len(report.preview_files),
                "errors_count": len(report.errors),
                "manifest_path": report.manifest_path,
            },
            "created_at": _utc_now_iso(),
        }
        self._send_to_optional_agent(agent=self.memory_agent, method_names=("remember", "store", "receive_payload", "record"), payload=payload, label="memory_agent")
        return payload

    def _emit_agent_event(self, *, event_type: str, user_id: Optional[str] = None, workspace_id: Optional[str] = None, payload: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        """Emit event for dashboard/API/event bus integrations."""

        event = {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "agent_name": self.agent_name,
            "agent_id": self.agent_id,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "payload": dict(payload or {}),
            "created_at": _utc_now_iso(),
        }
        try:
            if self.event_sink is None:
                self.logger.debug("Agent event: %s", event)
            elif callable(self.event_sink):
                self.event_sink(event)
            elif hasattr(self.event_sink, "append"):
                self.event_sink.append(event)
            elif hasattr(self.event_sink, "emit"):
                self.event_sink.emit(event)
        except Exception:
            self.logger.exception("Failed to emit agent event.")
        return event

    def _log_audit_event(self, *, user_id: str, workspace_id: str, action: str, resource: str, payload: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        """Log audit event for SaaS traceability."""

        audit_event = {
            "audit_id": str(uuid.uuid4()),
            "agent_name": self.agent_name,
            "agent_id": self.agent_id,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "action": action,
            "resource": resource,
            "payload": dict(payload or {}),
            "created_at": _utc_now_iso(),
        }
        try:
            if self.audit_sink is None:
                self.logger.info("AUDIT %s user=%s workspace=%s resource=%s", action, user_id, workspace_id, resource)
            elif callable(self.audit_sink):
                self.audit_sink(audit_event)
            elif hasattr(self.audit_sink, "append"):
                self.audit_sink.append(audit_event)
            elif hasattr(self.audit_sink, "record"):
                self.audit_sink.record(audit_event)
        except Exception:
            self.logger.exception("Failed to log audit event.")
        return audit_event

    def _safe_result(self, *, message: str, data: Optional[Mapping[str, Any]] = None, metadata: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        """Return standard success result."""

        return {
            "success": True,
            "message": message,
            "data": dict(data or {}),
            "error": None,
            "metadata": {
                "agent_name": self.agent_name,
                "agent_type": self.agent_type,
                "agent_id": self.agent_id,
                "version": self.version,
                "timestamp": _utc_now_iso(),
                **dict(metadata or {}),
            },
        }

    def _error_result(self, *, message: str, error: Optional[Any] = None, data: Optional[Mapping[str, Any]] = None, metadata: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        """Return standard error result."""

        return {
            "success": False,
            "message": message,
            "data": dict(data or {}),
            "error": _safe_text(error or message),
            "metadata": {
                "agent_name": self.agent_name,
                "agent_type": self.agent_type,
                "agent_id": self.agent_id,
                "version": self.version,
                "timestamp": _utc_now_iso(),
                **dict(metadata or {}),
            },
        }

    def _resolve_generation_root(self, *, user_id: str, workspace_id: str, project_path: Optional[Union[str, Path]] = None) -> Path:
        """Resolve isolated generation root."""

        isolated_root = self.safe_root / user_id / workspace_id
        if project_path:
            project_relative = self._validate_relative_directory_path(str(project_path))
            root = _safe_join(isolated_root, project_relative)
        else:
            root = isolated_root / "generated_files"
        root = root.resolve()
        try:
            root.relative_to(self.safe_root)
        except ValueError as exc:
            raise ValueError("Resolved generation root escapes safe root.") from exc
        return root

    def _write_single_file(self, *, root_path: Path, file_spec: GeneratedFileSpec, report: FileGenerationReport, batch_overwrite: bool) -> None:
        """Write one generated file safely."""

        try:
            target = _safe_join(root_path, file_spec.path)
            content = self._render_file_content(file_spec)
            target.parent.mkdir(parents=True, exist_ok=True)
            can_overwrite = bool(self.allow_overwrite or batch_overwrite or file_spec.overwrite)
            if target.exists() and not can_overwrite:
                report.skipped_files.append(str(target))
                return
            existed_before = target.exists()
            target.write_text(content, encoding=file_spec.encoding or DEFAULT_FILE_ENCODING)
            if existed_before:
                report.overwritten_files.append(str(target))
            else:
                report.generated_files.append(str(target))
        except Exception as exc:
            self.logger.exception("Failed to write file: %s", file_spec.path)
            report.errors.append({"path": file_spec.path, "error": str(exc), "type": exc.__class__.__name__})

    def _write_manifest(self, *, root_path: Path, user_id: str, workspace_id: str, batch: FileGenerationBatch, report: FileGenerationReport) -> Path:
        """Write manifest for generated file batch."""

        manifest = {
            "manifest_version": "1.0",
            "system": "William / Jarvis Multi-Agent AI SaaS System",
            "brand": "Digital Promotix",
            "agent_name": self.agent_name,
            "agent_id": self.agent_id,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "root_path": str(root_path),
            "batch": {
                "project_path": batch.project_path,
                "overwrite_existing_files": batch.overwrite_existing_files,
                "dry_run": batch.dry_run,
                "metadata": batch.metadata,
                "files": [
                    {
                        "path": spec.path,
                        "template_name": spec.template_name,
                        "overwrite": spec.overwrite,
                        "encoding": spec.encoding,
                        "file_type": _guess_file_type(spec.path),
                        "content_sha256": _sha256_text(self._render_file_content(spec)),
                        "metadata": spec.metadata,
                    }
                    for spec in batch.files
                ],
            },
            "report": asdict(report),
            "created_at": _utc_now_iso(),
        }
        manifest_path = root_path / "file_generation_manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding=DEFAULT_FILE_ENCODING)
        if str(manifest_path) not in report.generated_files:
            report.generated_files.append(str(manifest_path))
        return manifest_path

    def _render_file_content(self, file_spec: GeneratedFileSpec) -> str:
        """Render final content for a file spec."""

        if file_spec.template_name:
            variables = dict(file_spec.variables or {})
            variables.setdefault("module_path", file_spec.path)
            variables.setdefault("title", Path(file_spec.path).stem.replace("_", " ").title())
            variables.setdefault("name", Path(file_spec.path).stem)
            variables.setdefault("description", file_spec.metadata.get("description", "Generated file."))
            variables.setdefault("purpose", file_spec.metadata.get("purpose", "Generated by FileGenerator."))
            variables.setdefault("class_name", self._class_name_from_path(file_spec.path))
            variables.setdefault("agent_name", _slugify_name(Path(file_spec.path).stem))
            variables.setdefault("agent_type", "code_agent")
            variables.setdefault("route_prefix", "/" + _slugify_name(Path(file_spec.path).stem))
            variables.setdefault("tag", Path(file_spec.path).stem.replace("_", " ").title())
            variables.setdefault("component_name", _slugify_name(Path(file_spec.path).stem))
            variables.setdefault("component_class", _slugify_name(Path(file_spec.path).stem).replace("-", "_"))
            return self.render_template(file_spec.template_name, variables)
        return str(file_spec.content or "")

    def _coerce_batch(self, raw_batch: Union[FileGenerationBatch, Mapping[str, Any]]) -> FileGenerationBatch:
        """Convert dict/API batch to FileGenerationBatch."""

        if isinstance(raw_batch, FileGenerationBatch):
            return raw_batch
        if not isinstance(raw_batch, Mapping):
            raise ValueError("batch must be a mapping or FileGenerationBatch.")
        raw_files = raw_batch.get("files")
        if raw_files is None:
            raw_files = [raw_batch] if raw_batch.get("path") else []
        files = [self._coerce_file_spec(item) for item in list(raw_files or [])]
        return FileGenerationBatch(
            files=files,
            project_path=str(raw_batch.get("project_path")) if raw_batch.get("project_path") else None,
            overwrite_existing_files=bool(raw_batch.get("overwrite_existing_files", raw_batch.get("overwrite", False))),
            dry_run=bool(raw_batch.get("dry_run", False)),
            metadata=dict(raw_batch.get("metadata") or {}),
        )

    def _coerce_file_spec(self, raw_file: Union[GeneratedFileSpec, Mapping[str, Any]]) -> GeneratedFileSpec:
        """Convert dict/API file payload to GeneratedFileSpec."""

        if isinstance(raw_file, GeneratedFileSpec):
            return raw_file
        if not isinstance(raw_file, Mapping):
            raise ValueError("file spec must be a mapping or GeneratedFileSpec.")
        return GeneratedFileSpec(
            path=str(raw_file.get("path", "")),
            content=str(raw_file.get("content", "")),
            template_name=str(raw_file.get("template_name")) if raw_file.get("template_name") else None,
            variables=dict(raw_file.get("variables") or {}),
            overwrite=bool(raw_file.get("overwrite", False)),
            encoding=str(raw_file.get("encoding", DEFAULT_FILE_ENCODING)),
            metadata=dict(raw_file.get("metadata") or {}),
        )

    def _validate_relative_file_path(self, path: str) -> str:
        """Validate safe relative file path."""

        normalized = str(path).strip().replace("\\", "/")
        if not normalized:
            raise ValueError("File path is required.")
        if normalized.startswith("/"):
            raise ValueError("Absolute file paths are not allowed.")
        if "\x00" in normalized:
            raise ValueError("Null bytes are not allowed in file paths.")
        if ".." in Path(normalized).parts:
            raise ValueError("Path traversal is not allowed.")
        if not SAFE_RELATIVE_PATH_PATTERN.match(normalized):
            raise ValueError(f"Unsafe file path: {normalized}")
        filename = Path(normalized).name
        if not filename or "." not in filename:
            raise ValueError("File path must include a filename with an extension.")
        if not SAFE_FILENAME_PATTERN.match(filename):
            raise ValueError(f"Unsafe filename: {filename}")
        for part in Path(normalized).parts:
            if _is_reserved_name(part):
                raise ValueError(f"Reserved path segment is not allowed: {part}")
        return normalized

    def _validate_relative_directory_path(self, path: str) -> str:
        """Validate safe relative directory path."""

        normalized = str(path).strip().replace("\\", "/").strip("/")
        if not normalized:
            raise ValueError("Directory path cannot be empty.")
        if normalized.startswith("/"):
            raise ValueError("Absolute directory paths are not allowed.")
        if "\x00" in normalized:
            raise ValueError("Null bytes are not allowed in directory paths.")
        if ".." in Path(normalized).parts:
            raise ValueError("Path traversal is not allowed.")
        if not SAFE_RELATIVE_PATH_PATTERN.match(normalized):
            raise ValueError(f"Unsafe directory path: {normalized}")
        for part in Path(normalized).parts:
            if _is_reserved_name(part):
                raise ValueError(f"Reserved path segment is not allowed: {part}")
        return normalized

    def _sanitize_template_value(self, value: Any) -> str:
        """Sanitize template variable values."""

        text = str(value)
        return text[:100_000] + "\n...[truncated]" if len(text) > 100_000 else text

    def _class_name_from_path(self, path: str) -> str:
        """Create a PascalCase class name from a file path."""

        stem = Path(path).stem
        parts = re.split(r"[^a-zA-Z0-9]+", stem)
        class_name = "".join(part[:1].upper() + part[1:] for part in parts if part)
        return class_name or "GeneratedClass"

    def _send_to_optional_agent(self, *, agent: Optional[Any], method_names: Sequence[str], payload: Mapping[str, Any], label: str) -> None:
        """Best-effort dispatch to optional connected agents."""

        if agent is None:
            return
        try:
            for method_name in method_names:
                if hasattr(agent, method_name):
                    getattr(agent, method_name)(dict(payload))
                    return
            if callable(agent):
                agent(dict(payload))
        except Exception:
            self.logger.exception("Failed to send payload to %s.", label)


def generate_file(
    *,
    user_id: Any,
    workspace_id: Any,
    path: str,
    content: str = "",
    template_name: Optional[str] = None,
    variables: Optional[Mapping[str, Any]] = None,
    project_path: Optional[str] = None,
    safe_root: Union[str, Path, None] = None,
    overwrite: bool = False,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Convenience helper for generating one file."""

    generator = FileGenerator(safe_root=safe_root)
    return generator.create_file(
        user_id=user_id,
        workspace_id=workspace_id,
        path=path,
        content=content,
        template_name=template_name,
        variables=variables or {},
        project_path=project_path,
        overwrite=overwrite,
        dry_run=dry_run,
    )


def list_default_file_templates() -> Dict[str, Any]:
    """Return default template registry through structured result."""

    generator = FileGenerator()
    return generator.list_templates()


__all__ = [
    "FileGenerator",
    "GeneratedFileSpec",
    "FileGenerationBatch",
    "FileGenerationReport",
    "generate_file",
    "list_default_file_templates",
]


# FILE COMPLETE
