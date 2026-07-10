"""
agents/code_agent/project_builder.py

ProjectBuilder for William / Jarvis Multi-Agent AI SaaS System by Digital Promotix.

Purpose:
    Creates full project architecture and folder structures in a safe, SaaS-isolated,
    import-safe, testable way.

This module is designed to work with:
    - Master Agent routing
    - BaseAgent compatibility
    - Security Agent approval flow
    - Verification Agent payload preparation
    - Memory Agent payload preparation
    - Dashboard/API integrations
    - Agent Registry / Agent Loader

Safety model:
    - Never mixes users/workspaces.
    - Requires user_id and workspace_id for user-specific operations.
    - Blocks path traversal and writes outside allowed root.
    - Sensitive filesystem creation requests can be routed through Security Agent.
    - Does not execute system commands.
    - Does not perform destructive actions by default.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Optional BaseAgent import with fallback
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for early-stage project builds

    class BaseAgent:  # type: ignore
        """
        Safe fallback BaseAgent.

        This keeps ProjectBuilder import-safe while the full William/Jarvis
        codebase is still being generated.
        """

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


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOGGER = logging.getLogger(__name__)
if not LOGGER.handlers:
    logging.basicConfig(level=logging.INFO)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_SAFE_ROOT = Path(os.getenv("WILLIAM_PROJECTS_ROOT", "./william_workspaces")).resolve()

SAFE_FILENAME_PATTERN = re.compile(r"^[a-zA-Z0-9._\-\s]+$")
SAFE_FOLDER_PATTERN = re.compile(r"^[a-zA-Z0-9._\-/\s]+$")

DEFAULT_FILE_ENCODING = "utf-8"

RESERVED_WINDOWS_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}

DEFAULT_IGNORED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    "node_modules",
    "dist",
    "build",
}

DEFAULT_AGENT_FOLDERS = [
    "agents",
    "agents/voice_agent",
    "agents/system_agent",
    "agents/browser_agent",
    "agents/code_agent",
    "agents/memory_agent",
    "agents/security_agent",
    "agents/verification_agent",
    "agents/visual_agent",
    "agents/workflow_agent",
    "agents/hologram_agent",
    "agents/call_agent",
    "agents/business_agent",
    "agents/finance_agent",
    "agents/creator_agent",
]

DEFAULT_CORE_FOLDERS = [
    "core",
    "api",
    "api/routes",
    "api/schemas",
    "api/dependencies",
    "dashboard",
    "dashboard/templates",
    "dashboard/static",
    "dashboard/static/css",
    "dashboard/static/js",
    "dashboard/static/images",
    "database",
    "database/migrations",
    "plugins",
    "services",
    "security",
    "memory",
    "verification",
    "workspaces",
    "storage",
    "storage/uploads",
    "storage/generated",
    "logs",
    "tests",
    "tests/unit",
    "tests/integration",
    "docs",
    "scripts",
    "config",
]

DEFAULT_PROJECT_FILES = {
    "README.md": "# William / Jarvis Multi-Agent AI SaaS System\n\nGenerated project structure.\n",
    ".gitignore": (
        "__pycache__/\n"
        "*.py[cod]\n"
        ".env\n"
        ".venv/\n"
        "venv/\n"
        "node_modules/\n"
        "logs/*.log\n"
        "storage/uploads/*\n"
        "storage/generated/*\n"
        "!storage/uploads/.gitkeep\n"
        "!storage/generated/.gitkeep\n"
    ),
    ".env.example": (
        "APP_ENV=development\n"
        "APP_SECRET_KEY=change-me\n"
        "DATABASE_URL=sqlite:///william.db\n"
        "WILLIAM_PROJECTS_ROOT=./william_workspaces\n"
    ),
    "requirements.txt": (
        "fastapi\n"
        "uvicorn\n"
        "pydantic\n"
        "sqlalchemy\n"
        "python-dotenv\n"
        "pytest\n"
    ),
    "pyproject.toml": (
        "[project]\n"
        'name = "william-jarvis-ai-saas"\n'
        'version = "0.1.0"\n'
        'description = "William / Jarvis Multi-Agent AI SaaS System"\n'
        'requires-python = ">=3.10"\n'
    ),
}

DEFAULT_GITKEEP_FOLDERS = [
    "storage/uploads",
    "storage/generated",
    "logs",
    "database/migrations",
]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ProjectFileSpec:
    """Represents a file to be created inside a project."""

    path: str
    content: str = ""
    overwrite: bool = False
    binary: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ProjectDirectorySpec:
    """Represents a directory to be created inside a project."""

    path: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ProjectBlueprint:
    """
    Full project creation blueprint.

    The blueprint is intentionally plain and serializable so it can be passed
    from Master Agent, Dashboard/API, or Workflow Agent.
    """

    project_name: str
    directories: List[ProjectDirectorySpec] = field(default_factory=list)
    files: List[ProjectFileSpec] = field(default_factory=list)
    include_default_architecture: bool = True
    include_gitkeep: bool = True
    overwrite_existing_files: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BuildReport:
    """Structured report returned after project creation."""

    project_name: str
    project_path: str
    created_directories: List[str] = field(default_factory=list)
    existing_directories: List[str] = field(default_factory=list)
    created_files: List[str] = field(default_factory=list)
    skipped_files: List[str] = field(default_factory=list)
    overwritten_files: List[str] = field(default_factory=list)
    errors: List[Dict[str, Any]] = field(default_factory=list)
    manifest_path: Optional[str] = None
    tree: Optional[str] = None
    duration_seconds: float = 0.0


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _utc_now_iso() -> str:
    """Return current UTC timestamp in ISO format."""

    return datetime.now(timezone.utc).isoformat()


def _normalize_id(value: Any, field_name: str) -> str:
    """Normalize and validate a user/workspace identifier."""

    if value is None:
        raise ValueError(f"{field_name} is required.")

    normalized = str(value).strip()
    if not normalized:
        raise ValueError(f"{field_name} cannot be empty.")

    if len(normalized) > 128:
        raise ValueError(f"{field_name} is too long.")

    if not re.match(r"^[a-zA-Z0-9_\-:.@]+$", normalized):
        raise ValueError(
            f"{field_name} contains unsafe characters. "
            "Allowed: letters, numbers, underscore, hyphen, colon, dot, @."
        )

    return normalized


def _slugify_project_name(project_name: str) -> str:
    """Create a safe folder name from a project name."""

    if not project_name or not str(project_name).strip():
        raise ValueError("project_name is required.")

    name = str(project_name).strip()
    name = re.sub(r"\s+", "-", name)
    name = re.sub(r"[^a-zA-Z0-9._\-]", "-", name)
    name = re.sub(r"-{2,}", "-", name).strip(".-")

    if not name:
        raise ValueError("project_name could not be converted to a safe folder name.")

    if name.upper() in RESERVED_WINDOWS_NAMES:
        name = f"{name}-project"

    return name[:120]


def _is_reserved_name(path_part: str) -> bool:
    """Check if a path segment is reserved on Windows."""

    stem = path_part.split(".")[0].upper()
    return stem in RESERVED_WINDOWS_NAMES


def _safe_join(root: Path, relative_path: Union[str, Path]) -> Path:
    """
    Safely join root with relative_path and prevent path traversal.

    Raises:
        ValueError: if the path is absolute, unsafe, or escapes root.
    """

    if isinstance(relative_path, Path):
        raw = str(relative_path)
    else:
        raw = str(relative_path)

    raw = raw.replace("\\", "/").strip()

    if not raw:
        raise ValueError("Path cannot be empty.")

    candidate_path = Path(raw)

    if candidate_path.is_absolute():
        raise ValueError(f"Absolute paths are not allowed: {raw}")

    parts = candidate_path.parts
    for part in parts:
        if part in {"..", ""}:
            raise ValueError(f"Unsafe path traversal detected: {raw}")
        if _is_reserved_name(part):
            raise ValueError(f"Reserved path name is not allowed: {part}")

    resolved = (root / candidate_path).resolve()

    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(f"Path escapes allowed project root: {raw}") from exc

    return resolved


def _safe_text(value: Any, max_length: int = 5000) -> str:
    """Convert any value to safe text for audit/event payloads."""

    text = str(value)
    if len(text) > max_length:
        return text[:max_length] + "...[truncated]"
    return text


def _dedupe_preserve_order(items: Iterable[str]) -> List[str]:
    """Deduplicate a list while preserving order."""

    seen = set()
    result = []
    for item in items:
        normalized = item.strip().replace("\\", "/")
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        result.append(normalized)
    return result


# ---------------------------------------------------------------------------
# ProjectBuilder
# ---------------------------------------------------------------------------

class ProjectBuilder(BaseAgent):
    """
    Creates full project architecture and folder structures.

    Master Agent integration:
        Master Agent can route a "create_project" task to ProjectBuilder.run().

    Security Agent integration:
        Sensitive write operations are detected by _requires_security_check().
        If a Security Agent object/callback is provided, _request_security_approval()
        delegates approval to it. Without one, safe local creation inside allowed root
        is allowed by default unless require_security_approval=True.

    Memory Agent integration:
        _prepare_memory_payload() returns compact project context that can be stored
        in user/workspace-scoped memory.

    Verification Agent integration:
        _prepare_verification_payload() returns created paths and checksums-ready
        metadata for verification.

    Dashboard/API integration:
        All public methods return JSON-style dicts with:
        success, message, data, error, metadata.
    """

    agent_name = "code_project_builder"
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
        require_security_approval: bool = False,
        allow_overwrite: bool = False,
        max_files_per_build: int = 500,
        max_directories_per_build: int = 1000,
        max_file_size_chars: int = 2_000_000,
        agent_id: Optional[str] = None,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        """
        Initialize ProjectBuilder.

        Args:
            safe_root: Root directory where projects may be created.
            security_agent: Optional Security Agent or approval callback.
            memory_agent: Optional Memory Agent integration.
            verification_agent: Optional Verification Agent integration.
            event_sink: Optional callable/list-like sink for agent events.
            audit_sink: Optional callable/list-like sink for audit logs.
            require_security_approval: Force approval before any write.
            allow_overwrite: Global overwrite policy.
            max_files_per_build: Safety limit.
            max_directories_per_build: Safety limit.
            max_file_size_chars: Safety limit for text file content.
            agent_id: Optional stable agent ID.
            logger: Optional logger.
        """

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
        self.max_files_per_build = int(max_files_per_build)
        self.max_directories_per_build = int(max_directories_per_build)
        self.max_file_size_chars = int(max_file_size_chars)
        self.logger = logger or logging.getLogger(self.__class__.__name__)

    # ------------------------------------------------------------------
    # Main BaseAgent-compatible entry point
    # ------------------------------------------------------------------

    def run(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        BaseAgent-compatible task router.

        Supported actions:
            - create_project
            - preview_project
            - validate_blueprint
            - render_tree
            - get_default_blueprint

        Example:
            builder.run({
                "action": "create_project",
                "user_id": "user_123",
                "workspace_id": "workspace_456",
                "project_name": "william_ai_system"
            })
        """

        started = time.time()

        try:
            context = self._validate_task_context(task)
            action = str(task.get("action", "create_project")).strip().lower()

            self._emit_agent_event(
                event_type="task_started",
                user_id=context["user_id"],
                workspace_id=context["workspace_id"],
                payload={"action": action},
            )

            if action == "create_project":
                result = self.create_project(
                    user_id=context["user_id"],
                    workspace_id=context["workspace_id"],
                    project_name=str(task.get("project_name", "william_ai_system")),
                    blueprint=task.get("blueprint"),
                    base_path=task.get("base_path"),
                    overwrite=bool(task.get("overwrite", False)),
                    dry_run=bool(task.get("dry_run", False)),
                    include_tree=bool(task.get("include_tree", True)),
                    request_metadata=dict(task.get("metadata") or {}),
                )
            elif action == "preview_project":
                result = self.preview_project(
                    user_id=context["user_id"],
                    workspace_id=context["workspace_id"],
                    project_name=str(task.get("project_name", "william_ai_system")),
                    blueprint=task.get("blueprint"),
                    base_path=task.get("base_path"),
                )
            elif action == "validate_blueprint":
                blueprint = self._coerce_blueprint(
                    project_name=str(task.get("project_name", "william_ai_system")),
                    raw_blueprint=task.get("blueprint"),
                )
                result = self.validate_blueprint(blueprint)
            elif action == "render_tree":
                project_path = task.get("project_path")
                result = self.render_tree_result(
                    user_id=context["user_id"],
                    workspace_id=context["workspace_id"],
                    project_path=project_path,
                    max_depth=int(task.get("max_depth", 5)),
                )
            elif action == "get_default_blueprint":
                blueprint = self.get_default_blueprint(
                    project_name=str(task.get("project_name", "william_ai_system"))
                )
                result = self._safe_result(
                    message="Default William/Jarvis project blueprint generated.",
                    data={"blueprint": self._blueprint_to_dict(blueprint)},
                    metadata={"duration_seconds": round(time.time() - started, 4)},
                )
            else:
                result = self._error_result(
                    message=f"Unsupported ProjectBuilder action: {action}",
                    error="UNSUPPORTED_ACTION",
                    metadata={"supported_actions": [
                        "create_project",
                        "preview_project",
                        "validate_blueprint",
                        "render_tree",
                        "get_default_blueprint",
                    ]},
                )

            self._emit_agent_event(
                event_type="task_completed" if result.get("success") else "task_failed",
                user_id=context["user_id"],
                workspace_id=context["workspace_id"],
                payload={
                    "action": action,
                    "success": result.get("success"),
                    "message": result.get("message"),
                },
            )
            return result

        except Exception as exc:
            self.logger.exception("ProjectBuilder.run failed.")
            return self._error_result(
                message="ProjectBuilder task failed.",
                error=str(exc),
                metadata={"duration_seconds": round(time.time() - started, 4)},
            )

    # ------------------------------------------------------------------
    # Public methods
    # ------------------------------------------------------------------

    def create_project(
        self,
        *,
        user_id: Any,
        workspace_id: Any,
        project_name: str,
        blueprint: Optional[Union[ProjectBlueprint, Mapping[str, Any]]] = None,
        base_path: Optional[Union[str, Path]] = None,
        overwrite: bool = False,
        dry_run: bool = False,
        include_tree: bool = True,
        request_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create a William/Jarvis project architecture safely.

        Args:
            user_id: SaaS user identifier.
            workspace_id: SaaS workspace identifier.
            project_name: Project folder name.
            blueprint: Optional custom blueprint.
            base_path: Optional user/workspace-safe base path inside safe_root.
            overwrite: Allows overwriting files if blueprint allows it too.
            dry_run: Validate and preview without writing.
            include_tree: Include a generated tree in response.
            request_metadata: Extra metadata for audit/dashboard.

        Returns:
            JSON-style structured result.
        """

        started = time.time()
        context = self._validate_task_context({
            "user_id": user_id,
            "workspace_id": workspace_id,
        })

        project_slug = _slugify_project_name(project_name)
        project_root = self._resolve_project_root(
            user_id=context["user_id"],
            workspace_id=context["workspace_id"],
            project_slug=project_slug,
            base_path=base_path,
        )

        effective_blueprint = self._coerce_blueprint(
            project_name=project_slug,
            raw_blueprint=blueprint,
        )
        validation = self.validate_blueprint(effective_blueprint)
        if not validation.get("success"):
            return validation

        sensitive = self._requires_security_check(
            action="create_project",
            user_id=context["user_id"],
            workspace_id=context["workspace_id"],
            target_path=str(project_root),
            payload={
                "project_name": project_slug,
                "file_count": len(effective_blueprint.files),
                "directory_count": len(effective_blueprint.directories),
                "overwrite": overwrite,
                "dry_run": dry_run,
            },
        )

        if sensitive:
            approval = self._request_security_approval(
                action="create_project",
                user_id=context["user_id"],
                workspace_id=context["workspace_id"],
                target_path=str(project_root),
                payload={
                    "project_name": project_slug,
                    "overwrite": overwrite,
                    "dry_run": dry_run,
                    "metadata": request_metadata or {},
                },
            )
            if not approval.get("approved"):
                return self._error_result(
                    message="Project creation blocked by Security Agent policy.",
                    error="SECURITY_APPROVAL_DENIED",
                    data={"approval": approval},
                    metadata={
                        "user_id": context["user_id"],
                        "workspace_id": context["workspace_id"],
                        "project_path": str(project_root),
                    },
                )

        report = BuildReport(project_name=project_slug, project_path=str(project_root))

        self._log_audit_event(
            user_id=context["user_id"],
            workspace_id=context["workspace_id"],
            action="project_create_requested",
            resource=str(project_root),
            payload={
                "project_name": project_slug,
                "dry_run": dry_run,
                "overwrite": overwrite,
                "metadata": request_metadata or {},
            },
        )

        if dry_run:
            report.tree = self._render_blueprint_tree(effective_blueprint)
            report.duration_seconds = round(time.time() - started, 4)

            verification_payload = self._prepare_verification_payload(
                user_id=context["user_id"],
                workspace_id=context["workspace_id"],
                action="preview_project",
                report=report,
            )

            return self._safe_result(
                message="Dry run completed. No files were written.",
                data={
                    "report": asdict(report),
                    "verification_payload": verification_payload,
                    "memory_payload": self._prepare_memory_payload(
                        user_id=context["user_id"],
                        workspace_id=context["workspace_id"],
                        action="preview_project",
                        report=report,
                    ),
                },
                metadata={
                    "user_id": context["user_id"],
                    "workspace_id": context["workspace_id"],
                    "project_path": str(project_root),
                    "duration_seconds": report.duration_seconds,
                    "dry_run": True,
                },
            )

        try:
            project_root.mkdir(parents=True, exist_ok=True)

            self._create_directories(
                project_root=project_root,
                directories=effective_blueprint.directories,
                report=report,
            )

            self._create_files(
                project_root=project_root,
                files=effective_blueprint.files,
                report=report,
                overwrite=bool(overwrite or self.allow_overwrite),
                blueprint_overwrite=effective_blueprint.overwrite_existing_files,
            )

            if effective_blueprint.include_gitkeep:
                self._create_gitkeep_files(project_root=project_root, report=report)

            manifest_path = self._write_manifest(
                project_root=project_root,
                user_id=context["user_id"],
                workspace_id=context["workspace_id"],
                blueprint=effective_blueprint,
                report=report,
                request_metadata=request_metadata or {},
            )
            report.manifest_path = str(manifest_path)

            if include_tree:
                report.tree = self.render_tree(project_root, max_depth=6)

            report.duration_seconds = round(time.time() - started, 4)

            verification_payload = self._prepare_verification_payload(
                user_id=context["user_id"],
                workspace_id=context["workspace_id"],
                action="create_project",
                report=report,
            )

            memory_payload = self._prepare_memory_payload(
                user_id=context["user_id"],
                workspace_id=context["workspace_id"],
                action="create_project",
                report=report,
            )

            self._log_audit_event(
                user_id=context["user_id"],
                workspace_id=context["workspace_id"],
                action="project_created",
                resource=str(project_root),
                payload={
                    "created_directories": len(report.created_directories),
                    "created_files": len(report.created_files),
                    "skipped_files": len(report.skipped_files),
                    "overwritten_files": len(report.overwritten_files),
                    "errors": report.errors,
                },
            )

            return self._safe_result(
                message="Project architecture created successfully.",
                data={
                    "report": asdict(report),
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                metadata={
                    "user_id": context["user_id"],
                    "workspace_id": context["workspace_id"],
                    "project_path": str(project_root),
                    "duration_seconds": report.duration_seconds,
                    "dry_run": False,
                },
            )

        except Exception as exc:
            self.logger.exception("Project creation failed.")
            report.errors.append({
                "path": str(project_root),
                "error": str(exc),
                "type": exc.__class__.__name__,
            })
            report.duration_seconds = round(time.time() - started, 4)

            self._log_audit_event(
                user_id=context["user_id"],
                workspace_id=context["workspace_id"],
                action="project_create_failed",
                resource=str(project_root),
                payload={"error": str(exc), "report": asdict(report)},
            )

            return self._error_result(
                message="Project architecture creation failed.",
                error=str(exc),
                data={"report": asdict(report)},
                metadata={
                    "user_id": context["user_id"],
                    "workspace_id": context["workspace_id"],
                    "project_path": str(project_root),
                    "duration_seconds": report.duration_seconds,
                },
            )

    def preview_project(
        self,
        *,
        user_id: Any,
        workspace_id: Any,
        project_name: str,
        blueprint: Optional[Union[ProjectBlueprint, Mapping[str, Any]]] = None,
        base_path: Optional[Union[str, Path]] = None,
    ) -> Dict[str, Any]:
        """Preview project creation without writing any files."""

        return self.create_project(
            user_id=user_id,
            workspace_id=workspace_id,
            project_name=project_name,
            blueprint=blueprint,
            base_path=base_path,
            overwrite=False,
            dry_run=True,
            include_tree=True,
            request_metadata={"preview": True},
        )

    def validate_blueprint(self, blueprint: ProjectBlueprint) -> Dict[str, Any]:
        """Validate a blueprint for safety and limits."""

        errors: List[str] = []

        if not isinstance(blueprint, ProjectBlueprint):
            errors.append("Blueprint must be a ProjectBlueprint instance.")

        if not getattr(blueprint, "project_name", None):
            errors.append("Blueprint project_name is required.")

        if len(getattr(blueprint, "files", [])) > self.max_files_per_build:
            errors.append(
                f"Too many files. Limit is {self.max_files_per_build}; "
                f"received {len(blueprint.files)}."
            )

        if len(getattr(blueprint, "directories", [])) > self.max_directories_per_build:
            errors.append(
                f"Too many directories. Limit is {self.max_directories_per_build}; "
                f"received {len(blueprint.directories)}."
            )

        directory_paths = []
        for directory in getattr(blueprint, "directories", []):
            try:
                directory_path = self._validate_relative_path(directory.path, is_file=False)
                directory_paths.append(directory_path)
            except Exception as exc:
                errors.append(f"Invalid directory path '{getattr(directory, 'path', '')}': {exc}")

        file_paths = []
        for file_spec in getattr(blueprint, "files", []):
            try:
                file_path = self._validate_relative_path(file_spec.path, is_file=True)
                file_paths.append(file_path)
                if not file_spec.binary and len(file_spec.content) > self.max_file_size_chars:
                    errors.append(
                        f"File '{file_spec.path}' exceeds max text size "
                        f"({self.max_file_size_chars} chars)."
                    )
            except Exception as exc:
                errors.append(f"Invalid file path '{getattr(file_spec, 'path', '')}': {exc}")

        duplicates = self._find_duplicates(file_paths)
        if duplicates:
            errors.append(f"Duplicate file paths detected: {duplicates}")

        if errors:
            return self._error_result(
                message="Blueprint validation failed.",
                error="BLUEPRINT_VALIDATION_FAILED",
                data={"errors": errors},
                metadata={
                    "file_count": len(getattr(blueprint, "files", [])),
                    "directory_count": len(getattr(blueprint, "directories", [])),
                },
            )

        return self._safe_result(
            message="Blueprint is valid.",
            data={
                "project_name": blueprint.project_name,
                "file_count": len(blueprint.files),
                "directory_count": len(blueprint.directories),
                "directory_paths": directory_paths,
                "file_paths": file_paths,
            },
            metadata={"validated_at": _utc_now_iso()},
        )

    def get_default_blueprint(self, project_name: str = "william_ai_system") -> ProjectBlueprint:
        """
        Return the default William/Jarvis project architecture blueprint.

        Includes core folders, all agent folders, starter files, and .gitkeep files.
        """

        project_slug = _slugify_project_name(project_name)

        directories = [
            ProjectDirectorySpec(path=path)
            for path in _dedupe_preserve_order(DEFAULT_CORE_FOLDERS + DEFAULT_AGENT_FOLDERS)
        ]

        files = [
            ProjectFileSpec(path=path, content=content, overwrite=False)
            for path, content in DEFAULT_PROJECT_FILES.items()
        ]

        files.extend([
            ProjectFileSpec(
                path="agents/__init__.py",
                content='"""William/Jarvis agents package."""\n',
                overwrite=False,
            ),
            ProjectFileSpec(
                path="agents/code_agent/__init__.py",
                content='"""Code Agent package."""\n',
                overwrite=False,
            ),
            ProjectFileSpec(
                path="core/__init__.py",
                content='"""Core William/Jarvis orchestration package."""\n',
                overwrite=False,
            ),
            ProjectFileSpec(
                path="api/__init__.py",
                content='"""API package for William/Jarvis SaaS dashboard."""\n',
                overwrite=False,
            ),
            ProjectFileSpec(
                path="config/__init__.py",
                content='"""Configuration package."""\n',
                overwrite=False,
            ),
        ])

        return ProjectBlueprint(
            project_name=project_slug,
            directories=directories,
            files=files,
            include_default_architecture=True,
            include_gitkeep=True,
            overwrite_existing_files=False,
            metadata={
                "system": "William / Jarvis Multi-Agent AI SaaS System",
                "brand": "Digital Promotix",
                "agent_count": 14,
                "generated_by": self.agent_name,
                "generated_at": _utc_now_iso(),
            },
        )

    def build_from_template(
        self,
        *,
        user_id: Any,
        workspace_id: Any,
        project_name: str,
        template_name: str = "william_default",
        base_path: Optional[Union[str, Path]] = None,
        overwrite: bool = False,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """
        Build a project from a named template.

        Currently supported:
            - william_default
            - minimal_agent_module
            - fastapi_dashboard_shell
        """

        template_name = str(template_name).strip().lower()

        if template_name == "william_default":
            blueprint = self.get_default_blueprint(project_name)
        elif template_name == "minimal_agent_module":
            blueprint = self._minimal_agent_module_blueprint(project_name)
        elif template_name == "fastapi_dashboard_shell":
            blueprint = self._fastapi_dashboard_shell_blueprint(project_name)
        else:
            return self._error_result(
                message=f"Unknown template: {template_name}",
                error="UNKNOWN_TEMPLATE",
                metadata={
                    "supported_templates": [
                        "william_default",
                        "minimal_agent_module",
                        "fastapi_dashboard_shell",
                    ]
                },
            )

        return self.create_project(
            user_id=user_id,
            workspace_id=workspace_id,
            project_name=project_name,
            blueprint=blueprint,
            base_path=base_path,
            overwrite=overwrite,
            dry_run=dry_run,
            include_tree=True,
            request_metadata={"template_name": template_name},
        )

    def render_tree_result(
        self,
        *,
        user_id: Any,
        workspace_id: Any,
        project_path: Optional[Union[str, Path]],
        max_depth: int = 5,
    ) -> Dict[str, Any]:
        """Render a project tree and return structured result."""

        context = self._validate_task_context({
            "user_id": user_id,
            "workspace_id": workspace_id,
        })

        if not project_path:
            return self._error_result(
                message="project_path is required for render_tree.",
                error="PROJECT_PATH_REQUIRED",
            )

        root = Path(project_path).resolve()
        try:
            root.relative_to(self.safe_root)
        except ValueError:
            return self._error_result(
                message="Cannot render tree outside ProjectBuilder safe root.",
                error="PATH_OUTSIDE_SAFE_ROOT",
                metadata={"safe_root": str(self.safe_root), "project_path": str(root)},
            )

        if not root.exists():
            return self._error_result(
                message="Project path does not exist.",
                error="PROJECT_PATH_NOT_FOUND",
                metadata={"project_path": str(root)},
            )

        tree = self.render_tree(root, max_depth=max_depth)

        self._log_audit_event(
            user_id=context["user_id"],
            workspace_id=context["workspace_id"],
            action="project_tree_rendered",
            resource=str(root),
            payload={"max_depth": max_depth},
        )

        return self._safe_result(
            message="Project tree rendered.",
            data={"tree": tree, "project_path": str(root)},
            metadata={
                "user_id": context["user_id"],
                "workspace_id": context["workspace_id"],
                "max_depth": max_depth,
            },
        )

    def render_tree(
        self,
        root: Union[str, Path],
        *,
        max_depth: int = 5,
        include_files: bool = True,
        ignored_dirs: Optional[Sequence[str]] = None,
    ) -> str:
        """
        Render a filesystem tree.

        This method reads directory names and file names only. It does not read file contents.
        """

        root_path = Path(root).resolve()
        ignored = set(ignored_dirs or DEFAULT_IGNORED_DIRS)
        max_depth = max(1, int(max_depth))

        if not root_path.exists():
            return f"{root_path.name}/ [missing]"

        lines = [f"{root_path.name}/"]

        def walk(path: Path, prefix: str = "", depth: int = 0) -> None:
            if depth >= max_depth:
                lines.append(f"{prefix}└── ...")
                return

            try:
                entries = sorted(
                    list(path.iterdir()),
                    key=lambda p: (not p.is_dir(), p.name.lower()),
                )
            except PermissionError:
                lines.append(f"{prefix}└── [permission denied]")
                return

            entries = [
                entry for entry in entries
                if entry.name not in ignored and (include_files or entry.is_dir())
            ]

            for index, entry in enumerate(entries):
                connector = "└── " if index == len(entries) - 1 else "├── "
                lines.append(f"{prefix}{connector}{entry.name}{'/' if entry.is_dir() else ''}")
                if entry.is_dir():
                    extension = "    " if index == len(entries) - 1 else "│   "
                    walk(entry, prefix + extension, depth + 1)

        walk(root_path)
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Required compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(self, task: Mapping[str, Any]) -> Dict[str, str]:
        """
        Validate user/workspace context for SaaS isolation.

        Every user-specific execution must include user_id and workspace_id.
        """

        user_id = _normalize_id(task.get("user_id"), "user_id")
        workspace_id = _normalize_id(task.get("workspace_id"), "workspace_id")
        return {"user_id": user_id, "workspace_id": workspace_id}

    def _requires_security_check(
        self,
        *,
        action: str,
        user_id: str,
        workspace_id: str,
        target_path: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Decide whether a Security Agent approval is required.

        Security is required if:
            - require_security_approval is enabled
            - overwrite is requested
            - target path is suspicious
            - file or directory count is unusually large
        """

        payload = payload or {}
        target = str(target_path)

        if self.require_security_approval:
            return True

        if bool(payload.get("overwrite")):
            return True

        if ".." in target.replace("\\", "/").split("/"):
            return True

        if int(payload.get("file_count") or 0) > 100:
            return True

        if int(payload.get("directory_count") or 0) > 200:
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
        """
        Request Security Agent approval.

        Supports:
            - security_agent.approve_action(payload)
            - security_agent.validate_action(payload)
            - callable security_agent(payload)
            - no security agent: safe deny if require_security_approval=True,
              otherwise allow local safe action.
        """

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
                    return {
                        "approved": False,
                        "reason": "Security approval required but no Security Agent is configured.",
                        "payload": approval_payload,
                    }
                return {
                    "approved": True,
                    "reason": "No Security Agent configured; safe local action allowed by default policy.",
                    "payload": approval_payload,
                }

            if hasattr(self.security_agent, "approve_action"):
                response = self.security_agent.approve_action(approval_payload)
            elif hasattr(self.security_agent, "validate_action"):
                response = self.security_agent.validate_action(approval_payload)
            elif callable(self.security_agent):
                response = self.security_agent(approval_payload)
            else:
                return {
                    "approved": False,
                    "reason": "Configured Security Agent has no supported approval method.",
                    "payload": approval_payload,
                }

            if isinstance(response, Mapping):
                approved = bool(response.get("approved", response.get("success", False)))
                return {
                    "approved": approved,
                    "reason": response.get("reason") or response.get("message") or "",
                    "response": dict(response),
                    "payload": approval_payload,
                }

            return {
                "approved": bool(response),
                "reason": "Security Agent returned a non-dict approval response.",
                "response": response,
                "payload": approval_payload,
            }

        except Exception as exc:
            self.logger.exception("Security approval request failed.")
            return {
                "approved": False,
                "reason": f"Security approval failed: {exc}",
                "payload": approval_payload,
            }

    def _prepare_verification_payload(
        self,
        *,
        user_id: str,
        workspace_id: str,
        action: str,
        report: BuildReport,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        Verification Agent can use this to confirm:
            - Project path exists
            - Directory/file counts match expected output
            - Manifest exists
        """

        payload = {
            "verification_type": "project_builder_result",
            "agent_name": self.agent_name,
            "agent_id": self.agent_id,
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "project_name": report.project_name,
            "project_path": report.project_path,
            "manifest_path": report.manifest_path,
            "created_directories_count": len(report.created_directories),
            "created_files_count": len(report.created_files),
            "skipped_files_count": len(report.skipped_files),
            "overwritten_files_count": len(report.overwritten_files),
            "errors_count": len(report.errors),
            "errors": report.errors,
            "created_at": _utc_now_iso(),
        }

        self._send_to_optional_agent(
            agent=self.verification_agent,
            method_names=("prepare_payload", "receive_payload", "record"),
            payload=payload,
            label="verification_agent",
        )

        return payload

    def _prepare_memory_payload(
        self,
        *,
        user_id: str,
        workspace_id: str,
        action: str,
        report: BuildReport,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent payload.

        Memory Agent can store a scoped project summary without leaking
        cross-user/workspace information.
        """

        payload = {
            "memory_type": "project_architecture_created",
            "agent_name": self.agent_name,
            "agent_id": self.agent_id,
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "summary": (
                f"Project '{report.project_name}' created at '{report.project_path}' "
                f"with {len(report.created_directories)} directories and "
                f"{len(report.created_files)} files."
            ),
            "project": {
                "project_name": report.project_name,
                "project_path": report.project_path,
                "manifest_path": report.manifest_path,
                "created_directories_count": len(report.created_directories),
                "created_files_count": len(report.created_files),
                "skipped_files_count": len(report.skipped_files),
                "overwritten_files_count": len(report.overwritten_files),
            },
            "created_at": _utc_now_iso(),
        }

        self._send_to_optional_agent(
            agent=self.memory_agent,
            method_names=("remember", "store", "receive_payload", "record"),
            payload=payload,
            label="memory_agent",
        )

        return payload

    def _emit_agent_event(
        self,
        *,
        event_type: str,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Emit an event for dashboard/API/event bus integrations.
        """

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
            else:
                self.logger.warning("Unsupported event_sink type: %s", type(self.event_sink))
        except Exception:
            self.logger.exception("Failed to emit agent event.")

        return event

    def _log_audit_event(
        self,
        *,
        user_id: str,
        workspace_id: str,
        action: str,
        resource: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Log audit event for SaaS dashboard and compliance trail.
        """

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
                self.logger.info(
                    "AUDIT %s user=%s workspace=%s resource=%s",
                    action,
                    user_id,
                    workspace_id,
                    resource,
                )
            elif callable(self.audit_sink):
                self.audit_sink(audit_event)
            elif hasattr(self.audit_sink, "append"):
                self.audit_sink.append(audit_event)
            elif hasattr(self.audit_sink, "record"):
                self.audit_sink.record(audit_event)
            else:
                self.logger.warning("Unsupported audit_sink type: %s", type(self.audit_sink))
        except Exception:
            self.logger.exception("Failed to log audit event.")

        return audit_event

    def _safe_result(
        self,
        *,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return a standard success result."""

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

    def _error_result(
        self,
        *,
        message: str,
        error: Optional[Any] = None,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return a standard error result."""

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

    # ------------------------------------------------------------------
    # Internal creation helpers
    # ------------------------------------------------------------------

    def _resolve_project_root(
        self,
        *,
        user_id: str,
        workspace_id: str,
        project_slug: str,
        base_path: Optional[Union[str, Path]] = None,
    ) -> Path:
        """
        Resolve project root with user/workspace isolation.

        Default:
            safe_root / user_id / workspace_id / project_slug

        If base_path is provided:
            safe_root / base_path / user_id / workspace_id / project_slug
        """

        if base_path:
            base = _safe_join(self.safe_root, base_path)
        else:
            base = self.safe_root

        isolated_root = base / user_id / workspace_id
        project_root = (isolated_root / project_slug).resolve()

        try:
            project_root.relative_to(self.safe_root)
        except ValueError as exc:
            raise ValueError("Resolved project root escapes safe root.") from exc

        return project_root

    def _create_directories(
        self,
        *,
        project_root: Path,
        directories: Sequence[ProjectDirectorySpec],
        report: BuildReport,
    ) -> None:
        """Create directories from blueprint."""

        for directory in directories:
            try:
                target = _safe_join(project_root, directory.path)
                if target.exists():
                    report.existing_directories.append(str(target))
                else:
                    target.mkdir(parents=True, exist_ok=True)
                    report.created_directories.append(str(target))
            except Exception as exc:
                self.logger.exception("Failed to create directory: %s", directory.path)
                report.errors.append({
                    "path": directory.path,
                    "error": str(exc),
                    "type": exc.__class__.__name__,
                })

    def _create_files(
        self,
        *,
        project_root: Path,
        files: Sequence[ProjectFileSpec],
        report: BuildReport,
        overwrite: bool,
        blueprint_overwrite: bool,
    ) -> None:
        """Create files from blueprint."""

        for file_spec in files:
            try:
                target = _safe_join(project_root, file_spec.path)
                target.parent.mkdir(parents=True, exist_ok=True)

                can_overwrite = bool(overwrite or blueprint_overwrite or file_spec.overwrite)

                if target.exists() and not can_overwrite:
                    report.skipped_files.append(str(target))
                    continue

                if file_spec.binary:
                    if isinstance(file_spec.content, bytes):
                        content_bytes = file_spec.content
                    else:
                        content_bytes = str(file_spec.content).encode(DEFAULT_FILE_ENCODING)
                    target.write_bytes(content_bytes)
                else:
                    target.write_text(str(file_spec.content), encoding=DEFAULT_FILE_ENCODING)

                if target.exists() and can_overwrite:
                    if str(target) not in report.created_files:
                        report.overwritten_files.append(str(target))
                else:
                    report.created_files.append(str(target))

                if str(target) not in report.created_files and str(target) not in report.overwritten_files:
                    report.created_files.append(str(target))

            except Exception as exc:
                self.logger.exception("Failed to create file: %s", file_spec.path)
                report.errors.append({
                    "path": file_spec.path,
                    "error": str(exc),
                    "type": exc.__class__.__name__,
                })

    def _create_gitkeep_files(self, *, project_root: Path, report: BuildReport) -> None:
        """Create .gitkeep files in important empty folders."""

        for folder in DEFAULT_GITKEEP_FOLDERS:
            try:
                target_dir = _safe_join(project_root, folder)
                target_dir.mkdir(parents=True, exist_ok=True)
                gitkeep = target_dir / ".gitkeep"
                if gitkeep.exists():
                    report.skipped_files.append(str(gitkeep))
                else:
                    gitkeep.write_text("", encoding=DEFAULT_FILE_ENCODING)
                    report.created_files.append(str(gitkeep))
            except Exception as exc:
                report.errors.append({
                    "path": f"{folder}/.gitkeep",
                    "error": str(exc),
                    "type": exc.__class__.__name__,
                })

    def _write_manifest(
        self,
        *,
        project_root: Path,
        user_id: str,
        workspace_id: str,
        blueprint: ProjectBlueprint,
        report: BuildReport,
        request_metadata: Mapping[str, Any],
    ) -> Path:
        """Write a project manifest used by dashboard, registry, and future analyzers."""

        manifest = {
            "manifest_version": "1.0",
            "system": "William / Jarvis Multi-Agent AI SaaS System",
            "brand": "Digital Promotix",
            "agent_name": self.agent_name,
            "agent_id": self.agent_id,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "project_name": blueprint.project_name,
            "project_path": str(project_root),
            "blueprint": self._blueprint_to_dict(blueprint),
            "report": asdict(report),
            "request_metadata": dict(request_metadata),
            "created_at": _utc_now_iso(),
        }

        manifest_path = project_root / "william_project_manifest.json"
        manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False),
            encoding=DEFAULT_FILE_ENCODING,
        )

        if str(manifest_path) not in report.created_files:
            report.created_files.append(str(manifest_path))

        return manifest_path

    # ------------------------------------------------------------------
    # Blueprint helpers
    # ------------------------------------------------------------------

    def _coerce_blueprint(
        self,
        *,
        project_name: str,
        raw_blueprint: Optional[Union[ProjectBlueprint, Mapping[str, Any]]],
    ) -> ProjectBlueprint:
        """Convert user/API blueprint into ProjectBlueprint."""

        if raw_blueprint is None:
            return self.get_default_blueprint(project_name)

        if isinstance(raw_blueprint, ProjectBlueprint):
            return raw_blueprint

        if not isinstance(raw_blueprint, Mapping):
            raise ValueError("blueprint must be a dict-like object or ProjectBlueprint.")

        project_slug = _slugify_project_name(
            str(raw_blueprint.get("project_name") or project_name)
        )

        include_default = bool(raw_blueprint.get("include_default_architecture", False))
        include_gitkeep = bool(raw_blueprint.get("include_gitkeep", True))
        overwrite_existing_files = bool(raw_blueprint.get("overwrite_existing_files", False))

        directories_raw = list(raw_blueprint.get("directories") or [])
        files_raw = list(raw_blueprint.get("files") or [])

        directories: List[ProjectDirectorySpec] = []
        files: List[ProjectFileSpec] = []

        if include_default:
            default_blueprint = self.get_default_blueprint(project_slug)
            directories.extend(default_blueprint.directories)
            files.extend(default_blueprint.files)

        for item in directories_raw:
            if isinstance(item, str):
                directories.append(ProjectDirectorySpec(path=item))
            elif isinstance(item, Mapping):
                directories.append(ProjectDirectorySpec(
                    path=str(item.get("path", "")),
                    metadata=dict(item.get("metadata") or {}),
                ))
            else:
                raise ValueError(f"Invalid directory spec: {item}")

        for item in files_raw:
            if isinstance(item, str):
                files.append(ProjectFileSpec(path=item, content=""))
            elif isinstance(item, Mapping):
                files.append(ProjectFileSpec(
                    path=str(item.get("path", "")),
                    content=str(item.get("content", "")),
                    overwrite=bool(item.get("overwrite", False)),
                    binary=bool(item.get("binary", False)),
                    metadata=dict(item.get("metadata") or {}),
                ))
            else:
                raise ValueError(f"Invalid file spec: {item}")

        directories = self._dedupe_directory_specs(directories)
        files = self._dedupe_file_specs(files)

        return ProjectBlueprint(
            project_name=project_slug,
            directories=directories,
            files=files,
            include_default_architecture=include_default,
            include_gitkeep=include_gitkeep,
            overwrite_existing_files=overwrite_existing_files,
            metadata=dict(raw_blueprint.get("metadata") or {}),
        )

    def _blueprint_to_dict(self, blueprint: ProjectBlueprint) -> Dict[str, Any]:
        """Serialize blueprint to plain dict."""

        return {
            "project_name": blueprint.project_name,
            "directories": [asdict(directory) for directory in blueprint.directories],
            "files": [
                {
                    "path": file_spec.path,
                    "content_length": len(file_spec.content),
                    "overwrite": file_spec.overwrite,
                    "binary": file_spec.binary,
                    "metadata": file_spec.metadata,
                }
                for file_spec in blueprint.files
            ],
            "include_default_architecture": blueprint.include_default_architecture,
            "include_gitkeep": blueprint.include_gitkeep,
            "overwrite_existing_files": blueprint.overwrite_existing_files,
            "metadata": blueprint.metadata,
        }

    def _dedupe_directory_specs(
        self,
        directories: Sequence[ProjectDirectorySpec],
    ) -> List[ProjectDirectorySpec]:
        """Deduplicate directory specs by normalized path."""

        seen = set()
        result = []
        for directory in directories:
            normalized = directory.path.strip().replace("\\", "/")
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            result.append(ProjectDirectorySpec(path=normalized, metadata=directory.metadata))
        return result

    def _dedupe_file_specs(
        self,
        files: Sequence[ProjectFileSpec],
    ) -> List[ProjectFileSpec]:
        """Deduplicate file specs by normalized path, keeping the last version."""

        by_path: Dict[str, ProjectFileSpec] = {}

        for file_spec in files:
            normalized = file_spec.path.strip().replace("\\", "/")
            if not normalized:
                continue
            by_path[normalized] = ProjectFileSpec(
                path=normalized,
                content=file_spec.content,
                overwrite=file_spec.overwrite,
                binary=file_spec.binary,
                metadata=file_spec.metadata,
            )

        return list(by_path.values())

    def _render_blueprint_tree(self, blueprint: ProjectBlueprint) -> str:
        """Render an in-memory blueprint tree."""

        paths = set()
        for directory in blueprint.directories:
            paths.add(directory.path.strip("/"))
        for file_spec in blueprint.files:
            paths.add(file_spec.path.strip("/"))

        tree: Dict[str, Any] = {}
        for path in sorted(paths):
            cursor = tree
            for part in path.split("/"):
                cursor = cursor.setdefault(part, {})

        lines = [f"{blueprint.project_name}/"]

        def walk(node: Dict[str, Any], prefix: str = "") -> None:
            items = sorted(node.items(), key=lambda item: item[0].lower())
            for index, (name, child) in enumerate(items):
                connector = "└── " if index == len(items) - 1 else "├── "
                suffix = "/" if child else ""
                lines.append(f"{prefix}{connector}{name}{suffix}")
                if child:
                    extension = "    " if index == len(items) - 1 else "│   "
                    walk(child, prefix + extension)

        walk(tree)
        return "\n".join(lines)

    def _minimal_agent_module_blueprint(self, project_name: str) -> ProjectBlueprint:
        """Small template for a single agent module."""

        project_slug = _slugify_project_name(project_name)
        return ProjectBlueprint(
            project_name=project_slug,
            directories=[
                ProjectDirectorySpec(path="agents"),
                ProjectDirectorySpec(path="agents/custom_agent"),
                ProjectDirectorySpec(path="tests"),
            ],
            files=[
                ProjectFileSpec(
                    path="agents/__init__.py",
                    content='"""Agents package."""\n',
                ),
                ProjectFileSpec(
                    path="agents/custom_agent/__init__.py",
                    content='"""Custom agent package."""\n',
                ),
                ProjectFileSpec(
                    path="agents/custom_agent/custom_agent.py",
                    content=(
                        '"""Custom William/Jarvis agent."""\n\n'
                        "class CustomAgent:\n"
                        "    agent_name = 'custom_agent'\n\n"
                        "    def run(self, task):\n"
                        "        return {\n"
                        "            'success': True,\n"
                        "            'message': 'Custom agent received task.',\n"
                        "            'data': {'task': dict(task or {})},\n"
                        "            'error': None,\n"
                        "            'metadata': {},\n"
                        "        }\n"
                    ),
                ),
                ProjectFileSpec(
                    path="README.md",
                    content="# Minimal William/Jarvis Agent Module\n",
                ),
            ],
            metadata={"template": "minimal_agent_module"},
        )

    def _fastapi_dashboard_shell_blueprint(self, project_name: str) -> ProjectBlueprint:
        """Small template for FastAPI dashboard shell."""

        project_slug = _slugify_project_name(project_name)
        return ProjectBlueprint(
            project_name=project_slug,
            directories=[
                ProjectDirectorySpec(path="api"),
                ProjectDirectorySpec(path="api/routes"),
                ProjectDirectorySpec(path="dashboard"),
                ProjectDirectorySpec(path="tests"),
            ],
            files=[
                ProjectFileSpec(
                    path="api/__init__.py",
                    content='"""API package."""\n',
                ),
                ProjectFileSpec(
                    path="api/main.py",
                    content=(
                        "from fastapi import FastAPI\n\n"
                        "app = FastAPI(title='William/Jarvis Dashboard API')\n\n"
                        "@app.get('/health')\n"
                        "def health():\n"
                        "    return {'success': True, 'message': 'OK'}\n"
                    ),
                ),
                ProjectFileSpec(
                    path="requirements.txt",
                    content="fastapi\nuvicorn\n",
                ),
                ProjectFileSpec(
                    path="README.md",
                    content="# William/Jarvis FastAPI Dashboard Shell\n",
                ),
            ],
            metadata={"template": "fastapi_dashboard_shell"},
        )

    # ------------------------------------------------------------------
    # Validation helpers
    # ------------------------------------------------------------------

    def _validate_relative_path(self, path: str, *, is_file: bool) -> str:
        """Validate a safe relative path."""

        normalized = str(path).strip().replace("\\", "/")

        if not normalized:
            raise ValueError("Path cannot be empty.")

        if normalized.startswith("/"):
            raise ValueError("Absolute paths are not allowed.")

        if "\x00" in normalized:
            raise ValueError("Null bytes are not allowed.")

        if ".." in Path(normalized).parts:
            raise ValueError("Path traversal is not allowed.")

        if is_file:
            filename = Path(normalized).name
            if not SAFE_FILENAME_PATTERN.match(filename):
                raise ValueError(f"Unsafe filename: {filename}")
        else:
            if not SAFE_FOLDER_PATTERN.match(normalized):
                raise ValueError(f"Unsafe folder path: {normalized}")

        for part in Path(normalized).parts:
            if _is_reserved_name(part):
                raise ValueError(f"Reserved path segment is not allowed: {part}")

        return normalized

    def _find_duplicates(self, paths: Sequence[str]) -> List[str]:
        """Find duplicate paths."""

        seen = set()
        duplicates = set()
        for path in paths:
            normalized = path.replace("\\", "/").strip().lower()
            if normalized in seen:
                duplicates.add(path)
            seen.add(normalized)
        return sorted(duplicates)

    # ------------------------------------------------------------------
    # Optional agent dispatch helper
    # ------------------------------------------------------------------

    def _send_to_optional_agent(
        self,
        *,
        agent: Optional[Any],
        method_names: Sequence[str],
        payload: Mapping[str, Any],
        label: str,
    ) -> None:
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
                return

            self.logger.debug("Optional %s has no supported methods.", label)
        except Exception:
            self.logger.exception("Failed to send payload to %s.", label)


# ---------------------------------------------------------------------------
# Convenience functions for direct import usage
# ---------------------------------------------------------------------------

def create_default_william_project(
    *,
    user_id: Any,
    workspace_id: Any,
    project_name: str = "william_ai_system",
    safe_root: Union[str, Path, None] = None,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """
    Convenience helper to create the default William/Jarvis architecture.

    This is safe for tests, scripts, and future dashboard integrations.
    """

    builder = ProjectBuilder(safe_root=safe_root)
    return builder.create_project(
        user_id=user_id,
        workspace_id=workspace_id,
        project_name=project_name,
        dry_run=dry_run,
    )


def get_project_builder_default_blueprint(
    project_name: str = "william_ai_system",
) -> Dict[str, Any]:
    """Return the default blueprint as a plain dict."""

    builder = ProjectBuilder()
    blueprint = builder.get_default_blueprint(project_name)
    return builder._blueprint_to_dict(blueprint)


__all__ = [
    "ProjectBuilder",
    "ProjectBlueprint",
    "ProjectDirectorySpec",
    "ProjectFileSpec",
    "BuildReport",
    "create_default_william_project",
    "get_project_builder_default_blueprint",
]


# FILE COMPLETE
