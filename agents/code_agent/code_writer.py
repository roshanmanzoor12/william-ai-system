"""
agents/code_agent/code_writer.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    CodeWriter is responsible for writing new production code files, classes,
    functions, APIs, components, configuration files, and module scaffolds.

Architecture Compatibility:
    - Compatible with BaseAgent, Agent Registry, Agent Loader, Agent Router,
      and Master Agent routing.
    - Supports SaaS user/workspace isolation.
    - Routes sensitive file-writing operations through Security Agent hooks.
    - Prepares Verification Agent payloads after successful actions.
    - Prepares Memory Agent payloads for useful generated-code context.
    - Emits agent events and audit logs for dashboard/API analytics.

Design Notes:
    This file is intentionally import-safe. If the wider William/Jarvis system
    modules are not created yet, this file provides lightweight fallback stubs
    so it can still be imported, tested, and integrated later.
"""

from __future__ import annotations

import ast
import difflib
import hashlib
import json
import logging
import os
import re
import shutil
import tempfile
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Safe optional imports for William/Jarvis architecture compatibility
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for early-stage projects
    class BaseAgent:
        """
        Fallback BaseAgent stub.

        This allows CodeWriter to be imported before the real BaseAgent exists.
        The real William/Jarvis BaseAgent should replace this automatically
        when available.
        """

        agent_name: str = "base_agent"
        agent_type: str = "generic"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.logger = logging.getLogger(self.__class__.__name__)

        def run(self, task: Mapping[str, Any]) -> Dict[str, Any]:
            raise NotImplementedError("BaseAgent.run must be implemented by child agents.")


try:
    from agents.security_agent.security_agent import SecurityAgent  # type: ignore
except Exception:  # pragma: no cover
    class SecurityAgent:
        """
        Fallback SecurityAgent stub.

        Default behavior is conservative but usable:
        - Allows normal safe writes inside an approved project root.
        - Rejects obviously dangerous paths/actions.
        """

        def approve_action(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
            target_path = str(payload.get("target_path", ""))
            action = str(payload.get("action", ""))

            dangerous_fragments = [
                "/etc/",
                "/bin/",
                "/sbin/",
                "/usr/bin/",
                "/usr/sbin/",
                "C:\\Windows",
                "System32",
                "..",
            ]

            if action in {"write_file", "write_multiple_files"}:
                if any(fragment in target_path for fragment in dangerous_fragments):
                    return {
                        "success": False,
                        "approved": False,
                        "message": "Security fallback rejected dangerous target path.",
                        "error": "dangerous_path",
                    }

            return {
                "success": True,
                "approved": True,
                "message": "Security fallback approved action.",
                "data": {},
                "error": None,
            }


try:
    from agents.verification_agent.verification_agent import VerificationAgent  # type: ignore
except Exception:  # pragma: no cover
    class VerificationAgent:
        """
        Fallback VerificationAgent stub.

        The real Verification Agent can later consume verification payloads
        prepared by CodeWriter.
        """

        def prepare_payload(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
            return {
                "success": True,
                "message": "Verification payload prepared by fallback.",
                "data": dict(payload),
                "error": None,
            }


try:
    from agents.memory_agent.memory_agent import MemoryAgent  # type: ignore
except Exception:  # pragma: no cover
    class MemoryAgent:
        """
        Fallback MemoryAgent stub.

        The real Memory Agent should store user/workspace-specific context.
        """

        def prepare_payload(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
            return {
                "success": True,
                "message": "Memory payload prepared by fallback.",
                "data": dict(payload),
                "error": None,
            }


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOGGER = logging.getLogger("william.code_agent.code_writer")
if not LOGGER.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )
    handler.setFormatter(formatter)
    LOGGER.addHandler(handler)

LOGGER.setLevel(logging.INFO)


# ---------------------------------------------------------------------------
# Enums and data structures
# ---------------------------------------------------------------------------

class CodeLanguage(str, Enum):
    """Supported high-level language identifiers."""

    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    HTML = "html"
    CSS = "css"
    JSON = "json"
    YAML = "yaml"
    MARKDOWN = "markdown"
    TEXT = "text"
    PHP = "php"
    SQL = "sql"
    UNKNOWN = "unknown"


class FileWriteMode(str, Enum):
    """Supported write behavior modes."""

    CREATE_ONLY = "create_only"
    OVERWRITE = "overwrite"
    APPEND = "append"
    UPSERT = "upsert"
    DRY_RUN = "dry_run"


class CodeArtifactType(str, Enum):
    """Common artifact types generated by the Code Agent."""

    FILE = "file"
    CLASS = "class"
    FUNCTION = "function"
    API = "api"
    COMPONENT = "component"
    CONFIG = "config"
    TEST = "test"
    DOCUMENTATION = "documentation"
    MODULE = "module"


@dataclass
class CodeWriteRequest:
    """
    Normalized request object used by CodeWriter.

    user_id and workspace_id are mandatory for SaaS isolation whenever the
    action writes or previews user-specific code.
    """

    user_id: str
    workspace_id: str
    target_path: Union[str, Path]
    content: str
    mode: FileWriteMode = FileWriteMode.CREATE_ONLY
    language: CodeLanguage = CodeLanguage.UNKNOWN
    artifact_type: CodeArtifactType = CodeArtifactType.FILE
    project_root: Optional[Union[str, Path]] = None
    encoding: str = "utf-8"
    create_parent_dirs: bool = True
    backup_existing: bool = True
    validate_syntax: bool = True
    format_content: bool = True
    dry_run: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CodeWriteResult:
    """Structured result for file write operations."""

    success: bool
    message: str
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GeneratedCodeSpec:
    """
    Specification for generating a code file from structured fields.

    This is useful for dashboard/API integrations where the frontend sends
    structured intent instead of raw file content.
    """

    user_id: str
    workspace_id: str
    target_path: Union[str, Path]
    name: str
    artifact_type: CodeArtifactType
    language: CodeLanguage = CodeLanguage.PYTHON
    description: str = ""
    imports: List[str] = field(default_factory=list)
    class_name: Optional[str] = None
    function_names: List[str] = field(default_factory=list)
    methods: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    project_root: Optional[Union[str, Path]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _utc_now_iso() -> str:
    """Return current UTC timestamp in ISO format."""

    return datetime.now(timezone.utc).isoformat()


def _sha256_text(value: str) -> str:
    """Return SHA256 hash for text content."""

    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _safe_json(data: Any) -> str:
    """Safely serialize JSON for logs/debugging."""

    try:
        return json.dumps(data, indent=2, sort_keys=True, default=str)
    except Exception:
        return str(data)


def _normalize_newlines(content: str) -> str:
    """Normalize line endings to Unix style."""

    return content.replace("\r\n", "\n").replace("\r", "\n")


def _ensure_trailing_newline(content: str) -> str:
    """Ensure files end with a newline."""

    return content if content.endswith("\n") else f"{content}\n"


def _guess_language_from_path(path: Union[str, Path]) -> CodeLanguage:
    """Infer language from file extension."""

    suffix = Path(path).suffix.lower()

    mapping = {
        ".py": CodeLanguage.PYTHON,
        ".js": CodeLanguage.JAVASCRIPT,
        ".jsx": CodeLanguage.JAVASCRIPT,
        ".ts": CodeLanguage.TYPESCRIPT,
        ".tsx": CodeLanguage.TYPESCRIPT,
        ".html": CodeLanguage.HTML,
        ".htm": CodeLanguage.HTML,
        ".css": CodeLanguage.CSS,
        ".json": CodeLanguage.JSON,
        ".yaml": CodeLanguage.YAML,
        ".yml": CodeLanguage.YAML,
        ".md": CodeLanguage.MARKDOWN,
        ".txt": CodeLanguage.TEXT,
        ".php": CodeLanguage.PHP,
        ".sql": CodeLanguage.SQL,
    }

    return mapping.get(suffix, CodeLanguage.UNKNOWN)


def _redact_sensitive_values(payload: Mapping[str, Any]) -> Dict[str, Any]:
    """
    Redact sensitive keys before audit/event logging.

    This avoids leaking secrets into logs, dashboard events, or memory payloads.
    """

    sensitive_patterns = [
        "password",
        "secret",
        "token",
        "api_key",
        "apikey",
        "private_key",
        "access_key",
        "refresh_token",
        "authorization",
    ]

    def redact(value: Any, key: str = "") -> Any:
        lower_key = key.lower()

        if any(pattern in lower_key for pattern in sensitive_patterns):
            return "***REDACTED***"

        if isinstance(value, Mapping):
            return {str(k): redact(v, str(k)) for k, v in value.items()}

        if isinstance(value, list):
            return [redact(item, key) for item in value]

        return value

    return redact(dict(payload))


# ---------------------------------------------------------------------------
# Main CodeWriter class
# ---------------------------------------------------------------------------

class CodeWriter(BaseAgent):
    """
    Production-level code writing agent/helper for William/Jarvis.

    Responsibilities:
        - Write new code files safely.
        - Generate simple production file templates.
        - Validate user/workspace context.
        - Validate paths and prevent path traversal.
        - Validate syntax where possible.
        - Create backups before overwriting.
        - Prepare security, verification, memory, audit, and event payloads.
        - Return structured dict/JSON-style results.

    Master Agent Usage:
        MasterAgent or AgentRouter can call:
            CodeWriter().run(task)

        where task may include:
            {
                "user_id": "...",
                "workspace_id": "...",
                "action": "write_file",
                "target_path": "agents/example.py",
                "content": "...",
                "mode": "create_only",
                "project_root": "/safe/project/root"
            }

    Public Methods:
        - run()
        - write_file()
        - write_multiple_files()
        - generate_python_class_file()
        - generate_python_function_file()
        - generate_from_spec()
        - preview_file_write()
        - validate_code_content()
    """

    agent_name = "code_writer"
    agent_type = "code_agent"
    version = "1.0.0"

    DEFAULT_BLOCKED_PATH_PARTS = {
        ".git",
        ".svn",
        ".hg",
        "__pycache__",
        "node_modules",
        ".venv",
        "venv",
        "env",
        ".env",
        ".ssh",
    }

    DEFAULT_BLOCKED_FILENAMES = {
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "known_hosts",
        "authorized_keys",
    }

    DEFAULT_ALLOWED_EXTENSIONS = {
        ".py",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".html",
        ".htm",
        ".css",
        ".json",
        ".yaml",
        ".yml",
        ".md",
        ".txt",
        ".php",
        ".sql",
        ".toml",
        ".ini",
        ".cfg",
        ".env.example",
        ".dockerfile",
        ".gitignore",
        ".editorconfig",
    }

    def __init__(
        self,
        security_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        event_emitter: Optional[Callable[[Mapping[str, Any]], None]] = None,
        audit_logger: Optional[Callable[[Mapping[str, Any]], None]] = None,
        default_project_root: Optional[Union[str, Path]] = None,
        allow_unknown_extensions: bool = True,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        super().__init__()

        self.logger = logger or LOGGER
        self.security_agent = security_agent or SecurityAgent()
        self.verification_agent = verification_agent or VerificationAgent()
        self.memory_agent = memory_agent or MemoryAgent()
        self.event_emitter = event_emitter
        self.audit_logger = audit_logger
        self.default_project_root = (
            Path(default_project_root).resolve()
            if default_project_root
            else None
        )
        self.allow_unknown_extensions = allow_unknown_extensions

    # ---------------------------------------------------------------------
    # BaseAgent/MasterAgent compatibility
    # ---------------------------------------------------------------------

    def run(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Main router-compatible entry point.

        Supported actions:
            - write_file
            - write_multiple_files
            - preview_file_write
            - generate_from_spec
            - generate_python_class_file
            - generate_python_function_file
            - validate_code_content
        """

        start_time = time.time()

        try:
            if not isinstance(task, Mapping):
                return self._error_result(
                    message="Task must be a mapping/dict.",
                    error="invalid_task_type",
                    metadata={"agent": self.agent_name},
                )

            action = str(task.get("action", "write_file")).strip()

            context_result = self._validate_task_context(task)
            if not context_result["success"]:
                return context_result

            self._emit_agent_event(
                {
                    "event": "code_writer.task_received",
                    "action": action,
                    "user_id": task.get("user_id"),
                    "workspace_id": task.get("workspace_id"),
                    "metadata": {
                        "agent": self.agent_name,
                        "version": self.version,
                    },
                }
            )

            if action == "write_file":
                result = self.write_file(
                    user_id=str(task["user_id"]),
                    workspace_id=str(task["workspace_id"]),
                    target_path=task["target_path"],
                    content=str(task.get("content", "")),
                    mode=task.get("mode", FileWriteMode.CREATE_ONLY),
                    project_root=task.get("project_root"),
                    language=task.get("language"),
                    artifact_type=task.get("artifact_type", CodeArtifactType.FILE),
                    encoding=str(task.get("encoding", "utf-8")),
                    create_parent_dirs=bool(task.get("create_parent_dirs", True)),
                    backup_existing=bool(task.get("backup_existing", True)),
                    validate_syntax=bool(task.get("validate_syntax", True)),
                    format_content=bool(task.get("format_content", True)),
                    dry_run=bool(task.get("dry_run", False)),
                    metadata=dict(task.get("metadata", {})),
                )

            elif action == "write_multiple_files":
                result = self.write_multiple_files(
                    user_id=str(task["user_id"]),
                    workspace_id=str(task["workspace_id"]),
                    files=list(task.get("files", [])),
                    project_root=task.get("project_root"),
                    mode=task.get("mode", FileWriteMode.CREATE_ONLY),
                    dry_run=bool(task.get("dry_run", False)),
                    metadata=dict(task.get("metadata", {})),
                )

            elif action == "preview_file_write":
                result = self.preview_file_write(
                    user_id=str(task["user_id"]),
                    workspace_id=str(task["workspace_id"]),
                    target_path=task["target_path"],
                    content=str(task.get("content", "")),
                    project_root=task.get("project_root"),
                    mode=task.get("mode", FileWriteMode.CREATE_ONLY),
                    metadata=dict(task.get("metadata", {})),
                )

            elif action == "generate_from_spec":
                spec = self._spec_from_task(task)
                result = self.generate_from_spec(
                    spec=spec,
                    mode=task.get("mode", FileWriteMode.CREATE_ONLY),
                    dry_run=bool(task.get("dry_run", False)),
                )

            elif action == "generate_python_class_file":
                result = self.generate_python_class_file(
                    user_id=str(task["user_id"]),
                    workspace_id=str(task["workspace_id"]),
                    target_path=task["target_path"],
                    class_name=str(task.get("class_name", "GeneratedClass")),
                    description=str(task.get("description", "")),
                    project_root=task.get("project_root"),
                    imports=list(task.get("imports", [])),
                    methods=list(task.get("methods", [])),
                    mode=task.get("mode", FileWriteMode.CREATE_ONLY),
                    dry_run=bool(task.get("dry_run", False)),
                    metadata=dict(task.get("metadata", {})),
                )

            elif action == "generate_python_function_file":
                result = self.generate_python_function_file(
                    user_id=str(task["user_id"]),
                    workspace_id=str(task["workspace_id"]),
                    target_path=task["target_path"],
                    function_name=str(task.get("function_name", "generated_function")),
                    description=str(task.get("description", "")),
                    project_root=task.get("project_root"),
                    imports=list(task.get("imports", [])),
                    mode=task.get("mode", FileWriteMode.CREATE_ONLY),
                    dry_run=bool(task.get("dry_run", False)),
                    metadata=dict(task.get("metadata", {})),
                )

            elif action == "validate_code_content":
                result = self.validate_code_content(
                    content=str(task.get("content", "")),
                    language=task.get("language") or CodeLanguage.UNKNOWN,
                    target_path=task.get("target_path"),
                )

            else:
                result = self._error_result(
                    message=f"Unsupported CodeWriter action: {action}",
                    error="unsupported_action",
                    metadata={
                        "supported_actions": [
                            "write_file",
                            "write_multiple_files",
                            "preview_file_write",
                            "generate_from_spec",
                            "generate_python_class_file",
                            "generate_python_function_file",
                            "validate_code_content",
                        ]
                    },
                )

            elapsed_ms = round((time.time() - start_time) * 1000, 2)
            result.setdefault("metadata", {})
            result["metadata"]["elapsed_ms"] = elapsed_ms
            result["metadata"]["agent"] = self.agent_name
            result["metadata"]["version"] = self.version

            return result

        except Exception as exc:
            self.logger.exception("CodeWriter.run failed.")
            return self._error_result(
                message="CodeWriter task failed unexpectedly.",
                error=str(exc),
                metadata={
                    "agent": self.agent_name,
                    "version": self.version,
                    "elapsed_ms": round((time.time() - start_time) * 1000, 2),
                },
            )

    # ---------------------------------------------------------------------
    # Public file-writing methods
    # ---------------------------------------------------------------------

    def write_file(
        self,
        user_id: str,
        workspace_id: str,
        target_path: Union[str, Path],
        content: str,
        mode: Union[str, FileWriteMode] = FileWriteMode.CREATE_ONLY,
        project_root: Optional[Union[str, Path]] = None,
        language: Optional[Union[str, CodeLanguage]] = None,
        artifact_type: Union[str, CodeArtifactType] = CodeArtifactType.FILE,
        encoding: str = "utf-8",
        create_parent_dirs: bool = True,
        backup_existing: bool = True,
        validate_syntax: bool = True,
        format_content: bool = True,
        dry_run: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Write a single code file safely.

        This method:
            1. Validates user/workspace context.
            2. Resolves and validates target path.
            3. Normalizes/formats content.
            4. Runs syntax validation where possible.
            5. Requests security approval when needed.
            6. Creates backup if overwriting.
            7. Writes atomically using a temp file.
            8. Emits audit, event, memory, and verification payloads.
        """

        metadata = metadata or {}

        try:
            normalized_mode = self._normalize_write_mode(mode)
            normalized_language = self._normalize_language(language, target_path)
            normalized_artifact_type = self._normalize_artifact_type(artifact_type)

            request = CodeWriteRequest(
                user_id=user_id,
                workspace_id=workspace_id,
                target_path=target_path,
                content=content,
                mode=normalized_mode,
                language=normalized_language,
                artifact_type=normalized_artifact_type,
                project_root=project_root,
                encoding=encoding,
                create_parent_dirs=create_parent_dirs,
                backup_existing=backup_existing,
                validate_syntax=validate_syntax,
                format_content=format_content,
                dry_run=dry_run or normalized_mode == FileWriteMode.DRY_RUN,
                metadata=metadata,
            )

            context_result = self._validate_task_context(
                {
                    "user_id": request.user_id,
                    "workspace_id": request.workspace_id,
                    "target_path": str(request.target_path),
                }
            )
            if not context_result["success"]:
                return context_result

            path_result = self._resolve_and_validate_path(
                target_path=request.target_path,
                project_root=request.project_root,
            )
            if not path_result["success"]:
                return path_result

            resolved_path = Path(path_result["data"]["resolved_path"])
            resolved_project_root = Path(path_result["data"]["project_root"])

            prepared_content = self._prepare_content(
                content=request.content,
                language=request.language,
                format_content=request.format_content,
            )

            validation_result = self.validate_code_content(
                content=prepared_content,
                language=request.language,
                target_path=resolved_path,
            )
            if request.validate_syntax and not validation_result["success"]:
                return validation_result

            operation_plan = self._build_operation_plan(
                request=request,
                resolved_path=resolved_path,
                resolved_project_root=resolved_project_root,
                prepared_content=prepared_content,
            )

            mode_result = self._validate_write_mode_against_path(
                mode=request.mode,
                resolved_path=resolved_path,
            )
            if not mode_result["success"]:
                return mode_result

            if self._requires_security_check(operation_plan):
                security_result = self._request_security_approval(operation_plan)
                if not security_result["success"]:
                    return security_result

            if request.dry_run:
                preview = self._build_preview(
                    target_path=resolved_path,
                    new_content=prepared_content,
                    mode=request.mode,
                    encoding=request.encoding,
                )

                result = self._safe_result(
                    message="Dry run completed. No file was written.",
                    data={
                        "target_path": str(resolved_path),
                        "project_root": str(resolved_project_root),
                        "language": request.language.value,
                        "artifact_type": request.artifact_type.value,
                        "mode": request.mode.value,
                        "preview": preview,
                        "content_hash": _sha256_text(prepared_content),
                    },
                    metadata={
                        "dry_run": True,
                        "user_id": request.user_id,
                        "workspace_id": request.workspace_id,
                    },
                )

                self._post_success_hooks(
                    request=request,
                    result=result,
                    resolved_path=resolved_path,
                    content=prepared_content,
                    action="dry_run_write_file",
                )
                return result

            if request.create_parent_dirs:
                resolved_path.parent.mkdir(parents=True, exist_ok=True)

            backup_path = None
            if resolved_path.exists() and request.backup_existing:
                backup_path = self._create_backup(resolved_path)

            write_result = self._atomic_write(
                path=resolved_path,
                content=prepared_content,
                mode=request.mode,
                encoding=request.encoding,
            )
            if not write_result["success"]:
                return write_result

            result = self._safe_result(
                message="Code file written successfully.",
                data={
                    "target_path": str(resolved_path),
                    "project_root": str(resolved_project_root),
                    "language": request.language.value,
                    "artifact_type": request.artifact_type.value,
                    "mode": request.mode.value,
                    "bytes_written": len(prepared_content.encode(request.encoding)),
                    "line_count": len(prepared_content.splitlines()),
                    "content_hash": _sha256_text(prepared_content),
                    "backup_path": str(backup_path) if backup_path else None,
                    "syntax_validation": validation_result,
                },
                metadata={
                    "user_id": request.user_id,
                    "workspace_id": request.workspace_id,
                    "dry_run": False,
                    "created_at": _utc_now_iso(),
                },
            )

            self._post_success_hooks(
                request=request,
                result=result,
                resolved_path=resolved_path,
                content=prepared_content,
                action="write_file",
            )

            return result

        except Exception as exc:
            self.logger.exception("write_file failed.")
            return self._error_result(
                message="Failed to write code file.",
                error=str(exc),
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "target_path": str(target_path),
                },
            )

    def write_multiple_files(
        self,
        user_id: str,
        workspace_id: str,
        files: List[Mapping[str, Any]],
        project_root: Optional[Union[str, Path]] = None,
        mode: Union[str, FileWriteMode] = FileWriteMode.CREATE_ONLY,
        dry_run: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Write multiple files with isolated structured results.

        Each item in files may include:
            {
                "target_path": "...",
                "content": "...",
                "language": "python",
                "artifact_type": "file",
                "mode": "create_only"
            }
        """

        metadata = metadata or {}

        if not isinstance(files, list) or not files:
            return self._error_result(
                message="files must be a non-empty list.",
                error="invalid_files",
                metadata={"user_id": user_id, "workspace_id": workspace_id},
            )

        batch_plan = {
            "action": "write_multiple_files",
            "user_id": user_id,
            "workspace_id": workspace_id,
            "file_count": len(files),
            "project_root": str(project_root or self.default_project_root or ""),
            "dry_run": dry_run,
            "metadata": metadata,
        }

        if self._requires_security_check(batch_plan):
            security_result = self._request_security_approval(batch_plan)
            if not security_result["success"]:
                return security_result

        results: List[Dict[str, Any]] = []
        success_count = 0
        failure_count = 0

        for index, file_item in enumerate(files):
            if not isinstance(file_item, Mapping):
                failure_count += 1
                results.append(
                    self._error_result(
                        message=f"File item at index {index} must be a mapping.",
                        error="invalid_file_item",
                        metadata={"index": index},
                    )
                )
                continue

            item_result = self.write_file(
                user_id=user_id,
                workspace_id=workspace_id,
                target_path=file_item.get("target_path", ""),
                content=str(file_item.get("content", "")),
                mode=file_item.get("mode", mode),
                project_root=file_item.get("project_root", project_root),
                language=file_item.get("language"),
                artifact_type=file_item.get("artifact_type", CodeArtifactType.FILE),
                encoding=str(file_item.get("encoding", "utf-8")),
                create_parent_dirs=bool(file_item.get("create_parent_dirs", True)),
                backup_existing=bool(file_item.get("backup_existing", True)),
                validate_syntax=bool(file_item.get("validate_syntax", True)),
                format_content=bool(file_item.get("format_content", True)),
                dry_run=bool(file_item.get("dry_run", dry_run)),
                metadata=dict(file_item.get("metadata", {})),
            )

            results.append(item_result)

            if item_result.get("success"):
                success_count += 1
            else:
                failure_count += 1

        batch_success = failure_count == 0

        result = self._safe_result(
            message=(
                "All files processed successfully."
                if batch_success
                else "Batch completed with one or more failures."
            ),
            data={
                "total_files": len(files),
                "success_count": success_count,
                "failure_count": failure_count,
                "results": results,
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "dry_run": dry_run,
                "created_at": _utc_now_iso(),
            },
        )

        if not batch_success:
            result["success"] = False
            result["error"] = "batch_partial_failure"

        self._emit_agent_event(
            {
                "event": "code_writer.batch_completed",
                "user_id": user_id,
                "workspace_id": workspace_id,
                "success_count": success_count,
                "failure_count": failure_count,
            }
        )

        return result

    def preview_file_write(
        self,
        user_id: str,
        workspace_id: str,
        target_path: Union[str, Path],
        content: str,
        project_root: Optional[Union[str, Path]] = None,
        mode: Union[str, FileWriteMode] = FileWriteMode.CREATE_ONLY,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Preview a file write without changing disk state."""

        return self.write_file(
            user_id=user_id,
            workspace_id=workspace_id,
            target_path=target_path,
            content=content,
            mode=mode,
            project_root=project_root,
            dry_run=True,
            metadata=metadata or {},
        )

    # ---------------------------------------------------------------------
    # Public generation methods
    # ---------------------------------------------------------------------

    def generate_from_spec(
        self,
        spec: GeneratedCodeSpec,
        mode: Union[str, FileWriteMode] = FileWriteMode.CREATE_ONLY,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """
        Generate a code file from a structured GeneratedCodeSpec.

        This is intentionally conservative and produces clean starter code
        rather than fake business logic.
        """

        try:
            content_result = self._generate_content_from_spec(spec)
            if not content_result["success"]:
                return content_result

            return self.write_file(
                user_id=spec.user_id,
                workspace_id=spec.workspace_id,
                target_path=spec.target_path,
                content=content_result["data"]["content"],
                mode=mode,
                project_root=spec.project_root,
                language=spec.language,
                artifact_type=spec.artifact_type,
                dry_run=dry_run,
                metadata=spec.metadata,
            )

        except Exception as exc:
            self.logger.exception("generate_from_spec failed.")
            return self._error_result(
                message="Failed to generate code from spec.",
                error=str(exc),
                metadata={
                    "user_id": spec.user_id,
                    "workspace_id": spec.workspace_id,
                    "target_path": str(spec.target_path),
                },
            )

    def generate_python_class_file(
        self,
        user_id: str,
        workspace_id: str,
        target_path: Union[str, Path],
        class_name: str,
        description: str = "",
        project_root: Optional[Union[str, Path]] = None,
        imports: Optional[List[str]] = None,
        methods: Optional[List[str]] = None,
        mode: Union[str, FileWriteMode] = FileWriteMode.CREATE_ONLY,
        dry_run: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Generate and write a Python class file."""

        spec = GeneratedCodeSpec(
            user_id=user_id,
            workspace_id=workspace_id,
            target_path=target_path,
            name=class_name,
            artifact_type=CodeArtifactType.CLASS,
            language=CodeLanguage.PYTHON,
            description=description,
            imports=imports or [],
            class_name=class_name,
            methods=methods or [],
            project_root=project_root,
            metadata=metadata or {},
        )

        return self.generate_from_spec(spec=spec, mode=mode, dry_run=dry_run)

    def generate_python_function_file(
        self,
        user_id: str,
        workspace_id: str,
        target_path: Union[str, Path],
        function_name: str,
        description: str = "",
        project_root: Optional[Union[str, Path]] = None,
        imports: Optional[List[str]] = None,
        mode: Union[str, FileWriteMode] = FileWriteMode.CREATE_ONLY,
        dry_run: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Generate and write a Python function file."""

        spec = GeneratedCodeSpec(
            user_id=user_id,
            workspace_id=workspace_id,
            target_path=target_path,
            name=function_name,
            artifact_type=CodeArtifactType.FUNCTION,
            language=CodeLanguage.PYTHON,
            description=description,
            imports=imports or [],
            function_names=[function_name],
            project_root=project_root,
            metadata=metadata or {},
        )

        return self.generate_from_spec(spec=spec, mode=mode, dry_run=dry_run)

    # ---------------------------------------------------------------------
    # Validation methods
    # ---------------------------------------------------------------------

    def validate_code_content(
        self,
        content: str,
        language: Union[str, CodeLanguage] = CodeLanguage.UNKNOWN,
        target_path: Optional[Union[str, Path]] = None,
    ) -> Dict[str, Any]:
        """
        Validate generated code content.

        Python:
            Uses ast.parse.

        JSON:
            Uses json.loads.

        YAML:
            Uses PyYAML if available.

        Other file types:
            Basic content safety validation only.
        """

        try:
            resolved_language = self._normalize_language(language, target_path)

            if not isinstance(content, str):
                return self._error_result(
                    message="Code content must be a string.",
                    error="invalid_content_type",
                )

            safety_result = self._validate_content_safety(content)
            if not safety_result["success"]:
                return safety_result

            if resolved_language == CodeLanguage.PYTHON:
                try:
                    ast.parse(content)
                except SyntaxError as exc:
                    return self._error_result(
                        message="Python syntax validation failed.",
                        error="python_syntax_error",
                        data={
                            "line": exc.lineno,
                            "offset": exc.offset,
                            "text": exc.text,
                            "detail": str(exc),
                        },
                    )

            elif resolved_language == CodeLanguage.JSON:
                try:
                    json.loads(content)
                except json.JSONDecodeError as exc:
                    return self._error_result(
                        message="JSON validation failed.",
                        error="json_decode_error",
                        data={
                            "line": exc.lineno,
                            "column": exc.colno,
                            "detail": str(exc),
                        },
                    )

            elif resolved_language == CodeLanguage.YAML:
                try:
                    import yaml  # type: ignore

                    yaml.safe_load(content)
                except ImportError:
                    return self._safe_result(
                        message="YAML syntax skipped because PyYAML is not installed.",
                        data={
                            "language": resolved_language.value,
                            "syntax_checked": False,
                        },
                    )
                except Exception as exc:
                    return self._error_result(
                        message="YAML validation failed.",
                        error="yaml_validation_error",
                        data={"detail": str(exc)},
                    )

            return self._safe_result(
                message="Code content validation passed.",
                data={
                    "language": resolved_language.value,
                    "syntax_checked": resolved_language.value
                    in {"python", "json", "yaml"},
                    "line_count": len(content.splitlines()),
                    "content_hash": _sha256_text(content),
                },
            )

        except Exception as exc:
            self.logger.exception("validate_code_content failed.")
            return self._error_result(
                message="Code validation failed unexpectedly.",
                error=str(exc),
            )

    # ---------------------------------------------------------------------
    # Required compatibility hooks
    # ---------------------------------------------------------------------

    def _validate_task_context(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Validate SaaS isolation context.

        user_id and workspace_id are required to prevent mixing generated files,
        logs, memory, analytics, and audit data between users/workspaces.
        """

        user_id = str(task.get("user_id", "")).strip()
        workspace_id = str(task.get("workspace_id", "")).strip()

        if not user_id:
            return self._error_result(
                message="user_id is required for CodeWriter execution.",
                error="missing_user_id",
            )

        if not workspace_id:
            return self._error_result(
                message="workspace_id is required for CodeWriter execution.",
                error="missing_workspace_id",
            )

        if len(user_id) > 128 or len(workspace_id) > 128:
            return self._error_result(
                message="user_id and workspace_id must be 128 characters or fewer.",
                error="invalid_context_length",
            )

        if not re.match(r"^[a-zA-Z0-9_\-:.@]+$", user_id):
            return self._error_result(
                message="user_id contains invalid characters.",
                error="invalid_user_id",
            )

        if not re.match(r"^[a-zA-Z0-9_\-:.@]+$", workspace_id):
            return self._error_result(
                message="workspace_id contains invalid characters.",
                error="invalid_workspace_id",
            )

        return self._safe_result(
            message="Task context validated.",
            data={
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )

    def _requires_security_check(self, operation: Mapping[str, Any]) -> bool:
        """
        Decide whether Security Agent approval is required.

        File-writing actions are sensitive by default because they can change
        project behavior. Dry-run validation is less risky but still checked
        for dangerous paths.
        """

        action = str(operation.get("action", ""))
        target_path = str(operation.get("target_path", ""))
        dry_run = bool(operation.get("dry_run", False))

        sensitive_actions = {
            "write_file",
            "write_multiple_files",
            "overwrite_file",
            "append_file",
            "dry_run_write_file",
        }

        dangerous_path_indicators = [
            "/etc/",
            "/bin/",
            "/sbin/",
            "/usr/bin/",
            "/usr/sbin/",
            "C:\\Windows",
            "System32",
            ".ssh",
            "authorized_keys",
            "id_rsa",
            "id_ed25519",
            "..",
        ]

        if action in sensitive_actions:
            return True

        if dry_run and any(indicator in target_path for indicator in dangerous_path_indicators):
            return True

        return False

    def _request_security_approval(self, operation: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Request approval from Security Agent.

        Supports several possible SecurityAgent interfaces:
            - approve_action(payload)
            - validate_action(payload)
            - run(payload)
        """

        sanitized_operation = _redact_sensitive_values(operation)

        try:
            if hasattr(self.security_agent, "approve_action"):
                response = self.security_agent.approve_action(sanitized_operation)
            elif hasattr(self.security_agent, "validate_action"):
                response = self.security_agent.validate_action(sanitized_operation)
            elif hasattr(self.security_agent, "run"):
                response = self.security_agent.run(
                    {
                        "action": "approve_code_writer_action",
                        "payload": sanitized_operation,
                    }
                )
            else:
                return self._error_result(
                    message="Security Agent does not expose an approval interface.",
                    error="security_agent_interface_missing",
                )

            if not isinstance(response, Mapping):
                return self._error_result(
                    message="Security Agent returned invalid response.",
                    error="invalid_security_response",
                    data={"response": str(response)},
                )

            approved = bool(
                response.get("approved")
                or response.get("success") is True
                and response.get("error") in {None, ""}
            )

            if not approved:
                return self._error_result(
                    message=str(response.get("message", "Security approval denied.")),
                    error=str(response.get("error", "security_denied")),
                    data=dict(response),
                    metadata={
                        "security_checked": True,
                        "approved": False,
                    },
                )

            return self._safe_result(
                message="Security approval granted.",
                data=dict(response),
                metadata={
                    "security_checked": True,
                    "approved": True,
                },
            )

        except Exception as exc:
            self.logger.exception("Security approval failed.")
            return self._error_result(
                message="Security approval failed.",
                error=str(exc),
                metadata={
                    "security_checked": True,
                    "approved": False,
                },
            )

    def _prepare_verification_payload(
        self,
        request: CodeWriteRequest,
        result: Mapping[str, Any],
        resolved_path: Path,
        content: str,
        action: str,
    ) -> Dict[str, Any]:
        """
        Prepare payload for Verification Agent.

        The Verification Agent can later use this to verify file existence,
        syntax, hash, imports, tests, or dashboard status.
        """

        payload = {
            "agent": self.agent_name,
            "action": action,
            "user_id": request.user_id,
            "workspace_id": request.workspace_id,
            "target_path": str(resolved_path),
            "language": request.language.value,
            "artifact_type": request.artifact_type.value,
            "content_hash": _sha256_text(content),
            "line_count": len(content.splitlines()),
            "success": bool(result.get("success")),
            "created_at": _utc_now_iso(),
            "metadata": _redact_sensitive_values(request.metadata),
        }

        return self._safe_result(
            message="Verification payload prepared.",
            data=payload,
        )

    def _prepare_memory_payload(
        self,
        request: CodeWriteRequest,
        result: Mapping[str, Any],
        resolved_path: Path,
        content: str,
        action: str,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent payload.

        This contains user/workspace-isolated useful context, not full secrets.
        Full generated content is intentionally not stored by default to avoid
        memory bloat and accidental secret retention.
        """

        safe_excerpt = content[:1200]

        payload = {
            "agent": self.agent_name,
            "action": action,
            "user_id": request.user_id,
            "workspace_id": request.workspace_id,
            "target_path": str(resolved_path),
            "language": request.language.value,
            "artifact_type": request.artifact_type.value,
            "summary": f"Generated/wrote {request.artifact_type.value} file at {resolved_path}",
            "content_hash": _sha256_text(content),
            "line_count": len(content.splitlines()),
            "safe_excerpt": safe_excerpt,
            "metadata": _redact_sensitive_values(request.metadata),
            "created_at": _utc_now_iso(),
            "result_success": bool(result.get("success")),
        }

        return self._safe_result(
            message="Memory payload prepared.",
            data=payload,
        )

    def _emit_agent_event(self, event: Mapping[str, Any]) -> None:
        """
        Emit an event for Agent Registry, dashboard analytics, or event stream.

        If no event_emitter is provided, logs the event safely.
        """

        safe_event = _redact_sensitive_values(event)

        try:
            if self.event_emitter:
                self.event_emitter(safe_event)
            else:
                self.logger.info("Agent event: %s", _safe_json(safe_event))
        except Exception:
            self.logger.exception("Failed to emit agent event.")

    def _log_audit_event(self, event: Mapping[str, Any]) -> None:
        """
        Log an audit event.

        The future William/Jarvis dashboard can replace audit_logger with a
        database-backed function.
        """

        safe_event = _redact_sensitive_values(event)

        try:
            if self.audit_logger:
                self.audit_logger(safe_event)
            else:
                self.logger.info("Audit event: %s", _safe_json(safe_event))
        except Exception:
            self.logger.exception("Failed to log audit event.")

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard successful result."""

        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        message: str,
        error: Union[str, Exception],
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard error result."""

        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": str(error),
            "metadata": metadata or {},
        }

    # ---------------------------------------------------------------------
    # Internal helpers
    # ---------------------------------------------------------------------

    def _post_success_hooks(
        self,
        request: CodeWriteRequest,
        result: Mapping[str, Any],
        resolved_path: Path,
        content: str,
        action: str,
    ) -> None:
        """Run verification, memory, event, and audit hooks after success."""

        verification_payload = self._prepare_verification_payload(
            request=request,
            result=result,
            resolved_path=resolved_path,
            content=content,
            action=action,
        )

        memory_payload = self._prepare_memory_payload(
            request=request,
            result=result,
            resolved_path=resolved_path,
            content=content,
            action=action,
        )

        event_payload = {
            "event": "code_writer.file_processed",
            "agent": self.agent_name,
            "action": action,
            "user_id": request.user_id,
            "workspace_id": request.workspace_id,
            "target_path": str(resolved_path),
            "language": request.language.value,
            "artifact_type": request.artifact_type.value,
            "success": bool(result.get("success")),
            "dry_run": request.dry_run,
            "created_at": _utc_now_iso(),
        }

        audit_payload = {
            "audit_type": "code_writer_file_operation",
            "agent": self.agent_name,
            "action": action,
            "user_id": request.user_id,
            "workspace_id": request.workspace_id,
            "target_path": str(resolved_path),
            "mode": request.mode.value,
            "content_hash": _sha256_text(content),
            "success": bool(result.get("success")),
            "created_at": _utc_now_iso(),
            "metadata": _redact_sensitive_values(request.metadata),
        }

        self._emit_agent_event(event_payload)
        self._log_audit_event(audit_payload)

        try:
            if hasattr(self.verification_agent, "prepare_payload"):
                self.verification_agent.prepare_payload(verification_payload["data"])
            elif hasattr(self.verification_agent, "run"):
                self.verification_agent.run(
                    {
                        "action": "verify_code_writer_output",
                        "payload": verification_payload["data"],
                    }
                )
        except Exception:
            self.logger.exception("Verification Agent hook failed.")

        try:
            if hasattr(self.memory_agent, "prepare_payload"):
                self.memory_agent.prepare_payload(memory_payload["data"])
            elif hasattr(self.memory_agent, "run"):
                self.memory_agent.run(
                    {
                        "action": "store_code_writer_context",
                        "payload": memory_payload["data"],
                    }
                )
        except Exception:
            self.logger.exception("Memory Agent hook failed.")

    def _resolve_and_validate_path(
        self,
        target_path: Union[str, Path],
        project_root: Optional[Union[str, Path]] = None,
    ) -> Dict[str, Any]:
        """Resolve target path safely and ensure it stays inside project root."""

        try:
            if not str(target_path).strip():
                return self._error_result(
                    message="target_path is required.",
                    error="missing_target_path",
                )

            raw_target = Path(str(target_path)).expanduser()

            selected_project_root = (
                Path(project_root).expanduser().resolve()
                if project_root
                else self.default_project_root
            )

            if selected_project_root is None:
                if raw_target.is_absolute():
                    selected_project_root = raw_target.parent.resolve()
                    resolved_path = raw_target.resolve()
                else:
                    selected_project_root = Path.cwd().resolve()
                    resolved_path = (selected_project_root / raw_target).resolve()
            else:
                selected_project_root = selected_project_root.resolve()
                resolved_path = (
                    raw_target.resolve()
                    if raw_target.is_absolute()
                    else (selected_project_root / raw_target).resolve()
                )

            try:
                resolved_path.relative_to(selected_project_root)
            except ValueError:
                return self._error_result(
                    message="Target path must stay inside project_root.",
                    error="path_outside_project_root",
                    data={
                        "target_path": str(resolved_path),
                        "project_root": str(selected_project_root),
                    },
                )

            path_parts = set(resolved_path.parts)
            blocked_parts = path_parts.intersection(self.DEFAULT_BLOCKED_PATH_PARTS)
            if blocked_parts:
                return self._error_result(
                    message="Target path contains blocked directory or file segment.",
                    error="blocked_path_segment",
                    data={"blocked_parts": sorted(blocked_parts)},
                )

            if resolved_path.name in self.DEFAULT_BLOCKED_FILENAMES:
                return self._error_result(
                    message="Target filename is blocked for safety.",
                    error="blocked_filename",
                    data={"filename": resolved_path.name},
                )

            extension_allowed = self._is_extension_allowed(resolved_path)
            if not extension_allowed:
                return self._error_result(
                    message="Target file extension is not allowed.",
                    error="extension_not_allowed",
                    data={
                        "target_path": str(resolved_path),
                        "suffix": resolved_path.suffix,
                    },
                )

            return self._safe_result(
                message="Target path validated.",
                data={
                    "resolved_path": str(resolved_path),
                    "project_root": str(selected_project_root),
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Path validation failed.",
                error=str(exc),
                data={"target_path": str(target_path)},
            )

    def _is_extension_allowed(self, path: Path) -> bool:
        """Check if file extension is allowed."""

        name_lower = path.name.lower()
        suffix = path.suffix.lower()

        if name_lower in {
            "dockerfile",
            "makefile",
            "readme",
            "license",
            ".gitignore",
            ".editorconfig",
        }:
            return True

        if name_lower.endswith(".env.example"):
            return True

        if suffix in self.DEFAULT_ALLOWED_EXTENSIONS:
            return True

        return self.allow_unknown_extensions

    def _prepare_content(
        self,
        content: str,
        language: CodeLanguage,
        format_content: bool = True,
    ) -> str:
        """Normalize and lightly format content without requiring heavy dependencies."""

        prepared = _normalize_newlines(str(content))

        if format_content:
            prepared = prepared.rstrip() + "\n"
        else:
            prepared = _ensure_trailing_newline(prepared)

        if language == CodeLanguage.PYTHON:
            prepared = self._light_format_python(prepared)

        return prepared

    def _light_format_python(self, content: str) -> str:
        """
        Lightweight Python cleanup.

        This avoids external formatters like black so the file remains dependency-light.
        """

        lines = content.splitlines()
        cleaned_lines: List[str] = []

        for line in lines:
            cleaned_lines.append(line.rstrip())

        return "\n".join(cleaned_lines).rstrip() + "\n"

    def _validate_content_safety(self, content: str) -> Dict[str, Any]:
        """
        Basic content safety checks.

        This does not replace Security Agent review. It catches obvious generated
        code mistakes such as embedded private keys or destructive auto-execution.
        """

        private_key_markers = [
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----",
        ]

        for marker in private_key_markers:
            if marker in content:
                return self._error_result(
                    message="Content appears to include a private key.",
                    error="private_key_detected",
                )

        risky_patterns = [
            r"rm\s+-rf\s+/",
            r"format\s+C:",
            r"del\s+/f\s+/s\s+/q\s+C:\\",
            r"mkfs\.",
        ]

        for pattern in risky_patterns:
            if re.search(pattern, content, flags=re.IGNORECASE):
                return self._error_result(
                    message="Content includes an obviously destructive command pattern.",
                    error="destructive_pattern_detected",
                    data={"pattern": pattern},
                )

        return self._safe_result(message="Content safety validation passed.")

    def _validate_write_mode_against_path(
        self,
        mode: FileWriteMode,
        resolved_path: Path,
    ) -> Dict[str, Any]:
        """Validate mode behavior against existing file state."""

        exists = resolved_path.exists()

        if mode == FileWriteMode.CREATE_ONLY and exists:
            return self._error_result(
                message="File already exists and mode is create_only.",
                error="file_exists",
                data={"target_path": str(resolved_path)},
            )

        if mode == FileWriteMode.APPEND and not exists:
            return self._error_result(
                message="File does not exist and mode is append.",
                error="file_missing_for_append",
                data={"target_path": str(resolved_path)},
            )

        return self._safe_result(
            message="Write mode validated.",
            data={"exists": exists, "mode": mode.value},
        )

    def _build_operation_plan(
        self,
        request: CodeWriteRequest,
        resolved_path: Path,
        resolved_project_root: Path,
        prepared_content: str,
    ) -> Dict[str, Any]:
        """Build sanitized operation plan for Security Agent."""

        action = "write_file"
        if request.mode == FileWriteMode.OVERWRITE:
            action = "overwrite_file"
        elif request.mode == FileWriteMode.APPEND:
            action = "append_file"
        elif request.dry_run:
            action = "dry_run_write_file"

        return {
            "action": action,
            "user_id": request.user_id,
            "workspace_id": request.workspace_id,
            "target_path": str(resolved_path),
            "project_root": str(resolved_project_root),
            "language": request.language.value,
            "artifact_type": request.artifact_type.value,
            "mode": request.mode.value,
            "dry_run": request.dry_run,
            "create_parent_dirs": request.create_parent_dirs,
            "backup_existing": request.backup_existing,
            "content_hash": _sha256_text(prepared_content),
            "line_count": len(prepared_content.splitlines()),
            "byte_count": len(prepared_content.encode(request.encoding)),
            "metadata": _redact_sensitive_values(request.metadata),
        }

    def _atomic_write(
        self,
        path: Path,
        content: str,
        mode: FileWriteMode,
        encoding: str = "utf-8",
    ) -> Dict[str, Any]:
        """
        Write content safely.

        For overwrite/create/upsert:
            Uses temp file then os.replace.

        For append:
            Appends directly because replacing the file would require merging
            content first.
        """

        try:
            if mode == FileWriteMode.APPEND:
                with path.open("a", encoding=encoding) as file_obj:
                    file_obj.write(content)

                return self._safe_result(
                    message="Content appended successfully.",
                    data={"target_path": str(path)},
                )

            if mode in {
                FileWriteMode.CREATE_ONLY,
                FileWriteMode.OVERWRITE,
                FileWriteMode.UPSERT,
                FileWriteMode.DRY_RUN,
            }:
                temp_fd = None
                temp_path = None

                try:
                    temp_fd, temp_name = tempfile.mkstemp(
                        prefix=f".{path.name}.",
                        suffix=".tmp",
                        dir=str(path.parent),
                        text=True,
                    )
                    temp_path = Path(temp_name)

                    with os.fdopen(temp_fd, "w", encoding=encoding) as temp_file:
                        temp_fd = None
                        temp_file.write(content)

                    os.replace(str(temp_path), str(path))

                    return self._safe_result(
                        message="Content written atomically.",
                        data={"target_path": str(path)},
                    )

                finally:
                    if temp_fd is not None:
                        try:
                            os.close(temp_fd)
                        except Exception:
                            pass

                    if temp_path and temp_path.exists():
                        try:
                            temp_path.unlink()
                        except Exception:
                            pass

            return self._error_result(
                message=f"Unsupported write mode: {mode}",
                error="unsupported_write_mode",
            )

        except Exception as exc:
            self.logger.exception("Atomic write failed.")
            return self._error_result(
                message="Atomic file write failed.",
                error=str(exc),
                data={"target_path": str(path)},
            )

    def _create_backup(self, path: Path) -> Optional[Path]:
        """Create timestamped backup of existing file."""

        if not path.exists() or not path.is_file():
            return None

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        backup_path = path.with_name(f"{path.name}.bak.{timestamp}")

        shutil.copy2(path, backup_path)
        return backup_path

    def _build_preview(
        self,
        target_path: Path,
        new_content: str,
        mode: FileWriteMode,
        encoding: str = "utf-8",
    ) -> Dict[str, Any]:
        """Build preview diff for dry-run operations."""

        old_content = ""

        if target_path.exists() and target_path.is_file():
            try:
                old_content = target_path.read_text(encoding=encoding)
            except UnicodeDecodeError:
                old_content = ""

        if mode == FileWriteMode.APPEND:
            preview_new_content = old_content + new_content
        else:
            preview_new_content = new_content

        diff = "\n".join(
            difflib.unified_diff(
                old_content.splitlines(),
                preview_new_content.splitlines(),
                fromfile=f"{target_path} (current)",
                tofile=f"{target_path} (new)",
                lineterm="",
            )
        )

        return {
            "target_exists": target_path.exists(),
            "mode": mode.value,
            "old_hash": _sha256_text(old_content) if old_content else None,
            "new_hash": _sha256_text(preview_new_content),
            "old_line_count": len(old_content.splitlines()),
            "new_line_count": len(preview_new_content.splitlines()),
            "diff": diff,
        }

    # ---------------------------------------------------------------------
    # Code generation internals
    # ---------------------------------------------------------------------

    def _generate_content_from_spec(self, spec: GeneratedCodeSpec) -> Dict[str, Any]:
        """Generate file content from a structured spec."""

        if spec.language == CodeLanguage.PYTHON:
            if spec.artifact_type == CodeArtifactType.CLASS:
                return self._safe_result(
                    message="Python class content generated.",
                    data={"content": self._generate_python_class_content(spec)},
                )

            if spec.artifact_type == CodeArtifactType.FUNCTION:
                return self._safe_result(
                    message="Python function content generated.",
                    data={"content": self._generate_python_function_content(spec)},
                )

            if spec.artifact_type == CodeArtifactType.MODULE:
                return self._safe_result(
                    message="Python module content generated.",
                    data={"content": self._generate_python_module_content(spec)},
                )

            return self._safe_result(
                message="Generic Python file content generated.",
                data={"content": self._generate_python_module_content(spec)},
            )

        if spec.language == CodeLanguage.JSON:
            return self._safe_result(
                message="JSON content generated.",
                data={
                    "content": json.dumps(
                        {
                            "name": spec.name,
                            "description": spec.description,
                            "artifact_type": spec.artifact_type.value,
                            "dependencies": spec.dependencies,
                            "metadata": spec.metadata,
                        },
                        indent=2,
                    )
                    + "\n"
                },
            )

        if spec.language == CodeLanguage.MARKDOWN:
            title = spec.name.replace("_", " ").replace("-", " ").title()
            content = f"# {title}\n\n{spec.description or 'Generated documentation file.'}\n"
            return self._safe_result(
                message="Markdown content generated.",
                data={"content": content},
            )

        return self._safe_result(
            message="Generic text content generated.",
            data={
                "content": (
                    f"{spec.name}\n"
                    f"{'=' * len(spec.name)}\n\n"
                    f"{spec.description or 'Generated file.'}\n"
                )
            },
        )

    def _generate_python_class_content(self, spec: GeneratedCodeSpec) -> str:
        """Generate clean Python class file content."""

        class_name = self._safe_python_identifier(
            spec.class_name or spec.name,
            default="GeneratedClass",
            class_name=True,
        )

        description = spec.description or f"{class_name} generated by CodeWriter."

        imports = self._render_python_imports(spec.imports)

        method_blocks = []
        for method_name in spec.methods:
            safe_method = self._safe_python_identifier(method_name, default="run")
            method_blocks.append(
                f"""    def {safe_method}(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        \"\"\"Execute {safe_method}.\"\"\"

        return {{
            "success": True,
            "message": "{safe_method} executed successfully.",
            "data": {{
                "args_count": len(args),
                "kwargs_keys": list(kwargs.keys()),
            }},
            "error": None,
            "metadata": {{}},
        }}
"""
            )

        if not method_blocks:
            method_blocks.append(
                """    def run(self, payload: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        \"\"\"Run the generated class with a structured payload.\"\"\"

        payload = dict(payload or {})

        return {
            "success": True,
            "message": "Run completed successfully.",
            "data": payload,
            "error": None,
            "metadata": {},
        }
"""
            )

        content = f'''"""
{description}

Generated by William/Jarvis CodeWriter.
"""

from __future__ import annotations

{imports}
from typing import Any, Dict, Mapping, Optional


class {class_name}:
    """
    {description}

    This class is generated as production-safe starter code and returns
    structured dict results compatible with William/Jarvis agents.
    """

    def __init__(self) -> None:
        self.name = "{class_name}"

{chr(10).join(method_blocks)}
'''

        return content

    def _generate_python_function_content(self, spec: GeneratedCodeSpec) -> str:
        """Generate clean Python function file content."""

        function_name = self._safe_python_identifier(
            spec.function_names[0] if spec.function_names else spec.name,
            default="generated_function",
        )

        description = spec.description or f"{function_name} generated by CodeWriter."
        imports = self._render_python_imports(spec.imports)

        content = f'''"""
{description}

Generated by William/Jarvis CodeWriter.
"""

from __future__ import annotations

{imports}
from typing import Any, Dict, Mapping, Optional


def {function_name}(payload: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """
    Execute {function_name} with a structured payload.

    Args:
        payload: Optional mapping containing input data.

    Returns:
        Structured result dictionary.
    """

    data = dict(payload or {{}})

    return {{
        "success": True,
        "message": "{function_name} executed successfully.",
        "data": data,
        "error": None,
        "metadata": {{}},
    }}
'''

        return content

    def _generate_python_module_content(self, spec: GeneratedCodeSpec) -> str:
        """Generate generic Python module content."""

        description = spec.description or f"{spec.name} generated by CodeWriter."
        imports = self._render_python_imports(spec.imports)

        content = f'''"""
{description}

Generated by William/Jarvis CodeWriter.
"""

from __future__ import annotations

{imports}
from typing import Any, Dict, Mapping, Optional


MODULE_NAME = "{spec.name}"


def run(payload: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """
    Module entrypoint compatible with William/Jarvis routing.

    Args:
        payload: Optional mapping containing task data.

    Returns:
        Structured result dictionary.
    """

    data = dict(payload or {{}})

    return {{
        "success": True,
        "message": f"{{MODULE_NAME}} completed successfully.",
        "data": data,
        "error": None,
        "metadata": {{
            "module": MODULE_NAME,
        }},
    }}
'''

        return content

    def _render_python_imports(self, imports: Iterable[str]) -> str:
        """Render safe Python imports."""

        safe_imports: List[str] = []

        for import_line in imports:
            line = str(import_line).strip()

            if not line:
                continue

            if line.startswith("import ") or line.startswith("from "):
                if ";" in line or "__import__" in line or "eval(" in line or "exec(" in line:
                    continue
                safe_imports.append(line)

        if not safe_imports:
            return ""

        return "\n".join(dict.fromkeys(safe_imports)) + "\n"

    def _safe_python_identifier(
        self,
        value: str,
        default: str,
        class_name: bool = False,
    ) -> str:
        """Convert arbitrary text into a safe Python identifier."""

        cleaned = re.sub(r"[^0-9a-zA-Z_]", "_", str(value).strip())
        cleaned = re.sub(r"_+", "_", cleaned).strip("_")

        if not cleaned:
            cleaned = default

        if cleaned[0].isdigit():
            cleaned = f"_{cleaned}"

        if class_name:
            cleaned = "".join(part.capitalize() for part in cleaned.split("_") if part)
            if not cleaned:
                cleaned = default

        return cleaned

    # ---------------------------------------------------------------------
    # Normalization helpers
    # ---------------------------------------------------------------------

    def _normalize_write_mode(self, mode: Union[str, FileWriteMode]) -> FileWriteMode:
        """Normalize write mode."""

        if isinstance(mode, FileWriteMode):
            return mode

        try:
            return FileWriteMode(str(mode))
        except Exception:
            return FileWriteMode.CREATE_ONLY

    def _normalize_language(
        self,
        language: Optional[Union[str, CodeLanguage]],
        target_path: Optional[Union[str, Path]] = None,
    ) -> CodeLanguage:
        """Normalize language from explicit value or target path."""

        if isinstance(language, CodeLanguage):
            if language != CodeLanguage.UNKNOWN:
                return language

        if language:
            try:
                parsed = CodeLanguage(str(language).lower())
                if parsed != CodeLanguage.UNKNOWN:
                    return parsed
            except Exception:
                pass

        if target_path:
            return _guess_language_from_path(target_path)

        return CodeLanguage.UNKNOWN

    def _normalize_artifact_type(
        self,
        artifact_type: Union[str, CodeArtifactType],
    ) -> CodeArtifactType:
        """Normalize artifact type."""

        if isinstance(artifact_type, CodeArtifactType):
            return artifact_type

        try:
            return CodeArtifactType(str(artifact_type))
        except Exception:
            return CodeArtifactType.FILE

    def _spec_from_task(self, task: Mapping[str, Any]) -> GeneratedCodeSpec:
        """Build GeneratedCodeSpec from task mapping."""

        return GeneratedCodeSpec(
            user_id=str(task["user_id"]),
            workspace_id=str(task["workspace_id"]),
            target_path=task["target_path"],
            name=str(task.get("name") or task.get("class_name") or task.get("function_name") or "generated_file"),
            artifact_type=self._normalize_artifact_type(
                task.get("artifact_type", CodeArtifactType.FILE)
            ),
            language=self._normalize_language(
                task.get("language", CodeLanguage.PYTHON),
                task.get("target_path"),
            ),
            description=str(task.get("description", "")),
            imports=list(task.get("imports", [])),
            class_name=task.get("class_name"),
            function_names=list(task.get("function_names", [])),
            methods=list(task.get("methods", [])),
            dependencies=list(task.get("dependencies", [])),
            project_root=task.get("project_root"),
            metadata=dict(task.get("metadata", {})),
        )

    # ---------------------------------------------------------------------
    # Export helpers
    # ---------------------------------------------------------------------

    def to_registry_manifest(self) -> Dict[str, Any]:
        """
        Return lightweight registry manifest.

        Agent Registry can use this for discovery.
        """

        return {
            "agent_name": self.agent_name,
            "agent_type": self.agent_type,
            "version": self.version,
            "class_name": self.__class__.__name__,
            "capabilities": [
                "write_file",
                "write_multiple_files",
                "preview_file_write",
                "generate_from_spec",
                "generate_python_class_file",
                "generate_python_function_file",
                "validate_code_content",
            ],
            "requires_context": ["user_id", "workspace_id"],
            "security_required": True,
            "supports_memory_payload": True,
            "supports_verification_payload": True,
            "import_path": "agents.code_agent.code_writer.CodeWriter",
        }


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------

def create_code_writer(
    default_project_root: Optional[Union[str, Path]] = None,
    security_agent: Optional[Any] = None,
    verification_agent: Optional[Any] = None,
    memory_agent: Optional[Any] = None,
) -> CodeWriter:
    """
    Factory helper for Agent Loader / Registry.

    Example:
        writer = create_code_writer(default_project_root="/app/project")
    """

    return CodeWriter(
        default_project_root=default_project_root,
        security_agent=security_agent,
        verification_agent=verification_agent,
        memory_agent=memory_agent,
    )


__all__ = [
    "CodeWriter",
    "CodeWriteRequest",
    "CodeWriteResult",
    "GeneratedCodeSpec",
    "CodeLanguage",
    "FileWriteMode",
    "CodeArtifactType",
    "create_code_writer",
]