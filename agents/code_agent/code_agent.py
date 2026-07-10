"""
William / Jarvis Multi-Agent AI SaaS System - Code Agent

File: agents/code_agent/code_agent.py
Purpose:
    Builder AI for project creation, code writing/editing, command running,
    debugging, testing, and deployment support.

This module is intentionally import-safe. It can run before the full William/Jarvis
platform exists because it includes defensive optional imports and fallback stubs.

Architecture compatibility:
    - Master Agent can route code/build/debug/deploy tasks here through `run()` or
      the explicit public methods.
    - Security Agent can approve sensitive operations before file writes, commands,
      tests, git, CI/CD, or deployment actions are executed.
    - Memory Agent can store useful coding context, summaries, task history, and
      generated artifacts through `_prepare_memory_payload()`.
    - Verification Agent can validate completion payloads through
      `_prepare_verification_payload()`.
    - Dashboard/API layers can consume the structured result dictionaries returned
      by every public method.

Safety notes:
    - This file does not perform destructive actions by default.
    - File writes, shell commands, tests, git, dependency installation, and deploy
      actions are permission-gated.
    - SaaS user/workspace isolation is enforced through required `user_id` and
      `workspace_id` task context for user-specific execution.
"""

from __future__ import annotations

import ast
import difflib
import hashlib
import json
import logging
import os
import re
import shlex
import subprocess
import sys
import time
import traceback
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Union


try:  # Real William/Jarvis import when available.
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # Import-safe fallback.
    class BaseAgent:  # type: ignore
        """Fallback BaseAgent so this file can import before the full system exists."""

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_type = kwargs.get("agent_type", "code")
            self.logger = logging.getLogger(self.agent_name)

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback event emitted: %s | %s", event_name, payload)

        def log_audit(self, event_name: str, payload: Dict[str, Any]) -> None:
            self.logger.info("Fallback audit event: %s | %s", event_name, payload)


try:
    from core.security import SecurityDecision  # type: ignore
except Exception:
    @dataclass
    class SecurityDecision:  # type: ignore
        approved: bool = False
        reason: str = "Security Agent unavailable; default-deny for sensitive action."
        metadata: Dict[str, Any] = field(default_factory=dict)


MODULE_NAME = "CodeAgent"
DEFAULT_MAX_FILE_BYTES = 2_000_000
DEFAULT_COMMAND_TIMEOUT_SECONDS = 60
DEFAULT_ALLOWED_EXTENSIONS = {
    ".py", ".txt", ".md", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg",
    ".env.example", ".html", ".css", ".js", ".ts", ".tsx", ".jsx", ".vue",
    ".sql", ".sh", ".bat", ".ps1", ".dockerfile", ".gitignore", ".example",
    ".xml", ".csv", ".lock", ".java", ".kt", ".swift", ".go", ".rs", ".php",
    ".rb", ".c", ".cpp", ".h", ".hpp", ".cs", ".dart",
}
DEFAULT_DENIED_PATH_PARTS = {
    ".ssh", ".aws", ".gcloud", ".azure", ".kube", "id_rsa", "id_dsa",
    "private_key", "secrets", "credentials",
}
DANGEROUS_COMMAND_PATTERNS = [
    r"\brm\s+-rf\b",
    r"\bdel\s+/f\b",
    r"\bformat\b",
    r"\bdd\b",
    r"\bmkfs\b",
    r"\bshutdown\b",
    r"\breboot\b",
    r"\bpoweroff\b",
    r":\(\)\s*\{",
    r"\bchmod\s+777\b",
    r"\bchown\s+-R\b",
]
SECRET_KEY_PATTERNS = [
    r"(?i)\b(api[_-]?key|secret|token|password|passwd|private[_-]?key)\b\s*[:=]\s*['\"][^'\"]{8,}['\"]",
    r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
    r"(?i)\bAKIA[0-9A-Z]{16}\b",
]


@dataclass
class CodeTaskContext:
    """Validated SaaS execution context for user/workspace-scoped tasks."""

    user_id: str
    workspace_id: str
    role: str = "user"
    subscription: str = "free"
    request_id: Optional[str] = None
    task_id: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, context: Mapping[str, Any]) -> "CodeTaskContext":
        user_id = str(context.get("user_id", "")).strip()
        workspace_id = str(context.get("workspace_id", "")).strip()
        if not user_id:
            raise ValueError("user_id is required for CodeAgent task execution.")
        if not workspace_id:
            raise ValueError("workspace_id is required for CodeAgent task execution.")

        permissions_raw = context.get("permissions", [])
        if isinstance(permissions_raw, str):
            permissions = [permissions_raw]
        elif isinstance(permissions_raw, Iterable):
            permissions = [str(item) for item in permissions_raw]
        else:
            permissions = []

        return cls(
            user_id=user_id,
            workspace_id=workspace_id,
            role=str(context.get("role", "user")),
            subscription=str(context.get("subscription", "free")),
            request_id=context.get("request_id"),
            task_id=context.get("task_id"),
            permissions=permissions,
            metadata=dict(context.get("metadata", {}) or {}),
        )


@dataclass
class FileChange:
    """Represents a safe file write/edit operation."""

    path: str
    action: str
    before_hash: Optional[str] = None
    after_hash: Optional[str] = None
    bytes_written: int = 0
    diff_preview: Optional[str] = None


@dataclass
class CommandResult:
    """Structured shell command execution result."""

    command: str
    cwd: str
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False


@dataclass
class CodeAgentConfig:
    """Runtime configuration for CodeAgent safety and project operations."""

    workspace_root: Union[str, Path] = "."
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    command_timeout_seconds: int = DEFAULT_COMMAND_TIMEOUT_SECONDS
    allowed_extensions: set = field(default_factory=lambda: set(DEFAULT_ALLOWED_EXTENSIONS))
    denied_path_parts: set = field(default_factory=lambda: set(DEFAULT_DENIED_PATH_PARTS))
    dry_run_default: bool = True
    allow_shell: bool = False
    allow_file_writes: bool = True
    allow_dependency_install: bool = False
    allow_git_operations: bool = False
    allow_deploy_operations: bool = False
    enable_audit_log: bool = True
    enable_event_emit: bool = True


class CodeAgent(BaseAgent):
    """
    Production-level Code Agent for the William/Jarvis multi-agent system.

    Main capabilities:
        - Project structure planning and creation.
        - Safe code file generation and editing.
        - Project and code analysis.
        - Python/JSON syntax validation and simple security diagnostics.
        - Controlled command/test execution behind security gates.
        - Deployment and dependency workflows as permission-gated actions.
        - Structured payloads for Master, Security, Memory, Verification, Dashboard/API,
          and Agent Registry integrations.
    """

    agent_name = "code_agent"
    agent_type = "code"
    registry_name = "CodeAgent"
    version = "1.0.0"

    def __init__(
        self,
        config: Optional[Union[CodeAgentConfig, Mapping[str, Any]]] = None,
        security_client: Optional[Any] = None,
        memory_client: Optional[Any] = None,
        verification_client: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        logger: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name=self.agent_name, agent_type=self.agent_type, **kwargs)
        self.logger = logger or logging.getLogger(MODULE_NAME)

        if config is None:
            self.config = CodeAgentConfig()
        elif isinstance(config, CodeAgentConfig):
            self.config = config
        else:
            self.config = CodeAgentConfig(**dict(config))

        self.workspace_root = Path(self.config.workspace_root).expanduser().resolve()
        self.security_client = security_client
        self.memory_client = memory_client
        self.verification_client = verification_client
        self.event_bus = event_bus
        self.audit_logger = audit_logger
        self._task_history: List[Dict[str, Any]] = []

    def run(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """Master Agent compatible task router."""

        started = time.time()
        try:
            context = self._validate_task_context(task.get("context", {}))
            action = str(task.get("action", "")).strip().lower()
            payload = dict(task.get("payload", {}) or {})
            dry_run = bool(task.get("dry_run", self.config.dry_run_default))

            if not action:
                return self._error_result(
                    "Missing action for CodeAgent task.",
                    error_code="missing_action",
                    metadata={"duration_seconds": self._duration(started)},
                )

            self._emit_agent_event("code_agent.task.received", {
                "action": action,
                "context": asdict(context),
                "dry_run": dry_run,
            })

            route_map: Dict[str, Callable[..., Dict[str, Any]]] = {
                "create_project": self.create_project,
                "generate_file": self.generate_file,
                "write_file": self.generate_file,
                "edit_file": self.edit_file,
                "analyze_project": self.analyze_project,
                "analyze_code": self.analyze_code,
                "run_command": self.run_command,
                "run_tests": self.run_tests,
                "install_dependencies": self.install_dependencies,
                "deploy_project": self.deploy_project,
                "build_api_scaffold": self.build_api_scaffold,
                "build_frontend_scaffold": self.build_frontend_scaffold,
                "build_database_scaffold": self.build_database_scaffold,
                "write_documentation": self.write_documentation,
                "debug_error": self.debug_error,
                "plan_project": self.plan_project,
            }

            handler = route_map.get(action)
            if handler is None:
                return self._error_result(
                    f"Unsupported CodeAgent action: {action}",
                    error_code="unsupported_action",
                    metadata={"available_actions": sorted(route_map.keys())},
                )

            result = handler(context=context, dry_run=dry_run, **payload)
            self._record_task_history(action, context, result, started)
            return result

        except Exception as exc:
            self.logger.exception("CodeAgent run failed.")
            return self._error_result(
                "CodeAgent task failed.",
                error=str(exc),
                error_code="task_failed",
                metadata={
                    "duration_seconds": self._duration(started),
                    "traceback": traceback.format_exc(limit=5),
                },
            )

    def plan_project(
        self,
        project_name: str,
        project_type: str,
        requirements: Optional[Sequence[str]] = None,
        context: Optional[Union[CodeTaskContext, Mapping[str, Any]]] = None,
        dry_run: bool = True,
        **_: Any,
    ) -> Dict[str, Any]:
        """Create a structured project plan without writing files."""

        started = time.time()
        ctx = self._coerce_context(context)
        project_name = self._safe_name(project_name)
        project_type = str(project_type or "python").strip().lower()
        requirements = [str(item) for item in (requirements or [])]

        plan = {
            "project_name": project_name,
            "project_type": project_type,
            "requirements": requirements,
            "recommended_structure": self._default_project_structure(project_type),
            "security_notes": [
                "Keep secrets in environment variables, not committed files.",
                "Run command/deployment actions only after Security Agent approval.",
                "Maintain user_id/workspace_id isolation in generated services.",
            ],
            "next_steps": [
                "Create project scaffold.",
                "Generate core files.",
                "Run syntax checks/tests.",
                "Prepare documentation and deployment checklist.",
            ],
        }

        result = self._safe_result(
            "Project plan prepared.",
            data={"plan": plan, "dry_run": dry_run},
            metadata=self._standard_metadata(ctx, started, "plan_project"),
        )
        self._after_success("plan_project", ctx, result)
        return result

    def create_project(
        self,
        project_name: str,
        project_type: str = "python",
        files: Optional[Mapping[str, str]] = None,
        context: Optional[Union[CodeTaskContext, Mapping[str, Any]]] = None,
        dry_run: bool = True,
        overwrite: bool = False,
        **_: Any,
    ) -> Dict[str, Any]:
        """Create a project scaffold inside the configured workspace root."""

        started = time.time()
        ctx = self._coerce_context(context)
        project_name = self._safe_name(project_name)
        project_type = str(project_type or "python").strip().lower()
        relative_root = project_name
        project_root = self._resolve_safe_path(relative_root, must_be_file=False)
        scaffold_files = dict(files or self._default_project_files(project_name, project_type))
        planned_changes: List[FileChange] = []

        security = self._maybe_request_security(
            action="create_project",
            context=ctx,
            target=str(project_root),
            dry_run=dry_run,
            details={"project_type": project_type, "file_count": len(scaffold_files)},
        )
        if not security["approved"]:
            return security["result"]

        for rel_path, content in scaffold_files.items():
            full_path = self._resolve_safe_path(str(Path(relative_root) / rel_path), must_be_file=True)
            self._validate_file_write(full_path, content)
            old = full_path.read_text("utf-8", errors="replace") if full_path.exists() else ""
            planned_changes.append(FileChange(
                path=str(full_path),
                action="create" if not full_path.exists() else "overwrite" if overwrite else "skip",
                before_hash=self._hash_text(old) if old else None,
                after_hash=self._hash_text(content),
                bytes_written=len(content.encode("utf-8")),
                diff_preview=self._diff_preview(old, content),
            ))

        if not dry_run:
            project_root.mkdir(parents=True, exist_ok=True)
            for rel_path, content in scaffold_files.items():
                full_path = self._resolve_safe_path(str(Path(relative_root) / rel_path), must_be_file=True)
                if full_path.exists() and not overwrite:
                    continue
                full_path.parent.mkdir(parents=True, exist_ok=True)
                full_path.write_text(content, encoding="utf-8")

        result = self._safe_result(
            "Project scaffold planned." if dry_run else "Project scaffold created.",
            data={
                "project_root": str(project_root),
                "project_name": project_name,
                "project_type": project_type,
                "changes": [asdict(change) for change in planned_changes],
                "dry_run": dry_run,
            },
            metadata=self._standard_metadata(ctx, started, "create_project"),
        )
        self._after_success("create_project", ctx, result)
        return result

    def generate_file(
        self,
        file_path: str,
        content: str,
        context: Optional[Union[CodeTaskContext, Mapping[str, Any]]] = None,
        dry_run: bool = True,
        overwrite: bool = False,
        append: bool = False,
        **_: Any,
    ) -> Dict[str, Any]:
        """Generate or append a code/documentation file safely."""

        started = time.time()
        ctx = self._coerce_context(context)
        target = self._resolve_safe_path(file_path, must_be_file=True)
        content = str(content)

        if append and target.exists():
            old = target.read_text(encoding="utf-8", errors="replace")
            new_content = old + content
            action = "append"
        else:
            old = target.read_text(encoding="utf-8", errors="replace") if target.exists() else ""
            new_content = content
            action = "overwrite" if target.exists() else "create"

        if target.exists() and not overwrite and not append:
            return self._error_result(
                f"File already exists and overwrite=False: {target}",
                error_code="file_exists",
                metadata=self._standard_metadata(ctx, started, "generate_file"),
            )

        self._validate_file_write(target, new_content)
        secret_findings = self._scan_for_secret_patterns(new_content)
        security = self._maybe_request_security(
            action="generate_file",
            context=ctx,
            target=str(target),
            dry_run=dry_run,
            details={"action": action, "secret_findings": secret_findings},
        )
        if not security["approved"]:
            return security["result"]

        change = FileChange(
            path=str(target),
            action=action,
            before_hash=self._hash_text(old) if old else None,
            after_hash=self._hash_text(new_content),
            bytes_written=len(new_content.encode("utf-8")),
            diff_preview=self._diff_preview(old, new_content),
        )
        syntax = self._syntax_check_by_extension(target, new_content)

        if not dry_run:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(new_content, encoding="utf-8")

        result = self._safe_result(
            "File generation planned." if dry_run else "File generated successfully.",
            data={
                "file_path": str(target),
                "change": asdict(change),
                "syntax": syntax,
                "secret_findings": secret_findings,
                "dry_run": dry_run,
            },
            metadata=self._standard_metadata(ctx, started, "generate_file"),
        )
        self._after_success("generate_file", ctx, result)
        return result

    def edit_file(
        self,
        file_path: str,
        replacements: Optional[Sequence[Mapping[str, str]]] = None,
        new_content: Optional[str] = None,
        context: Optional[Union[CodeTaskContext, Mapping[str, Any]]] = None,
        dry_run: bool = True,
        create_if_missing: bool = False,
        **_: Any,
    ) -> Dict[str, Any]:
        """Edit a file through full replacement or old/new replacements."""

        started = time.time()
        ctx = self._coerce_context(context)
        target = self._resolve_safe_path(file_path, must_be_file=True)

        if not target.exists() and not create_if_missing:
            return self._error_result(
                f"File does not exist: {target}",
                error_code="file_not_found",
                metadata=self._standard_metadata(ctx, started, "edit_file"),
            )

        old_content = target.read_text(encoding="utf-8", errors="replace") if target.exists() else ""
        if new_content is not None:
            final_content = str(new_content)
            edit_summary = {"mode": "full_replace"}
        else:
            final_content = old_content
            applied: List[Dict[str, Any]] = []
            for item in replacements or []:
                old = str(item.get("old", ""))
                new = str(item.get("new", ""))
                try:
                    count = int(item.get("count", 1))
                except Exception:
                    count = 1
                if old == "":
                    applied.append({"old": old, "new": new, "applied": 0, "reason": "empty old pattern"})
                    continue
                before = final_content
                final_content = final_content.replace(old, new, count)
                applied_count = before.count(old) if count < 0 else min(before.count(old), count)
                applied.append({"old_preview": old[:120], "new_preview": new[:120], "applied": applied_count})
            edit_summary = {"mode": "replacements", "applied": applied}

        self._validate_file_write(target, final_content)
        secret_findings = self._scan_for_secret_patterns(final_content)
        security = self._maybe_request_security(
            action="edit_file",
            context=ctx,
            target=str(target),
            dry_run=dry_run,
            details={"edit_summary": edit_summary, "secret_findings": secret_findings},
        )
        if not security["approved"]:
            return security["result"]

        change = FileChange(
            path=str(target),
            action="edit" if target.exists() else "create",
            before_hash=self._hash_text(old_content) if old_content else None,
            after_hash=self._hash_text(final_content),
            bytes_written=len(final_content.encode("utf-8")),
            diff_preview=self._diff_preview(old_content, final_content),
        )
        syntax = self._syntax_check_by_extension(target, final_content)

        if not dry_run:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(final_content, encoding="utf-8")

        result = self._safe_result(
            "File edit planned." if dry_run else "File edited successfully.",
            data={
                "file_path": str(target),
                "edit_summary": edit_summary,
                "change": asdict(change),
                "syntax": syntax,
                "secret_findings": secret_findings,
                "dry_run": dry_run,
            },
            metadata=self._standard_metadata(ctx, started, "edit_file"),
        )
        self._after_success("edit_file", ctx, result)
        return result

    def analyze_project(
        self,
        project_path: str = ".",
        context: Optional[Union[CodeTaskContext, Mapping[str, Any]]] = None,
        dry_run: bool = True,
        max_files: int = 500,
        **_: Any,
    ) -> Dict[str, Any]:
        """Analyze project structure, languages, risks, and likely entry points."""

        started = time.time()
        ctx = self._coerce_context(context)
        root = self._resolve_safe_path(project_path, must_be_file=False)
        if not root.exists():
            return self._error_result(
                f"Project path does not exist: {root}",
                error_code="project_not_found",
                metadata=self._standard_metadata(ctx, started, "analyze_project"),
            )

        files: List[Path] = []
        for path in root.rglob("*"):
            if len(files) >= max_files:
                break
            if path.is_file() and self._is_safe_read_path(path):
                files.append(path)

        language_counts: Dict[str, int] = {}
        extension_counts: Dict[str, int] = {}
        total_bytes = 0
        entry_points: List[str] = []
        config_files: List[str] = []
        risky_files: List[str] = []

        for path in files:
            ext = path.suffix.lower() or path.name.lower()
            extension_counts[ext] = extension_counts.get(ext, 0) + 1
            language = self._language_from_extension(ext)
            language_counts[language] = language_counts.get(language, 0) + 1
            try:
                total_bytes += path.stat().st_size
            except OSError:
                pass

            rel = str(path.relative_to(root))
            if path.name in {"main.py", "app.py", "run.py", "server.py", "manage.py", "package.json", "pubspec.yaml"}:
                entry_points.append(rel)
            if path.name in {"requirements.txt", "pyproject.toml", "package.json", "Dockerfile", "docker-compose.yml", ".env.example"}:
                config_files.append(rel)
            if self._path_has_denied_part(path) or self._looks_like_secret_file(path):
                risky_files.append(rel)

        recommendations = self._project_recommendations(language_counts, config_files, risky_files)
        result = self._safe_result(
            "Project analysis completed.",
            data={
                "project_path": str(root),
                "file_count": len(files),
                "total_bytes": total_bytes,
                "languages": language_counts,
                "extensions": extension_counts,
                "entry_points": entry_points,
                "config_files": config_files,
                "risky_files": risky_files,
                "recommendations": recommendations,
                "dry_run": dry_run,
            },
            metadata=self._standard_metadata(ctx, started, "analyze_project"),
        )
        self._after_success("analyze_project", ctx, result)
        return result

    def analyze_code(
        self,
        code: Optional[str] = None,
        file_path: Optional[str] = None,
        language: Optional[str] = None,
        context: Optional[Union[CodeTaskContext, Mapping[str, Any]]] = None,
        dry_run: bool = True,
        **_: Any,
    ) -> Dict[str, Any]:
        """Analyze code text or a file for syntax, structure, and simple risks."""

        started = time.time()
        ctx = self._coerce_context(context)
        if file_path:
            path = self._resolve_safe_path(file_path, must_be_file=True)
            if not path.exists():
                return self._error_result(
                    f"Code file does not exist: {path}",
                    error_code="file_not_found",
                    metadata=self._standard_metadata(ctx, started, "analyze_code"),
                )
            code_text = path.read_text(encoding="utf-8", errors="replace")
            inferred_language = language or self._language_from_extension(path.suffix.lower())
        else:
            code_text = str(code or "")
            inferred_language = language or "text"

        syntax = self._syntax_check_language(inferred_language, code_text)
        result = self._safe_result(
            "Code analysis completed.",
            data={
                "language": inferred_language,
                "syntax": syntax,
                "metrics": self._simple_code_metrics(code_text, inferred_language),
                "secret_findings": self._scan_for_secret_patterns(code_text),
                "security_notes": self._static_security_notes(code_text, inferred_language),
                "dry_run": dry_run,
            },
            metadata=self._standard_metadata(ctx, started, "analyze_code"),
        )
        self._after_success("analyze_code", ctx, result)
        return result

    def debug_error(
        self,
        error_text: str,
        code: Optional[str] = None,
        file_path: Optional[str] = None,
        context: Optional[Union[CodeTaskContext, Mapping[str, Any]]] = None,
        dry_run: bool = True,
        **_: Any,
    ) -> Dict[str, Any]:
        """Analyze an error/log and return likely causes plus fix suggestions."""

        started = time.time()
        ctx = self._coerce_context(context)
        code_text = code or ""
        if file_path and not code:
            path = self._resolve_safe_path(file_path, must_be_file=True)
            if path.exists():
                code_text = path.read_text(encoding="utf-8", errors="replace")

        result = self._safe_result(
            "Error analysis completed.",
            data={"findings": self._diagnose_error(str(error_text or ""), code_text), "dry_run": dry_run},
            metadata=self._standard_metadata(ctx, started, "debug_error"),
        )
        self._after_success("debug_error", ctx, result)
        return result

    def run_command(
        self,
        command: Union[str, Sequence[str]],
        cwd: str = ".",
        context: Optional[Union[CodeTaskContext, Mapping[str, Any]]] = None,
        dry_run: bool = True,
        timeout_seconds: Optional[int] = None,
        env: Optional[Mapping[str, str]] = None,
        shell: bool = False,
        **_: Any,
    ) -> Dict[str, Any]:
        """Run a command behind strict security checks; dry-run by default."""

        started = time.time()
        ctx = self._coerce_context(context)
        workdir = self._resolve_safe_path(cwd, must_be_file=False)
        timeout = int(timeout_seconds or self.config.command_timeout_seconds)
        command_display = command if isinstance(command, str) else " ".join(map(shlex.quote, command))

        validation_error = self._validate_command(str(command_display), shell=shell)
        if validation_error:
            return self._error_result(
                validation_error,
                error_code="unsafe_command",
                metadata=self._standard_metadata(ctx, started, "run_command"),
            )
        if shell and not self.config.allow_shell:
            return self._error_result(
                "Shell execution is disabled by CodeAgent configuration.",
                error_code="shell_disabled",
                metadata=self._standard_metadata(ctx, started, "run_command"),
            )

        security = self._maybe_request_security(
            action="run_command",
            context=ctx,
            target=str(workdir),
            dry_run=dry_run,
            details={"command": command_display, "shell": shell, "timeout_seconds": timeout},
            force_sensitive=True,
        )
        if not security["approved"]:
            return security["result"]

        if dry_run:
            result = self._safe_result(
                "Command execution planned.",
                data={"command": command_display, "cwd": str(workdir), "timeout_seconds": timeout, "shell": shell, "dry_run": True},
                metadata=self._standard_metadata(ctx, started, "run_command"),
            )
            self._after_success("run_command", ctx, result)
            return result

        safe_env = os.environ.copy()
        for key, value in dict(env or {}).items():
            safe_env[str(key)] = str(value)

        exec_started = time.time()
        try:
            completed = subprocess.run(
                command if not isinstance(command, str) or shell else shlex.split(command),
                cwd=str(workdir),
                env=safe_env,
                shell=shell,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            cmd_result = CommandResult(
                command=str(command_display),
                cwd=str(workdir),
                returncode=completed.returncode,
                stdout=completed.stdout[-20000:],
                stderr=completed.stderr[-20000:],
                duration_seconds=self._duration(exec_started),
                timed_out=False,
            )
        except subprocess.TimeoutExpired as exc:
            cmd_result = CommandResult(
                command=str(command_display),
                cwd=str(workdir),
                returncode=124,
                stdout=(exc.stdout or "")[-20000:] if isinstance(exc.stdout, str) else "",
                stderr=(exc.stderr or "")[-20000:] if isinstance(exc.stderr, str) else "Command timed out.",
                duration_seconds=self._duration(exec_started),
                timed_out=True,
            )

        result = self._safe_result(
            "Command timed out." if cmd_result.timed_out else "Command executed.",
            data={"command_result": asdict(cmd_result), "dry_run": False},
            metadata=self._standard_metadata(ctx, started, "run_command"),
        )
        self._after_success("run_command", ctx, result)
        return result

    def run_tests(
        self,
        test_command: Optional[Union[str, Sequence[str]]] = None,
        project_path: str = ".",
        context: Optional[Union[CodeTaskContext, Mapping[str, Any]]] = None,
        dry_run: bool = True,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Run project tests through the same secured command pathway."""

        root = self._resolve_safe_path(project_path, must_be_file=False)
        inferred = test_command or self._infer_test_command(root)
        return self.run_command(command=inferred, cwd=str(root), context=context, dry_run=dry_run, shell=False, **kwargs)

    def install_dependencies(
        self,
        install_command: Optional[Union[str, Sequence[str]]] = None,
        project_path: str = ".",
        context: Optional[Union[CodeTaskContext, Mapping[str, Any]]] = None,
        dry_run: bool = True,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Install dependencies only when dependency operations are enabled."""

        started = time.time()
        ctx = self._coerce_context(context)
        if not self.config.allow_dependency_install and not dry_run:
            return self._error_result(
                "Dependency installation is disabled by CodeAgent configuration.",
                error_code="dependency_install_disabled",
                metadata=self._standard_metadata(ctx, started, "install_dependencies"),
            )
        root = self._resolve_safe_path(project_path, must_be_file=False)
        command = install_command or self._infer_install_command(root)
        return self.run_command(command=command, cwd=str(root), context=ctx, dry_run=dry_run, shell=False, **kwargs)

    def deploy_project(
        self,
        deploy_command: Optional[Union[str, Sequence[str]]] = None,
        project_path: str = ".",
        environment: str = "staging",
        context: Optional[Union[CodeTaskContext, Mapping[str, Any]]] = None,
        dry_run: bool = True,
        checklist_only: bool = False,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Prepare or run deployment through strict security gates."""

        started = time.time()
        ctx = self._coerce_context(context)
        root = self._resolve_safe_path(project_path, must_be_file=False)
        checklist = self._deployment_checklist(root, environment)

        if checklist_only or not deploy_command:
            result = self._safe_result(
                "Deployment checklist prepared.",
                data={"project_path": str(root), "environment": environment, "checklist": checklist, "dry_run": dry_run},
                metadata=self._standard_metadata(ctx, started, "deploy_project"),
            )
            self._after_success("deploy_project", ctx, result)
            return result

        if not self.config.allow_deploy_operations and not dry_run:
            return self._error_result(
                "Deployment operations are disabled by CodeAgent configuration.",
                error_code="deploy_disabled",
                metadata=self._standard_metadata(ctx, started, "deploy_project"),
            )
        return self.run_command(command=deploy_command, cwd=str(root), context=ctx, dry_run=dry_run, shell=False, **kwargs)

    def build_api_scaffold(self, project_name: str, framework: str = "fastapi", context: Optional[Union[CodeTaskContext, Mapping[str, Any]]] = None, dry_run: bool = True, **_: Any) -> Dict[str, Any]:
        """Generate a safe API scaffold plan/files."""
        return self.create_project(project_name=project_name, project_type=f"api-{framework}", files=self._api_scaffold_files(project_name, framework), context=context, dry_run=dry_run, overwrite=False)

    def build_frontend_scaffold(self, project_name: str, framework: str = "react", context: Optional[Union[CodeTaskContext, Mapping[str, Any]]] = None, dry_run: bool = True, **_: Any) -> Dict[str, Any]:
        """Generate a safe frontend scaffold plan/files."""
        return self.create_project(project_name=project_name, project_type=f"frontend-{framework}", files=self._frontend_scaffold_files(project_name, framework), context=context, dry_run=dry_run, overwrite=False)

    def build_database_scaffold(self, project_name: str, database: str = "postgres", context: Optional[Union[CodeTaskContext, Mapping[str, Any]]] = None, dry_run: bool = True, **_: Any) -> Dict[str, Any]:
        """Generate migration/schema starter files."""
        return self.create_project(project_name=project_name, project_type=f"database-{database}", files=self._database_scaffold_files(project_name, database), context=context, dry_run=dry_run, overwrite=False)

    def write_documentation(self, project_name: str, project_summary: str, output_path: Optional[str] = None, context: Optional[Union[CodeTaskContext, Mapping[str, Any]]] = None, dry_run: bool = True, **_: Any) -> Dict[str, Any]:
        """Generate a README-style documentation file."""
        output = output_path or f"{self._safe_name(project_name)}/README.md"
        content = f"""# {project_name}

## Overview

{project_summary}

## Architecture

This project is designed for safe, modular development with clear ownership of configuration, application code, tests, documentation, and deployment notes.

## Security Notes

- Do not commit secrets.
- Use environment variables and `.env.example`.
- Validate all user/workspace boundaries when building SaaS features.
- Route sensitive operations through the William/Jarvis Security Agent.

## Verification

Use the William/Jarvis Verification Agent payloads to validate generated files, commands, tests, and deployment readiness.
"""
        return self.generate_file(file_path=output, content=content, context=context, dry_run=dry_run, overwrite=True)

    def _validate_task_context(self, context: Mapping[str, Any]) -> CodeTaskContext:
        """Validate SaaS execution boundaries with user_id and workspace_id."""
        if isinstance(context, CodeTaskContext):
            return context
        return CodeTaskContext.from_mapping(context or {})

    def _requires_security_check(self, action: str, details: Optional[Mapping[str, Any]] = None) -> bool:
        """Return whether an action should be approved by Security Agent."""
        sensitive_actions = {"create_project", "generate_file", "edit_file", "run_command", "run_tests", "install_dependencies", "deploy_project", "git_operation", "delete_file", "move_file"}
        if action in sensitive_actions:
            return True
        details = dict(details or {})
        if details.get("force_sensitive"):
            return True
        target = str(details.get("target", ""))
        return any(part in target.lower() for part in DEFAULT_DENIED_PATH_PARTS)

    def _request_security_approval(self, action: str, context: CodeTaskContext, target: Optional[str] = None, details: Optional[Mapping[str, Any]] = None) -> SecurityDecision:
        """Ask Security Agent/client for approval when available; fallback to permissions."""
        details_dict = dict(details or {})
        dry_run = bool(details_dict.get("dry_run", False))
        if dry_run:
            return SecurityDecision(approved=True, reason="Dry-run approved without executing sensitive action.", metadata={"mode": "dry_run"})

        if self.security_client is not None:
            try:
                if hasattr(self.security_client, "approve"):
                    response = self.security_client.approve({"agent": self.agent_name, "action": action, "target": target, "context": asdict(context), "details": details_dict})
                elif hasattr(self.security_client, "request_approval"):
                    response = self.security_client.request_approval(agent=self.agent_name, action=action, target=target, context=asdict(context), details=details_dict)
                else:
                    response = None
                if isinstance(response, SecurityDecision):
                    return response
                if isinstance(response, Mapping):
                    return SecurityDecision(approved=bool(response.get("approved", False)), reason=str(response.get("reason", "Security client response.")), metadata=dict(response.get("metadata", {}) or {}))
            except Exception as exc:
                return SecurityDecision(approved=False, reason=f"Security approval failed: {exc}", metadata={"exception": str(exc)})

        allowed = f"code_agent:{action}" in context.permissions or "code_agent:*" in context.permissions
        return SecurityDecision(approved=allowed, reason="Approved by context permission." if allowed else "Security approval required for this action.", metadata={"fallback": True, "required_permission": f"code_agent:{action}"})

    def _prepare_verification_payload(self, action: str, context: CodeTaskContext, result: Mapping[str, Any]) -> Dict[str, Any]:
        """Prepare a Verification Agent compatible payload."""
        return {
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "action": action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "task_id": context.task_id,
            "result_success": bool(result.get("success")),
            "result_message": result.get("message"),
            "data_keys": sorted(list((result.get("data") or {}).keys())),
            "checks": ["validate_structured_result", "validate_user_workspace_isolation", "validate_security_decision_present_for_sensitive_actions", "validate_no_secret_leakage_in_output"],
            "timestamp": self._utc_timestamp(),
        }

    def _prepare_memory_payload(self, action: str, context: CodeTaskContext, result: Mapping[str, Any]) -> Dict[str, Any]:
        """Prepare a Memory Agent compatible payload."""
        data = dict(result.get("data", {}) or {})
        return {
            "agent": self.agent_name,
            "action": action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "message": result.get("message"),
            "success": bool(result.get("success")),
            "metadata": result.get("metadata", {}),
            "artifact_paths": self._extract_artifact_paths(data),
            "timestamp": self._utc_timestamp(),
        }

    def _emit_agent_event(self, event_name: str, payload: Mapping[str, Any]) -> None:
        """Emit agent events for dashboard/API/registry integrations."""
        if not self.config.enable_event_emit:
            return
        safe_payload = self._json_safe(dict(payload))
        try:
            if self.event_bus is not None:
                if hasattr(self.event_bus, "emit"):
                    self.event_bus.emit(event_name, safe_payload)
                    return
                if hasattr(self.event_bus, "publish"):
                    self.event_bus.publish(event_name, safe_payload)
                    return
            try:
                super().emit_event(event_name, safe_payload)  # type: ignore[misc]
            except Exception:
                pass
            self.logger.debug("Event: %s | %s", event_name, safe_payload)
        except Exception as exc:
            self.logger.warning("Failed to emit event %s: %s", event_name, exc)

    def _log_audit_event(self, event_name: str, payload: Mapping[str, Any]) -> None:
        """Log audit-safe activity for SaaS traceability."""
        if not self.config.enable_audit_log:
            return
        safe_payload = self._json_safe(dict(payload))
        try:
            if self.audit_logger is not None:
                if hasattr(self.audit_logger, "log"):
                    self.audit_logger.log(event_name, safe_payload)
                    return
                if callable(self.audit_logger):
                    self.audit_logger(event_name, safe_payload)
                    return
            try:
                super().log_audit(event_name, safe_payload)  # type: ignore[misc]
            except Exception:
                pass
            self.logger.info("Audit: %s | %s", event_name, safe_payload)
        except Exception as exc:
            self.logger.warning("Failed to log audit event %s: %s", event_name, exc)

    def _safe_result(self, message: str, data: Optional[Mapping[str, Any]] = None, metadata: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        """Return a standard success result."""
        return {"success": True, "message": message, "data": self._json_safe(dict(data or {})), "error": None, "metadata": self._json_safe(dict(metadata or {}))}

    def _error_result(self, message: str, error: Optional[str] = None, error_code: Optional[str] = None, data: Optional[Mapping[str, Any]] = None, metadata: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        """Return a standard error result."""
        return {"success": False, "message": message, "data": self._json_safe(dict(data or {})), "error": {"code": error_code or "code_agent_error", "detail": error or message}, "metadata": self._json_safe(dict(metadata or {}))}

    def _coerce_context(self, context: Optional[Union[CodeTaskContext, Mapping[str, Any]]]) -> CodeTaskContext:
        if isinstance(context, CodeTaskContext):
            return context
        return self._validate_task_context(context or {})

    def _maybe_request_security(self, action: str, context: CodeTaskContext, target: Optional[str], dry_run: bool, details: Optional[Mapping[str, Any]] = None, force_sensitive: bool = False) -> Dict[str, Any]:
        details_dict = dict(details or {})
        details_dict["dry_run"] = dry_run
        details_dict["force_sensitive"] = force_sensitive
        if not self._requires_security_check(action, {**details_dict, "target": target or ""}):
            return {"approved": True, "decision": None, "result": None}
        decision = self._request_security_approval(action, context, target=target, details=details_dict)
        self._log_audit_event("code_agent.security_decision", {"agent": self.agent_name, "action": action, "target": target, "context": asdict(context), "approved": decision.approved, "reason": decision.reason, "metadata": decision.metadata})
        if not decision.approved:
            return {"approved": False, "decision": decision, "result": self._error_result(f"Security approval denied for action: {action}", error=decision.reason, error_code="security_denied", metadata={"security": asdict(decision)})}
        return {"approved": True, "decision": decision, "result": None}

    def _after_success(self, action: str, context: CodeTaskContext, result: Dict[str, Any]) -> None:
        verification = self._prepare_verification_payload(action, context, result)
        memory = self._prepare_memory_payload(action, context, result)
        result.setdefault("metadata", {})
        result["metadata"]["verification_payload"] = verification
        result["metadata"]["memory_payload"] = memory
        self._emit_agent_event("code_agent.task.completed", {"action": action, "context": asdict(context), "success": result.get("success"), "message": result.get("message")})
        self._log_audit_event("code_agent.task.completed", {"action": action, "context": asdict(context), "success": result.get("success"), "message": result.get("message")})
        if self.memory_client is not None:
            try:
                if hasattr(self.memory_client, "store"):
                    self.memory_client.store(memory)
                elif hasattr(self.memory_client, "remember"):
                    self.memory_client.remember(memory)
            except Exception as exc:
                self.logger.debug("Memory client store skipped/failed: %s", exc)
        if self.verification_client is not None:
            try:
                if hasattr(self.verification_client, "submit"):
                    self.verification_client.submit(verification)
                elif hasattr(self.verification_client, "verify"):
                    self.verification_client.verify(verification)
            except Exception as exc:
                self.logger.debug("Verification client submit skipped/failed: %s", exc)

    def _record_task_history(self, action: str, context: CodeTaskContext, result: Mapping[str, Any], started: float) -> None:
        self._task_history.append({"action": action, "user_id": context.user_id, "workspace_id": context.workspace_id, "success": bool(result.get("success")), "duration_seconds": self._duration(started), "timestamp": self._utc_timestamp()})
        self._task_history = self._task_history[-100:]

    def _resolve_safe_path(self, path: str, must_be_file: bool = True) -> Path:
        raw = Path(str(path).strip()).expanduser()
        candidate = raw.resolve() if raw.is_absolute() else (self.workspace_root / raw).resolve()
        try:
            candidate.relative_to(self.workspace_root)
        except ValueError:
            raise ValueError(f"Path escapes workspace root: {candidate}")
        if self._path_has_denied_part(candidate):
            raise ValueError(f"Path contains denied sensitive part: {candidate}")
        if must_be_file:
            suffix = candidate.suffix.lower()
            name_lower = candidate.name.lower()
            allowed_names = {"dockerfile", "makefile", "license", "readme", ".gitignore", ".env.example"}
            if suffix not in self.config.allowed_extensions and name_lower not in self.config.allowed_extensions and name_lower not in allowed_names:
                raise ValueError(f"File extension/name is not allowed for CodeAgent writes: {candidate.name}")
        return candidate

    def _validate_file_write(self, target: Path, content: str) -> None:
        if not self.config.allow_file_writes:
            raise PermissionError("File writes are disabled by CodeAgent configuration.")
        byte_count = len(content.encode("utf-8"))
        if byte_count > self.config.max_file_bytes:
            raise ValueError(f"File content exceeds max_file_bytes ({byte_count} > {self.config.max_file_bytes}).")
        if self._looks_like_secret_file(target):
            raise ValueError(f"Refusing to write likely secret/credential file: {target.name}")

    def _is_safe_read_path(self, path: Path) -> bool:
        if self._path_has_denied_part(path):
            return False
        if any(part in {".git", "__pycache__", "node_modules", ".venv", "venv", "dist", "build"} for part in path.parts):
            return False
        try:
            return path.stat().st_size <= self.config.max_file_bytes
        except OSError:
            return False

    def _path_has_denied_part(self, path: Path) -> bool:
        lowered = [part.lower() for part in path.parts]
        return any(denied.lower() in lowered or denied.lower() in str(path).lower() for denied in self.config.denied_path_parts)

    def _looks_like_secret_file(self, path: Path) -> bool:
        name = path.name.lower()
        sensitive_names = {".env", "credentials.json", "token.json", "service-account.json", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}
        return name in sensitive_names or "secret" in name or "private_key" in name

    def _safe_name(self, value: str) -> str:
        cleaned = re.sub(r"[^a-zA-Z0-9_.-]+", "-", str(value).strip()).strip("-._")
        return cleaned or "project"

    def _hash_text(self, content: str) -> str:
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def _diff_preview(self, before: str, after: str, max_lines: int = 120) -> str:
        diff = difflib.unified_diff(before.splitlines(), after.splitlines(), fromfile="before", tofile="after", lineterm="")
        lines = list(diff)
        if len(lines) > max_lines:
            lines = lines[:max_lines] + ["... diff truncated ..."]
        return "\n".join(lines)

    def _scan_for_secret_patterns(self, content: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for pattern in SECRET_KEY_PATTERNS:
            for match in re.finditer(pattern, content):
                line_no = content[:match.start()].count("\n") + 1
                findings.append({"line": line_no, "pattern": pattern, "preview": self._redact(match.group(0)), "severity": "high"})
        return findings

    def _redact(self, text: str) -> str:
        if len(text) <= 8:
            return "***"
        return text[:4] + "***" + text[-4:]

    def _syntax_check_by_extension(self, path: Path, content: str) -> Dict[str, Any]:
        return self._syntax_check_language(self._language_from_extension(path.suffix.lower() or path.name.lower()), content)

    def _syntax_check_language(self, language: str, content: str) -> Dict[str, Any]:
        language = (language or "text").lower()
        if language == "python":
            try:
                ast.parse(content)
                return {"ok": True, "language": "python", "errors": []}
            except SyntaxError as exc:
                return {"ok": False, "language": "python", "errors": [{"message": exc.msg, "line": exc.lineno, "offset": exc.offset, "text": exc.text}]}
        if language == "json":
            try:
                json.loads(content or "{}")
                return {"ok": True, "language": "json", "errors": []}
            except json.JSONDecodeError as exc:
                return {"ok": False, "language": "json", "errors": [{"message": exc.msg, "line": exc.lineno, "column": exc.colno}]}
        return {"ok": True, "language": language, "errors": [], "note": "No parser configured for this language."}

    def _language_from_extension(self, ext: str) -> str:
        mapping = {".py": "python", ".json": "json", ".js": "javascript", ".jsx": "javascript", ".ts": "typescript", ".tsx": "typescript", ".html": "html", ".css": "css", ".md": "markdown", ".yaml": "yaml", ".yml": "yaml", ".toml": "toml", ".sql": "sql", ".sh": "shell", ".ps1": "powershell", ".java": "java", ".kt": "kotlin", ".swift": "swift", ".go": "go", ".rs": "rust", ".php": "php", ".rb": "ruby", ".dart": "dart"}
        return mapping.get((ext or "").lower(), "text")

    def _simple_code_metrics(self, code: str, language: str) -> Dict[str, Any]:
        lines = code.splitlines()
        non_empty = [line for line in lines if line.strip()]
        comment_prefixes = ("#", "//", "/*", "*", "<!--")
        comment_lines = [line for line in non_empty if line.strip().startswith(comment_prefixes)]
        metrics: Dict[str, Any] = {"line_count": len(lines), "non_empty_line_count": len(non_empty), "comment_line_count": len(comment_lines), "approx_character_count": len(code)}
        if language.lower() == "python":
            try:
                tree = ast.parse(code)
                metrics["function_count"] = sum(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) for n in ast.walk(tree))
                metrics["class_count"] = sum(isinstance(n, ast.ClassDef) for n in ast.walk(tree))
                metrics["import_count"] = sum(isinstance(n, (ast.Import, ast.ImportFrom)) for n in ast.walk(tree))
            except Exception:
                metrics["python_ast_metrics_available"] = False
        return metrics

    def _static_security_notes(self, code: str, language: str) -> List[Dict[str, Any]]:
        notes: List[Dict[str, Any]] = []
        patterns = [
            (r"\beval\s*\(", "Use of eval can execute arbitrary code.", "high"),
            (r"\bexec\s*\(", "Use of exec can execute arbitrary code.", "high"),
            (r"subprocess\.(Popen|run|call)\(.*shell\s*=\s*True", "subprocess with shell=True needs strict validation.", "high"),
            (r"\bpickle\.loads?\s*\(", "Pickle loading untrusted data is unsafe.", "medium"),
            (r"\binnerHTML\s*=", "innerHTML can create XSS if user data is inserted.", "medium"),
        ]
        for pattern, message, severity in patterns:
            for match in re.finditer(pattern, code, flags=re.IGNORECASE | re.DOTALL):
                notes.append({"line": code[:match.start()].count("\n") + 1, "message": message, "severity": severity, "pattern": pattern})
        return notes

    def _diagnose_error(self, error_text: str, code: str = "") -> List[Dict[str, Any]]:
        text = error_text.lower()
        findings: List[Dict[str, Any]] = []
        if "modulenotfounderror" in text or "no module named" in text:
            findings.append({"type": "missing_dependency_or_path", "confidence": 0.9, "message": "A required module cannot be imported.", "suggestions": ["Confirm the package is installed in the active virtual environment.", "Confirm you are running the command from the project root.", "Check folder names and __init__.py files for package imports."]})
        if "syntaxerror" in text:
            findings.append({"type": "syntax_error", "confidence": 0.85, "message": "The code has invalid syntax.", "suggestions": ["Check the line and caret shown in the traceback.", "Run python -m py_compile on the target file.", "Look for missing brackets, quotes, colons, or indentation issues."]})
        if "permission denied" in text or "access is denied" in text:
            findings.append({"type": "permission_error", "confidence": 0.8, "message": "The process lacks permission to access a file, folder, or command.", "suggestions": ["Check file ownership and locks.", "Run in a project folder where the user has write access.", "Avoid protected system directories."]})
        if "port" in text and ("already in use" in text or "address already in use" in text):
            findings.append({"type": "port_in_use", "confidence": 0.8, "message": "The server port is already being used.", "suggestions": ["Stop the existing process using the port.", "Change the app port.", "On Windows, use netstat -ano to find the process."]})
        if "indentationerror" in text:
            findings.append({"type": "indentation_error", "confidence": 0.9, "message": "Python indentation is inconsistent or invalid.", "suggestions": ["Use spaces consistently.", "Check the block before the reported line.", "Format the file with a Python formatter after fixing syntax."]})
        if code and not findings:
            findings.append({"type": "general_debug", "confidence": 0.5, "message": "No specific known error pattern matched.", "suggestions": ["Read the first traceback line that points to your project file.", "Check recent changes around the failing function.", "Run tests with verbose output."], "code_metrics": self._simple_code_metrics(code, "python")})
        return findings or [{"type": "unknown", "confidence": 0.3, "message": "No specific diagnosis found from the provided error text.", "suggestions": ["Provide the full traceback and the related file for a more precise diagnosis."]}]

    def _validate_command(self, command: str, shell: bool = False) -> Optional[str]:
        normalized = command.strip()
        if not normalized:
            return "Command cannot be empty."
        for pattern in DANGEROUS_COMMAND_PATTERNS:
            if re.search(pattern, normalized, flags=re.IGNORECASE):
                return f"Command rejected by safety policy: pattern {pattern}"
        if shell and any(token in normalized for token in ["&&", "||", ";", "|", "`", "$("]):
            return "Complex shell chaining/substitution is not allowed by default."
        return None

    def _infer_test_command(self, root: Path) -> List[str]:
        if (root / "pytest.ini").exists() or (root / "pyproject.toml").exists() or (root / "tests").exists():
            return [sys.executable, "-m", "pytest"]
        if (root / "package.json").exists():
            return ["npm", "test"]
        if (root / "pubspec.yaml").exists():
            return ["flutter", "test"]
        return [sys.executable, "-m", "unittest", "discover"]

    def _infer_install_command(self, root: Path) -> List[str]:
        if (root / "requirements.txt").exists():
            return [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"]
        if (root / "pyproject.toml").exists():
            return [sys.executable, "-m", "pip", "install", "-e", "."]
        if (root / "package.json").exists():
            return ["npm", "install"]
        if (root / "pubspec.yaml").exists():
            return ["flutter", "pub", "get"]
        return [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"]

    def _deployment_checklist(self, root: Path, environment: str) -> List[Dict[str, Any]]:
        checks = [
            {"item": "Secrets are stored outside repository", "status": "manual_review_required"},
            {"item": "Tests pass", "status": "run_tests_required"},
            {"item": "Dependency lock files reviewed", "status": "manual_review_required"},
            {"item": "Environment variables configured", "status": "manual_review_required"},
            {"item": "Rollback plan prepared", "status": "manual_review_required"},
            {"item": f"Deployment environment selected: {environment}", "status": "noted"},
        ]
        if (root / "Dockerfile").exists():
            checks.append({"item": "Dockerfile detected", "status": "available"})
        if (root / "requirements.txt").exists() or (root / "package.json").exists():
            checks.append({"item": "Dependency manifest detected", "status": "available"})
        return checks

    def _default_project_structure(self, project_type: str) -> List[str]:
        if "fastapi" in project_type or "api" in project_type:
            return ["app/main.py", "app/routes/", "app/models/", "tests/", "requirements.txt", ".env.example", "README.md"]
        if "frontend" in project_type or "react" in project_type:
            return ["src/App.tsx", "src/main.tsx", "src/components/", "package.json", "README.md"]
        if "flutter" in project_type:
            return ["lib/main.dart", "lib/screens/", "lib/widgets/", "pubspec.yaml", "README.md"]
        return ["main.py", "src/", "tests/", "requirements.txt", ".env.example", "README.md"]

    def _default_project_files(self, project_name: str, project_type: str) -> Dict[str, str]:
        if "fastapi" in project_type or "api" in project_type:
            return self._api_scaffold_files(project_name, "fastapi")
        if "frontend" in project_type or "react" in project_type:
            return self._frontend_scaffold_files(project_name, "react")
        return {
            "README.md": f"# {project_name}\n\nGenerated by William/Jarvis CodeAgent.\n",
            ".env.example": "# Add environment variable names here. Do not commit real secrets.\n",
            "main.py": '"""Application entry point."""\n\ndef main() -> None:\n    print(\'Hello from ' + project_name.replace("'", "") + "\')\n\nif __name__ == '__main__':\n    main()\n",
            "requirements.txt": "",
            "tests/test_main.py": "def test_placeholder() -> None:\n    assert True\n",
        }

    def _api_scaffold_files(self, project_name: str, framework: str) -> Dict[str, str]:
        return {
            "README.md": f"# {project_name}\n\nFastAPI scaffold generated by William/Jarvis CodeAgent.\n",
            ".env.example": "APP_ENV=development\n",
            "requirements.txt": "fastapi\nuvicorn\npydantic\n",
            "app/__init__.py": "",
            "app/main.py": '"""FastAPI application entry point."""\n\nfrom fastapi import FastAPI\n\napp = FastAPI(title="' + project_name.replace('"', '') + '")\n\n@app.get("/health")\ndef health() -> dict:\n    return {"success": True, "message": "healthy"}\n',
            "tests/test_health.py": "from fastapi.testclient import TestClient\nfrom app.main import app\n\ndef test_health() -> None:\n    client = TestClient(app)\n    response = client.get('/health')\n    assert response.status_code == 200\n",
        }

    def _frontend_scaffold_files(self, project_name: str, framework: str) -> Dict[str, str]:
        package = {
            "name": self._safe_name(project_name).lower(),
            "version": "0.1.0",
            "private": True,
            "scripts": {"dev": "vite", "build": "vite build", "test": "echo \"No tests configured\""},
            "dependencies": {"@vitejs/plugin-react": "latest", "vite": "latest", "react": "latest", "react-dom": "latest", "typescript": "latest"},
            "devDependencies": {},
        }
        return {
            "README.md": f"# {project_name}\n\nFrontend scaffold generated by William/Jarvis CodeAgent.\n",
            "package.json": json.dumps(package, indent=2) + "\n",
            "src/App.tsx": "export default function App() {\n  return (\n    <main>\n      <h1>" + project_name.replace("<", "").replace(">", "") + "</h1>\n      <p>Generated by William/Jarvis CodeAgent.</p>\n    </main>\n  );\n}\n",
            "src/main.tsx": "import React from 'react';\nimport { createRoot } from 'react-dom/client';\nimport App from './App';\n\ncreateRoot(document.getElementById('root')!).render(\n  <React.StrictMode><App /></React.StrictMode>\n);\n",
            "index.html": "<div id=\"root\"></div><script type=\"module\" src=\"/src/main.tsx\"></script>\n",
        }

    def _database_scaffold_files(self, project_name: str, database: str) -> Dict[str, str]:
        return {
            "README.md": f"# {project_name} Database\n\nDatabase scaffold for {database}.\n",
            "migrations/001_initial.sql": "-- Initial migration generated by William/Jarvis CodeAgent\nCREATE TABLE IF NOT EXISTS audit_log (\n    id INTEGER PRIMARY KEY,\n    user_id TEXT NOT NULL,\n    workspace_id TEXT NOT NULL,\n    event_name TEXT NOT NULL,\n    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP\n);\n",
            "schema.sql": "-- Add application schema here.\n",
        }

    def _project_recommendations(self, language_counts: Mapping[str, int], config_files: Sequence[str], risky_files: Sequence[str]) -> List[str]:
        recommendations: List[str] = []
        if "python" in language_counts and "requirements.txt" not in config_files and "pyproject.toml" not in config_files:
            recommendations.append("Add requirements.txt or pyproject.toml for reproducible Python installs.")
        if "javascript" in language_counts and "package.json" not in config_files:
            recommendations.append("Add package.json for JavaScript project scripts/dependencies.")
        if risky_files:
            recommendations.append("Review risky/secret-like files and ensure they are not committed or exposed.")
        if not recommendations:
            recommendations.append("Project structure looks ready for deeper module-specific analysis.")
        return recommendations

    def _extract_artifact_paths(self, data: Mapping[str, Any]) -> List[str]:
        paths: List[str] = []
        for key in ("file_path", "project_root", "project_path"):
            value = data.get(key)
            if isinstance(value, str):
                paths.append(value)
        change = data.get("change")
        if isinstance(change, Mapping) and isinstance(change.get("path"), str):
            paths.append(str(change["path"]))
        changes = data.get("changes")
        if isinstance(changes, list):
            for item in changes:
                if isinstance(item, Mapping) and isinstance(item.get("path"), str):
                    paths.append(str(item["path"]))
        return sorted(set(paths))

    def _standard_metadata(self, context: CodeTaskContext, started: float, action: str) -> Dict[str, Any]:
        return {"agent": self.agent_name, "agent_type": self.agent_type, "version": self.version, "action": action, "user_id": context.user_id, "workspace_id": context.workspace_id, "request_id": context.request_id, "task_id": context.task_id, "duration_seconds": self._duration(started), "timestamp": self._utc_timestamp()}

    def _duration(self, started: float) -> float:
        return round(time.time() - started, 6)

    def _utc_timestamp(self) -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def _json_safe(self, value: Any) -> Any:
        try:
            json.dumps(value)
            return value
        except TypeError:
            if isinstance(value, Mapping):
                return {str(k): self._json_safe(v) for k, v in value.items()}
            if isinstance(value, (list, tuple, set)):
                return [self._json_safe(v) for v in value]
            if isinstance(value, Path):
                return str(value)
            return str(value)

    def get_capabilities(self) -> Dict[str, Any]:
        """Expose capabilities for Agent Registry, Dashboard, and Master Agent."""
        return {
            "agent": self.agent_name,
            "class": self.__class__.__name__,
            "type": self.agent_type,
            "version": self.version,
            "capabilities": ["project_planning", "project_creation", "file_generation", "file_editing", "code_analysis", "error_debugging", "secured_command_execution", "test_running", "dependency_installation_planning", "deployment_checklists", "api_scaffold_generation", "frontend_scaffold_generation", "database_scaffold_generation", "documentation_writing"],
            "sensitive_actions": ["create_project", "generate_file", "edit_file", "run_command", "run_tests", "install_dependencies", "deploy_project"],
            "requires_context": ["user_id", "workspace_id"],
        }

    def health_check(self) -> Dict[str, Any]:
        """Simple import/runtime health check for platform diagnostics."""
        return self._safe_result(
            "CodeAgent is healthy.",
            data={
                "workspace_root": str(self.workspace_root),
                "config": {
                    "dry_run_default": self.config.dry_run_default,
                    "allow_shell": self.config.allow_shell,
                    "allow_file_writes": self.config.allow_file_writes,
                    "allow_dependency_install": self.config.allow_dependency_install,
                    "allow_git_operations": self.config.allow_git_operations,
                    "allow_deploy_operations": self.config.allow_deploy_operations,
                },
                "capabilities": self.get_capabilities(),
            },
            metadata={"timestamp": self._utc_timestamp()},
        )


__all__ = ["CodeAgent", "CodeAgentConfig", "CodeTaskContext", "FileChange", "CommandResult", "SecurityDecision"]
