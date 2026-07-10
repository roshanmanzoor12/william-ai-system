"""
agents/code_agent/code_editor.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Safely modifies existing files, patches blocks, preserves structure.

This module provides the CodeEditor class used by the Code Agent layer to:
    - Read and write project files safely.
    - Apply text replacements.
    - Patch code blocks between markers.
    - Insert content before/after anchors.
    - Replace line ranges.
    - Create backups before edits.
    - Validate SaaS user/workspace context.
    - Prepare Security Agent approval payloads.
    - Prepare Verification Agent payloads.
    - Prepare Memory Agent payloads.
    - Emit audit/dashboard/agent events in structured format.

Design rules:
    - Import-safe even if other William/Jarvis files are missing.
    - No hardcoded secrets.
    - No destructive file actions without permission/security checks.
    - Every public method returns structured dict/JSON-style results.
    - Ready for FastAPI/dashboard integration.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import logging
import os
import re
import shutil
import tempfile
import time
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Optional BaseAgent compatibility
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps the file import-safe before the full William/Jarvis
        agent system is available.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)

        def run(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent does not implement run().",
                "data": {},
                "error": None,
                "metadata": {
                    "fallback": True,
                    "agent": self.__class__.__name__,
                },
            }


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
if not logger.handlers:
    logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class TaskContext:
    """
    SaaS execution context.

    user_id and workspace_id are required for user-specific execution.
    This prevents edits, logs, analytics, memory, and audit data from mixing
    across SaaS users/workspaces.
    """

    user_id: Union[str, int]
    workspace_id: Union[str, int]
    role: Optional[str] = None
    subscription: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    request_id: Optional[str] = None
    session_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EditOperation:
    """
    Represents a requested file edit operation.
    """

    operation: str
    path: str
    content: Optional[str] = None
    old_text: Optional[str] = None
    new_text: Optional[str] = None
    start_marker: Optional[str] = None
    end_marker: Optional[str] = None
    anchor: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    create_if_missing: bool = False
    allow_multiple: bool = False
    preserve_newline: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FileSnapshot:
    """
    File metadata captured before/after an edit.
    """

    path: str
    exists: bool
    size_bytes: int = 0
    sha256: Optional[str] = None
    modified_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EditResult:
    """
    Internal normalized result for file edits.
    """

    changed: bool
    path: str
    before: FileSnapshot
    after: FileSnapshot
    backup_path: Optional[str]
    diff: str
    details: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# CodeEditor
# ---------------------------------------------------------------------------

class CodeEditor(BaseAgent):
    """
    Production-ready safe file editor for the William/Jarvis Code Agent.

    Master Agent:
        Can route code-edit tasks to this class.

    Security Agent:
        Sensitive or destructive edits are detected by _requires_security_check()
        and can be approved through _request_security_approval().

    Verification Agent:
        Every successful edit prepares a structured verification payload.

    Memory Agent:
        Every useful edit can prepare a safe memory payload without leaking
        private user/workspace data into other tenants.

    Dashboard/API:
        Structured results are compatible with future FastAPI endpoints,
        task history views, analytics cards, and audit logs.

    Registry/Loader:
        The class is import-safe and can be loaded by an Agent Registry even
        before all other system modules exist.
    """

    DEFAULT_ALLOWED_EXTENSIONS = {
        ".py", ".txt", ".md", ".json", ".yaml", ".yml", ".toml",
        ".ini", ".cfg", ".env.example", ".html", ".css", ".js",
        ".ts", ".tsx", ".jsx", ".dart", ".php", ".sql", ".sh",
        ".bat", ".ps1", ".xml", ".csv", ".gitignore", ".dockerignore",
        ".dockerfile",
    }

    DEFAULT_DENIED_FILENAMES = {
        ".env",
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "known_hosts",
        "authorized_keys",
    }

    DEFAULT_DENIED_PATH_PARTS = {
        ".git",
        ".svn",
        ".hg",
        "__pycache__",
        "node_modules",
        ".venv",
        "venv",
        "env",
        ".mypy_cache",
        ".pytest_cache",
        ".tox",
        "dist",
        "build",
    }

    SENSITIVE_PATTERNS = [
        re.compile(r"\b(api[_-]?key|secret|token|password|passwd|private[_-]?key)\b", re.I),
        re.compile(r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----", re.I),
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        re.compile(r"\bghp_[A-Za-z0-9_]{20,}\b"),
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    ]

    def __init__(
        self,
        project_root: Optional[Union[str, Path]] = None,
        *,
        agent_name: str = "CodeEditor",
        allowed_extensions: Optional[Iterable[str]] = None,
        denied_filenames: Optional[Iterable[str]] = None,
        denied_path_parts: Optional[Iterable[str]] = None,
        backup_dir_name: str = ".william_backups",
        max_file_size_bytes: int = 5 * 1024 * 1024,
        security_callback: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        audit_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        super().__init__(agent_name=agent_name)

        self.agent_name = agent_name
        self.project_root = Path(project_root or os.getcwd()).resolve()
        self.backup_dir_name = backup_dir_name
        self.max_file_size_bytes = max_file_size_bytes

        self.allowed_extensions = set(allowed_extensions or self.DEFAULT_ALLOWED_EXTENSIONS)
        self.denied_filenames = set(denied_filenames or self.DEFAULT_DENIED_FILENAMES)
        self.denied_path_parts = set(denied_path_parts or self.DEFAULT_DENIED_PATH_PARTS)

        self.security_callback = security_callback
        self.audit_callback = audit_callback
        self.event_callback = event_callback

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        BaseAgent-compatible entrypoint.

        Expected task shape:
            {
                "context": {"user_id": 1, "workspace_id": 1, ...},
                "operation": "replace_text",
                "path": "app/main.py",
                ...
            }
        """

        try:
            context_data = task.get("context") or {}
            context = self._coerce_context(context_data)

            operation = task.get("operation")
            if not operation:
                return self._error_result(
                    "Missing operation.",
                    error_code="missing_operation",
                    metadata={"agent": self.agent_name},
                )

            if operation == "read_file":
                return self.read_file(task.get("path", ""), context=context)

            if operation == "write_file":
                return self.write_file(
                    path=task.get("path", ""),
                    content=task.get("content", ""),
                    context=context,
                    create_if_missing=bool(task.get("create_if_missing", True)),
                    overwrite=bool(task.get("overwrite", True)),
                )

            if operation == "replace_text":
                return self.replace_text(
                    path=task.get("path", ""),
                    old_text=task.get("old_text", ""),
                    new_text=task.get("new_text", ""),
                    context=context,
                    allow_multiple=bool(task.get("allow_multiple", False)),
                )

            if operation == "patch_between_markers":
                return self.patch_between_markers(
                    path=task.get("path", ""),
                    start_marker=task.get("start_marker", ""),
                    end_marker=task.get("end_marker", ""),
                    new_content=task.get("new_content", task.get("content", "")),
                    context=context,
                    include_markers=bool(task.get("include_markers", False)),
                )

            if operation == "insert_before":
                return self.insert_before(
                    path=task.get("path", ""),
                    anchor=task.get("anchor", ""),
                    content=task.get("content", ""),
                    context=context,
                    allow_multiple=bool(task.get("allow_multiple", False)),
                )

            if operation == "insert_after":
                return self.insert_after(
                    path=task.get("path", ""),
                    anchor=task.get("anchor", ""),
                    content=task.get("content", ""),
                    context=context,
                    allow_multiple=bool(task.get("allow_multiple", False)),
                )

            if operation == "replace_line_range":
                return self.replace_line_range(
                    path=task.get("path", ""),
                    line_start=int(task.get("line_start", 0)),
                    line_end=int(task.get("line_end", 0)),
                    new_content=task.get("new_content", task.get("content", "")),
                    context=context,
                )

            if operation == "apply_operations":
                operations = task.get("operations") or []
                return self.apply_operations(operations, context=context)

            return self._error_result(
                f"Unsupported operation: {operation}",
                error_code="unsupported_operation",
                metadata={"operation": operation},
            )

        except Exception as exc:
            logger.exception("CodeEditor.run failed.")
            return self._error_result(
                "CodeEditor task failed.",
                error=exc,
                error_code="run_failed",
                metadata={"agent": self.agent_name},
            )

    def read_file(
        self,
        path: Union[str, Path],
        *,
        context: Union[TaskContext, Dict[str, Any]],
        encoding: str = "utf-8",
    ) -> Dict[str, Any]:
        """
        Safely read a text file inside project_root.
        """

        ctx = self._coerce_context(context)
        validation = self._validate_task_context(ctx)
        if not validation["success"]:
            return validation

        path_result = self._resolve_safe_path(path, must_exist=True)
        if not path_result["success"]:
            return path_result

        file_path = path_result["data"]["path"]

        try:
            self._validate_file_size(file_path)
            content = file_path.read_text(encoding=encoding)

            result = self._safe_result(
                message="File read successfully.",
                data={
                    "path": self._relative_path(file_path),
                    "content": content,
                    "snapshot": self._snapshot(file_path).to_dict(),
                },
                metadata={
                    "agent": self.agent_name,
                    "operation": "read_file",
                    "context": ctx.to_dict(),
                },
            )

            self._emit_agent_event("code_editor.file_read", result)
            return result

        except Exception as exc:
            return self._error_result(
                "Failed to read file.",
                error=exc,
                error_code="read_file_failed",
                metadata={"path": str(path)},
            )

    def write_file(
        self,
        path: Union[str, Path],
        content: str,
        *,
        context: Union[TaskContext, Dict[str, Any]],
        create_if_missing: bool = True,
        overwrite: bool = True,
        encoding: str = "utf-8",
        make_backup: bool = True,
    ) -> Dict[str, Any]:
        """
        Safely write a text file.

        This method can create a file if allowed.
        Existing files are backed up by default before overwrite.
        """

        ctx = self._coerce_context(context)
        validation = self._validate_task_context(ctx)
        if not validation["success"]:
            return validation

        path_result = self._resolve_safe_path(path, must_exist=False)
        if not path_result["success"]:
            return path_result

        file_path = path_result["data"]["path"]

        if file_path.exists() and not overwrite:
            return self._error_result(
                "File already exists and overwrite=False.",
                error_code="file_exists",
                metadata={"path": self._relative_path(file_path)},
            )

        if not file_path.exists() and not create_if_missing:
            return self._error_result(
                "File does not exist and create_if_missing=False.",
                error_code="file_missing",
                metadata={"path": self._relative_path(file_path)},
            )

        operation = EditOperation(
            operation="write_file",
            path=str(path),
            content=content,
            create_if_missing=create_if_missing,
            metadata={"overwrite": overwrite},
        )

        security = self._handle_security_if_required(operation, ctx)
        if not security["success"]:
            return security

        try:
            before = self._snapshot(file_path)
            old_content = file_path.read_text(encoding=encoding) if file_path.exists() else ""

            file_path.parent.mkdir(parents=True, exist_ok=True)
            backup_path = self._create_backup(file_path, ctx) if make_backup and file_path.exists() else None

            self._atomic_write(file_path, content, encoding=encoding)

            after = self._snapshot(file_path)
            diff = self._make_diff(old_content, content, self._relative_path(file_path))

            edit_result = EditResult(
                changed=(old_content != content),
                path=self._relative_path(file_path),
                before=before,
                after=after,
                backup_path=backup_path,
                diff=diff,
                details={"operation": "write_file"},
            )

            return self._finalize_edit_result(edit_result, ctx, operation)

        except Exception as exc:
            return self._error_result(
                "Failed to write file.",
                error=exc,
                error_code="write_file_failed",
                metadata={"path": str(path)},
            )

    def replace_text(
        self,
        path: Union[str, Path],
        old_text: str,
        new_text: str,
        *,
        context: Union[TaskContext, Dict[str, Any]],
        allow_multiple: bool = False,
        encoding: str = "utf-8",
        make_backup: bool = True,
    ) -> Dict[str, Any]:
        """
        Replace text in a file.

        By default, exactly one occurrence must exist.
        Set allow_multiple=True to replace all occurrences.
        """

        ctx = self._coerce_context(context)
        validation = self._validate_task_context(ctx)
        if not validation["success"]:
            return validation

        if not old_text:
            return self._error_result(
                "old_text cannot be empty.",
                error_code="empty_old_text",
            )

        path_result = self._resolve_safe_path(path, must_exist=True)
        if not path_result["success"]:
            return path_result

        file_path = path_result["data"]["path"]

        operation = EditOperation(
            operation="replace_text",
            path=str(path),
            old_text=old_text,
            new_text=new_text,
            allow_multiple=allow_multiple,
        )

        security = self._handle_security_if_required(operation, ctx)
        if not security["success"]:
            return security

        try:
            self._validate_file_size(file_path)
            before = self._snapshot(file_path)
            old_content = file_path.read_text(encoding=encoding)
            count = old_content.count(old_text)

            if count == 0:
                return self._error_result(
                    "Text to replace was not found.",
                    error_code="old_text_not_found",
                    metadata={"path": self._relative_path(file_path)},
                )

            if count > 1 and not allow_multiple:
                return self._error_result(
                    "Text appears multiple times. Set allow_multiple=True to replace all.",
                    error_code="multiple_matches",
                    metadata={
                        "path": self._relative_path(file_path),
                        "matches": count,
                    },
                )

            new_content = old_content.replace(old_text, new_text)

            backup_path = self._create_backup(file_path, ctx) if make_backup else None
            self._atomic_write(file_path, new_content, encoding=encoding)

            after = self._snapshot(file_path)
            diff = self._make_diff(old_content, new_content, self._relative_path(file_path))

            edit_result = EditResult(
                changed=True,
                path=self._relative_path(file_path),
                before=before,
                after=after,
                backup_path=backup_path,
                diff=diff,
                details={
                    "operation": "replace_text",
                    "matches_replaced": count,
                    "allow_multiple": allow_multiple,
                },
            )

            return self._finalize_edit_result(edit_result, ctx, operation)

        except Exception as exc:
            return self._error_result(
                "Failed to replace text.",
                error=exc,
                error_code="replace_text_failed",
                metadata={"path": str(path)},
            )

    def patch_between_markers(
        self,
        path: Union[str, Path],
        start_marker: str,
        end_marker: str,
        new_content: str,
        *,
        context: Union[TaskContext, Dict[str, Any]],
        include_markers: bool = False,
        encoding: str = "utf-8",
        make_backup: bool = True,
    ) -> Dict[str, Any]:
        """
        Replace content between two marker strings.

        If include_markers=False:
            markers are preserved and only inner block is replaced.

        If include_markers=True:
            start marker, inner block, and end marker are replaced by new_content.
        """

        ctx = self._coerce_context(context)
        validation = self._validate_task_context(ctx)
        if not validation["success"]:
            return validation

        if not start_marker or not end_marker:
            return self._error_result(
                "start_marker and end_marker are required.",
                error_code="missing_markers",
            )

        path_result = self._resolve_safe_path(path, must_exist=True)
        if not path_result["success"]:
            return path_result

        file_path = path_result["data"]["path"]

        operation = EditOperation(
            operation="patch_between_markers",
            path=str(path),
            start_marker=start_marker,
            end_marker=end_marker,
            content=new_content,
            metadata={"include_markers": include_markers},
        )

        security = self._handle_security_if_required(operation, ctx)
        if not security["success"]:
            return security

        try:
            self._validate_file_size(file_path)
            before = self._snapshot(file_path)
            old_content = file_path.read_text(encoding=encoding)

            start_index = old_content.find(start_marker)
            if start_index == -1:
                return self._error_result(
                    "start_marker not found.",
                    error_code="start_marker_not_found",
                    metadata={"path": self._relative_path(file_path)},
                )

            end_search_start = start_index + len(start_marker)
            end_index = old_content.find(end_marker, end_search_start)
            if end_index == -1:
                return self._error_result(
                    "end_marker not found after start_marker.",
                    error_code="end_marker_not_found",
                    metadata={"path": self._relative_path(file_path)},
                )

            if include_markers:
                replace_start = start_index
                replace_end = end_index + len(end_marker)
                replacement = new_content
            else:
                replace_start = start_index + len(start_marker)
                replace_end = end_index
                replacement = self._normalize_inner_block(new_content, old_content, replace_start, replace_end)

            new_file_content = old_content[:replace_start] + replacement + old_content[replace_end:]

            if new_file_content == old_content:
                return self._safe_result(
                    message="Patch produced no changes.",
                    data={
                        "path": self._relative_path(file_path),
                        "changed": False,
                    },
                    metadata={
                        "agent": self.agent_name,
                        "operation": "patch_between_markers",
                        "context": ctx.to_dict(),
                    },
                )

            backup_path = self._create_backup(file_path, ctx) if make_backup else None
            self._atomic_write(file_path, new_file_content, encoding=encoding)

            after = self._snapshot(file_path)
            diff = self._make_diff(old_content, new_file_content, self._relative_path(file_path))

            edit_result = EditResult(
                changed=True,
                path=self._relative_path(file_path),
                before=before,
                after=after,
                backup_path=backup_path,
                diff=diff,
                details={
                    "operation": "patch_between_markers",
                    "include_markers": include_markers,
                },
            )

            return self._finalize_edit_result(edit_result, ctx, operation)

        except Exception as exc:
            return self._error_result(
                "Failed to patch between markers.",
                error=exc,
                error_code="patch_between_markers_failed",
                metadata={"path": str(path)},
            )

    def insert_before(
        self,
        path: Union[str, Path],
        anchor: str,
        content: str,
        *,
        context: Union[TaskContext, Dict[str, Any]],
        allow_multiple: bool = False,
        encoding: str = "utf-8",
        make_backup: bool = True,
    ) -> Dict[str, Any]:
        """
        Insert content before an anchor string.
        """

        return self._insert_relative_to_anchor(
            path=path,
            anchor=anchor,
            content=content,
            context=context,
            position="before",
            allow_multiple=allow_multiple,
            encoding=encoding,
            make_backup=make_backup,
        )

    def insert_after(
        self,
        path: Union[str, Path],
        anchor: str,
        content: str,
        *,
        context: Union[TaskContext, Dict[str, Any]],
        allow_multiple: bool = False,
        encoding: str = "utf-8",
        make_backup: bool = True,
    ) -> Dict[str, Any]:
        """
        Insert content after an anchor string.
        """

        return self._insert_relative_to_anchor(
            path=path,
            anchor=anchor,
            content=content,
            context=context,
            position="after",
            allow_multiple=allow_multiple,
            encoding=encoding,
            make_backup=make_backup,
        )

    def replace_line_range(
        self,
        path: Union[str, Path],
        line_start: int,
        line_end: int,
        new_content: str,
        *,
        context: Union[TaskContext, Dict[str, Any]],
        encoding: str = "utf-8",
        make_backup: bool = True,
    ) -> Dict[str, Any]:
        """
        Replace a 1-based inclusive line range.

        Example:
            line_start=10, line_end=15 replaces lines 10 through 15.
        """

        ctx = self._coerce_context(context)
        validation = self._validate_task_context(ctx)
        if not validation["success"]:
            return validation

        if line_start < 1 or line_end < line_start:
            return self._error_result(
                "Invalid line range. Use 1-based inclusive lines.",
                error_code="invalid_line_range",
                metadata={"line_start": line_start, "line_end": line_end},
            )

        path_result = self._resolve_safe_path(path, must_exist=True)
        if not path_result["success"]:
            return path_result

        file_path = path_result["data"]["path"]

        operation = EditOperation(
            operation="replace_line_range",
            path=str(path),
            line_start=line_start,
            line_end=line_end,
            content=new_content,
        )

        security = self._handle_security_if_required(operation, ctx)
        if not security["success"]:
            return security

        try:
            self._validate_file_size(file_path)
            before = self._snapshot(file_path)
            old_content = file_path.read_text(encoding=encoding)
            lines = old_content.splitlines(keepends=True)

            if line_start > len(lines):
                return self._error_result(
                    "line_start is beyond the file length.",
                    error_code="line_start_out_of_range",
                    metadata={
                        "path": self._relative_path(file_path),
                        "total_lines": len(lines),
                    },
                )

            end_index = min(line_end, len(lines))
            replacement_lines = self._content_to_lines(new_content)

            new_lines = (
                lines[:line_start - 1]
                + replacement_lines
                + lines[end_index:]
            )
            new_file_content = "".join(new_lines)

            backup_path = self._create_backup(file_path, ctx) if make_backup else None
            self._atomic_write(file_path, new_file_content, encoding=encoding)

            after = self._snapshot(file_path)
            diff = self._make_diff(old_content, new_file_content, self._relative_path(file_path))

            edit_result = EditResult(
                changed=(old_content != new_file_content),
                path=self._relative_path(file_path),
                before=before,
                after=after,
                backup_path=backup_path,
                diff=diff,
                details={
                    "operation": "replace_line_range",
                    "line_start": line_start,
                    "line_end": line_end,
                    "actual_line_end": end_index,
                },
            )

            return self._finalize_edit_result(edit_result, ctx, operation)

        except Exception as exc:
            return self._error_result(
                "Failed to replace line range.",
                error=exc,
                error_code="replace_line_range_failed",
                metadata={"path": str(path)},
            )

    def apply_operations(
        self,
        operations: List[Dict[str, Any]],
        *,
        context: Union[TaskContext, Dict[str, Any]],
        stop_on_error: bool = True,
    ) -> Dict[str, Any]:
        """
        Apply multiple edit operations in order.

        Supported operation names:
            - write_file
            - replace_text
            - patch_between_markers
            - insert_before
            - insert_after
            - replace_line_range
        """

        ctx = self._coerce_context(context)
        validation = self._validate_task_context(ctx)
        if not validation["success"]:
            return validation

        if not isinstance(operations, list) or not operations:
            return self._error_result(
                "operations must be a non-empty list.",
                error_code="invalid_operations",
            )

        results: List[Dict[str, Any]] = []
        errors: List[Dict[str, Any]] = []

        for index, operation in enumerate(operations):
            op_name = operation.get("operation")
            task = {
                **operation,
                "context": ctx.to_dict(),
            }

            result = self.run(task)
            result["metadata"] = {
                **result.get("metadata", {}),
                "batch_index": index,
                "batch_operation": op_name,
            }

            results.append(result)

            if not result.get("success"):
                errors.append(result)
                if stop_on_error:
                    break

        success = not errors

        final = self._safe_result(
            message="Batch operations completed." if success else "Batch operations completed with errors.",
            data={
                "results": results,
                "errors": errors,
                "total": len(operations),
                "completed": len(results),
                "failed": len(errors),
            },
            metadata={
                "agent": self.agent_name,
                "operation": "apply_operations",
                "context": ctx.to_dict(),
                "stop_on_error": stop_on_error,
            },
        )
        final["success"] = success

        self._emit_agent_event("code_editor.batch_completed", final)
        self._log_audit_event("code_editor.batch_completed", final)

        return final

    def preview_replace_text(
        self,
        path: Union[str, Path],
        old_text: str,
        new_text: str,
        *,
        context: Union[TaskContext, Dict[str, Any]],
        allow_multiple: bool = False,
        encoding: str = "utf-8",
    ) -> Dict[str, Any]:
        """
        Preview a replace_text operation without writing changes.
        """

        ctx = self._coerce_context(context)
        validation = self._validate_task_context(ctx)
        if not validation["success"]:
            return validation

        path_result = self._resolve_safe_path(path, must_exist=True)
        if not path_result["success"]:
            return path_result

        file_path = path_result["data"]["path"]

        try:
            old_content = file_path.read_text(encoding=encoding)
            count = old_content.count(old_text)

            if count == 0:
                return self._error_result(
                    "Text to replace was not found.",
                    error_code="old_text_not_found",
                    metadata={"path": self._relative_path(file_path)},
                )

            if count > 1 and not allow_multiple:
                return self._error_result(
                    "Text appears multiple times. Set allow_multiple=True to preview all replacements.",
                    error_code="multiple_matches",
                    metadata={"matches": count},
                )

            new_content = old_content.replace(old_text, new_text)
            diff = self._make_diff(old_content, new_content, self._relative_path(file_path))

            return self._safe_result(
                message="Preview generated successfully.",
                data={
                    "path": self._relative_path(file_path),
                    "matches": count,
                    "changed": old_content != new_content,
                    "diff": diff,
                },
                metadata={
                    "agent": self.agent_name,
                    "operation": "preview_replace_text",
                    "context": ctx.to_dict(),
                },
            )

        except Exception as exc:
            return self._error_result(
                "Failed to preview replacement.",
                error=exc,
                error_code="preview_replace_text_failed",
                metadata={"path": str(path)},
            )

    # ------------------------------------------------------------------
    # Internal edit helpers
    # ------------------------------------------------------------------

    def _insert_relative_to_anchor(
        self,
        *,
        path: Union[str, Path],
        anchor: str,
        content: str,
        context: Union[TaskContext, Dict[str, Any]],
        position: str,
        allow_multiple: bool,
        encoding: str,
        make_backup: bool,
    ) -> Dict[str, Any]:
        ctx = self._coerce_context(context)
        validation = self._validate_task_context(ctx)
        if not validation["success"]:
            return validation

        if not anchor:
            return self._error_result(
                "anchor cannot be empty.",
                error_code="empty_anchor",
            )

        if position not in {"before", "after"}:
            return self._error_result(
                "position must be 'before' or 'after'.",
                error_code="invalid_position",
            )

        path_result = self._resolve_safe_path(path, must_exist=True)
        if not path_result["success"]:
            return path_result

        file_path = path_result["data"]["path"]

        operation = EditOperation(
            operation=f"insert_{position}",
            path=str(path),
            anchor=anchor,
            content=content,
            allow_multiple=allow_multiple,
        )

        security = self._handle_security_if_required(operation, ctx)
        if not security["success"]:
            return security

        try:
            self._validate_file_size(file_path)
            before = self._snapshot(file_path)
            old_content = file_path.read_text(encoding=encoding)
            count = old_content.count(anchor)

            if count == 0:
                return self._error_result(
                    "Anchor was not found.",
                    error_code="anchor_not_found",
                    metadata={"path": self._relative_path(file_path)},
                )

            if count > 1 and not allow_multiple:
                return self._error_result(
                    "Anchor appears multiple times. Set allow_multiple=True to insert at all matches.",
                    error_code="multiple_anchors",
                    metadata={
                        "path": self._relative_path(file_path),
                        "matches": count,
                    },
                )

            if position == "before":
                replacement = content + anchor
            else:
                replacement = anchor + content

            new_file_content = old_content.replace(anchor, replacement)

            backup_path = self._create_backup(file_path, ctx) if make_backup else None
            self._atomic_write(file_path, new_file_content, encoding=encoding)

            after = self._snapshot(file_path)
            diff = self._make_diff(old_content, new_file_content, self._relative_path(file_path))

            edit_result = EditResult(
                changed=(old_content != new_file_content),
                path=self._relative_path(file_path),
                before=before,
                after=after,
                backup_path=backup_path,
                diff=diff,
                details={
                    "operation": f"insert_{position}",
                    "matches": count,
                    "allow_multiple": allow_multiple,
                },
            )

            return self._finalize_edit_result(edit_result, ctx, operation)

        except Exception as exc:
            return self._error_result(
                f"Failed to insert {position} anchor.",
                error=exc,
                error_code=f"insert_{position}_failed",
                metadata={"path": str(path)},
            )

    def _finalize_edit_result(
        self,
        edit_result: EditResult,
        context: TaskContext,
        operation: EditOperation,
    ) -> Dict[str, Any]:
        verification_payload = self._prepare_verification_payload(edit_result, context, operation)
        memory_payload = self._prepare_memory_payload(edit_result, context, operation)

        result = self._safe_result(
            message="File edit completed successfully.",
            data={
                "changed": edit_result.changed,
                "path": edit_result.path,
                "before": edit_result.before.to_dict(),
                "after": edit_result.after.to_dict(),
                "backup_path": edit_result.backup_path,
                "diff": edit_result.diff,
                "details": edit_result.details,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                "agent": self.agent_name,
                "operation": operation.operation,
                "context": context.to_dict(),
            },
        )

        self._emit_agent_event("code_editor.file_changed", result)
        self._log_audit_event("code_editor.file_changed", result)

        return result

    # ------------------------------------------------------------------
    # Required compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(self, context: TaskContext) -> Dict[str, Any]:
        """
        Validate SaaS context.

        Every user-specific execution must include user_id and workspace_id.
        """

        if context is None:
            return self._error_result(
                "Task context is required.",
                error_code="missing_context",
            )

        if context.user_id in (None, "", 0):
            return self._error_result(
                "user_id is required for SaaS-safe execution.",
                error_code="missing_user_id",
            )

        if context.workspace_id in (None, "", 0):
            return self._error_result(
                "workspace_id is required for SaaS-safe execution.",
                error_code="missing_workspace_id",
            )

        return self._safe_result(
            message="Task context validated.",
            data={"context": context.to_dict()},
            metadata={"agent": self.agent_name},
        )

    def _requires_security_check(
        self,
        operation: EditOperation,
        context: TaskContext,
    ) -> bool:
        """
        Decide whether the Security Agent must approve this edit.

        Security approval is required for:
            - Files likely to contain secrets.
            - Paths outside normal source/config docs.
            - Destructive overwrite-style edits.
            - Content that appears to include secrets.
            - Shell scripts or executable configs.
        """

        path = Path(operation.path)
        name = path.name.lower()
        suffix = path.suffix.lower()

        if name in self.denied_filenames:
            return True

        if suffix in {".sh", ".bat", ".ps1", ".cmd"}:
            return True

        combined_text = "\n".join(
            str(value or "")
            for value in [
                operation.content,
                operation.old_text,
                operation.new_text,
                operation.start_marker,
                operation.end_marker,
                operation.anchor,
            ]
        )

        if self._contains_sensitive_pattern(combined_text):
            return True

        if operation.operation in {
            "write_file",
            "replace_line_range",
            "patch_between_markers",
        }:
            return True

        return False

    def _request_security_approval(
        self,
        operation: EditOperation,
        context: TaskContext,
    ) -> Dict[str, Any]:
        """
        Request approval from Security Agent.

        If a security_callback is provided, it is called.
        Otherwise, safe default policy allows normal source edits and blocks
        obvious secret files.
        """

        payload = {
            "agent": self.agent_name,
            "event": "security_approval_requested",
            "operation": asdict(operation),
            "context": context.to_dict(),
            "timestamp": self._utc_now(),
            "risk": self._classify_operation_risk(operation),
        }

        if self.security_callback:
            try:
                response = self.security_callback(payload)
                if not isinstance(response, dict):
                    return self._error_result(
                        "Security callback returned invalid response.",
                        error_code="invalid_security_response",
                        metadata={"payload": payload},
                    )
                return response
            except Exception as exc:
                return self._error_result(
                    "Security approval callback failed.",
                    error=exc,
                    error_code="security_callback_failed",
                    metadata={"payload": payload},
                )

        path = Path(operation.path)
        if path.name.lower() in self.denied_filenames:
            return self._error_result(
                "Security policy blocked editing protected secret file.",
                error_code="security_blocked_secret_file",
                metadata=payload,
            )

        if self._contains_sensitive_pattern(str(operation.content or "")):
            return self._error_result(
                "Security policy blocked writing sensitive-looking content.",
                error_code="security_blocked_sensitive_content",
                metadata=payload,
            )

        return self._safe_result(
            message="Security approval granted by default safe policy.",
            data={"approved": True, "security_payload": payload},
            metadata={"agent": self.agent_name},
        )

    def _prepare_verification_payload(
        self,
        edit_result: EditResult,
        context: TaskContext,
        operation: EditOperation,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        The Verification Agent can use this to check:
            - File exists.
            - Hash changed when expected.
            - Diff is valid.
            - Syntax checks can run later.
        """

        return {
            "agent": self.agent_name,
            "target_agent": "VerificationAgent",
            "type": "code_edit_verification",
            "operation": operation.operation,
            "path": edit_result.path,
            "changed": edit_result.changed,
            "before": edit_result.before.to_dict(),
            "after": edit_result.after.to_dict(),
            "backup_path": edit_result.backup_path,
            "checks": {
                "file_exists": edit_result.after.exists,
                "hash_changed": edit_result.before.sha256 != edit_result.after.sha256,
                "has_diff": bool(edit_result.diff.strip()),
                "size_within_limit": edit_result.after.size_bytes <= self.max_file_size_bytes,
            },
            "context": context.to_dict(),
            "timestamp": self._utc_now(),
        }

    def _prepare_memory_payload(
        self,
        edit_result: EditResult,
        context: TaskContext,
        operation: EditOperation,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent payload.

        Stores safe metadata about the edit, not full code content by default.
        """

        return {
            "agent": self.agent_name,
            "target_agent": "MemoryAgent",
            "type": "code_edit_memory",
            "summary": f"{operation.operation} applied to {edit_result.path}",
            "path": edit_result.path,
            "changed": edit_result.changed,
            "details": edit_result.details,
            "context": {
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
                "request_id": context.request_id,
                "session_id": context.session_id,
            },
            "timestamp": self._utc_now(),
        }

    def _emit_agent_event(self, event_name: str, payload: Dict[str, Any]) -> None:
        """
        Emit event for Agent Registry, Dashboard, analytics, or task history.
        """

        event = {
            "event": event_name,
            "agent": self.agent_name,
            "payload": payload,
            "timestamp": self._utc_now(),
        }

        if self.event_callback:
            try:
                self.event_callback(event)
            except Exception:
                logger.exception("CodeEditor event callback failed.")

        logger.debug("Agent event emitted: %s", event_name)

    def _log_audit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
        """
        Log audit event.

        In production this can be wired to the Audit Log service.
        """

        audit_event = {
            "event": event_name,
            "agent": self.agent_name,
            "payload": self._safe_audit_payload(payload),
            "timestamp": self._utc_now(),
        }

        if self.audit_callback:
            try:
                self.audit_callback(audit_event)
            except Exception:
                logger.exception("CodeEditor audit callback failed.")

        logger.info("Audit event: %s", event_name)

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        error: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard success response.
        """

        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": self._serialize_error(error) if error else None,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        message: str,
        *,
        error: Optional[Any] = None,
        error_code: str = "error",
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard error response.
        """

        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": {
                "code": error_code,
                "detail": self._serialize_error(error) if error else message,
            },
            "metadata": metadata or {},
        }

    # ------------------------------------------------------------------
    # Path / filesystem safety
    # ------------------------------------------------------------------

    def _resolve_safe_path(
        self,
        path: Union[str, Path],
        *,
        must_exist: bool,
    ) -> Dict[str, Any]:
        """
        Resolve and validate a path inside project_root.
        """

        if path is None or str(path).strip() == "":
            return self._error_result(
                "Path is required.",
                error_code="missing_path",
            )

        raw_path = Path(str(path).strip())

        if raw_path.is_absolute():
            candidate = raw_path.resolve()
        else:
            candidate = (self.project_root / raw_path).resolve()

        try:
            candidate.relative_to(self.project_root)
        except ValueError:
            return self._error_result(
                "Path escapes project_root and is not allowed.",
                error_code="path_escape_blocked",
                metadata={
                    "project_root": str(self.project_root),
                    "path": str(candidate),
                },
            )

        parts_lower = {part.lower() for part in candidate.parts}
        denied_hit = parts_lower.intersection({p.lower() for p in self.denied_path_parts})
        if denied_hit:
            return self._error_result(
                "Path contains denied folder.",
                error_code="denied_path_part",
                metadata={"denied": sorted(denied_hit), "path": str(candidate)},
            )

        if candidate.name.lower() in {name.lower() for name in self.denied_filenames}:
            return self._error_result(
                "Editing this filename is blocked by default policy.",
                error_code="denied_filename",
                metadata={"filename": candidate.name},
            )

        if must_exist and not candidate.exists():
            return self._error_result(
                "File does not exist.",
                error_code="file_not_found",
                metadata={"path": self._relative_path(candidate)},
            )

        if candidate.exists() and not candidate.is_file():
            return self._error_result(
                "Path is not a file.",
                error_code="not_a_file",
                metadata={"path": self._relative_path(candidate)},
            )

        if not self._extension_allowed(candidate):
            return self._error_result(
                "File extension is not allowed for CodeEditor.",
                error_code="extension_not_allowed",
                metadata={
                    "path": self._relative_path(candidate),
                    "suffix": candidate.suffix,
                },
            )

        return self._safe_result(
            message="Path validated.",
            data={"path": candidate},
            metadata={"project_root": str(self.project_root)},
        )

    def _extension_allowed(self, path: Path) -> bool:
        """
        Validate extension or special filename.
        """

        name_lower = path.name.lower()
        suffix_lower = path.suffix.lower()

        if name_lower in {".gitignore", ".dockerignore", "dockerfile", "makefile"}:
            return True

        if suffix_lower in self.allowed_extensions:
            return True

        if name_lower.endswith(".env.example"):
            return True

        return False

    def _validate_file_size(self, path: Path) -> None:
        if path.exists() and path.stat().st_size > self.max_file_size_bytes:
            raise ValueError(
                f"File exceeds max size limit: {path.stat().st_size} > {self.max_file_size_bytes}"
            )

    def _create_backup(self, file_path: Path, context: TaskContext) -> Optional[str]:
        """
        Create a backup copy before editing.
        """

        if not file_path.exists():
            return None

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        safe_user = self._safe_slug(str(context.user_id))
        safe_workspace = self._safe_slug(str(context.workspace_id))

        backup_root = self.project_root / self.backup_dir_name / safe_user / safe_workspace
        backup_root.mkdir(parents=True, exist_ok=True)

        relative = Path(self._relative_path(file_path))
        backup_name = f"{relative.name}.{timestamp}.bak"
        backup_path = backup_root / relative.parent / backup_name
        backup_path.parent.mkdir(parents=True, exist_ok=True)

        shutil.copy2(file_path, backup_path)

        return self._relative_path(backup_path)

    def _atomic_write(self, file_path: Path, content: str, *, encoding: str = "utf-8") -> None:
        """
        Write file atomically to reduce corruption risk.
        """

        file_path.parent.mkdir(parents=True, exist_ok=True)

        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding=encoding,
            dir=str(file_path.parent),
            delete=False,
            newline="",
        ) as tmp:
            tmp.write(content)
            tmp_path = Path(tmp.name)

        os.replace(tmp_path, file_path)

    # ------------------------------------------------------------------
    # Content helpers
    # ------------------------------------------------------------------

    def _make_diff(self, old_content: str, new_content: str, path: str) -> str:
        """
        Create unified diff.
        """

        old_lines = old_content.splitlines(keepends=True)
        new_lines = new_content.splitlines(keepends=True)

        return "".join(
            difflib.unified_diff(
                old_lines,
                new_lines,
                fromfile=f"{path}:before",
                tofile=f"{path}:after",
                lineterm="",
            )
        )

    def _normalize_inner_block(
        self,
        new_content: str,
        old_content: str,
        replace_start: int,
        replace_end: int,
    ) -> str:
        """
        Preserve marker-adjacent newline style when replacing inner blocks.
        """

        before_char = old_content[replace_start - 1:replace_start] if replace_start > 0 else ""
        after_char = old_content[replace_end:replace_end + 1]

        result = new_content

        if before_char != "\n" and not result.startswith("\n"):
            result = "\n" + result

        if after_char != "\n" and not result.endswith("\n"):
            result = result + "\n"

        return result

    def _content_to_lines(self, content: str) -> List[str]:
        """
        Convert replacement content to keepends-style lines.
        """

        if content == "":
            return []

        lines = content.splitlines(keepends=True)
        if lines and not lines[-1].endswith(("\n", "\r")):
            lines[-1] = lines[-1] + "\n"

        return lines

    def _contains_sensitive_pattern(self, text: str) -> bool:
        if not text:
            return False

        return any(pattern.search(text) for pattern in self.SENSITIVE_PATTERNS)

    def _classify_operation_risk(self, operation: EditOperation) -> Dict[str, Any]:
        text = "\n".join(
            str(value or "")
            for value in [
                operation.path,
                operation.content,
                operation.old_text,
                operation.new_text,
            ]
        )

        risk_level = "low"
        reasons: List[str] = []

        if operation.operation in {"write_file", "replace_line_range", "patch_between_markers"}:
            risk_level = "medium"
            reasons.append("operation_changes_large_or_structural_content")

        if self._contains_sensitive_pattern(text):
            risk_level = "high"
            reasons.append("sensitive_pattern_detected")

        if Path(operation.path).suffix.lower() in {".sh", ".bat", ".ps1", ".cmd"}:
            risk_level = "high"
            reasons.append("script_or_executable_file")

        if Path(operation.path).name.lower() in self.denied_filenames:
            risk_level = "critical"
            reasons.append("protected_secret_filename")

        return {
            "level": risk_level,
            "reasons": reasons,
        }

    # ------------------------------------------------------------------
    # Snapshot / hashing
    # ------------------------------------------------------------------

    def _snapshot(self, file_path: Path) -> FileSnapshot:
        if not file_path.exists():
            return FileSnapshot(
                path=self._relative_path(file_path),
                exists=False,
            )

        stat = file_path.stat()

        return FileSnapshot(
            path=self._relative_path(file_path),
            exists=True,
            size_bytes=stat.st_size,
            sha256=self._sha256_file(file_path),
            modified_at=datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
        )

    def _sha256_file(self, file_path: Path) -> str:
        digest = hashlib.sha256()
        with file_path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    # ------------------------------------------------------------------
    # Context / serialization helpers
    # ------------------------------------------------------------------

    def _coerce_context(self, context: Union[TaskContext, Dict[str, Any]]) -> TaskContext:
        if isinstance(context, TaskContext):
            return context

        if not isinstance(context, dict):
            return TaskContext(user_id="", workspace_id="")

        return TaskContext(
            user_id=context.get("user_id", ""),
            workspace_id=context.get("workspace_id", ""),
            role=context.get("role"),
            subscription=context.get("subscription"),
            permissions=list(context.get("permissions") or []),
            request_id=context.get("request_id"),
            session_id=context.get("session_id"),
            ip_address=context.get("ip_address"),
            user_agent=context.get("user_agent"),
        )

    def _handle_security_if_required(
        self,
        operation: EditOperation,
        context: TaskContext,
    ) -> Dict[str, Any]:
        if not self._requires_security_check(operation, context):
            return self._safe_result(
                message="Security check not required.",
                data={"approved": True},
            )

        approval = self._request_security_approval(operation, context)
        if not approval.get("success"):
            return approval

        approved = approval.get("data", {}).get("approved", True)
        if approved is False:
            return self._error_result(
                "Security Agent did not approve this edit.",
                error_code="security_not_approved",
                metadata={
                    "operation": operation.operation,
                    "path": operation.path,
                },
            )

        return approval

    def _safe_audit_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Strip very large or sensitive fields from audit logs.
        """

        safe = json.loads(json.dumps(payload, default=str))

        data = safe.get("data")
        if isinstance(data, dict):
            if "diff" in data and isinstance(data["diff"], str):
                data["diff_preview"] = data["diff"][:2000]
                data.pop("diff", None)

            if "memory_payload" in data:
                data["memory_payload"] = {
                    "type": data["memory_payload"].get("type"),
                    "summary": data["memory_payload"].get("summary"),
                    "path": data["memory_payload"].get("path"),
                }

            if "verification_payload" in data:
                data["verification_payload"] = {
                    "type": data["verification_payload"].get("type"),
                    "path": data["verification_payload"].get("path"),
                    "changed": data["verification_payload"].get("changed"),
                    "checks": data["verification_payload"].get("checks"),
                }

        return safe

    def _serialize_error(self, error: Any) -> Any:
        if error is None:
            return None

        if isinstance(error, Exception):
            return {
                "type": error.__class__.__name__,
                "message": str(error),
            }

        return str(error)

    def _relative_path(self, path: Path) -> str:
        try:
            return str(path.resolve().relative_to(self.project_root))
        except Exception:
            return str(path)

    def _safe_slug(self, value: str) -> str:
        value = re.sub(r"[^a-zA-Z0-9_.-]+", "_", value.strip())
        return value[:80] or "unknown"

    def _utc_now(self) -> str:
        return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Optional standalone smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    editor = CodeEditor(project_root=os.getcwd())

    demo_context = {
        "user_id": "demo_user",
        "workspace_id": "demo_workspace",
        "role": "admin",
        "permissions": ["code:edit"],
    }

    demo_path = "tmp_code_editor_demo.txt"

    print(
        json.dumps(
            editor.write_file(
                demo_path,
                "Hello William\n",
                context=demo_context,
                create_if_missing=True,
                overwrite=True,
            ),
            indent=2,
            default=str,
        )
    )

    print(
        json.dumps(
            editor.replace_text(
                demo_path,
                "Hello William",
                "Hello Jarvis",
                context=demo_context,
            ),
            indent=2,
            default=str,
        )
    )