"""
agents/system_agent/file_manager.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Safe file and folder management helper for the System Agent.

Responsibilities:
    - Create files and folders.
    - Rename files and folders.
    - Move files and folders.
    - Copy files and folders.
    - Delete files and folders with security approval.
    - Backup files and folders.
    - Search files and folders safely.
    - Compress files and folders into ZIP archives.
    - Organize files by extension, date, or type.
    - Maintain SaaS user/workspace isolation.
    - Route sensitive actions through Security Agent hooks.
    - Prepare Verification Agent payloads.
    - Prepare Memory Agent compatible payloads.
    - Emit agent events for dashboard/API/task history.
    - Log tenant-scoped audit events.

Design Notes:
    This file is import-safe. If William/Jarvis BaseAgent, config, Security Agent,
    Memory Agent, Verification Agent, or Event Bus modules do not exist yet,
    safe fallback stubs are used.

    File operations are restricted to a controlled workspace root. The class
    prevents path traversal and blocks unsafe system paths.

Expected Path:
    agents/system_agent/file_manager.py
"""

from __future__ import annotations

import datetime
import fnmatch
import hashlib
import json
import logging
import mimetypes
import os
import re
import shutil
import stat
import time
import uuid
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Optional William/Jarvis imports with safe fallbacks
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover

    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        Used only when the real William/Jarvis BaseAgent does not exist yet.
        Keeps this file import-safe.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_type = kwargs.get("agent_type", "system")
            self.logger = logging.getLogger(self.agent_name)


try:
    from core.config import settings  # type: ignore
except Exception:  # pragma: no cover

    class _FallbackSettings:
        """
        Safe fallback settings.

        Real project settings can override these later.
        """

        ENVIRONMENT = os.getenv("WILLIAM_ENVIRONMENT", "development")
        DEBUG = os.getenv("WILLIAM_DEBUG", "false").lower() in {"1", "true", "yes"}
        FILE_MANAGER_ROOT = os.getenv(
            "FILE_MANAGER_ROOT",
            str(Path.cwd() / "storage" / "workspaces"),
        )
        FILE_MANAGER_BACKUP_ROOT = os.getenv(
            "FILE_MANAGER_BACKUP_ROOT",
            str(Path.cwd() / "storage" / "backups"),
        )
        FILE_MANAGER_MAX_FILE_BYTES = int(
            os.getenv("FILE_MANAGER_MAX_FILE_BYTES", str(50 * 1024 * 1024))
        )
        FILE_MANAGER_MAX_SEARCH_RESULTS = int(
            os.getenv("FILE_MANAGER_MAX_SEARCH_RESULTS", "500")
        )
        FILE_MANAGER_ALLOW_DELETE = os.getenv(
            "FILE_MANAGER_ALLOW_DELETE",
            "true",
        ).lower() in {"1", "true", "yes"}
        FILE_MANAGER_ALLOW_COMPRESS = os.getenv(
            "FILE_MANAGER_ALLOW_COMPRESS",
            "true",
        ).lower() in {"1", "true", "yes"}

    settings = _FallbackSettings()  # type: ignore


# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------

LOGGER = logging.getLogger("William.SystemAgent.FileManager")
if not LOGGER.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class TaskContext:
    """
    Normalized SaaS task context.

    Every user/workspace-specific operation must include user_id and workspace_id.
    This prevents cross-user or cross-workspace file access.
    """

    user_id: str
    workspace_id: str
    request_id: str
    role: Optional[str] = None
    session_id: Optional[str] = None
    agent_name: str = "FileManager"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FileOperationRecord:
    """
    Audit-friendly record for a file operation.
    """

    operation_id: str
    action: str
    source_path: Optional[str]
    target_path: Optional[str]
    started_at: str
    finished_at: Optional[str] = None
    duration_ms: Optional[int] = None
    success: bool = False
    user_id: Optional[str] = None
    workspace_id: Optional[str] = None
    request_id: Optional[str] = None


@dataclass(frozen=True)
class FileManagerConfig:
    """
    File Manager runtime configuration.
    """

    root_path: Path
    backup_root_path: Path
    max_file_bytes: int = 50 * 1024 * 1024
    max_search_results: int = 500
    allow_delete: bool = True
    allow_compress: bool = True


# ---------------------------------------------------------------------------
# Safety constants
# ---------------------------------------------------------------------------

BLOCKED_PATH_PARTS: Tuple[str, ...] = (
    ".ssh",
    ".aws",
    ".gcp",
    ".azure",
    ".kube",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "authorized_keys",
    "known_hosts",
    "shadow",
    "passwd",
    "sudoers",
)

BLOCKED_EXTENSIONS: Tuple[str, ...] = (
    ".pem",
    ".key",
    ".crt",
    ".p12",
    ".pfx",
    ".env",
    ".secret",
    ".secrets",
)

TEXT_EXTENSIONS: Tuple[str, ...] = (
    ".txt",
    ".md",
    ".json",
    ".yaml",
    ".yml",
    ".csv",
    ".log",
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".html",
    ".css",
    ".scss",
    ".xml",
    ".sql",
    ".ini",
    ".cfg",
    ".toml",
)

IMAGE_EXTENSIONS: Tuple[str, ...] = (
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".webp",
    ".svg",
    ".bmp",
    ".tiff",
)

DOCUMENT_EXTENSIONS: Tuple[str, ...] = (
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
)

ARCHIVE_EXTENSIONS: Tuple[str, ...] = (
    ".zip",
    ".tar",
    ".gz",
    ".rar",
    ".7z",
)

SAFE_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9._@+\-\s()]{1,255}$")
SECRET_PATTERN = re.compile(
    r"(?i)(api[_-]?key|secret|token|password|passwd|authorization|bearer)\s*[:=]\s*[^\s]+"
)


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class FileManager(BaseAgent):
    """
    Safe file/folder manager for William/Jarvis System Agent.

    Integration:
        - Master Agent:
            Routes file tasks to public methods.
        - Security Agent:
            Sensitive operations call _requires_security_check() and
            _request_security_approval().
        - Memory Agent:
            Useful context is prepared through _prepare_memory_payload().
        - Verification Agent:
            Completed operations generate verification payloads.
        - Dashboard/API:
            All methods return structured dicts.
        - Registry/Loader/Router:
            Import-safe and BaseAgent-compatible.
    """

    agent_name = "FileManager"
    agent_type = "system"
    version = "1.0.0"

    def __init__(
        self,
        security_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        config: Optional[FileManagerConfig] = None,
        root_path: Optional[Union[str, Path]] = None,
        backup_root_path: Optional[Union[str, Path]] = None,
        max_file_bytes: Optional[int] = None,
        max_search_results: Optional[int] = None,
        allow_delete: Optional[bool] = None,
        allow_compress: Optional[bool] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name=self.agent_name, agent_type=self.agent_type, **kwargs)

        self.logger = getattr(self, "logger", LOGGER) or LOGGER

        self.security_agent = security_agent
        self.memory_agent = memory_agent
        self.verification_agent = verification_agent
        self.event_bus = event_bus
        self.audit_logger = audit_logger

        if config is None:
            config = FileManagerConfig(
                root_path=Path(
                    root_path
                    or getattr(settings, "FILE_MANAGER_ROOT", Path.cwd() / "storage" / "workspaces")
                ).expanduser().resolve(),
                backup_root_path=Path(
                    backup_root_path
                    or getattr(settings, "FILE_MANAGER_BACKUP_ROOT", Path.cwd() / "storage" / "backups")
                ).expanduser().resolve(),
                max_file_bytes=int(
                    max_file_bytes
                    if max_file_bytes is not None
                    else getattr(settings, "FILE_MANAGER_MAX_FILE_BYTES", 50 * 1024 * 1024)
                ),
                max_search_results=int(
                    max_search_results
                    if max_search_results is not None
                    else getattr(settings, "FILE_MANAGER_MAX_SEARCH_RESULTS", 500)
                ),
                allow_delete=bool(
                    allow_delete
                    if allow_delete is not None
                    else getattr(settings, "FILE_MANAGER_ALLOW_DELETE", True)
                ),
                allow_compress=bool(
                    allow_compress
                    if allow_compress is not None
                    else getattr(settings, "FILE_MANAGER_ALLOW_COMPRESS", True)
                ),
            )

        self.config = config
        self.config.root_path.mkdir(parents=True, exist_ok=True)
        self.config.backup_root_path.mkdir(parents=True, exist_ok=True)

        self._operation_history: List[FileOperationRecord] = []

    # -----------------------------------------------------------------------
    # Public methods
    # -----------------------------------------------------------------------

    def create_file(
        self,
        relative_path: Union[str, Path],
        content: Union[str, bytes] = "",
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        overwrite: bool = False,
        encoding: str = "utf-8",
        role: Optional[str] = None,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create a file inside the user's isolated workspace.
        """

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            session_id=session_id,
            request_id=request_id,
            metadata=metadata,
        )
        if not context_result["success"]:
            return context_result

        context: TaskContext = context_result["data"]["context"]

        path_result = self._resolve_workspace_path(context, relative_path)
        if not path_result["success"]:
            return path_result

        file_path: Path = path_result["data"]["path"]

        if file_path.exists() and not overwrite:
            return self._error_result(
                message="File already exists. Set overwrite=True to replace it.",
                error="file_exists",
                data={"path": self._display_path(file_path, context)},
                metadata=self._result_metadata(context, action="create_file"),
            )

        content_size = len(content.encode(encoding)) if isinstance(content, str) else len(content)
        if content_size > self.config.max_file_bytes:
            return self._error_result(
                message="File content exceeds configured maximum size.",
                error="file_too_large",
                data={
                    "size_bytes": content_size,
                    "max_file_bytes": self.config.max_file_bytes,
                },
                metadata=self._result_metadata(context, action="create_file"),
            )

        security_needed = self._requires_security_check(
            action="create_file",
            payload={
                "path": str(file_path),
                "overwrite": overwrite,
                "size_bytes": content_size,
            },
            context=context,
        )
        if security_needed:
            approval = self._request_security_approval(
                action="create_file",
                payload={
                    "relative_path": str(relative_path),
                    "overwrite": overwrite,
                    "size_bytes": content_size,
                },
                context=context,
            )
            if not approval.get("approved", False):
                return self._error_result(
                    message="Security approval denied for file creation.",
                    error="security_approval_denied",
                    metadata=self._result_metadata(context, action="create_file"),
                )

        operation = self._start_operation("create_file", context, file_path, None)

        try:
            file_path.parent.mkdir(parents=True, exist_ok=True)

            if isinstance(content, bytes):
                file_path.write_bytes(content)
            else:
                file_path.write_text(content, encoding=encoding)

            data = self._file_info(file_path, context)
            self._finish_operation(operation, True)

            self._log_audit_event(
                action="file_created",
                context=context,
                success=True,
                details={
                    "path": self._display_path(file_path, context),
                    "size_bytes": data.get("size_bytes"),
                    "overwrite": overwrite,
                },
            )

            verification_payload = self._prepare_verification_payload(
                action="create_file",
                context=context,
                result_data=data,
                success=True,
            )
            memory_payload = self._prepare_memory_payload(
                action="create_file",
                context=context,
                result_data=data,
            )

            self._emit_agent_event(
                event_name="file_created",
                context=context,
                payload=data,
            )

            return self._safe_result(
                message="File created successfully.",
                data=data,
                metadata=self._result_metadata(
                    context,
                    action="create_file",
                    verification_payload=verification_payload,
                    memory_payload=memory_payload,
                ),
            )

        except Exception as exc:
            self._finish_operation(operation, False)
            self.logger.exception("Failed to create file.")
            return self._error_result(
                message="Failed to create file.",
                error=str(exc),
                metadata=self._result_metadata(context, action="create_file"),
            )

    def create_folder(
        self,
        relative_path: Union[str, Path],
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        exist_ok: bool = True,
        role: Optional[str] = None,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create a folder inside the user's isolated workspace.
        """

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            session_id=session_id,
            request_id=request_id,
            metadata=metadata,
        )
        if not context_result["success"]:
            return context_result

        context: TaskContext = context_result["data"]["context"]

        path_result = self._resolve_workspace_path(context, relative_path)
        if not path_result["success"]:
            return path_result

        folder_path: Path = path_result["data"]["path"]
        operation = self._start_operation("create_folder", context, folder_path, None)

        try:
            folder_path.mkdir(parents=True, exist_ok=exist_ok)
            data = self._file_info(folder_path, context)
            self._finish_operation(operation, True)

            self._log_audit_event(
                action="folder_created",
                context=context,
                success=True,
                details={"path": self._display_path(folder_path, context)},
            )

            verification_payload = self._prepare_verification_payload(
                action="create_folder",
                context=context,
                result_data=data,
                success=True,
            )

            self._emit_agent_event(
                event_name="folder_created",
                context=context,
                payload=data,
            )

            return self._safe_result(
                message="Folder created successfully.",
                data=data,
                metadata=self._result_metadata(
                    context,
                    action="create_folder",
                    verification_payload=verification_payload,
                ),
            )

        except Exception as exc:
            self._finish_operation(operation, False)
            self.logger.exception("Failed to create folder.")
            return self._error_result(
                message="Failed to create folder.",
                error=str(exc),
                metadata=self._result_metadata(context, action="create_folder"),
            )

    def read_file(
        self,
        relative_path: Union[str, Path],
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        encoding: str = "utf-8",
        max_bytes: Optional[int] = None,
        role: Optional[str] = None,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Read a text file safely inside the isolated workspace.
        """

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            session_id=session_id,
            request_id=request_id,
            metadata=metadata,
        )
        if not context_result["success"]:
            return context_result

        context: TaskContext = context_result["data"]["context"]

        path_result = self._resolve_workspace_path(context, relative_path)
        if not path_result["success"]:
            return path_result

        file_path: Path = path_result["data"]["path"]

        if not file_path.exists() or not file_path.is_file():
            return self._error_result(
                message="File does not exist.",
                error="file_not_found",
                metadata=self._result_metadata(context, action="read_file"),
            )

        if self._is_blocked_extension(file_path):
            return self._error_result(
                message="Reading this file type is blocked by safety policy.",
                error="blocked_file_type",
                metadata=self._result_metadata(context, action="read_file"),
            )

        size = file_path.stat().st_size
        read_limit = int(max_bytes or self.config.max_file_bytes)

        if size > read_limit:
            return self._error_result(
                message="File is larger than the read limit.",
                error="file_too_large",
                data={"size_bytes": size, "read_limit": read_limit},
                metadata=self._result_metadata(context, action="read_file"),
            )

        try:
            content = file_path.read_text(encoding=encoding, errors="replace")
            content = self._sanitize_content(content)

            data = {
                **self._file_info(file_path, context),
                "content": content,
                "encoding": encoding,
            }

            self._log_audit_event(
                action="file_read",
                context=context,
                success=True,
                details={
                    "path": self._display_path(file_path, context),
                    "size_bytes": size,
                },
            )

            return self._safe_result(
                message="File read successfully.",
                data=data,
                metadata=self._result_metadata(context, action="read_file"),
            )

        except Exception as exc:
            self.logger.exception("Failed to read file.")
            return self._error_result(
                message="Failed to read file.",
                error=str(exc),
                metadata=self._result_metadata(context, action="read_file"),
            )

    def rename(
        self,
        source_relative_path: Union[str, Path],
        new_name: str,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        overwrite: bool = False,
        role: Optional[str] = None,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Rename a file or folder inside the user's workspace.
        """

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            session_id=session_id,
            request_id=request_id,
            metadata=metadata,
        )
        if not context_result["success"]:
            return context_result

        context: TaskContext = context_result["data"]["context"]

        if not self._safe_name(new_name):
            return self._error_result(
                message="New name is invalid or unsafe.",
                error="invalid_name",
                metadata=self._result_metadata(context, action="rename"),
            )

        source_result = self._resolve_workspace_path(context, source_relative_path)
        if not source_result["success"]:
            return source_result

        source_path: Path = source_result["data"]["path"]
        target_path = source_path.with_name(new_name)

        target_result = self._validate_resolved_path(context, target_path)
        if not target_result["success"]:
            return target_result

        if not source_path.exists():
            return self._error_result(
                message="Source path does not exist.",
                error="source_not_found",
                metadata=self._result_metadata(context, action="rename"),
            )

        if target_path.exists() and not overwrite:
            return self._error_result(
                message="Target path already exists.",
                error="target_exists",
                metadata=self._result_metadata(context, action="rename"),
            )

        security_needed = self._requires_security_check(
            action="rename",
            payload={
                "source": str(source_path),
                "target": str(target_path),
                "overwrite": overwrite,
            },
            context=context,
        )
        if security_needed:
            approval = self._request_security_approval(
                action="rename",
                payload={
                    "source": self._display_path(source_path, context),
                    "target": self._display_path(target_path, context),
                    "overwrite": overwrite,
                },
                context=context,
            )
            if not approval.get("approved", False):
                return self._error_result(
                    message="Security approval denied for rename operation.",
                    error="security_approval_denied",
                    metadata=self._result_metadata(context, action="rename"),
                )

        operation = self._start_operation("rename", context, source_path, target_path)

        try:
            if target_path.exists() and overwrite:
                self._delete_path(target_path)

            source_path.rename(target_path)
            data = {
                "source": self._display_path(source_path, context),
                "target": self._file_info(target_path, context),
            }

            self._finish_operation(operation, True)
            self._log_audit_event(
                action="path_renamed",
                context=context,
                success=True,
                details=data,
            )

            verification_payload = self._prepare_verification_payload(
                action="rename",
                context=context,
                result_data=data,
                success=True,
            )
            memory_payload = self._prepare_memory_payload(
                action="rename",
                context=context,
                result_data=data,
            )

            self._emit_agent_event(
                event_name="path_renamed",
                context=context,
                payload=data,
            )

            return self._safe_result(
                message="Path renamed successfully.",
                data=data,
                metadata=self._result_metadata(
                    context,
                    action="rename",
                    verification_payload=verification_payload,
                    memory_payload=memory_payload,
                ),
            )

        except Exception as exc:
            self._finish_operation(operation, False)
            self.logger.exception("Failed to rename path.")
            return self._error_result(
                message="Failed to rename path.",
                error=str(exc),
                metadata=self._result_metadata(context, action="rename"),
            )

    def move(
        self,
        source_relative_path: Union[str, Path],
        target_relative_path: Union[str, Path],
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        overwrite: bool = False,
        role: Optional[str] = None,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Move a file or folder within the isolated workspace.
        """

        return self._copy_or_move(
            action="move",
            source_relative_path=source_relative_path,
            target_relative_path=target_relative_path,
            user_id=user_id,
            workspace_id=workspace_id,
            overwrite=overwrite,
            role=role,
            session_id=session_id,
            request_id=request_id,
            metadata=metadata,
        )

    def copy(
        self,
        source_relative_path: Union[str, Path],
        target_relative_path: Union[str, Path],
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        overwrite: bool = False,
        role: Optional[str] = None,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Copy a file or folder within the isolated workspace.
        """

        return self._copy_or_move(
            action="copy",
            source_relative_path=source_relative_path,
            target_relative_path=target_relative_path,
            user_id=user_id,
            workspace_id=workspace_id,
            overwrite=overwrite,
            role=role,
            session_id=session_id,
            request_id=request_id,
            metadata=metadata,
        )

    def delete(
        self,
        relative_path: Union[str, Path],
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        backup_before_delete: bool = True,
        permanent: bool = False,
        role: Optional[str] = None,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Delete a file or folder after Security Agent approval.

        By default, this creates a backup before deletion.
        """

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            session_id=session_id,
            request_id=request_id,
            metadata=metadata,
        )
        if not context_result["success"]:
            return context_result

        context: TaskContext = context_result["data"]["context"]

        if not self.config.allow_delete:
            return self._error_result(
                message="Delete operations are disabled by configuration.",
                error="delete_disabled",
                metadata=self._result_metadata(context, action="delete"),
            )

        path_result = self._resolve_workspace_path(context, relative_path)
        if not path_result["success"]:
            return path_result

        target_path: Path = path_result["data"]["path"]

        if not target_path.exists():
            return self._error_result(
                message="Path does not exist.",
                error="path_not_found",
                metadata=self._result_metadata(context, action="delete"),
            )

        approval = self._request_security_approval(
            action="delete",
            payload={
                "path": self._display_path(target_path, context),
                "backup_before_delete": backup_before_delete,
                "permanent": permanent,
                "reason": "Delete is a destructive file operation.",
            },
            context=context,
        )
        if not approval.get("approved", False):
            return self._error_result(
                message="Security approval denied for delete operation.",
                error="security_approval_denied",
                metadata=self._result_metadata(context, action="delete"),
            )

        operation = self._start_operation("delete", context, target_path, None)

        try:
            backup_data = None
            if backup_before_delete:
                backup_result = self.backup(
                    relative_path=relative_path,
                    user_id=context.user_id,
                    workspace_id=context.workspace_id,
                    role=context.role,
                    session_id=context.session_id,
                    request_id=context.request_id,
                    metadata={"source": "delete_backup"},
                )
                if not backup_result["success"]:
                    self._finish_operation(operation, False)
                    return self._error_result(
                        message="Delete aborted because backup failed.",
                        error="backup_failed",
                        data={"backup_result": backup_result},
                        metadata=self._result_metadata(context, action="delete"),
                    )
                backup_data = backup_result["data"]

            deleted_info = self._file_info(target_path, context)
            self._delete_path(target_path)
            self._finish_operation(operation, True)

            data = {
                "deleted": deleted_info,
                "backup": backup_data,
                "permanent": permanent,
            }

            self._log_audit_event(
                action="path_deleted",
                context=context,
                success=True,
                details=data,
            )

            verification_payload = self._prepare_verification_payload(
                action="delete",
                context=context,
                result_data=data,
                success=True,
            )
            memory_payload = self._prepare_memory_payload(
                action="delete",
                context=context,
                result_data=data,
            )

            self._emit_agent_event(
                event_name="path_deleted",
                context=context,
                payload=data,
            )

            return self._safe_result(
                message="Path deleted successfully.",
                data=data,
                metadata=self._result_metadata(
                    context,
                    action="delete",
                    verification_payload=verification_payload,
                    memory_payload=memory_payload,
                ),
            )

        except Exception as exc:
            self._finish_operation(operation, False)
            self.logger.exception("Failed to delete path.")
            return self._error_result(
                message="Failed to delete path.",
                error=str(exc),
                metadata=self._result_metadata(context, action="delete"),
            )

    def backup(
        self,
        relative_path: Union[str, Path],
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        role: Optional[str] = None,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Backup a file or folder into isolated backup storage.
        """

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            session_id=session_id,
            request_id=request_id,
            metadata=metadata,
        )
        if not context_result["success"]:
            return context_result

        context: TaskContext = context_result["data"]["context"]

        source_result = self._resolve_workspace_path(context, relative_path)
        if not source_result["success"]:
            return source_result

        source_path: Path = source_result["data"]["path"]

        if not source_path.exists():
            return self._error_result(
                message="Source path does not exist.",
                error="source_not_found",
                metadata=self._result_metadata(context, action="backup"),
            )

        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
        backup_workspace = self._backup_workspace_root(context)
        backup_workspace.mkdir(parents=True, exist_ok=True)

        safe_name = source_path.name.replace(" ", "_")
        backup_name = f"{timestamp}_{uuid.uuid4().hex[:8]}_{safe_name}"
        backup_path = backup_workspace / backup_name

        operation = self._start_operation("backup", context, source_path, backup_path)

        try:
            if source_path.is_dir():
                shutil.copytree(source_path, backup_path)
            else:
                backup_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source_path, backup_path)

            self._finish_operation(operation, True)

            data = {
                "source": self._display_path(source_path, context),
                "backup": self._backup_display_path(backup_path, context),
                "backup_info": self._backup_file_info(backup_path, context),
            }

            self._log_audit_event(
                action="path_backed_up",
                context=context,
                success=True,
                details=data,
            )

            verification_payload = self._prepare_verification_payload(
                action="backup",
                context=context,
                result_data=data,
                success=True,
            )
            memory_payload = self._prepare_memory_payload(
                action="backup",
                context=context,
                result_data=data,
            )

            self._emit_agent_event(
                event_name="path_backed_up",
                context=context,
                payload=data,
            )

            return self._safe_result(
                message="Path backed up successfully.",
                data=data,
                metadata=self._result_metadata(
                    context,
                    action="backup",
                    verification_payload=verification_payload,
                    memory_payload=memory_payload,
                ),
            )

        except Exception as exc:
            self._finish_operation(operation, False)
            self.logger.exception("Failed to backup path.")
            return self._error_result(
                message="Failed to backup path.",
                error=str(exc),
                metadata=self._result_metadata(context, action="backup"),
            )

    def search(
        self,
        query: str = "*",
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        base_relative_path: Union[str, Path] = ".",
        include_content: bool = False,
        content_query: Optional[str] = None,
        file_extensions: Optional[Sequence[str]] = None,
        max_results: Optional[int] = None,
        role: Optional[str] = None,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Search files/folders safely inside the isolated workspace.

        Supports:
            - filename glob matching
            - optional extension filtering
            - optional text content search for safe text files
        """

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            session_id=session_id,
            request_id=request_id,
            metadata=metadata,
        )
        if not context_result["success"]:
            return context_result

        context: TaskContext = context_result["data"]["context"]

        base_result = self._resolve_workspace_path(context, base_relative_path)
        if not base_result["success"]:
            return base_result

        base_path: Path = base_result["data"]["path"]

        if not base_path.exists():
            return self._error_result(
                message="Base search path does not exist.",
                error="base_path_not_found",
                metadata=self._result_metadata(context, action="search"),
            )

        result_limit = self._safe_int(
            max_results or self.config.max_search_results,
            default=self.config.max_search_results,
            minimum=1,
            maximum=self.config.max_search_results,
        )

        normalized_extensions = self._normalize_extensions(file_extensions)

        if content_query:
            content_query = str(content_query)[:500]

        try:
            results: List[Dict[str, Any]] = []
            scanned = 0

            for path in base_path.rglob("*"):
                if len(results) >= result_limit:
                    break

                scanned += 1

                if not self._is_path_safe(path):
                    continue

                name_match = fnmatch.fnmatch(path.name.lower(), query.lower())
                extension_match = True
                if normalized_extensions:
                    extension_match = path.suffix.lower() in normalized_extensions

                content_match = False
                content_preview = None

                if content_query and path.is_file() and self._is_text_file(path):
                    try:
                        if path.stat().st_size <= min(self.config.max_file_bytes, 5 * 1024 * 1024):
                            text = path.read_text(encoding="utf-8", errors="replace")
                            if content_query.lower() in text.lower():
                                content_match = True
                                content_preview = self._extract_content_preview(
                                    text,
                                    content_query,
                                )
                    except Exception:
                        content_match = False

                if content_query:
                    matched = extension_match and content_match
                else:
                    matched = name_match and extension_match

                if matched:
                    item = self._file_info(path, context)
                    if include_content and content_preview:
                        item["content_preview"] = content_preview
                    results.append(item)

            data = {
                "query": query,
                "base_path": self._display_path(base_path, context),
                "include_content": include_content,
                "content_query": content_query,
                "file_extensions": sorted(normalized_extensions) if normalized_extensions else None,
                "scanned": scanned,
                "count": len(results),
                "max_results": result_limit,
                "results": results,
            }

            self._log_audit_event(
                action="files_searched",
                context=context,
                success=True,
                details={
                    "query": query,
                    "base_path": self._display_path(base_path, context),
                    "count": len(results),
                },
            )

            verification_payload = self._prepare_verification_payload(
                action="search",
                context=context,
                result_data={
                    "query": query,
                    "count": len(results),
                    "scanned": scanned,
                },
                success=True,
            )

            return self._safe_result(
                message="Search completed successfully.",
                data=data,
                metadata=self._result_metadata(
                    context,
                    action="search",
                    verification_payload=verification_payload,
                ),
            )

        except Exception as exc:
            self.logger.exception("Search failed.")
            return self._error_result(
                message="Search failed.",
                error=str(exc),
                metadata=self._result_metadata(context, action="search"),
            )

    def compress(
        self,
        source_relative_paths: Sequence[Union[str, Path]],
        archive_relative_path: Union[str, Path],
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        overwrite: bool = False,
        role: Optional[str] = None,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Compress one or more files/folders into a ZIP archive inside workspace.
        """

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            session_id=session_id,
            request_id=request_id,
            metadata=metadata,
        )
        if not context_result["success"]:
            return context_result

        context: TaskContext = context_result["data"]["context"]

        if not self.config.allow_compress:
            return self._error_result(
                message="Compression is disabled by configuration.",
                error="compress_disabled",
                metadata=self._result_metadata(context, action="compress"),
            )

        if not source_relative_paths:
            return self._error_result(
                message="At least one source path is required.",
                error="missing_sources",
                metadata=self._result_metadata(context, action="compress"),
            )

        archive_result = self._resolve_workspace_path(context, archive_relative_path)
        if not archive_result["success"]:
            return archive_result

        archive_path: Path = archive_result["data"]["path"]

        if archive_path.suffix.lower() != ".zip":
            archive_path = archive_path.with_suffix(".zip")

        if archive_path.exists() and not overwrite:
            return self._error_result(
                message="Archive already exists. Set overwrite=True to replace it.",
                error="archive_exists",
                metadata=self._result_metadata(context, action="compress"),
            )

        source_paths: List[Path] = []
        for source in source_relative_paths:
            source_result = self._resolve_workspace_path(context, source)
            if not source_result["success"]:
                return source_result

            source_path: Path = source_result["data"]["path"]
            if not source_path.exists():
                return self._error_result(
                    message=f"Source path does not exist: {source}",
                    error="source_not_found",
                    metadata=self._result_metadata(context, action="compress"),
                )
            source_paths.append(source_path)

        approval = self._request_security_approval(
            action="compress",
            payload={
                "sources": [self._display_path(path, context) for path in source_paths],
                "archive": self._display_path(archive_path, context),
                "overwrite": overwrite,
                "reason": "Compression reads files and creates an archive.",
            },
            context=context,
        )
        if not approval.get("approved", False):
            return self._error_result(
                message="Security approval denied for compression.",
                error="security_approval_denied",
                metadata=self._result_metadata(context, action="compress"),
            )

        operation = self._start_operation("compress", context, None, archive_path)

        try:
            archive_path.parent.mkdir(parents=True, exist_ok=True)
            if archive_path.exists() and overwrite:
                archive_path.unlink()

            workspace_root = self._workspace_root(context)

            added_files = 0
            with zipfile.ZipFile(
                archive_path,
                mode="w",
                compression=zipfile.ZIP_DEFLATED,
                allowZip64=True,
            ) as zip_file:
                for source_path in source_paths:
                    if source_path.is_file():
                        arcname = source_path.relative_to(workspace_root)
                        zip_file.write(source_path, arcname=str(arcname))
                        added_files += 1
                    elif source_path.is_dir():
                        for child in source_path.rglob("*"):
                            if child.is_file() and self._is_path_safe(child):
                                arcname = child.relative_to(workspace_root)
                                zip_file.write(child, arcname=str(arcname))
                                added_files += 1

            self._finish_operation(operation, True)

            data = {
                "archive": self._file_info(archive_path, context),
                "sources": [self._display_path(path, context) for path in source_paths],
                "added_files": added_files,
            }

            self._log_audit_event(
                action="paths_compressed",
                context=context,
                success=True,
                details=data,
            )

            verification_payload = self._prepare_verification_payload(
                action="compress",
                context=context,
                result_data=data,
                success=True,
            )
            memory_payload = self._prepare_memory_payload(
                action="compress",
                context=context,
                result_data=data,
            )

            self._emit_agent_event(
                event_name="paths_compressed",
                context=context,
                payload=data,
            )

            return self._safe_result(
                message="Archive created successfully.",
                data=data,
                metadata=self._result_metadata(
                    context,
                    action="compress",
                    verification_payload=verification_payload,
                    memory_payload=memory_payload,
                ),
            )

        except Exception as exc:
            self._finish_operation(operation, False)
            self.logger.exception("Compression failed.")
            return self._error_result(
                message="Compression failed.",
                error=str(exc),
                metadata=self._result_metadata(context, action="compress"),
            )

    def organize(
        self,
        base_relative_path: Union[str, Path],
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        strategy: str = "extension",
        dry_run: bool = True,
        role: Optional[str] = None,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Organize files inside a folder.

        Strategies:
            - extension: group files by extension.
            - type: group files into images, documents, archives, text, other.
            - date: group files by modified year/month.

        dry_run=True by default for safety.
        """

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            session_id=session_id,
            request_id=request_id,
            metadata=metadata,
        )
        if not context_result["success"]:
            return context_result

        context: TaskContext = context_result["data"]["context"]

        strategy = str(strategy or "extension").lower().strip()
        if strategy not in {"extension", "type", "date"}:
            return self._error_result(
                message="Invalid organize strategy.",
                error="invalid_strategy",
                data={"allowed": ["extension", "type", "date"]},
                metadata=self._result_metadata(context, action="organize"),
            )

        base_result = self._resolve_workspace_path(context, base_relative_path)
        if not base_result["success"]:
            return base_result

        base_path: Path = base_result["data"]["path"]

        if not base_path.exists() or not base_path.is_dir():
            return self._error_result(
                message="Base path must be an existing folder.",
                error="invalid_base_folder",
                metadata=self._result_metadata(context, action="organize"),
            )

        if not dry_run:
            approval = self._request_security_approval(
                action="organize",
                payload={
                    "base_path": self._display_path(base_path, context),
                    "strategy": strategy,
                    "dry_run": dry_run,
                    "reason": "Organize moves multiple files.",
                },
                context=context,
            )
            if not approval.get("approved", False):
                return self._error_result(
                    message="Security approval denied for organize operation.",
                    error="security_approval_denied",
                    metadata=self._result_metadata(context, action="organize"),
                )

        operation = self._start_operation("organize", context, base_path, None)

        try:
            planned_moves: List[Dict[str, str]] = []

            for item in base_path.iterdir():
                if not item.is_file():
                    continue

                if not self._is_path_safe(item):
                    continue

                folder_name = self._organization_folder_name(item, strategy)
                target_dir = base_path / folder_name
                target_path = target_dir / item.name

                if target_path == item:
                    continue

                planned_moves.append(
                    {
                        "source": self._display_path(item, context),
                        "target": self._display_path(target_path, context),
                    }
                )

                if not dry_run:
                    target_dir.mkdir(parents=True, exist_ok=True)
                    final_target = self._unique_path(target_path)
                    shutil.move(str(item), str(final_target))

            self._finish_operation(operation, True)

            data = {
                "base_path": self._display_path(base_path, context),
                "strategy": strategy,
                "dry_run": dry_run,
                "planned_count": len(planned_moves),
                "moves": planned_moves,
            }

            self._log_audit_event(
                action="folder_organized",
                context=context,
                success=True,
                details={
                    "base_path": self._display_path(base_path, context),
                    "strategy": strategy,
                    "dry_run": dry_run,
                    "planned_count": len(planned_moves),
                },
            )

            verification_payload = self._prepare_verification_payload(
                action="organize",
                context=context,
                result_data=data,
                success=True,
            )
            memory_payload = self._prepare_memory_payload(
                action="organize",
                context=context,
                result_data=data,
            )

            self._emit_agent_event(
                event_name="folder_organized",
                context=context,
                payload=data,
            )

            return self._safe_result(
                message="Folder organization completed successfully."
                if not dry_run
                else "Folder organization dry run completed successfully.",
                data=data,
                metadata=self._result_metadata(
                    context,
                    action="organize",
                    verification_payload=verification_payload,
                    memory_payload=memory_payload,
                ),
            )

        except Exception as exc:
            self._finish_operation(operation, False)
            self.logger.exception("Organize operation failed.")
            return self._error_result(
                message="Organize operation failed.",
                error=str(exc),
                metadata=self._result_metadata(context, action="organize"),
            )

    def list_directory(
        self,
        relative_path: Union[str, Path] = ".",
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        recursive: bool = False,
        limit: int = 200,
        role: Optional[str] = None,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        List files and folders inside the isolated workspace.
        """

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            session_id=session_id,
            request_id=request_id,
            metadata=metadata,
        )
        if not context_result["success"]:
            return context_result

        context: TaskContext = context_result["data"]["context"]
        limit = self._safe_int(limit, default=200, minimum=1, maximum=1000)

        path_result = self._resolve_workspace_path(context, relative_path)
        if not path_result["success"]:
            return path_result

        base_path: Path = path_result["data"]["path"]

        if not base_path.exists():
            return self._error_result(
                message="Directory does not exist.",
                error="directory_not_found",
                metadata=self._result_metadata(context, action="list_directory"),
            )

        if not base_path.is_dir():
            return self._error_result(
                message="Path is not a directory.",
                error="not_a_directory",
                metadata=self._result_metadata(context, action="list_directory"),
            )

        try:
            iterator = base_path.rglob("*") if recursive else base_path.iterdir()
            items: List[Dict[str, Any]] = []

            for item in iterator:
                if len(items) >= limit:
                    break
                if not self._is_path_safe(item):
                    continue
                items.append(self._file_info(item, context))

            data = {
                "path": self._display_path(base_path, context),
                "recursive": recursive,
                "limit": limit,
                "count": len(items),
                "items": items,
            }

            return self._safe_result(
                message="Directory listed successfully.",
                data=data,
                metadata=self._result_metadata(context, action="list_directory"),
            )

        except Exception as exc:
            self.logger.exception("Failed to list directory.")
            return self._error_result(
                message="Failed to list directory.",
                error=str(exc),
                metadata=self._result_metadata(context, action="list_directory"),
            )

    def get_operation_history(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        limit: int = 25,
        role: Optional[str] = None,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Get in-memory file operation history scoped to user/workspace.
        """

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            session_id=session_id,
            request_id=request_id,
            metadata=metadata,
        )
        if not context_result["success"]:
            return context_result

        context: TaskContext = context_result["data"]["context"]
        limit = self._safe_int(limit, default=25, minimum=1, maximum=200)

        scoped_history = [
            asdict(record)
            for record in self._operation_history
            if str(record.user_id) == str(context.user_id)
            and str(record.workspace_id) == str(context.workspace_id)
        ][-limit:]

        return self._safe_result(
            message="Operation history loaded successfully.",
            data={
                "history": scoped_history,
                "count": len(scoped_history),
                "limit": limit,
            },
            metadata=self._result_metadata(context, action="get_operation_history"),
        )

    def health_check(self) -> Dict[str, Any]:
        """
        Lightweight runtime health check.
        """

        return self._safe_result(
            message="FileManager is healthy.",
            data={
                "agent_name": self.agent_name,
                "agent_type": self.agent_type,
                "version": self.version,
                "root_path": str(self.config.root_path),
                "backup_root_path": str(self.config.backup_root_path),
                "max_file_bytes": self.config.max_file_bytes,
                "max_search_results": self.config.max_search_results,
                "allow_delete": self.config.allow_delete,
                "allow_compress": self.config.allow_compress,
                "timestamp": self._utc_now(),
            },
            metadata={
                "request_id": str(uuid.uuid4()),
                "agent": self.agent_name,
                "action": "health_check",
            },
        )

    # -----------------------------------------------------------------------
    # Shared operation method
    # -----------------------------------------------------------------------

    def _copy_or_move(
        self,
        *,
        action: str,
        source_relative_path: Union[str, Path],
        target_relative_path: Union[str, Path],
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        overwrite: bool = False,
        role: Optional[str] = None,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Shared implementation for copy and move.
        """

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            session_id=session_id,
            request_id=request_id,
            metadata=metadata,
        )
        if not context_result["success"]:
            return context_result

        context: TaskContext = context_result["data"]["context"]

        if action not in {"copy", "move"}:
            return self._error_result(
                message="Invalid file operation.",
                error="invalid_operation",
                metadata=self._result_metadata(context, action=action),
            )

        source_result = self._resolve_workspace_path(context, source_relative_path)
        if not source_result["success"]:
            return source_result

        target_result = self._resolve_workspace_path(context, target_relative_path)
        if not target_result["success"]:
            return target_result

        source_path: Path = source_result["data"]["path"]
        target_path: Path = target_result["data"]["path"]

        if not source_path.exists():
            return self._error_result(
                message="Source path does not exist.",
                error="source_not_found",
                metadata=self._result_metadata(context, action=action),
            )

        if target_path.exists() and not overwrite:
            return self._error_result(
                message="Target path already exists.",
                error="target_exists",
                metadata=self._result_metadata(context, action=action),
            )

        security_needed = self._requires_security_check(
            action=action,
            payload={
                "source": str(source_path),
                "target": str(target_path),
                "overwrite": overwrite,
            },
            context=context,
        )
        if security_needed:
            approval = self._request_security_approval(
                action=action,
                payload={
                    "source": self._display_path(source_path, context),
                    "target": self._display_path(target_path, context),
                    "overwrite": overwrite,
                },
                context=context,
            )
            if not approval.get("approved", False):
                return self._error_result(
                    message=f"Security approval denied for {action} operation.",
                    error="security_approval_denied",
                    metadata=self._result_metadata(context, action=action),
                )

        operation = self._start_operation(action, context, source_path, target_path)

        try:
            target_path.parent.mkdir(parents=True, exist_ok=True)

            if target_path.exists() and overwrite:
                self._delete_path(target_path)

            if action == "copy":
                if source_path.is_dir():
                    shutil.copytree(source_path, target_path)
                else:
                    shutil.copy2(source_path, target_path)
            else:
                shutil.move(str(source_path), str(target_path))

            self._finish_operation(operation, True)

            data = {
                "action": action,
                "source": self._display_path(source_path, context),
                "target": self._file_info(target_path, context),
                "overwrite": overwrite,
            }

            self._log_audit_event(
                action=f"path_{action}d",
                context=context,
                success=True,
                details=data,
            )

            verification_payload = self._prepare_verification_payload(
                action=action,
                context=context,
                result_data=data,
                success=True,
            )
            memory_payload = self._prepare_memory_payload(
                action=action,
                context=context,
                result_data=data,
            )

            self._emit_agent_event(
                event_name=f"path_{action}d",
                context=context,
                payload=data,
            )

            return self._safe_result(
                message=f"Path {action} completed successfully.",
                data=data,
                metadata=self._result_metadata(
                    context,
                    action=action,
                    verification_payload=verification_payload,
                    memory_payload=memory_payload,
                ),
            )

        except Exception as exc:
            self._finish_operation(operation, False)
            self.logger.exception("Failed to %s path.", action)
            return self._error_result(
                message=f"Failed to {action} path.",
                error=str(exc),
                metadata=self._result_metadata(context, action=action),
            )

    # -----------------------------------------------------------------------
    # Compatibility hooks required by architecture
    # -----------------------------------------------------------------------

    def _validate_task_context(
        self,
        *,
        user_id: Union[str, int, None],
        workspace_id: Union[str, int, None],
        role: Optional[str] = None,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Validate SaaS task context.
        """

        if user_id is None or str(user_id).strip() == "":
            return self._error_result(
                message="user_id is required for file operations.",
                error="missing_user_id",
            )

        if workspace_id is None or str(workspace_id).strip() == "":
            return self._error_result(
                message="workspace_id is required for file operations.",
                error="missing_workspace_id",
            )

        clean_user_id = str(user_id).strip()
        clean_workspace_id = str(workspace_id).strip()

        if len(clean_user_id) > 128 or len(clean_workspace_id) > 128:
            return self._error_result(
                message="Invalid context identifier length.",
                error="invalid_context_identifier",
            )

        context = TaskContext(
            user_id=clean_user_id,
            workspace_id=clean_workspace_id,
            request_id=str(request_id or uuid.uuid4()),
            role=role,
            session_id=session_id,
            agent_name=self.agent_name,
            metadata=dict(metadata or {}),
        )

        return self._safe_result(
            message="Task context validated.",
            data={"context": context},
            metadata={
                "request_id": context.request_id,
                "agent": self.agent_name,
                "action": "_validate_task_context",
            },
        )

    def _requires_security_check(
        self,
        *,
        action: str,
        payload: Optional[Dict[str, Any]] = None,
        context: Optional[TaskContext] = None,
    ) -> bool:
        """
        Determine whether Security Agent approval is required.
        """

        sensitive_actions = {
            "delete",
            "move",
            "rename",
            "copy",
            "compress",
            "organize",
        }

        if action in sensitive_actions:
            return True

        payload = payload or {}
        path = str(payload.get("path") or payload.get("source") or payload.get("target") or "")
        lowered = path.lower()

        if any(part.lower() in lowered for part in BLOCKED_PATH_PARTS):
            return True

        if any(lowered.endswith(ext) for ext in BLOCKED_EXTENSIONS):
            return True

        if action == "create_file" and bool(payload.get("overwrite")):
            return True

        return False

    def _request_security_approval(
        self,
        *,
        action: str,
        payload: Optional[Dict[str, Any]] = None,
        context: Optional[TaskContext] = None,
    ) -> Dict[str, Any]:
        """
        Request approval from Security Agent.

        Falls back to safe local policy if Security Agent is not attached.
        """

        payload = payload or {}

        if self.security_agent is not None:
            for method_name in (
                "approve_action",
                "request_approval",
                "validate_action",
                "check_permission",
            ):
                method = getattr(self.security_agent, method_name, None)
                if callable(method):
                    try:
                        result = method(
                            action=action,
                            payload=payload,
                            user_id=context.user_id if context else None,
                            workspace_id=context.workspace_id if context else None,
                            request_id=context.request_id if context else None,
                            agent_name=self.agent_name,
                        )

                        if isinstance(result, dict):
                            approved = bool(
                                result.get("approved")
                                or result.get("success")
                                or result.get("allowed")
                            )
                            return {
                                "approved": approved,
                                "source": f"security_agent.{method_name}",
                                "raw": result,
                            }

                        if isinstance(result, bool):
                            return {
                                "approved": result,
                                "source": f"security_agent.{method_name}",
                            }

                    except Exception as exc:
                        self.logger.warning(
                            "Security Agent approval method failed: %s",
                            exc,
                        )
                        return {
                            "approved": False,
                            "source": f"security_agent.{method_name}",
                            "error": str(exc),
                        }

        if action == "delete" and not self.config.allow_delete:
            return {
                "approved": False,
                "source": "fallback_policy",
                "message": "Delete is disabled by configuration.",
            }

        return {
            "approved": True,
            "source": "fallback_workspace_policy",
            "message": "Approved because operation is workspace-scoped.",
        }

    def _prepare_verification_payload(
        self,
        *,
        action: str,
        context: TaskContext,
        result_data: Optional[Dict[str, Any]] = None,
        success: bool = True,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent compatible payload.
        """

        payload = {
            "verification_id": str(uuid.uuid4()),
            "agent": self.agent_name,
            "action": action,
            "success": success,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "timestamp": self._utc_now(),
            "result_summary": self._safe_summary(result_data or {}),
            "checks": {
                "tenant_context_present": bool(context.user_id and context.workspace_id),
                "workspace_path_enforced": True,
                "structured_result": True,
            },
        }

        if self.verification_agent is not None:
            method = getattr(self.verification_agent, "prepare_payload", None)
            if callable(method):
                try:
                    external_payload = method(payload)
                    if isinstance(external_payload, dict):
                        return external_payload
                except Exception as exc:
                    self.logger.warning("Verification payload hook failed: %s", exc)

        return payload

    def _prepare_memory_payload(
        self,
        *,
        action: str,
        context: TaskContext,
        result_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.
        """

        payload = {
            "memory_id": str(uuid.uuid4()),
            "agent": self.agent_name,
            "action": action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "timestamp": self._utc_now(),
            "memory_type": "file_operation",
            "content": self._safe_summary(result_data or {}),
            "metadata": {
                "source": "FileManager",
                "safe_to_store": True,
                "contains_file_content": False,
            },
        }

        if self.memory_agent is not None:
            method = getattr(self.memory_agent, "prepare_payload", None)
            if callable(method):
                try:
                    external_payload = method(payload)
                    if isinstance(external_payload, dict):
                        return external_payload
                except Exception as exc:
                    self.logger.warning("Memory payload hook failed: %s", exc)

        return payload

    def _emit_agent_event(
        self,
        *,
        event_name: str,
        context: TaskContext,
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Emit event for dashboard/API/task history integration.
        """

        event = {
            "event_id": str(uuid.uuid4()),
            "event_name": event_name,
            "agent": self.agent_name,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "timestamp": self._utc_now(),
            "payload": payload or {},
        }

        if self.event_bus is not None:
            for method_name in ("emit", "publish", "send"):
                method = getattr(self.event_bus, method_name, None)
                if callable(method):
                    try:
                        method(event_name, event)
                        return
                    except TypeError:
                        try:
                            method(event)
                            return
                        except Exception:
                            pass
                    except Exception as exc:
                        self.logger.warning("Event bus emit failed: %s", exc)
                        return

        self.logger.debug("Agent event: %s", json.dumps(event, default=str))

    def _log_audit_event(
        self,
        *,
        action: str,
        context: TaskContext,
        success: bool,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log tenant-scoped audit event.
        """

        audit_event = {
            "audit_id": str(uuid.uuid4()),
            "agent": self.agent_name,
            "action": action,
            "success": success,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "timestamp": self._utc_now(),
            "details": self._sanitize_audit_details(details or {}),
        }

        if self.audit_logger is not None:
            for method_name in ("log", "write", "record", "create"):
                method = getattr(self.audit_logger, method_name, None)
                if callable(method):
                    try:
                        method(audit_event)
                        return
                    except Exception as exc:
                        self.logger.warning("Audit logger failed: %s", exc)
                        return

        self.logger.info("AUDIT | %s", json.dumps(audit_event, default=str))

    def _safe_result(
        self,
        *,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard success response.
        """

        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        *,
        message: str,
        error: Union[str, Dict[str, Any], None],
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
            "error": error,
            "metadata": metadata or {},
        }

    # -----------------------------------------------------------------------
    # Path safety helpers
    # -----------------------------------------------------------------------

    def _workspace_root(self, context: TaskContext) -> Path:
        """
        Get isolated root path for a user/workspace.
        """

        user_part = self._safe_path_segment(context.user_id)
        workspace_part = self._safe_path_segment(context.workspace_id)
        root = (self.config.root_path / user_part / workspace_part).resolve()
        root.mkdir(parents=True, exist_ok=True)
        return root

    def _backup_workspace_root(self, context: TaskContext) -> Path:
        """
        Get isolated backup root path for a user/workspace.
        """

        user_part = self._safe_path_segment(context.user_id)
        workspace_part = self._safe_path_segment(context.workspace_id)
        root = (self.config.backup_root_path / user_part / workspace_part).resolve()
        root.mkdir(parents=True, exist_ok=True)
        return root

    def _resolve_workspace_path(
        self,
        context: TaskContext,
        relative_path: Union[str, Path],
    ) -> Dict[str, Any]:
        """
        Resolve and validate a workspace-relative path.
        """

        try:
            raw_path = Path(str(relative_path).strip())

            if raw_path.is_absolute():
                return self._error_result(
                    message="Absolute paths are not allowed.",
                    error="absolute_path_blocked",
                    metadata=self._result_metadata(context, action="_resolve_workspace_path"),
                )

            if str(raw_path).strip() in {"", "."}:
                candidate = self._workspace_root(context)
            else:
                candidate = (self._workspace_root(context) / raw_path).resolve()

            return self._validate_resolved_path(context, candidate)

        except Exception as exc:
            return self._error_result(
                message="Failed to resolve workspace path.",
                error=str(exc),
                metadata=self._result_metadata(context, action="_resolve_workspace_path"),
            )

    def _validate_resolved_path(
        self,
        context: TaskContext,
        path: Path,
    ) -> Dict[str, Any]:
        """
        Validate that a resolved path stays inside workspace root.
        """

        try:
            workspace_root = self._workspace_root(context).resolve()
            resolved = path.resolve()

            if not self._is_relative_to(resolved, workspace_root):
                return self._error_result(
                    message="Path traversal blocked. Path must stay inside workspace.",
                    error="path_traversal_blocked",
                    metadata=self._result_metadata(context, action="_validate_resolved_path"),
                )

            if not self._is_path_safe(resolved):
                return self._error_result(
                    message="Path is blocked by safety policy.",
                    error="blocked_path",
                    metadata=self._result_metadata(context, action="_validate_resolved_path"),
                )

            return self._safe_result(
                message="Path validated.",
                data={"path": resolved},
                metadata=self._result_metadata(context, action="_validate_resolved_path"),
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to validate path.",
                error=str(exc),
                metadata=self._result_metadata(context, action="_validate_resolved_path"),
            )

    def _is_relative_to(self, path: Path, parent: Path) -> bool:
        """
        Python 3.8 compatible Path.is_relative_to.
        """

        try:
            path.relative_to(parent)
            return True
        except ValueError:
            return False

    def _safe_path_segment(self, value: str) -> str:
        """
        Convert user/workspace identifier into safe filesystem segment.
        """

        cleaned = re.sub(r"[^a-zA-Z0-9_.@+-]", "_", str(value).strip())
        return cleaned[:128] or "unknown"

    def _safe_name(self, value: str) -> bool:
        """
        Validate safe file/folder name.
        """

        value = str(value or "").strip()
        if not value:
            return False

        if value in {".", ".."}:
            return False

        if "/" in value or "\\" in value:
            return False

        if not SAFE_NAME_PATTERN.match(value):
            return False

        lowered = value.lower()
        if any(part.lower() == lowered for part in BLOCKED_PATH_PARTS):
            return False

        return True

    def _is_path_safe(self, path: Path) -> bool:
        """
        Check path against blocked sensitive names/extensions.
        """

        parts = [part.lower() for part in path.parts]
        for blocked in BLOCKED_PATH_PARTS:
            if blocked.lower() in parts:
                return False

        if self._is_blocked_extension(path):
            return False

        return True

    def _is_blocked_extension(self, path: Path) -> bool:
        """
        Check blocked sensitive file extensions.
        """

        return path.suffix.lower() in BLOCKED_EXTENSIONS

    # -----------------------------------------------------------------------
    # File metadata helpers
    # -----------------------------------------------------------------------

    def _file_info(self, path: Path, context: TaskContext) -> Dict[str, Any]:
        """
        Build safe file/folder info.
        """

        try:
            stat_info = path.stat()
            is_file = path.is_file()
            is_dir = path.is_dir()

            mime_type, _ = mimetypes.guess_type(str(path))

            return {
                "name": path.name,
                "relative_path": self._display_path(path, context),
                "type": "directory" if is_dir else "file" if is_file else "other",
                "extension": path.suffix.lower() if is_file else "",
                "mime_type": mime_type,
                "size_bytes": int(stat_info.st_size) if is_file else self._directory_size(path),
                "created_at": datetime.datetime.fromtimestamp(
                    stat_info.st_ctime,
                    tz=datetime.timezone.utc,
                ).isoformat(),
                "modified_at": datetime.datetime.fromtimestamp(
                    stat_info.st_mtime,
                    tz=datetime.timezone.utc,
                ).isoformat(),
                "is_file": is_file,
                "is_dir": is_dir,
                "checksum_sha256": self._sha256(path) if is_file and stat_info.st_size <= self.config.max_file_bytes else None,
            }

        except Exception as exc:
            return {
                "name": path.name,
                "relative_path": self._display_path(path, context),
                "error": str(exc),
            }

    def _backup_file_info(self, path: Path, context: TaskContext) -> Dict[str, Any]:
        """
        Build safe backup file/folder info.
        """

        try:
            stat_info = path.stat()
            return {
                "name": path.name,
                "backup_relative_path": self._backup_display_path(path, context),
                "type": "directory" if path.is_dir() else "file" if path.is_file() else "other",
                "size_bytes": int(stat_info.st_size) if path.is_file() else self._directory_size(path),
                "created_at": datetime.datetime.fromtimestamp(
                    stat_info.st_ctime,
                    tz=datetime.timezone.utc,
                ).isoformat(),
                "modified_at": datetime.datetime.fromtimestamp(
                    stat_info.st_mtime,
                    tz=datetime.timezone.utc,
                ).isoformat(),
            }
        except Exception as exc:
            return {
                "name": path.name,
                "backup_relative_path": self._backup_display_path(path, context),
                "error": str(exc),
            }

    def _display_path(self, path: Path, context: TaskContext) -> str:
        """
        Display workspace-relative path.
        """

        try:
            return str(path.resolve().relative_to(self._workspace_root(context).resolve()))
        except Exception:
            return path.name

    def _backup_display_path(self, path: Path, context: TaskContext) -> str:
        """
        Display backup-root-relative path.
        """

        try:
            return str(path.resolve().relative_to(self._backup_workspace_root(context).resolve()))
        except Exception:
            return path.name

    def _directory_size(self, path: Path) -> int:
        """
        Calculate directory size safely.
        """

        if not path.is_dir():
            return 0

        total = 0
        try:
            for child in path.rglob("*"):
                if child.is_file() and self._is_path_safe(child):
                    try:
                        total += child.stat().st_size
                    except Exception:
                        continue
        except Exception:
            return 0

        return total

    def _sha256(self, path: Path) -> Optional[str]:
        """
        SHA256 checksum for safe file integrity verification.
        """

        if not path.is_file():
            return None

        try:
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            return digest.hexdigest()
        except Exception:
            return None

    # -----------------------------------------------------------------------
    # Content helpers
    # -----------------------------------------------------------------------

    def _sanitize_content(self, content: str) -> str:
        """
        Redact likely secrets from file content before returning.
        """

        return SECRET_PATTERN.sub(lambda match: self._redact_secret(match.group(0)), content)

    def _redact_secret(self, value: str) -> str:
        """
        Redact secret-like content.
        """

        if ":" in value:
            key = value.split(":", 1)[0]
            return f"{key}: [REDACTED]"
        if "=" in value:
            key = value.split("=", 1)[0]
            return f"{key}=[REDACTED]"
        return "[REDACTED]"

    def _is_text_file(self, path: Path) -> bool:
        """
        Check whether a file is safe text-like file.
        """

        return path.suffix.lower() in TEXT_EXTENSIONS

    def _extract_content_preview(self, text: str, query: str, radius: int = 80) -> str:
        """
        Extract short preview around content search match.
        """

        lower_text = text.lower()
        lower_query = query.lower()
        index = lower_text.find(lower_query)
        if index < 0:
            return ""

        start = max(0, index - radius)
        end = min(len(text), index + len(query) + radius)
        preview = text[start:end].replace("\n", " ")
        return self._sanitize_content(preview)

    def _normalize_extensions(
        self,
        extensions: Optional[Sequence[str]],
    ) -> Optional[set[str]]:
        """
        Normalize extensions to `.ext` lowercase format.
        """

        if not extensions:
            return None

        normalized = set()
        for ext in extensions:
            clean = str(ext).strip().lower()
            if not clean:
                continue
            if not clean.startswith("."):
                clean = f".{clean}"
            if clean in BLOCKED_EXTENSIONS:
                continue
            normalized.add(clean)

        return normalized or None

    # -----------------------------------------------------------------------
    # Operation helpers
    # -----------------------------------------------------------------------

    def _start_operation(
        self,
        action: str,
        context: TaskContext,
        source_path: Optional[Path],
        target_path: Optional[Path],
    ) -> FileOperationRecord:
        """
        Start operation tracking.
        """

        record = FileOperationRecord(
            operation_id=str(uuid.uuid4()),
            action=action,
            source_path=str(source_path) if source_path else None,
            target_path=str(target_path) if target_path else None,
            started_at=self._utc_now(),
            user_id=context.user_id,
            workspace_id=context.workspace_id,
            request_id=context.request_id,
        )
        self._operation_history.append(record)
        return record

    def _finish_operation(self, record: FileOperationRecord, success: bool) -> None:
        """
        Finish operation tracking.
        """

        record.finished_at = self._utc_now()
        record.success = success

        try:
            started = datetime.datetime.fromisoformat(record.started_at)
            finished = datetime.datetime.fromisoformat(record.finished_at)
            record.duration_ms = int((finished - started).total_seconds() * 1000)
        except Exception:
            record.duration_ms = None

    def _delete_path(self, path: Path) -> None:
        """
        Delete path safely after caller has performed security checks.
        """

        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink(missing_ok=True)

    def _unique_path(self, path: Path) -> Path:
        """
        Return unique path if target already exists.
        """

        if not path.exists():
            return path

        stem = path.stem
        suffix = path.suffix
        parent = path.parent

        for index in range(1, 10_000):
            candidate = parent / f"{stem}_{index}{suffix}"
            if not candidate.exists():
                return candidate

        return parent / f"{stem}_{uuid.uuid4().hex[:8]}{suffix}"

    def _organization_folder_name(self, path: Path, strategy: str) -> str:
        """
        Determine organize target folder name.
        """

        if strategy == "extension":
            return path.suffix.lower().lstrip(".") or "no_extension"

        if strategy == "type":
            ext = path.suffix.lower()
            if ext in IMAGE_EXTENSIONS:
                return "images"
            if ext in DOCUMENT_EXTENSIONS:
                return "documents"
            if ext in ARCHIVE_EXTENSIONS:
                return "archives"
            if ext in TEXT_EXTENSIONS:
                return "text"
            return "other"

        if strategy == "date":
            try:
                modified = datetime.datetime.fromtimestamp(
                    path.stat().st_mtime,
                    tz=datetime.timezone.utc,
                )
                return f"{modified.year}/{modified.month:02d}"
            except Exception:
                return "unknown_date"

        return "other"

    # -----------------------------------------------------------------------
    # Result/audit helpers
    # -----------------------------------------------------------------------

    def _safe_summary(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build safe summary without raw file content.
        """

        summary: Dict[str, Any] = {}

        for key, value in data.items():
            if key.lower() in {"content", "raw", "bytes", "file_content"}:
                continue

            if isinstance(value, (str, int, float, bool)) or value is None:
                summary[key] = value
            elif isinstance(value, dict):
                summary[key] = {
                    k: v
                    for k, v in value.items()
                    if isinstance(v, (str, int, float, bool)) or v is None
                }
            elif isinstance(value, list):
                summary[key] = {
                    "type": "list",
                    "count": len(value),
                }
            else:
                summary[key] = str(type(value).__name__)

        return summary

    def _sanitize_audit_details(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize audit details.
        """

        try:
            serialized = json.dumps(details, default=str)
            sanitized = self._sanitize_content(serialized)
            return json.loads(sanitized)
        except Exception:
            return {"summary": self._sanitize_content(str(details))}

    def _result_metadata(
        self,
        context: TaskContext,
        *,
        action: str,
        verification_payload: Optional[Dict[str, Any]] = None,
        memory_payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard metadata for structured results.
        """

        metadata: Dict[str, Any] = {
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "version": self.version,
            "action": action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "session_id": context.session_id,
            "timestamp": self._utc_now(),
        }

        if verification_payload is not None:
            metadata["verification_payload"] = verification_payload

        if memory_payload is not None:
            metadata["memory_payload"] = memory_payload

        return metadata

    def _safe_int(
        self,
        value: Any,
        *,
        default: int,
        minimum: int,
        maximum: int,
    ) -> int:
        """
        Safe integer coercion.
        """

        try:
            number = int(value)
        except Exception:
            number = default

        if number < minimum:
            return minimum
        if number > maximum:
            return maximum
        return number

    def _utc_now(self) -> str:
        """
        Current UTC timestamp.
        """

        return datetime.datetime.now(datetime.timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Standalone smoke test
# ---------------------------------------------------------------------------

def _demo() -> None:
    """
    Safe local smoke test.

    Run:
        python agents/system_agent/file_manager.py
    """

    manager = FileManager()

    print(json.dumps(manager.health_check(), indent=2, default=str))

    create_folder_result = manager.create_folder(
        "demo",
        user_id="demo_user",
        workspace_id="demo_workspace",
    )
    print(json.dumps(create_folder_result, indent=2, default=str))

    create_file_result = manager.create_file(
        "demo/hello.txt",
        "Hello from William FileManager.",
        user_id="demo_user",
        workspace_id="demo_workspace",
        overwrite=True,
    )
    print(json.dumps(create_file_result, indent=2, default=str))

    list_result = manager.list_directory(
        "demo",
        user_id="demo_user",
        workspace_id="demo_workspace",
    )
    print(json.dumps(list_result, indent=2, default=str))

    search_result = manager.search(
        "*.txt",
        user_id="demo_user",
        workspace_id="demo_workspace",
        base_relative_path="demo",
    )
    print(json.dumps(search_result, indent=2, default=str))

    backup_result = manager.backup(
        "demo/hello.txt",
        user_id="demo_user",
        workspace_id="demo_workspace",
    )
    print(json.dumps(backup_result, indent=2, default=str))


if __name__ == "__main__":
    _demo()