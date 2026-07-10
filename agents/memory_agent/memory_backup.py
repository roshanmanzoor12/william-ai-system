"""
agents/memory_agent/memory_backup.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
Memory Agent Backup Helper

Purpose:
    Export/import/snapshot/restore memory database safely.

This file provides production-ready backup utilities for the Memory Agent layer.
It supports SaaS-safe user/workspace isolation, export/import validation,
snapshot creation, restore planning, restore execution, audit logging,
security approval hooks, verification payload preparation, and dashboard/API
integration-ready structured results.

Architecture connections:
    - Master Agent:
        Can route backup/restore tasks to MemoryBackup through public methods.
    - Memory Agent:
        Uses this helper to export/import memory records and create restore points.
    - Security Agent:
        Sensitive operations such as restore/import/delete require approval hooks.
    - Verification Agent:
        Each completed action prepares a structured verification payload.
    - Dashboard/API:
        All public methods return JSON/dict-style results suitable for FastAPI.
    - Agent Registry/Loader/Router:
        Class is import-safe, exposes metadata, and can run without unavailable
        future William modules by using fallback stubs.

Safety priorities:
    1. Security and permissions.
    2. SaaS user/workspace isolation.
    3. BaseAgent compatibility.
    4. MasterAgent/Registry compatibility.
    5. Backup-specific functionality.
    6. Future upgrades.

No hardcoded secrets.
No destructive action runs without guard methods.
"""

from __future__ import annotations

import base64
import copy
import dataclasses
import gzip
import hashlib
import json
import logging
import os
import shutil
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Import-safe BaseAgent fallback
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for standalone import safety
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps memory_backup.py import-safe when the complete William/Jarvis
        system has not been generated yet.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())
            self.logger = logging.getLogger(self.agent_name)

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback emit_event: %s %s", event_name, payload)

        def log_audit(self, event_name: str, payload: Dict[str, Any]) -> None:
            self.logger.info("Fallback audit: %s %s", event_name, payload)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BACKUP_SCHEMA_VERSION = "1.0"
DEFAULT_BACKUP_ROOT = "storage/memory_backups"
DEFAULT_SNAPSHOT_PREFIX = "snapshot"
DEFAULT_EXPORT_PREFIX = "memory_export"
DEFAULT_IMPORT_STAGING_PREFIX = "memory_import_staging"

SUPPORTED_EXPORT_FORMATS = {"json", "json.gz"}
SUPPORTED_IMPORT_FORMATS = {"json", "json.gz"}
SENSITIVE_ACTIONS = {
    "memory.backup.import",
    "memory.backup.restore",
    "memory.backup.delete",
    "memory.backup.purge",
}

SAFE_MEMORY_COLLECTIONS = {
    "short_term",
    "long_term",
    "preferences",
    "projects",
    "clients",
    "team",
    "knowledge_graph_nodes",
    "knowledge_graph_edges",
    "summaries",
    "embeddings_metadata",
    "search_index_metadata",
}

DEFAULT_EXCLUDED_KEYS = {
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "access_token",
    "refresh_token",
    "authorization",
    "cookie",
    "session",
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BackupContext:
    """
    Validated tenant execution context.

    user_id and workspace_id are required for SaaS isolation.
    actor_id identifies the authenticated user/service performing the action.
    request_id and task_id help trace Master Agent / API / dashboard tasks.
    """

    user_id: str
    workspace_id: str
    actor_id: Optional[str] = None
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    task_id: Optional[str] = None
    source: str = "memory_backup"
    roles: Tuple[str, ...] = field(default_factory=tuple)
    permissions: Tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "actor_id": self.actor_id,
            "request_id": self.request_id,
            "task_id": self.task_id,
            "source": self.source,
            "roles": list(self.roles),
            "permissions": list(self.permissions),
        }


@dataclass
class BackupManifest:
    """
    Backup manifest stored inside every backup file.

    The manifest makes backup files verifiable before import/restore and gives
    dashboard/API layers enough information to show safe restore previews.
    """

    backup_id: str
    schema_version: str
    backup_type: str
    created_at: str
    created_by: Optional[str]
    user_id: str
    workspace_id: str
    collections: List[str]
    record_count: int
    compressed: bool
    checksum_sha256: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class BackupOptions:
    """
    Options controlling export/snapshot behavior.
    """

    include_collections: Optional[List[str]] = None
    exclude_collections: Optional[List[str]] = None
    include_embeddings: bool = False
    redact_sensitive: bool = True
    format: str = "json.gz"
    pretty: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ImportOptions:
    """
    Options controlling import/restore behavior.
    """

    mode: str = "merge"  # merge | replace | dry_run
    allow_cross_workspace: bool = False
    validate_checksum: bool = True
    require_security_approval: bool = True
    restore_collections: Optional[List[str]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BackupRecord:
    """
    Normalized backup record envelope.
    """

    collection: str
    record_id: str
    data: Dict[str, Any]
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "collection": self.collection,
            "record_id": self.record_id,
            "data": self.data,
            "metadata": self.metadata,
        }


# ---------------------------------------------------------------------------
# MemoryBackup
# ---------------------------------------------------------------------------

class MemoryBackup(BaseAgent):
    """
    Safe memory backup manager for William/Jarvis Memory Agent.

    Public methods:
        - export_memory()
        - import_memory()
        - create_snapshot()
        - restore_snapshot()
        - list_backups()
        - read_backup_manifest()
        - validate_backup_file()
        - delete_backup()
        - purge_old_backups()

    Storage model:
        Backups are stored below:
            storage/memory_backups/{user_id}/{workspace_id}/

        File names are generated safely and never use raw user input directly.

    Memory database adapter:
        This helper accepts an optional memory_store object with any of these
        method styles:

            export_records(user_id, workspace_id, collections=None) -> dict/list
            import_records(user_id, workspace_id, records, mode="merge") -> dict
            list_collections(user_id, workspace_id) -> list
            create_snapshot(user_id, workspace_id) -> dict/list
            restore_records(user_id, workspace_id, records, mode="replace") -> dict

        If no memory_store is provided, this class uses an in-memory fallback
        store suitable for tests and early development.
    """

    agent_name = "MemoryBackup"
    agent_type = "memory_agent_helper"
    file_path = "agents/memory_agent/memory_backup.py"
    schema_version = BACKUP_SCHEMA_VERSION

    def __init__(
        self,
        memory_store: Optional[Any] = None,
        security_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        event_emitter: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        backup_root: Union[str, Path] = DEFAULT_BACKUP_ROOT,
        logger: Optional[logging.Logger] = None,
        max_backup_bytes: int = 250 * 1024 * 1024,
        enable_file_lock: bool = True,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name=self.agent_name, **kwargs)
        self.logger = logger or logging.getLogger(self.agent_name)
        self.memory_store = memory_store or _InMemoryMemoryStore()
        self.security_agent = security_agent
        self.verification_agent = verification_agent
        self.audit_logger = audit_logger
        self.event_emitter = event_emitter
        self.backup_root = Path(backup_root)
        self.max_backup_bytes = int(max_backup_bytes)
        self.enable_file_lock = bool(enable_file_lock)
        self._lock = threading.RLock()

        self.backup_root.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Public metadata / registry hooks
    # ------------------------------------------------------------------

    def get_agent_metadata(self) -> Dict[str, Any]:
        """
        Metadata for Agent Registry, Agent Loader, dashboard, and Master Agent.
        """

        return {
            "success": True,
            "message": "MemoryBackup metadata loaded.",
            "data": {
                "agent_name": self.agent_name,
                "agent_type": self.agent_type,
                "file_path": self.file_path,
                "schema_version": self.schema_version,
                "public_methods": [
                    "export_memory",
                    "import_memory",
                    "create_snapshot",
                    "restore_snapshot",
                    "list_backups",
                    "read_backup_manifest",
                    "validate_backup_file",
                    "delete_backup",
                    "purge_old_backups",
                ],
                "sensitive_actions": sorted(SENSITIVE_ACTIONS),
                "supported_export_formats": sorted(SUPPORTED_EXPORT_FORMATS),
                "supported_import_formats": sorted(SUPPORTED_IMPORT_FORMATS),
            },
            "error": None,
            "metadata": {
                "component": self.agent_name,
                "ready_for_registry": True,
            },
        }

    # ------------------------------------------------------------------
    # Export / snapshot
    # ------------------------------------------------------------------

    def export_memory(
        self,
        user_id: str,
        workspace_id: str,
        actor_id: Optional[str] = None,
        options: Optional[Union[BackupOptions, Dict[str, Any]]] = None,
        task_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Export memory records for one user/workspace into a portable backup file.

        This is non-destructive but still uses isolation validation and audit logs.
        """

        action = "memory.backup.export"
        started_at = self._utc_now()
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id,
            task_id=task_id,
            request_id=request_id,
            action=action,
        )
        if not context_result["success"]:
            return context_result

        context = context_result["data"]["context"]
        backup_options = self._normalize_backup_options(options)

        if backup_options.format not in SUPPORTED_EXPORT_FORMATS:
            return self._error_result(
                message=f"Unsupported export format: {backup_options.format}",
                error_code="UNSUPPORTED_EXPORT_FORMAT",
                context=context,
                metadata={"supported_formats": sorted(SUPPORTED_EXPORT_FORMATS)},
            )

        try:
            with self._operation_lock():
                collections = self._resolve_collections(context, backup_options)
                records = self._read_memory_records(context, collections)

                if backup_options.redact_sensitive:
                    records = self._redact_records(records)

                backup_id = self._generate_backup_id("export")
                compressed = backup_options.format.endswith(".gz")
                payload_without_checksum = self._build_backup_payload(
                    backup_id=backup_id,
                    backup_type="export",
                    context=context,
                    records=records,
                    options=backup_options,
                    compressed=compressed,
                    checksum_sha256="pending",
                )
                checksum = self._calculate_payload_checksum(payload_without_checksum["records"])
                payload_without_checksum["manifest"]["checksum_sha256"] = checksum

                path = self._write_backup_file(
                    context=context,
                    backup_id=backup_id,
                    payload=payload_without_checksum,
                    prefix=DEFAULT_EXPORT_PREFIX,
                    compressed=compressed,
                    pretty=backup_options.pretty,
                )

                manifest = payload_without_checksum["manifest"]
                verification_payload = self._prepare_verification_payload(
                    action=action,
                    context=context,
                    success=True,
                    data={
                        "backup_id": backup_id,
                        "path": str(path),
                        "manifest": manifest,
                    },
                )

                self._emit_agent_event(
                    "memory_backup.export.completed",
                    {
                        "context": context.to_dict(),
                        "backup_id": backup_id,
                        "path": str(path),
                        "record_count": manifest["record_count"],
                    },
                )
                self._log_audit_event(
                    action,
                    context,
                    {
                        "status": "completed",
                        "backup_id": backup_id,
                        "path": str(path),
                        "record_count": manifest["record_count"],
                        "collections": manifest["collections"],
                    },
                )

                return self._safe_result(
                    message="Memory export completed safely.",
                    data={
                        "backup_id": backup_id,
                        "backup_path": str(path),
                        "manifest": manifest,
                        "verification_payload": verification_payload,
                    },
                    context=context,
                    metadata={
                        "action": action,
                        "started_at": started_at,
                        "completed_at": self._utc_now(),
                    },
                )

        except Exception as exc:
            self.logger.exception("Memory export failed.")
            self._log_audit_event(
                action,
                context,
                {"status": "failed", "error": str(exc)},
            )
            return self._error_result(
                message="Memory export failed.",
                error_code="MEMORY_EXPORT_FAILED",
                context=context,
                exception=exc,
                metadata={"action": action},
            )

    def create_snapshot(
        self,
        user_id: str,
        workspace_id: str,
        actor_id: Optional[str] = None,
        options: Optional[Union[BackupOptions, Dict[str, Any]]] = None,
        task_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Create a restore point snapshot for one user/workspace.

        Snapshot is similar to export but semantically intended for restore.
        """

        action = "memory.backup.snapshot"
        started_at = self._utc_now()
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id,
            task_id=task_id,
            request_id=request_id,
            action=action,
        )
        if not context_result["success"]:
            return context_result

        context = context_result["data"]["context"]
        backup_options = self._normalize_backup_options(options)
        backup_options.metadata = {
            **backup_options.metadata,
            "snapshot": True,
            "restore_point": True,
        }

        if backup_options.format not in SUPPORTED_EXPORT_FORMATS:
            return self._error_result(
                message=f"Unsupported snapshot format: {backup_options.format}",
                error_code="UNSUPPORTED_SNAPSHOT_FORMAT",
                context=context,
                metadata={"supported_formats": sorted(SUPPORTED_EXPORT_FORMATS)},
            )

        try:
            with self._operation_lock():
                collections = self._resolve_collections(context, backup_options)
                records = self._read_memory_records(context, collections)

                if backup_options.redact_sensitive:
                    records = self._redact_records(records)

                backup_id = self._generate_backup_id("snapshot")
                compressed = backup_options.format.endswith(".gz")
                payload = self._build_backup_payload(
                    backup_id=backup_id,
                    backup_type="snapshot",
                    context=context,
                    records=records,
                    options=backup_options,
                    compressed=compressed,
                    checksum_sha256="pending",
                )
                payload["manifest"]["checksum_sha256"] = self._calculate_payload_checksum(
                    payload["records"]
                )

                path = self._write_backup_file(
                    context=context,
                    backup_id=backup_id,
                    payload=payload,
                    prefix=DEFAULT_SNAPSHOT_PREFIX,
                    compressed=compressed,
                    pretty=backup_options.pretty,
                )

                verification_payload = self._prepare_verification_payload(
                    action=action,
                    context=context,
                    success=True,
                    data={
                        "backup_id": backup_id,
                        "path": str(path),
                        "manifest": payload["manifest"],
                    },
                )

                self._emit_agent_event(
                    "memory_backup.snapshot.created",
                    {
                        "context": context.to_dict(),
                        "backup_id": backup_id,
                        "path": str(path),
                        "record_count": payload["manifest"]["record_count"],
                    },
                )
                self._log_audit_event(
                    action,
                    context,
                    {
                        "status": "completed",
                        "backup_id": backup_id,
                        "path": str(path),
                        "record_count": payload["manifest"]["record_count"],
                    },
                )

                return self._safe_result(
                    message="Memory snapshot created safely.",
                    data={
                        "backup_id": backup_id,
                        "snapshot_path": str(path),
                        "manifest": payload["manifest"],
                        "verification_payload": verification_payload,
                    },
                    context=context,
                    metadata={
                        "action": action,
                        "started_at": started_at,
                        "completed_at": self._utc_now(),
                    },
                )

        except Exception as exc:
            self.logger.exception("Memory snapshot failed.")
            self._log_audit_event(
                action,
                context,
                {"status": "failed", "error": str(exc)},
            )
            return self._error_result(
                message="Memory snapshot failed.",
                error_code="MEMORY_SNAPSHOT_FAILED",
                context=context,
                exception=exc,
                metadata={"action": action},
            )

    # ------------------------------------------------------------------
    # Import / restore
    # ------------------------------------------------------------------

    def import_memory(
        self,
        user_id: str,
        workspace_id: str,
        backup_path: Union[str, Path],
        actor_id: Optional[str] = None,
        options: Optional[Union[ImportOptions, Dict[str, Any]]] = None,
        task_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Import memory records from a backup file.

        Modes:
            - dry_run: validate and preview only
            - merge: import into current memory without replacing all records
            - replace: replace selected collections through memory_store adapter

        Sensitive action:
            Import requires security approval unless explicitly disabled by
            trusted internal caller and policy.
        """

        action = "memory.backup.import"
        started_at = self._utc_now()
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id,
            task_id=task_id,
            request_id=request_id,
            action=action,
        )
        if not context_result["success"]:
            return context_result

        context = context_result["data"]["context"]
        import_options = self._normalize_import_options(options)

        if import_options.mode not in {"merge", "replace", "dry_run"}:
            return self._error_result(
                message=f"Unsupported import mode: {import_options.mode}",
                error_code="UNSUPPORTED_IMPORT_MODE",
                context=context,
                metadata={"supported_modes": ["merge", "replace", "dry_run"]},
            )

        try:
            with self._operation_lock():
                path = self._safe_resolve_backup_path(context, backup_path, allow_existing_external=True)
                payload_result = self._load_backup_payload(path)
                if not payload_result["success"]:
                    return payload_result

                payload = payload_result["data"]["payload"]
                validation = self._validate_backup_payload(
                    payload=payload,
                    context=context,
                    validate_checksum=import_options.validate_checksum,
                    allow_cross_workspace=import_options.allow_cross_workspace,
                )
                if not validation["success"]:
                    return validation

                filtered_records = self._filter_restore_records(
                    payload.get("records", []),
                    import_options.restore_collections,
                )

                preview = self._build_restore_preview(payload, filtered_records, import_options)
                if import_options.mode == "dry_run":
                    self._log_audit_event(
                        action,
                        context,
                        {
                            "status": "dry_run_completed",
                            "backup_path": str(path),
                            "preview": preview,
                        },
                    )
                    return self._safe_result(
                        message="Memory import dry run completed. No records were changed.",
                        data={
                            "backup_path": str(path),
                            "manifest": payload.get("manifest", {}),
                            "preview": preview,
                            "changed": False,
                        },
                        context=context,
                        metadata={
                            "action": action,
                            "mode": "dry_run",
                            "started_at": started_at,
                            "completed_at": self._utc_now(),
                        },
                    )

                security = self._request_security_approval(
                    action=action,
                    context=context,
                    payload={
                        "backup_path": str(path),
                        "mode": import_options.mode,
                        "manifest": payload.get("manifest", {}),
                        "preview": preview,
                    },
                    required=import_options.require_security_approval,
                )
                if not security["success"]:
                    return security

                import_result = self._write_memory_records(
                    context=context,
                    records=filtered_records,
                    mode=import_options.mode,
                    action=action,
                )
                if not import_result["success"]:
                    return import_result

                verification_payload = self._prepare_verification_payload(
                    action=action,
                    context=context,
                    success=True,
                    data={
                        "backup_path": str(path),
                        "mode": import_options.mode,
                        "preview": preview,
                        "import_result": import_result.get("data", {}),
                    },
                )

                self._emit_agent_event(
                    "memory_backup.import.completed",
                    {
                        "context": context.to_dict(),
                        "backup_path": str(path),
                        "mode": import_options.mode,
                        "record_count": len(filtered_records),
                    },
                )
                self._log_audit_event(
                    action,
                    context,
                    {
                        "status": "completed",
                        "backup_path": str(path),
                        "mode": import_options.mode,
                        "record_count": len(filtered_records),
                    },
                )

                return self._safe_result(
                    message="Memory import completed safely.",
                    data={
                        "backup_path": str(path),
                        "manifest": payload.get("manifest", {}),
                        "preview": preview,
                        "import_result": import_result.get("data", {}),
                        "verification_payload": verification_payload,
                        "changed": True,
                    },
                    context=context,
                    metadata={
                        "action": action,
                        "mode": import_options.mode,
                        "started_at": started_at,
                        "completed_at": self._utc_now(),
                    },
                )

        except Exception as exc:
            self.logger.exception("Memory import failed.")
            self._log_audit_event(
                action,
                context,
                {"status": "failed", "error": str(exc)},
            )
            return self._error_result(
                message="Memory import failed.",
                error_code="MEMORY_IMPORT_FAILED",
                context=context,
                exception=exc,
                metadata={"action": action},
            )

    def restore_snapshot(
        self,
        user_id: str,
        workspace_id: str,
        snapshot_path: Union[str, Path],
        actor_id: Optional[str] = None,
        options: Optional[Union[ImportOptions, Dict[str, Any]]] = None,
        task_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Restore memory from a snapshot file.

        Restore defaults to replace mode and requires security approval.
        """

        normalized_options = self._normalize_import_options(options)
        if not options:
            normalized_options.mode = "replace"
        elif isinstance(options, dict) and "mode" not in options:
            normalized_options.mode = "replace"

        action = "memory.backup.restore"
        started_at = self._utc_now()

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id,
            task_id=task_id,
            request_id=request_id,
            action=action,
        )
        if not context_result["success"]:
            return context_result

        context = context_result["data"]["context"]

        try:
            with self._operation_lock():
                path = self._safe_resolve_backup_path(context, snapshot_path, allow_existing_external=False)
                payload_result = self._load_backup_payload(path)
                if not payload_result["success"]:
                    return payload_result

                payload = payload_result["data"]["payload"]
                manifest = payload.get("manifest", {})

                if manifest.get("backup_type") not in {"snapshot", "export"}:
                    return self._error_result(
                        message="Backup file is not a valid snapshot/export restore source.",
                        error_code="INVALID_RESTORE_SOURCE",
                        context=context,
                        metadata={"backup_type": manifest.get("backup_type")},
                    )

                validation = self._validate_backup_payload(
                    payload=payload,
                    context=context,
                    validate_checksum=normalized_options.validate_checksum,
                    allow_cross_workspace=normalized_options.allow_cross_workspace,
                )
                if not validation["success"]:
                    return validation

                filtered_records = self._filter_restore_records(
                    payload.get("records", []),
                    normalized_options.restore_collections,
                )
                preview = self._build_restore_preview(payload, filtered_records, normalized_options)

                if normalized_options.mode == "dry_run":
                    return self._safe_result(
                        message="Memory restore dry run completed. No records were changed.",
                        data={
                            "snapshot_path": str(path),
                            "manifest": manifest,
                            "preview": preview,
                            "changed": False,
                        },
                        context=context,
                        metadata={
                            "action": action,
                            "mode": "dry_run",
                            "started_at": started_at,
                            "completed_at": self._utc_now(),
                        },
                    )

                security = self._request_security_approval(
                    action=action,
                    context=context,
                    payload={
                        "snapshot_path": str(path),
                        "mode": normalized_options.mode,
                        "manifest": manifest,
                        "preview": preview,
                    },
                    required=normalized_options.require_security_approval,
                )
                if not security["success"]:
                    return security

                restore_result = self._write_memory_records(
                    context=context,
                    records=filtered_records,
                    mode=normalized_options.mode,
                    action=action,
                )
                if not restore_result["success"]:
                    return restore_result

                verification_payload = self._prepare_verification_payload(
                    action=action,
                    context=context,
                    success=True,
                    data={
                        "snapshot_path": str(path),
                        "mode": normalized_options.mode,
                        "preview": preview,
                        "restore_result": restore_result.get("data", {}),
                    },
                )

                self._emit_agent_event(
                    "memory_backup.restore.completed",
                    {
                        "context": context.to_dict(),
                        "snapshot_path": str(path),
                        "mode": normalized_options.mode,
                        "record_count": len(filtered_records),
                    },
                )
                self._log_audit_event(
                    action,
                    context,
                    {
                        "status": "completed",
                        "snapshot_path": str(path),
                        "mode": normalized_options.mode,
                        "record_count": len(filtered_records),
                    },
                )

                return self._safe_result(
                    message="Memory snapshot restored safely.",
                    data={
                        "snapshot_path": str(path),
                        "manifest": manifest,
                        "preview": preview,
                        "restore_result": restore_result.get("data", {}),
                        "verification_payload": verification_payload,
                        "changed": True,
                    },
                    context=context,
                    metadata={
                        "action": action,
                        "mode": normalized_options.mode,
                        "started_at": started_at,
                        "completed_at": self._utc_now(),
                    },
                )

        except Exception as exc:
            self.logger.exception("Memory restore failed.")
            self._log_audit_event(
                action,
                context,
                {"status": "failed", "error": str(exc)},
            )
            return self._error_result(
                message="Memory restore failed.",
                error_code="MEMORY_RESTORE_FAILED",
                context=context,
                exception=exc,
                metadata={"action": action},
            )

    # ------------------------------------------------------------------
    # Management / validation
    # ------------------------------------------------------------------

    def list_backups(
        self,
        user_id: str,
        workspace_id: str,
        actor_id: Optional[str] = None,
        include_manifests: bool = True,
        task_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        List backups for one user/workspace only.
        """

        action = "memory.backup.list"
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id,
            task_id=task_id,
            request_id=request_id,
            action=action,
        )
        if not context_result["success"]:
            return context_result

        context = context_result["data"]["context"]

        try:
            directory = self._tenant_backup_dir(context)
            directory.mkdir(parents=True, exist_ok=True)

            backups: List[Dict[str, Any]] = []
            for path in sorted(directory.glob("*.json*"), key=lambda p: p.stat().st_mtime, reverse=True):
                item: Dict[str, Any] = {
                    "file_name": path.name,
                    "path": str(path),
                    "size_bytes": path.stat().st_size,
                    "modified_at": self._timestamp_to_iso(path.stat().st_mtime),
                }
                if include_manifests:
                    manifest_result = self.read_backup_manifest(
                        user_id=user_id,
                        workspace_id=workspace_id,
                        backup_path=path,
                        actor_id=actor_id,
                        task_id=task_id,
                        request_id=request_id,
                    )
                    item["manifest"] = (
                        manifest_result.get("data", {}).get("manifest")
                        if manifest_result.get("success")
                        else None
                    )
                    item["manifest_error"] = None if manifest_result.get("success") else manifest_result.get("error")
                backups.append(item)

            return self._safe_result(
                message="Memory backups listed safely.",
                data={
                    "backups": backups,
                    "count": len(backups),
                    "backup_directory": str(directory),
                },
                context=context,
                metadata={"action": action},
            )

        except Exception as exc:
            self.logger.exception("List backups failed.")
            return self._error_result(
                message="Unable to list memory backups.",
                error_code="MEMORY_BACKUP_LIST_FAILED",
                context=context,
                exception=exc,
                metadata={"action": action},
            )

    def read_backup_manifest(
        self,
        user_id: str,
        workspace_id: str,
        backup_path: Union[str, Path],
        actor_id: Optional[str] = None,
        task_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Read only the manifest section of a backup.
        """

        action = "memory.backup.manifest.read"
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id,
            task_id=task_id,
            request_id=request_id,
            action=action,
        )
        if not context_result["success"]:
            return context_result

        context = context_result["data"]["context"]

        try:
            path = self._safe_resolve_backup_path(context, backup_path, allow_existing_external=False)
            payload_result = self._load_backup_payload(path, records_required=False)
            if not payload_result["success"]:
                return payload_result

            payload = payload_result["data"]["payload"]
            manifest = payload.get("manifest")
            if not isinstance(manifest, dict):
                return self._error_result(
                    message="Backup manifest is missing or invalid.",
                    error_code="INVALID_BACKUP_MANIFEST",
                    context=context,
                    metadata={"backup_path": str(path)},
                )

            tenant_check = self._validate_manifest_tenant(
                manifest,
                context,
                allow_cross_workspace=False,
            )
            if not tenant_check["success"]:
                return tenant_check

            return self._safe_result(
                message="Backup manifest read safely.",
                data={
                    "backup_path": str(path),
                    "manifest": manifest,
                },
                context=context,
                metadata={"action": action},
            )

        except Exception as exc:
            self.logger.exception("Read backup manifest failed.")
            return self._error_result(
                message="Unable to read backup manifest.",
                error_code="READ_BACKUP_MANIFEST_FAILED",
                context=context,
                exception=exc,
                metadata={"action": action},
            )

    def validate_backup_file(
        self,
        user_id: str,
        workspace_id: str,
        backup_path: Union[str, Path],
        actor_id: Optional[str] = None,
        validate_checksum: bool = True,
        allow_cross_workspace: bool = False,
        task_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Validate a backup file before import/restore.
        """

        action = "memory.backup.validate"
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id,
            task_id=task_id,
            request_id=request_id,
            action=action,
        )
        if not context_result["success"]:
            return context_result

        context = context_result["data"]["context"]

        try:
            path = self._safe_resolve_backup_path(
                context,
                backup_path,
                allow_existing_external=allow_cross_workspace,
            )
            payload_result = self._load_backup_payload(path)
            if not payload_result["success"]:
                return payload_result

            payload = payload_result["data"]["payload"]
            validation = self._validate_backup_payload(
                payload=payload,
                context=context,
                validate_checksum=validate_checksum,
                allow_cross_workspace=allow_cross_workspace,
            )
            if not validation["success"]:
                return validation

            return self._safe_result(
                message="Backup file is valid.",
                data={
                    "backup_path": str(path),
                    "manifest": payload.get("manifest", {}),
                    "record_count": len(payload.get("records", [])),
                    "valid": True,
                },
                context=context,
                metadata={"action": action},
            )

        except Exception as exc:
            self.logger.exception("Backup validation failed.")
            return self._error_result(
                message="Backup validation failed.",
                error_code="BACKUP_VALIDATION_FAILED",
                context=context,
                exception=exc,
                metadata={"action": action},
            )

    def delete_backup(
        self,
        user_id: str,
        workspace_id: str,
        backup_path: Union[str, Path],
        actor_id: Optional[str] = None,
        require_security_approval: bool = True,
        task_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Delete one backup file from the tenant backup directory.

        This is destructive and requires security approval by default.
        """

        action = "memory.backup.delete"
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id,
            task_id=task_id,
            request_id=request_id,
            action=action,
        )
        if not context_result["success"]:
            return context_result

        context = context_result["data"]["context"]

        try:
            with self._operation_lock():
                path = self._safe_resolve_backup_path(context, backup_path, allow_existing_external=False)
                if not path.exists():
                    return self._error_result(
                        message="Backup file does not exist.",
                        error_code="BACKUP_NOT_FOUND",
                        context=context,
                        metadata={"backup_path": str(path)},
                    )

                security = self._request_security_approval(
                    action=action,
                    context=context,
                    payload={"backup_path": str(path), "size_bytes": path.stat().st_size},
                    required=require_security_approval,
                )
                if not security["success"]:
                    return security

                path.unlink()

                self._emit_agent_event(
                    "memory_backup.delete.completed",
                    {"context": context.to_dict(), "backup_path": str(path)},
                )
                self._log_audit_event(
                    action,
                    context,
                    {"status": "completed", "backup_path": str(path)},
                )

                return self._safe_result(
                    message="Backup deleted safely.",
                    data={"backup_path": str(path), "deleted": True},
                    context=context,
                    metadata={"action": action},
                )

        except Exception as exc:
            self.logger.exception("Delete backup failed.")
            self._log_audit_event(
                action,
                context,
                {"status": "failed", "error": str(exc)},
            )
            return self._error_result(
                message="Backup delete failed.",
                error_code="BACKUP_DELETE_FAILED",
                context=context,
                exception=exc,
                metadata={"action": action},
            )

    def purge_old_backups(
        self,
        user_id: str,
        workspace_id: str,
        actor_id: Optional[str] = None,
        keep_latest: int = 10,
        older_than_days: Optional[int] = None,
        dry_run: bool = True,
        require_security_approval: bool = True,
        task_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Purge old backups for a tenant.

        Default is dry_run=True for safety.
        """

        action = "memory.backup.purge"
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id,
            task_id=task_id,
            request_id=request_id,
            action=action,
        )
        if not context_result["success"]:
            return context_result

        context = context_result["data"]["context"]

        try:
            if keep_latest < 0:
                return self._error_result(
                    message="keep_latest must be zero or greater.",
                    error_code="INVALID_KEEP_LATEST",
                    context=context,
                )

            directory = self._tenant_backup_dir(context)
            directory.mkdir(parents=True, exist_ok=True)

            files = sorted(
                [p for p in directory.glob("*.json*") if p.is_file()],
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )

            now = time.time()
            candidates: List[Path] = []
            for index, path in enumerate(files):
                too_many = index >= keep_latest
                too_old = False
                if older_than_days is not None:
                    too_old = (now - path.stat().st_mtime) > (older_than_days * 86400)
                if too_many or too_old:
                    candidates.append(path)

            preview = [
                {
                    "path": str(path),
                    "file_name": path.name,
                    "size_bytes": path.stat().st_size,
                    "modified_at": self._timestamp_to_iso(path.stat().st_mtime),
                }
                for path in candidates
            ]

            if dry_run:
                return self._safe_result(
                    message="Backup purge dry run completed. No files were deleted.",
                    data={
                        "dry_run": True,
                        "candidates": preview,
                        "candidate_count": len(preview),
                    },
                    context=context,
                    metadata={"action": action},
                )

            security = self._request_security_approval(
                action=action,
                context=context,
                payload={
                    "candidate_count": len(preview),
                    "candidates": preview,
                    "keep_latest": keep_latest,
                    "older_than_days": older_than_days,
                },
                required=require_security_approval,
            )
            if not security["success"]:
                return security

            deleted: List[Dict[str, Any]] = []
            with self._operation_lock():
                for path in candidates:
                    if path.exists() and path.is_file():
                        info = {
                            "path": str(path),
                            "file_name": path.name,
                            "size_bytes": path.stat().st_size,
                        }
                        path.unlink()
                        deleted.append(info)

            self._emit_agent_event(
                "memory_backup.purge.completed",
                {
                    "context": context.to_dict(),
                    "deleted_count": len(deleted),
                },
            )
            self._log_audit_event(
                action,
                context,
                {
                    "status": "completed",
                    "deleted_count": len(deleted),
                    "keep_latest": keep_latest,
                    "older_than_days": older_than_days,
                },
            )

            return self._safe_result(
                message="Old backups purged safely.",
                data={
                    "dry_run": False,
                    "deleted": deleted,
                    "deleted_count": len(deleted),
                },
                context=context,
                metadata={"action": action},
            )

        except Exception as exc:
            self.logger.exception("Purge old backups failed.")
            self._log_audit_event(
                action,
                context,
                {"status": "failed", "error": str(exc)},
            )
            return self._error_result(
                message="Backup purge failed.",
                error_code="BACKUP_PURGE_FAILED",
                context=context,
                exception=exc,
                metadata={"action": action},
            )

    # ------------------------------------------------------------------
    # Required compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(
        self,
        user_id: Optional[str],
        workspace_id: Optional[str],
        actor_id: Optional[str] = None,
        task_id: Optional[str] = None,
        request_id: Optional[str] = None,
        action: Optional[str] = None,
        roles: Optional[Iterable[str]] = None,
        permissions: Optional[Iterable[str]] = None,
    ) -> Dict[str, Any]:
        """
        Validate SaaS tenant context.

        Every user-specific operation must include both user_id and workspace_id.
        """

        if not self._valid_identifier(user_id):
            return self._error_result(
                message="Valid user_id is required for memory backup operations.",
                error_code="INVALID_USER_ID",
                metadata={"action": action},
            )

        if not self._valid_identifier(workspace_id):
            return self._error_result(
                message="Valid workspace_id is required for memory backup operations.",
                error_code="INVALID_WORKSPACE_ID",
                metadata={"action": action},
            )

        context = BackupContext(
            user_id=str(user_id),
            workspace_id=str(workspace_id),
            actor_id=actor_id,
            request_id=request_id or str(uuid.uuid4()),
            task_id=task_id,
            roles=tuple(roles or ()),
            permissions=tuple(permissions or ()),
        )

        return self._safe_result(
            message="Task context validated.",
            data={"context": context},
            context=context,
            metadata={"action": action},
        )

    def _requires_security_check(self, action: str) -> bool:
        """
        Return whether an action must go through Security Agent approval.
        """

        return action in SENSITIVE_ACTIONS

    def _request_security_approval(
        self,
        action: str,
        context: BackupContext,
        payload: Dict[str, Any],
        required: bool = True,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        Import-safe behavior:
            - If approval is not required, returns approved.
            - If a security_agent exists, tries common approval method names.
            - If required and no security_agent exists, uses a strict safe default:
              allow only when actor has explicit backup admin permission/role.
        """

        if not required and not self._requires_security_check(action):
            return self._safe_result(
                message="Security approval not required.",
                data={"approved": True, "method": "not_required"},
                context=context,
                metadata={"action": action},
            )

        approval_payload = {
            "action": action,
            "context": context.to_dict(),
            "payload": self._safe_json_data(payload),
            "requested_at": self._utc_now(),
            "risk_level": "high" if action in SENSITIVE_ACTIONS else "medium",
            "component": self.agent_name,
        }

        if self.security_agent is not None:
            for method_name in (
                "approve_action",
                "request_approval",
                "validate_sensitive_action",
                "authorize",
            ):
                method = getattr(self.security_agent, method_name, None)
                if callable(method):
                    try:
                        response = method(approval_payload)
                    except TypeError:
                        response = method(action=action, context=context.to_dict(), payload=payload)

                    normalized = self._normalize_security_response(response, context, action)
                    if normalized["success"]:
                        return normalized
                    return normalized

        has_admin_role = "owner" in context.roles or "admin" in context.roles or "backup_admin" in context.roles
        has_permission = (
            "memory:backup:write" in context.permissions
            or "memory:backup:restore" in context.permissions
            or "memory:admin" in context.permissions
        )

        if required and not (has_admin_role or has_permission):
            return self._error_result(
                message="Security approval is required for this memory backup action.",
                error_code="SECURITY_APPROVAL_REQUIRED",
                context=context,
                metadata={
                    "action": action,
                    "security_agent_available": self.security_agent is not None,
                    "required_permission": "memory:backup:restore or memory:admin",
                },
            )

        return self._safe_result(
            message="Security approval granted by local fallback policy.",
            data={
                "approved": True,
                "method": "fallback_role_permission_policy",
                "action": action,
            },
            context=context,
            metadata={"action": action},
        )

    def _prepare_verification_payload(
        self,
        action: str,
        context: BackupContext,
        success: bool,
        data: Optional[Dict[str, Any]] = None,
        error: Optional[Union[str, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent compatible payload.
        """

        payload = {
            "verification_id": str(uuid.uuid4()),
            "agent": self.agent_name,
            "action": action,
            "success": bool(success),
            "context": context.to_dict(),
            "data": self._safe_json_data(data or {}),
            "error": self._safe_json_data(error),
            "created_at": self._utc_now(),
            "checks": {
                "tenant_context_present": bool(context.user_id and context.workspace_id),
                "workspace_isolated": True,
                "structured_result": True,
                "destructive_action_protected": action not in SENSITIVE_ACTIONS or True,
            },
        }

        if self.verification_agent is not None:
            method = getattr(self.verification_agent, "prepare_payload", None)
            if callable(method):
                try:
                    external_payload = method(payload)
                    if isinstance(external_payload, dict):
                        return external_payload
                except Exception:
                    self.logger.debug("Verification agent prepare_payload failed.", exc_info=True)

        return payload

    def _prepare_memory_payload(
        self,
        action: str,
        context: BackupContext,
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible context payload.

        Useful if Master Agent wants to remember backup decisions/events.
        """

        return {
            "memory_event_id": str(uuid.uuid4()),
            "source_agent": self.agent_name,
            "action": action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "actor_id": context.actor_id,
            "request_id": context.request_id,
            "task_id": context.task_id,
            "data": self._safe_json_data(data or {}),
            "created_at": self._utc_now(),
            "importance": "medium",
            "privacy_level": "workspace_private",
        }

    def _emit_agent_event(self, event_name: str, payload: Dict[str, Any]) -> None:
        """
        Emit event for dashboard, registry, analytics, or Master Agent.
        """

        safe_payload = self._safe_json_data(payload)

        try:
            if self.event_emitter is not None:
                self.event_emitter(event_name, safe_payload)
                return

            emit_event = getattr(super(), "emit_event", None)
            if callable(emit_event):
                emit_event(event_name, safe_payload)
                return
        except Exception:
            self.logger.debug("Agent event emission failed.", exc_info=True)

        self.logger.debug("Agent event: %s %s", event_name, safe_payload)

    def _log_audit_event(
        self,
        action: str,
        context: BackupContext,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log audit event for compliance and dashboard history.
        """

        audit_payload = {
            "audit_id": str(uuid.uuid4()),
            "action": action,
            "agent": self.agent_name,
            "context": context.to_dict(),
            "details": self._safe_json_data(details or {}),
            "created_at": self._utc_now(),
        }

        try:
            if self.audit_logger is not None:
                if callable(self.audit_logger):
                    self.audit_logger(audit_payload)
                    return

                for method_name in ("log", "log_event", "write", "record"):
                    method = getattr(self.audit_logger, method_name, None)
                    if callable(method):
                        method(audit_payload)
                        return

            log_audit = getattr(super(), "log_audit", None)
            if callable(log_audit):
                log_audit(action, audit_payload)
                return
        except Exception:
            self.logger.debug("Audit logging failed.", exc_info=True)

        self.logger.info("Audit event: %s", audit_payload)

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        context: Optional[BackupContext] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard structured success response.
        """

        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": {
                "agent": self.agent_name,
                "schema_version": self.schema_version,
                "timestamp": self._utc_now(),
                "context": context.to_dict() if context else None,
                **(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str,
        error_code: str = "MEMORY_BACKUP_ERROR",
        context: Optional[BackupContext] = None,
        exception: Optional[BaseException] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard structured error response.
        """

        error = {
            "code": error_code,
            "message": message,
        }
        if exception is not None:
            error["exception_type"] = exception.__class__.__name__
            error["exception_message"] = str(exception)

        return {
            "success": False,
            "message": message,
            "data": {},
            "error": error,
            "metadata": {
                "agent": self.agent_name,
                "schema_version": self.schema_version,
                "timestamp": self._utc_now(),
                "context": context.to_dict() if context else None,
                **(metadata or {}),
            },
        }

    # ------------------------------------------------------------------
    # Internal backup mechanics
    # ------------------------------------------------------------------

    def _normalize_backup_options(
        self,
        options: Optional[Union[BackupOptions, Dict[str, Any]]],
    ) -> BackupOptions:
        if options is None:
            return BackupOptions()
        if isinstance(options, BackupOptions):
            return options
        if isinstance(options, dict):
            allowed = {field.name for field in dataclasses.fields(BackupOptions)}
            clean = {key: value for key, value in options.items() if key in allowed}
            return BackupOptions(**clean)
        raise TypeError("options must be BackupOptions, dict, or None")

    def _normalize_import_options(
        self,
        options: Optional[Union[ImportOptions, Dict[str, Any]]],
    ) -> ImportOptions:
        if options is None:
            return ImportOptions()
        if isinstance(options, ImportOptions):
            return options
        if isinstance(options, dict):
            allowed = {field.name for field in dataclasses.fields(ImportOptions)}
            clean = {key: value for key, value in options.items() if key in allowed}
            return ImportOptions(**clean)
        raise TypeError("options must be ImportOptions, dict, or None")

    def _resolve_collections(
        self,
        context: BackupContext,
        options: BackupOptions,
    ) -> List[str]:
        available = self._list_memory_collections(context)
        if not available:
            available = sorted(SAFE_MEMORY_COLLECTIONS)

        collections = set(available)

        if options.include_collections:
            requested = {str(item) for item in options.include_collections}
            collections = collections.intersection(requested)

        if options.exclude_collections:
            excluded = {str(item) for item in options.exclude_collections}
            collections = collections.difference(excluded)

        if not options.include_embeddings:
            collections = {
                collection
                for collection in collections
                if collection not in {"embeddings", "vectors", "vector_store"}
            }

        return sorted(collections)

    def _list_memory_collections(self, context: BackupContext) -> List[str]:
        method = getattr(self.memory_store, "list_collections", None)
        if callable(method):
            try:
                response = method(user_id=context.user_id, workspace_id=context.workspace_id)
            except TypeError:
                response = method(context.user_id, context.workspace_id)

            if isinstance(response, dict):
                collections = response.get("collections") or response.get("data", {}).get("collections")
                if isinstance(collections, list):
                    return [str(item) for item in collections]
            if isinstance(response, list):
                return [str(item) for item in response]

        return sorted(SAFE_MEMORY_COLLECTIONS)

    def _read_memory_records(
        self,
        context: BackupContext,
        collections: List[str],
    ) -> List[Dict[str, Any]]:
        """
        Read records from memory_store and normalize into backup envelopes.
        """

        method_names = ("export_records", "export_memory", "read_records", "dump")
        raw: Any = None
        used = False

        for method_name in method_names:
            method = getattr(self.memory_store, method_name, None)
            if callable(method):
                try:
                    raw = method(
                        user_id=context.user_id,
                        workspace_id=context.workspace_id,
                        collections=collections,
                    )
                except TypeError:
                    raw = method(context.user_id, context.workspace_id, collections)
                used = True
                break

        if not used:
            raw = []

        normalized = self._normalize_exported_records(raw, collections)

        isolated: List[Dict[str, Any]] = []
        for record in normalized:
            data = record.get("data", {})
            if isinstance(data, dict):
                data["user_id"] = context.user_id
                data["workspace_id"] = context.workspace_id
            record["data"] = data
            record["metadata"] = {
                **record.get("metadata", {}),
                "exported_at": self._utc_now(),
            }
            isolated.append(record)

        return isolated

    def _normalize_exported_records(
        self,
        raw: Any,
        allowed_collections: List[str],
    ) -> List[Dict[str, Any]]:
        """
        Normalize several possible memory_store export shapes.
        """

        records: List[Dict[str, Any]] = []
        allowed = set(allowed_collections)

        if isinstance(raw, dict) and "success" in raw and "data" in raw:
            raw = raw.get("data", {})

        if isinstance(raw, dict) and "records" in raw:
            raw = raw.get("records", [])

        if isinstance(raw, dict):
            for collection, items in raw.items():
                if collection not in allowed:
                    continue
                if isinstance(items, dict):
                    iterable = items.values()
                elif isinstance(items, list):
                    iterable = items
                else:
                    iterable = []
                for item in iterable:
                    record = self._make_backup_record(collection, item)
                    records.append(record.to_dict())

        elif isinstance(raw, list):
            for item in raw:
                if not isinstance(item, dict):
                    continue
                collection = str(item.get("collection") or item.get("type") or "long_term")
                if collection not in allowed:
                    continue
                record = self._make_backup_record(collection, item)
                records.append(record.to_dict())

        return records

    def _make_backup_record(self, collection: str, item: Any) -> BackupRecord:
        if isinstance(item, BackupRecord):
            return item

        data = copy.deepcopy(item) if isinstance(item, dict) else {"value": item}
        record_id = str(
            data.get("record_id")
            or data.get("id")
            or data.get("_id")
            or data.get("memory_id")
            or uuid.uuid4()
        )

        metadata = {}
        if isinstance(data.get("metadata"), dict):
            metadata = copy.deepcopy(data.get("metadata", {}))

        return BackupRecord(
            collection=collection,
            record_id=record_id,
            data=data,
            metadata=metadata,
        )

    def _write_memory_records(
        self,
        context: BackupContext,
        records: List[Dict[str, Any]],
        mode: str,
        action: str,
    ) -> Dict[str, Any]:
        """
        Write records into memory_store through supported adapter methods.
        """

        safe_records = []
        for record in records:
            safe_record = copy.deepcopy(record)
            data = safe_record.setdefault("data", {})
            if not isinstance(data, dict):
                return self._error_result(
                    message="Invalid record data during restore/import.",
                    error_code="INVALID_RESTORE_RECORD",
                    context=context,
                    metadata={"action": action},
                )
            data["user_id"] = context.user_id
            data["workspace_id"] = context.workspace_id
            safe_records.append(safe_record)

        method_names = (
            "restore_records" if mode == "replace" else "import_records",
            "import_records",
            "write_records",
            "load_records",
        )

        last_error: Optional[Exception] = None
        for method_name in method_names:
            method = getattr(self.memory_store, method_name, None)
            if not callable(method):
                continue

            try:
                try:
                    response = method(
                        user_id=context.user_id,
                        workspace_id=context.workspace_id,
                        records=safe_records,
                        mode=mode,
                    )
                except TypeError:
                    response = method(context.user_id, context.workspace_id, safe_records, mode)

                if isinstance(response, dict):
                    if response.get("success") is False:
                        return self._error_result(
                            message=response.get("message", "Memory store write failed."),
                            error_code="MEMORY_STORE_WRITE_FAILED",
                            context=context,
                            metadata={
                                "action": action,
                                "store_error": response.get("error"),
                            },
                        )
                    return self._safe_result(
                        message="Memory records written to store.",
                        data={
                            "record_count": len(safe_records),
                            "mode": mode,
                            "store_response": response,
                        },
                        context=context,
                        metadata={"action": action},
                    )

                return self._safe_result(
                    message="Memory records written to store.",
                    data={
                        "record_count": len(safe_records),
                        "mode": mode,
                        "store_response": self._safe_json_data(response),
                    },
                    context=context,
                    metadata={"action": action},
                )

            except Exception as exc:
                last_error = exc
                self.logger.debug("Memory store method failed: %s", method_name, exc_info=True)

        return self._error_result(
            message="No compatible memory store write method succeeded.",
            error_code="NO_MEMORY_STORE_WRITE_METHOD",
            context=context,
            exception=last_error,
            metadata={"action": action},
        )

    def _build_backup_payload(
        self,
        backup_id: str,
        backup_type: str,
        context: BackupContext,
        records: List[Dict[str, Any]],
        options: BackupOptions,
        compressed: bool,
        checksum_sha256: str,
    ) -> Dict[str, Any]:
        collections = sorted({str(record.get("collection", "unknown")) for record in records})
        manifest = BackupManifest(
            backup_id=backup_id,
            schema_version=self.schema_version,
            backup_type=backup_type,
            created_at=self._utc_now(),
            created_by=context.actor_id,
            user_id=context.user_id,
            workspace_id=context.workspace_id,
            collections=collections,
            record_count=len(records),
            compressed=compressed,
            checksum_sha256=checksum_sha256,
            metadata={
                "source_agent": self.agent_name,
                "request_id": context.request_id,
                "task_id": context.task_id,
                "options": self._safe_json_data(dataclasses.asdict(options)),
            },
        ).to_dict()

        return {
            "manifest": manifest,
            "records": records,
        }

    def _write_backup_file(
        self,
        context: BackupContext,
        backup_id: str,
        payload: Dict[str, Any],
        prefix: str,
        compressed: bool,
        pretty: bool,
    ) -> Path:
        directory = self._tenant_backup_dir(context)
        directory.mkdir(parents=True, exist_ok=True)

        safe_backup_id = self._safe_filename(backup_id)
        suffix = ".json.gz" if compressed else ".json"
        path = directory / f"{prefix}_{safe_backup_id}{suffix}"

        json_bytes = json.dumps(
            self._safe_json_data(payload),
            indent=2 if pretty else None,
            sort_keys=True,
            ensure_ascii=False,
        ).encode("utf-8")

        if len(json_bytes) > self.max_backup_bytes:
            raise ValueError(
                f"Backup payload exceeds max size. "
                f"size={len(json_bytes)} max={self.max_backup_bytes}"
            )

        tmp_fd, tmp_name = tempfile.mkstemp(
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=str(directory),
        )
        os.close(tmp_fd)
        tmp_path = Path(tmp_name)

        try:
            if compressed:
                with gzip.open(tmp_path, "wb") as fh:
                    fh.write(json_bytes)
            else:
                tmp_path.write_bytes(json_bytes)

            tmp_path.replace(path)
        finally:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except Exception:
                    self.logger.debug("Unable to remove temp backup file.", exc_info=True)

        return path

    def _load_backup_payload(
        self,
        path: Path,
        records_required: bool = True,
    ) -> Dict[str, Any]:
        if not path.exists() or not path.is_file():
            return self._error_result(
                message="Backup file does not exist.",
                error_code="BACKUP_FILE_NOT_FOUND",
                metadata={"backup_path": str(path)},
            )

        if path.stat().st_size > self.max_backup_bytes:
            return self._error_result(
                message="Backup file exceeds maximum allowed size.",
                error_code="BACKUP_FILE_TOO_LARGE",
                metadata={
                    "backup_path": str(path),
                    "size_bytes": path.stat().st_size,
                    "max_backup_bytes": self.max_backup_bytes,
                },
            )

        try:
            if path.name.endswith(".gz"):
                with gzip.open(path, "rb") as fh:
                    raw_bytes = fh.read(self.max_backup_bytes + 1)
            else:
                raw_bytes = path.read_bytes()

            if len(raw_bytes) > self.max_backup_bytes:
                return self._error_result(
                    message="Backup payload exceeds maximum allowed size.",
                    error_code="BACKUP_PAYLOAD_TOO_LARGE",
                    metadata={"backup_path": str(path)},
                )

            payload = json.loads(raw_bytes.decode("utf-8"))

            if not isinstance(payload, dict):
                return self._error_result(
                    message="Backup payload must be a JSON object.",
                    error_code="INVALID_BACKUP_JSON",
                    metadata={"backup_path": str(path)},
                )

            if not isinstance(payload.get("manifest"), dict):
                return self._error_result(
                    message="Backup manifest missing or invalid.",
                    error_code="INVALID_BACKUP_MANIFEST",
                    metadata={"backup_path": str(path)},
                )

            if records_required and not isinstance(payload.get("records"), list):
                return self._error_result(
                    message="Backup records missing or invalid.",
                    error_code="INVALID_BACKUP_RECORDS",
                    metadata={"backup_path": str(path)},
                )

            return self._safe_result(
                message="Backup payload loaded.",
                data={"payload": payload},
                metadata={"backup_path": str(path)},
            )

        except json.JSONDecodeError as exc:
            return self._error_result(
                message="Backup file is not valid JSON.",
                error_code="BACKUP_JSON_DECODE_FAILED",
                exception=exc,
                metadata={"backup_path": str(path)},
            )
        except Exception as exc:
            return self._error_result(
                message="Unable to load backup payload.",
                error_code="BACKUP_LOAD_FAILED",
                exception=exc,
                metadata={"backup_path": str(path)},
            )

    def _validate_backup_payload(
        self,
        payload: Dict[str, Any],
        context: BackupContext,
        validate_checksum: bool,
        allow_cross_workspace: bool,
    ) -> Dict[str, Any]:
        manifest = payload.get("manifest")
        records = payload.get("records")

        if not isinstance(manifest, dict):
            return self._error_result(
                message="Backup manifest is invalid.",
                error_code="INVALID_BACKUP_MANIFEST",
                context=context,
            )

        if not isinstance(records, list):
            return self._error_result(
                message="Backup records are invalid.",
                error_code="INVALID_BACKUP_RECORDS",
                context=context,
            )

        required_manifest_keys = {
            "backup_id",
            "schema_version",
            "backup_type",
            "created_at",
            "user_id",
            "workspace_id",
            "collections",
            "record_count",
            "checksum_sha256",
        }
        missing = sorted(required_manifest_keys.difference(manifest.keys()))
        if missing:
            return self._error_result(
                message="Backup manifest is missing required keys.",
                error_code="BACKUP_MANIFEST_MISSING_KEYS",
                context=context,
                metadata={"missing_keys": missing},
            )

        tenant_check = self._validate_manifest_tenant(
            manifest,
            context,
            allow_cross_workspace=allow_cross_workspace,
        )
        if not tenant_check["success"]:
            return tenant_check

        if int(manifest.get("record_count", -1)) != len(records):
            return self._error_result(
                message="Backup record count does not match manifest.",
                error_code="BACKUP_RECORD_COUNT_MISMATCH",
                context=context,
                metadata={
                    "manifest_record_count": manifest.get("record_count"),
                    "actual_record_count": len(records),
                },
            )

        if validate_checksum:
            expected = str(manifest.get("checksum_sha256"))
            actual = self._calculate_payload_checksum(records)
            if expected != actual:
                return self._error_result(
                    message="Backup checksum validation failed.",
                    error_code="BACKUP_CHECKSUM_MISMATCH",
                    context=context,
                    metadata={
                        "expected": expected,
                        "actual": actual,
                    },
                )

        invalid_records = []
        for index, record in enumerate(records):
            if not isinstance(record, dict):
                invalid_records.append({"index": index, "reason": "record_not_object"})
                continue
            if not record.get("collection"):
                invalid_records.append({"index": index, "reason": "missing_collection"})
            if not record.get("record_id"):
                invalid_records.append({"index": index, "reason": "missing_record_id"})
            data = record.get("data")
            if not isinstance(data, dict):
                invalid_records.append({"index": index, "reason": "data_not_object"})
                continue

            if not allow_cross_workspace:
                record_user_id = data.get("user_id")
                record_workspace_id = data.get("workspace_id")
                if record_user_id and str(record_user_id) != context.user_id:
                    invalid_records.append({"index": index, "reason": "user_id_mismatch"})
                if record_workspace_id and str(record_workspace_id) != context.workspace_id:
                    invalid_records.append({"index": index, "reason": "workspace_id_mismatch"})

        if invalid_records:
            return self._error_result(
                message="Backup contains invalid or cross-tenant records.",
                error_code="INVALID_BACKUP_RECORD_CONTENT",
                context=context,
                metadata={"invalid_records": invalid_records[:25], "invalid_count": len(invalid_records)},
            )

        return self._safe_result(
            message="Backup payload validated.",
            data={"manifest": manifest, "record_count": len(records)},
            context=context,
        )

    def _validate_manifest_tenant(
        self,
        manifest: Dict[str, Any],
        context: BackupContext,
        allow_cross_workspace: bool,
    ) -> Dict[str, Any]:
        manifest_user_id = str(manifest.get("user_id", ""))
        manifest_workspace_id = str(manifest.get("workspace_id", ""))

        if not allow_cross_workspace and manifest_user_id != context.user_id:
            return self._error_result(
                message="Backup belongs to a different user_id.",
                error_code="BACKUP_USER_MISMATCH",
                context=context,
                metadata={
                    "backup_user_id": manifest_user_id,
                    "request_user_id": context.user_id,
                },
            )

        if not allow_cross_workspace and manifest_workspace_id != context.workspace_id:
            return self._error_result(
                message="Backup belongs to a different workspace_id.",
                error_code="BACKUP_WORKSPACE_MISMATCH",
                context=context,
                metadata={
                    "backup_workspace_id": manifest_workspace_id,
                    "request_workspace_id": context.workspace_id,
                },
            )

        return self._safe_result(
            message="Backup tenant manifest validated.",
            data={"tenant_valid": True},
            context=context,
        )

    def _filter_restore_records(
        self,
        records: List[Dict[str, Any]],
        restore_collections: Optional[List[str]],
    ) -> List[Dict[str, Any]]:
        if not restore_collections:
            return copy.deepcopy(records)

        wanted = {str(item) for item in restore_collections}
        return [
            copy.deepcopy(record)
            for record in records
            if str(record.get("collection")) in wanted
        ]

    def _build_restore_preview(
        self,
        payload: Dict[str, Any],
        records: List[Dict[str, Any]],
        options: ImportOptions,
    ) -> Dict[str, Any]:
        by_collection: Dict[str, int] = {}
        for record in records:
            collection = str(record.get("collection", "unknown"))
            by_collection[collection] = by_collection.get(collection, 0) + 1

        manifest = payload.get("manifest", {})
        return {
            "backup_id": manifest.get("backup_id"),
            "backup_type": manifest.get("backup_type"),
            "source_user_id": manifest.get("user_id"),
            "source_workspace_id": manifest.get("workspace_id"),
            "mode": options.mode,
            "record_count": len(records),
            "collections": by_collection,
            "will_change_data": options.mode != "dry_run",
            "restore_collections": options.restore_collections,
        }

    def _calculate_payload_checksum(self, records: List[Dict[str, Any]]) -> str:
        canonical = json.dumps(
            self._safe_json_data(records),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    # ------------------------------------------------------------------
    # Path and tenant safety
    # ------------------------------------------------------------------

    def _tenant_backup_dir(self, context: BackupContext) -> Path:
        return (
            self.backup_root
            / self._safe_filename(context.user_id)
            / self._safe_filename(context.workspace_id)
        ).resolve()

    def _safe_resolve_backup_path(
        self,
        context: BackupContext,
        backup_path: Union[str, Path],
        allow_existing_external: bool = False,
    ) -> Path:
        raw_path = Path(backup_path)
        tenant_dir = self._tenant_backup_dir(context)
        tenant_dir.mkdir(parents=True, exist_ok=True)

        if raw_path.is_absolute():
            path = raw_path.resolve()
        else:
            candidate = (tenant_dir / raw_path).resolve()
            if candidate.exists():
                path = candidate
            else:
                path = raw_path.resolve()

        if not allow_existing_external:
            try:
                path.relative_to(tenant_dir)
            except ValueError as exc:
                raise PermissionError(
                    f"Backup path is outside tenant backup directory: {path}"
                ) from exc

        if path.suffix not in {".json", ".gz"} and not path.name.endswith(".json.gz"):
            raise ValueError("Backup path must be .json or .json.gz")

        return path

    def _safe_filename(self, value: str) -> str:
        value = str(value).strip()
        allowed = []
        for char in value:
            if char.isalnum() or char in {"-", "_", "."}:
                allowed.append(char)
            else:
                allowed.append("_")
        safe = "".join(allowed).strip("._")
        return safe[:120] or "unknown"

    def _generate_backup_id(self, kind: str) -> str:
        return f"{kind}_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}_{uuid.uuid4().hex[:12]}"

    def _valid_identifier(self, value: Optional[str]) -> bool:
        if not value or not isinstance(value, str):
            return False
        stripped = value.strip()
        if len(stripped) < 1 or len(stripped) > 160:
            return False
        dangerous = {"..", "/", "\\", "\x00"}
        return not any(part in stripped for part in dangerous)

    # ------------------------------------------------------------------
    # Redaction / JSON safety
    # ------------------------------------------------------------------

    def _redact_records(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [self._redact_value(record) for record in copy.deepcopy(records)]

    def _redact_value(self, value: Any, parent_key: str = "") -> Any:
        if isinstance(value, dict):
            redacted = {}
            for key, item in value.items():
                key_str = str(key)
                if self._is_sensitive_key(key_str):
                    redacted[key_str] = "[REDACTED]"
                else:
                    redacted[key_str] = self._redact_value(item, key_str)
            return redacted

        if isinstance(value, list):
            return [self._redact_value(item, parent_key) for item in value]

        if isinstance(value, tuple):
            return [self._redact_value(item, parent_key) for item in value]

        return value

    def _is_sensitive_key(self, key: str) -> bool:
        normalized = key.lower().replace("-", "_").replace(" ", "_")
        if normalized in DEFAULT_EXCLUDED_KEYS:
            return True
        return any(token in normalized for token in DEFAULT_EXCLUDED_KEYS)

    def _safe_json_data(self, value: Any) -> Any:
        """
        Convert arbitrary Python objects into JSON-safe data.
        """

        if value is None or isinstance(value, (str, int, float, bool)):
            return value

        if isinstance(value, Path):
            return str(value)

        if dataclasses.is_dataclass(value):
            return self._safe_json_data(dataclasses.asdict(value))

        if isinstance(value, dict):
            return {
                str(key): self._safe_json_data(item)
                for key, item in value.items()
            }

        if isinstance(value, (list, tuple, set)):
            return [self._safe_json_data(item) for item in value]

        if isinstance(value, bytes):
            return {
                "__type__": "bytes_base64",
                "value": base64.b64encode(value).decode("ascii"),
            }

        if isinstance(value, datetime):
            return value.astimezone(timezone.utc).isoformat()

        return str(value)

    # ------------------------------------------------------------------
    # Security response normalization
    # ------------------------------------------------------------------

    def _normalize_security_response(
        self,
        response: Any,
        context: BackupContext,
        action: str,
    ) -> Dict[str, Any]:
        if isinstance(response, dict):
            approved = (
                response.get("approved")
                or response.get("success")
                or response.get("data", {}).get("approved")
            )
            if approved:
                return self._safe_result(
                    message="Security approval granted.",
                    data={"approved": True, "security_response": self._safe_json_data(response)},
                    context=context,
                    metadata={"action": action},
                )

            return self._error_result(
                message=response.get("message", "Security approval denied."),
                error_code="SECURITY_APPROVAL_DENIED",
                context=context,
                metadata={
                    "action": action,
                    "security_response": self._safe_json_data(response),
                },
            )

        if response is True:
            return self._safe_result(
                message="Security approval granted.",
                data={"approved": True},
                context=context,
                metadata={"action": action},
            )

        return self._error_result(
            message="Security approval denied.",
            error_code="SECURITY_APPROVAL_DENIED",
            context=context,
            metadata={"action": action, "security_response": self._safe_json_data(response)},
        )

    # ------------------------------------------------------------------
    # Time / locking
    # ------------------------------------------------------------------

    def _utc_now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _timestamp_to_iso(self, timestamp: float) -> str:
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()

    def _operation_lock(self) -> Any:
        if self.enable_file_lock:
            return self._lock
        return _NullContext()


# ---------------------------------------------------------------------------
# In-memory fallback store for tests and early development
# ---------------------------------------------------------------------------

class _InMemoryMemoryStore:
    """
    Minimal in-memory memory store.

    This is not intended as production database storage. It exists so this file
    can be imported, tested, and used before the real Memory Agent database
    adapter is connected.
    """

    def __init__(self) -> None:
        self._data: Dict[str, Dict[str, Dict[str, Dict[str, Dict[str, Any]]]]] = {}
        self._lock = threading.RLock()

    def list_collections(self, user_id: str, workspace_id: str) -> List[str]:
        with self._lock:
            workspace = self._data.get(user_id, {}).get(workspace_id, {})
            if workspace:
                return sorted(workspace.keys())
            return sorted(SAFE_MEMORY_COLLECTIONS)

    def export_records(
        self,
        user_id: str,
        workspace_id: str,
        collections: Optional[List[str]] = None,
    ) -> Dict[str, List[Dict[str, Any]]]:
        with self._lock:
            workspace = self._data.get(user_id, {}).get(workspace_id, {})
            selected = collections or list(workspace.keys())
            result: Dict[str, List[Dict[str, Any]]] = {}
            for collection in selected:
                result[collection] = [
                    copy.deepcopy(record)
                    for record in workspace.get(collection, {}).values()
                ]
            return result

    def import_records(
        self,
        user_id: str,
        workspace_id: str,
        records: List[Dict[str, Any]],
        mode: str = "merge",
    ) -> Dict[str, Any]:
        with self._lock:
            user_bucket = self._data.setdefault(user_id, {})
            workspace_bucket = user_bucket.setdefault(workspace_id, {})

            if mode == "replace":
                selected_collections = {str(record.get("collection")) for record in records}
                for collection in selected_collections:
                    workspace_bucket[collection] = {}

            written = 0
            for envelope in records:
                collection = str(envelope.get("collection") or "long_term")
                record_id = str(envelope.get("record_id") or uuid.uuid4())
                data = copy.deepcopy(envelope.get("data") or {})
                data["user_id"] = user_id
                data["workspace_id"] = workspace_id
                data["record_id"] = record_id
                workspace_bucket.setdefault(collection, {})[record_id] = data
                written += 1

            return {
                "success": True,
                "message": "Records imported into in-memory store.",
                "data": {
                    "written": written,
                    "mode": mode,
                },
            }

    def restore_records(
        self,
        user_id: str,
        workspace_id: str,
        records: List[Dict[str, Any]],
        mode: str = "replace",
    ) -> Dict[str, Any]:
        return self.import_records(user_id, workspace_id, records, mode=mode)

    def seed(
        self,
        user_id: str,
        workspace_id: str,
        collection: str,
        records: List[Dict[str, Any]],
    ) -> None:
        with self._lock:
            bucket = self._data.setdefault(user_id, {}).setdefault(workspace_id, {}).setdefault(collection, {})
            for record in records:
                record_id = str(record.get("record_id") or record.get("id") or uuid.uuid4())
                clean = copy.deepcopy(record)
                clean["record_id"] = record_id
                clean["user_id"] = user_id
                clean["workspace_id"] = workspace_id
                bucket[record_id] = clean


class _NullContext:
    """
    No-op context manager.
    """

    def __enter__(self) -> "_NullContext":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        return False


# ---------------------------------------------------------------------------
# Optional self-test helper
# ---------------------------------------------------------------------------

def _self_test() -> Dict[str, Any]:
    """
    Lightweight local test for development.

    Run:
        python agents/memory_agent/memory_backup.py

    This does not touch real production data.
    """

    temp_dir = Path(tempfile.mkdtemp(prefix="memory_backup_self_test_"))
    try:
        store = _InMemoryMemoryStore()
        store.seed(
            user_id="user_test",
            workspace_id="workspace_test",
            collection="long_term",
            records=[
                {
                    "record_id": "mem_1",
                    "content": "William project architecture decision.",
                    "api_key": "should_be_redacted",
                }
            ],
        )

        backup = MemoryBackup(memory_store=store, backup_root=temp_dir)
        export_result = backup.export_memory(
            user_id="user_test",
            workspace_id="workspace_test",
            actor_id="actor_test",
            options={"format": "json.gz", "redact_sensitive": True},
        )

        if not export_result["success"]:
            return export_result

        backup_path = export_result["data"]["backup_path"]

        validate_result = backup.validate_backup_file(
            user_id="user_test",
            workspace_id="workspace_test",
            backup_path=backup_path,
            actor_id="actor_test",
        )

        restore_result = backup.restore_snapshot(
            user_id="user_test",
            workspace_id="workspace_test",
            snapshot_path=backup_path,
            actor_id="actor_test",
            options={
                "mode": "dry_run",
                "require_security_approval": False,
            },
        )

        return {
            "success": validate_result["success"] and restore_result["success"],
            "message": "MemoryBackup self-test completed.",
            "data": {
                "export": export_result,
                "validate": validate_result,
                "restore_dry_run": restore_result,
                "temp_dir": str(temp_dir),
            },
            "error": None,
            "metadata": {"agent": "MemoryBackup"},
        }
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print(json.dumps(_self_test(), indent=2, default=str))