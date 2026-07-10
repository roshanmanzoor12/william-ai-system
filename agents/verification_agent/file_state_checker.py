"""
agents/verification_agent/file_state_checker.py

William / Jarvis Multi-Agent AI SaaS System
Verification Agent Helper: FileStateChecker

Purpose:
    Confirms file/folder state changes such as:
    - Created
    - Moved / renamed
    - Modified
    - Backed up / copied
    - Deleted / missing
    - Folder existence and contents
    - File metadata snapshots
    - File hash comparison where safe and requested

Architecture Compatibility:
    - Master Agent routing compatible
    - Verification Agent payload compatible
    - Security Agent approval hook compatible
    - Memory Agent payload compatible
    - SaaS user_id / workspace_id isolation compatible
    - Dashboard / FastAPI structured response compatible
    - Import-safe even if future William modules do not exist yet

Safety:
    This module does NOT create, modify, move, delete, overwrite, or execute files.
    It only reads metadata and optionally hashes files for verification.
"""

from __future__ import annotations

import hashlib
import json
import logging
import mimetypes
import os
import platform
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Optional William / Jarvis imports with safe fallbacks
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for import safety
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps the file import-safe when the main William BaseAgent has not
        been generated yet. The real BaseAgent should replace this automatically
        when available.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())

        def emit_event(self, *args: Any, **kwargs: Any) -> None:
            return None


try:
    from agents.verification_agent.config import VerificationConfig  # type: ignore
except Exception:  # pragma: no cover
    class VerificationConfig:  # type: ignore
        """
        Fallback verification config.

        The future config.py can override these values.
        """

        MAX_HASH_FILE_SIZE_BYTES = 100 * 1024 * 1024
        DEFAULT_HASH_ALGORITHM = "sha256"
        SENSITIVE_PATH_KEYWORDS = [
            ".ssh",
            "credentials",
            "secret",
            "secrets",
            ".env",
            "token",
            "private_key",
            "id_rsa",
            "database.yml",
            "wp-config.php",
        ]
        ALLOW_HASHING_SENSITIVE_FILES = False
        ALLOW_METADATA_ON_SENSITIVE_FILES = True


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
if not logger.handlers:
    logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

PathLike = Union[str, Path]


@dataclass
class FileSnapshot:
    """
    Safe file/folder metadata snapshot.

    This is designed for Verification Agent proof payloads, audit logs,
    dashboard display, and optional Memory Agent storage.
    """

    path: str
    exists: bool
    is_file: bool = False
    is_dir: bool = False
    is_symlink: bool = False
    name: Optional[str] = None
    suffix: Optional[str] = None
    mime_type: Optional[str] = None
    size_bytes: Optional[int] = None
    modified_at: Optional[str] = None
    created_at: Optional[str] = None
    accessed_at: Optional[str] = None
    inode: Optional[int] = None
    device: Optional[int] = None
    permissions_octal: Optional[str] = None
    owner_uid: Optional[int] = None
    group_gid: Optional[int] = None
    hash_algorithm: Optional[str] = None
    hash_value: Optional[str] = None
    hash_skipped_reason: Optional[str] = None
    child_count: Optional[int] = None
    children_sample: List[str] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class FileStateExpectation:
    """
    Declarative expected state for a file/folder verification check.
    """

    path: str
    should_exist: Optional[bool] = None
    should_be_file: Optional[bool] = None
    should_be_dir: Optional[bool] = None
    min_size_bytes: Optional[int] = None
    max_size_bytes: Optional[int] = None
    expected_size_bytes: Optional[int] = None
    expected_hash: Optional[str] = None
    hash_algorithm: str = "sha256"
    modified_after: Optional[Union[str, float, int, datetime]] = None
    modified_before: Optional[Union[str, float, int, datetime]] = None
    must_contain_children: List[str] = field(default_factory=list)


@dataclass
class FileStateDiff:
    """
    Comparison object between two snapshots.
    """

    same_path: bool
    exists_changed: bool
    type_changed: bool
    size_changed: bool
    modified_time_changed: bool
    hash_changed: Optional[bool]
    old_snapshot: Dict[str, Any]
    new_snapshot: Dict[str, Any]
    changes: Dict[str, Any]


# ---------------------------------------------------------------------------
# Main checker
# ---------------------------------------------------------------------------

class FileStateChecker(BaseAgent):
    """
    Confirms file and folder states for the William / Jarvis Verification Agent.

    This class is intentionally read-only. It does not perform file mutations.
    It verifies whether another agent or external process successfully created,
    deleted, moved, modified, or backed up files/folders.

    Master Agent Usage:
        Master Agent can route file verification requests here after Code Agent,
        System Agent, Browser Agent, Creator Agent, Workflow Agent, or any plugin
        agent claims a file-related action is complete.

    Security Agent Usage:
        Sensitive paths trigger _requires_security_check(). If a real Security
        Agent integration exists, _request_security_approval() can be replaced
        or overridden.

    Memory Agent Usage:
        _prepare_memory_payload() returns compact context that can be stored
        without mixing users/workspaces.

    Dashboard/API Usage:
        Every public method returns a structured dict:
            {
                "success": bool,
                "message": str,
                "data": dict/list/None,
                "error": str/None,
                "metadata": dict
            }
    """

    AGENT_NAME = "FileStateChecker"
    AGENT_TYPE = "verification_helper"
    AGENT_VERSION = "1.0.0"

    def __init__(
        self,
        config: Optional[Any] = None,
        security_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            agent_name=self.AGENT_NAME,
            agent_id="verification_file_state_checker",
            **kwargs,
        )
        self.config = config or VerificationConfig()
        self.security_agent = security_agent
        self.memory_agent = memory_agent
        self.audit_logger = audit_logger
        self.event_bus = event_bus

    # -----------------------------------------------------------------------
    # Required compatibility hooks
    # -----------------------------------------------------------------------

    def _validate_task_context(
        self,
        user_id: Optional[str],
        workspace_id: Optional[str],
        task_id: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Validate SaaS isolation context.

        Every user-specific verification task must include user_id and
        workspace_id so file verification results cannot be mixed across
        accounts/workspaces.
        """

        if not user_id or not isinstance(user_id, str) or not user_id.strip():
            return self._error_result(
                message="Missing or invalid user_id.",
                error="VALIDATION_ERROR",
                metadata={
                    "task_id": task_id,
                    "workspace_id": workspace_id,
                    "extra": extra or {},
                },
            )

        if not workspace_id or not isinstance(workspace_id, str) or not workspace_id.strip():
            return self._error_result(
                message="Missing or invalid workspace_id.",
                error="VALIDATION_ERROR",
                metadata={
                    "task_id": task_id,
                    "user_id": user_id,
                    "extra": extra or {},
                },
            )

        return self._safe_result(
            success=True,
            message="Task context validated.",
            data={
                "user_id": user_id.strip(),
                "workspace_id": workspace_id.strip(),
                "task_id": task_id,
                "extra": extra or {},
            },
            metadata={
                "agent": self.AGENT_NAME,
                "validation": "passed",
            },
        )

    def _requires_security_check(
        self,
        path: Optional[PathLike] = None,
        operation: str = "metadata_read",
        include_hash: bool = False,
        **kwargs: Any,
    ) -> bool:
        """
        Determine whether a file verification request should go through
        Security Agent approval.

        This checker is read-only, but sensitive paths may expose secrets through
        metadata or file hashes. The real Security Agent can enforce stricter
        policies.
        """

        operation_lower = (operation or "").lower().strip()
        sensitive_operations = {
            "hash",
            "content_hash",
            "backup_verification",
            "deletion_verification",
            "recursive_folder_scan",
            "metadata_read_sensitive",
        }

        if include_hash:
            return True

        if operation_lower in sensitive_operations:
            return True

        if path is None:
            return False

        normalized = str(path).replace("\\", "/").lower()
        keywords = getattr(self.config, "SENSITIVE_PATH_KEYWORDS", []) or []

        return any(str(keyword).lower() in normalized for keyword in keywords)

    def _request_security_approval(
        self,
        user_id: str,
        workspace_id: str,
        path: Optional[PathLike],
        operation: str,
        reason: str,
        task_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval if available.

        Fallback behavior:
            - Read-only metadata checks are allowed.
            - Hashing sensitive files is denied by default unless config allows it.
        """

        request_payload = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "task_id": task_id,
            "agent": self.AGENT_NAME,
            "operation": operation,
            "path": str(path) if path is not None else None,
            "reason": reason,
            "metadata": metadata or {},
            "timestamp": self._utc_now(),
        }

        if self.security_agent is not None:
            try:
                approval_method = getattr(self.security_agent, "approve_action", None)
                if callable(approval_method):
                    approval = approval_method(request_payload)
                    if isinstance(approval, dict):
                        return approval
            except Exception as exc:
                logger.warning("Security approval request failed: %s", exc)

        if operation in {"hash", "content_hash"}:
            allow_sensitive_hashing = bool(
                getattr(self.config, "ALLOW_HASHING_SENSITIVE_FILES", False)
            )
            return {
                "approved": allow_sensitive_hashing,
                "reason": (
                    "Fallback policy allows sensitive hashing."
                    if allow_sensitive_hashing
                    else "Fallback policy blocks sensitive file hashing."
                ),
                "source": "fallback_security_policy",
                "request": request_payload,
            }

        allow_metadata = bool(
            getattr(self.config, "ALLOW_METADATA_ON_SENSITIVE_FILES", True)
        )
        return {
            "approved": allow_metadata,
            "reason": (
                "Fallback policy allows read-only metadata verification."
                if allow_metadata
                else "Fallback policy blocks sensitive metadata verification."
            ),
            "source": "fallback_security_policy",
            "request": request_payload,
        }

    def _prepare_verification_payload(
        self,
        user_id: str,
        workspace_id: str,
        verification_type: str,
        status: str,
        confidence: float,
        evidence: Optional[Dict[str, Any]] = None,
        task_id: Optional[str] = None,
        target_path: Optional[PathLike] = None,
    ) -> Dict[str, Any]:
        """
        Prepare standard Verification Agent payload.
        """

        return {
            "agent": self.AGENT_NAME,
            "agent_type": self.AGENT_TYPE,
            "agent_version": self.AGENT_VERSION,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "task_id": task_id,
            "verification_type": verification_type,
            "target_path": str(target_path) if target_path is not None else None,
            "status": status,
            "confidence": self._clamp_confidence(confidence),
            "evidence": evidence or {},
            "timestamp": self._utc_now(),
        }

    def _prepare_memory_payload(
        self,
        user_id: str,
        workspace_id: str,
        summary: str,
        data: Optional[Dict[str, Any]] = None,
        task_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Prepare compact Memory Agent compatible payload.

        This payload intentionally stores metadata and verification summaries,
        not sensitive file contents.
        """

        return {
            "memory_type": "verification_file_state",
            "user_id": user_id,
            "workspace_id": workspace_id,
            "task_id": task_id,
            "summary": summary,
            "data": data or {},
            "created_at": self._utc_now(),
            "source_agent": self.AGENT_NAME,
        }

    def _emit_agent_event(
        self,
        event_name: str,
        payload: Dict[str, Any],
    ) -> None:
        """
        Emit agent event for dashboard, task history, analytics, or registry.
        """

        event = {
            "event_name": event_name,
            "agent": self.AGENT_NAME,
            "timestamp": self._utc_now(),
            "payload": payload,
        }

        try:
            if self.event_bus is not None:
                publish = getattr(self.event_bus, "publish", None)
                if callable(publish):
                    publish(event)
                    return

            emit = getattr(self, "emit_event", None)
            if callable(emit):
                emit(event_name, payload)
        except Exception as exc:
            logger.debug("Agent event emit failed: %s", exc)

    def _log_audit_event(
        self,
        user_id: str,
        workspace_id: str,
        action: str,
        outcome: str,
        task_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log audit event.

        A real audit logger can be injected. Fallback logs to Python logger only.
        """

        audit_payload = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "task_id": task_id,
            "agent": self.AGENT_NAME,
            "action": action,
            "outcome": outcome,
            "details": details or {},
            "timestamp": self._utc_now(),
        }

        try:
            if self.audit_logger is not None:
                log_method = getattr(self.audit_logger, "log", None)
                if callable(log_method):
                    log_method(audit_payload)
                    return

            logger.info("AUDIT_EVENT %s", json.dumps(audit_payload, default=str))
        except Exception as exc:
            logger.debug("Audit logging failed: %s", exc)

    def _safe_result(
        self,
        success: bool,
        message: str,
        data: Optional[Any] = None,
        error: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard structured success/result wrapper.
        """

        return {
            "success": bool(success),
            "message": message,
            "data": data,
            "error": error,
            "metadata": {
                "agent": self.AGENT_NAME,
                "agent_type": self.AGENT_TYPE,
                "agent_version": self.AGENT_VERSION,
                "timestamp": self._utc_now(),
                **(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str,
        error: Union[str, Exception],
        data: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard structured error wrapper.
        """

        error_text = str(error)
        return self._safe_result(
            success=False,
            message=message,
            data=data,
            error=error_text,
            metadata=metadata or {},
        )

    # -----------------------------------------------------------------------
    # Public file/folder state verification methods
    # -----------------------------------------------------------------------

    def snapshot_path(
        self,
        path: PathLike,
        user_id: str,
        workspace_id: str,
        task_id: Optional[str] = None,
        include_hash: bool = False,
        hash_algorithm: Optional[str] = None,
        include_children: bool = False,
        max_children_sample: int = 25,
    ) -> Dict[str, Any]:
        """
        Build a safe metadata snapshot for a file/folder.

        Args:
            path: File or folder path.
            user_id: SaaS user id.
            workspace_id: SaaS workspace id.
            task_id: Optional task id.
            include_hash: Whether to hash file content.
            hash_algorithm: sha256, sha1, md5, etc. sha256 recommended.
            include_children: Include child count and a small children sample for folders.
            max_children_sample: Maximum child names to include.

        Returns:
            Structured result containing FileSnapshot.
        """

        context = self._validate_task_context(user_id, workspace_id, task_id)
        if not context["success"]:
            return context

        normalized_path = self._normalize_path(path)
        operation = "content_hash" if include_hash else "metadata_read"

        if self._requires_security_check(
            normalized_path,
            operation=operation,
            include_hash=include_hash,
        ):
            approval = self._request_security_approval(
                user_id=user_id,
                workspace_id=workspace_id,
                path=normalized_path,
                operation="hash" if include_hash else "metadata_read_sensitive",
                reason="File state snapshot requested for verification.",
                task_id=task_id,
                metadata={"include_hash": include_hash},
            )
            if not bool(approval.get("approved", False)):
                self._log_audit_event(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    task_id=task_id,
                    action="snapshot_path",
                    outcome="blocked_by_security",
                    details={
                        "path": str(normalized_path),
                        "approval": approval,
                    },
                )
                return self._error_result(
                    message="Security approval denied for file state snapshot.",
                    error="SECURITY_APPROVAL_DENIED",
                    metadata={
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                        "task_id": task_id,
                        "path": str(normalized_path),
                        "approval": approval,
                    },
                )

        snapshot = self._create_snapshot(
            normalized_path,
            include_hash=include_hash,
            hash_algorithm=hash_algorithm,
            include_children=include_children,
            max_children_sample=max_children_sample,
        )

        payload = self._prepare_verification_payload(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            verification_type="file_snapshot",
            target_path=normalized_path,
            status="captured" if snapshot.exists else "missing",
            confidence=1.0,
            evidence={"snapshot": asdict(snapshot)},
        )

        self._emit_agent_event("verification.file_snapshot", payload)
        self._log_audit_event(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            action="snapshot_path",
            outcome="success",
            details={"path": str(normalized_path), "exists": snapshot.exists},
        )

        return self._safe_result(
            success=True,
            message="File/folder snapshot captured successfully.",
            data={
                "snapshot": asdict(snapshot),
                "verification_payload": payload,
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "task_id": task_id,
                "path": str(normalized_path),
            },
        )

    def confirm_created(
        self,
        path: PathLike,
        user_id: str,
        workspace_id: str,
        task_id: Optional[str] = None,
        expected_type: Optional[str] = None,
        min_size_bytes: Optional[int] = None,
        include_hash: bool = False,
    ) -> Dict[str, Any]:
        """
        Confirm that a file or folder was created.

        expected_type:
            - None: any path type
            - "file"
            - "folder" / "dir" / "directory"
        """

        snap_result = self.snapshot_path(
            path=path,
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            include_hash=include_hash,
            include_children=True,
        )
        if not snap_result["success"]:
            return snap_result

        snapshot = snap_result["data"]["snapshot"]
        checks = []
        success = True

        exists_ok = bool(snapshot.get("exists"))
        checks.append({"check": "exists", "passed": exists_ok})
        success = success and exists_ok

        if expected_type:
            type_lower = expected_type.lower().strip()
            if type_lower == "file":
                type_ok = bool(snapshot.get("is_file"))
            elif type_lower in {"folder", "dir", "directory"}:
                type_ok = bool(snapshot.get("is_dir"))
            else:
                type_ok = False

            checks.append({
                "check": "expected_type",
                "expected": expected_type,
                "passed": type_ok,
            })
            success = success and type_ok

        if min_size_bytes is not None:
            size = snapshot.get("size_bytes")
            size_ok = size is not None and int(size) >= int(min_size_bytes)
            checks.append({
                "check": "min_size_bytes",
                "expected": min_size_bytes,
                "actual": size,
                "passed": size_ok,
            })
            success = success and size_ok

        status = "created_confirmed" if success else "created_not_confirmed"
        message = (
            "File/folder creation confirmed."
            if success
            else "File/folder creation could not be confirmed."
        )

        verification_payload = self._prepare_verification_payload(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            verification_type="file_created",
            target_path=path,
            status=status,
            confidence=0.98 if success else 0.75,
            evidence={
                "snapshot": snapshot,
                "checks": checks,
            },
        )

        self._emit_agent_event("verification.file_created", verification_payload)
        self._log_audit_event(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            action="confirm_created",
            outcome="success" if success else "failed",
            details={"path": str(path), "checks": checks},
        )

        return self._safe_result(
            success=success,
            message=message,
            data={
                "created": success,
                "checks": checks,
                "snapshot": snapshot,
                "verification_payload": verification_payload,
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "task_id": task_id,
            },
        )

    def confirm_deleted(
        self,
        path: PathLike,
        user_id: str,
        workspace_id: str,
        task_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Confirm that a file or folder no longer exists.

        This is read-only. It does not delete anything.
        """

        normalized_path = self._normalize_path(path)
        context = self._validate_task_context(user_id, workspace_id, task_id)
        if not context["success"]:
            return context

        if self._requires_security_check(
            normalized_path,
            operation="deletion_verification",
        ):
            approval = self._request_security_approval(
                user_id=user_id,
                workspace_id=workspace_id,
                path=normalized_path,
                operation="deletion_verification",
                reason="Verify whether file/folder deletion completed.",
                task_id=task_id,
            )
            if not bool(approval.get("approved", False)):
                return self._error_result(
                    message="Security approval denied for deletion verification.",
                    error="SECURITY_APPROVAL_DENIED",
                    metadata={
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                        "task_id": task_id,
                        "path": str(normalized_path),
                        "approval": approval,
                    },
                )

        exists = normalized_path.exists()
        snapshot = self._create_snapshot(normalized_path, include_hash=False)
        success = not exists

        verification_payload = self._prepare_verification_payload(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            verification_type="file_deleted",
            target_path=normalized_path,
            status="deleted_confirmed" if success else "still_exists",
            confidence=0.99,
            evidence={
                "path": str(normalized_path),
                "exists": exists,
                "snapshot": asdict(snapshot),
            },
        )

        self._emit_agent_event("verification.file_deleted", verification_payload)
        self._log_audit_event(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            action="confirm_deleted",
            outcome="success" if success else "failed",
            details={"path": str(normalized_path), "exists": exists},
        )

        return self._safe_result(
            success=success,
            message=(
                "File/folder deletion confirmed."
                if success
                else "File/folder still exists; deletion not confirmed."
            ),
            data={
                "deleted": success,
                "exists": exists,
                "snapshot": asdict(snapshot),
                "verification_payload": verification_payload,
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "task_id": task_id,
                "path": str(normalized_path),
            },
        )

    def confirm_modified(
        self,
        path: PathLike,
        user_id: str,
        workspace_id: str,
        task_id: Optional[str] = None,
        previous_snapshot: Optional[Dict[str, Any]] = None,
        modified_after: Optional[Union[str, float, int, datetime]] = None,
        expected_hash: Optional[str] = None,
        include_hash: bool = False,
        hash_algorithm: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Confirm that a file/folder was modified.

        Modification can be confirmed by:
            - Comparing with previous snapshot
            - Checking modified_after timestamp
            - Matching expected hash
        """

        snap_result = self.snapshot_path(
            path=path,
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            include_hash=include_hash or bool(expected_hash),
            hash_algorithm=hash_algorithm,
        )
        if not snap_result["success"]:
            return snap_result

        current_snapshot = snap_result["data"]["snapshot"]
        checks: List[Dict[str, Any]] = []
        modified_signals = 0
        hard_fail = False

        if not current_snapshot.get("exists"):
            hard_fail = True
            checks.append({
                "check": "exists",
                "passed": False,
                "reason": "Path does not exist.",
            })

        if previous_snapshot:
            diff = self._diff_snapshot_dicts(previous_snapshot, current_snapshot)
            changed = any([
                diff.exists_changed,
                diff.type_changed,
                diff.size_changed,
                diff.modified_time_changed,
                diff.hash_changed is True,
            ])
            checks.append({
                "check": "previous_snapshot_diff",
                "passed": changed,
                "changes": diff.changes,
            })
            if changed:
                modified_signals += 1

        if modified_after is not None:
            modified_after_dt = self._parse_datetime(modified_after)
            current_modified_dt = self._parse_datetime(current_snapshot.get("modified_at"))
            time_ok = (
                current_modified_dt is not None
                and modified_after_dt is not None
                and current_modified_dt > modified_after_dt
            )
            checks.append({
                "check": "modified_after",
                "expected_after": self._datetime_to_iso(modified_after_dt),
                "actual_modified_at": current_snapshot.get("modified_at"),
                "passed": time_ok,
            })
            if time_ok:
                modified_signals += 1

        if expected_hash:
            actual_hash = current_snapshot.get("hash_value")
            hash_ok = bool(actual_hash) and actual_hash.lower() == expected_hash.lower()
            checks.append({
                "check": "expected_hash",
                "expected_hash": expected_hash,
                "actual_hash": actual_hash,
                "passed": hash_ok,
            })
            if hash_ok:
                modified_signals += 1
            else:
                hard_fail = True

        if not previous_snapshot and modified_after is None and expected_hash is None:
            checks.append({
                "check": "modified_evidence",
                "passed": False,
                "reason": "No previous_snapshot, modified_after, or expected_hash was provided.",
            })

        success = (modified_signals > 0) and not hard_fail

        verification_payload = self._prepare_verification_payload(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            verification_type="file_modified",
            target_path=path,
            status="modified_confirmed" if success else "modified_not_confirmed",
            confidence=0.93 if success else 0.65,
            evidence={
                "current_snapshot": current_snapshot,
                "previous_snapshot": previous_snapshot,
                "checks": checks,
                "modified_signals": modified_signals,
            },
        )

        self._emit_agent_event("verification.file_modified", verification_payload)
        self._log_audit_event(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            action="confirm_modified",
            outcome="success" if success else "failed",
            details={"path": str(path), "checks": checks},
        )

        return self._safe_result(
            success=success,
            message=(
                "File/folder modification confirmed."
                if success
                else "File/folder modification could not be confirmed."
            ),
            data={
                "modified": success,
                "checks": checks,
                "current_snapshot": current_snapshot,
                "verification_payload": verification_payload,
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "task_id": task_id,
            },
        )

    def confirm_moved(
        self,
        old_path: PathLike,
        new_path: PathLike,
        user_id: str,
        workspace_id: str,
        task_id: Optional[str] = None,
        include_hash: bool = False,
        require_old_missing: bool = True,
    ) -> Dict[str, Any]:
        """
        Confirm that a file/folder was moved or renamed.

        Checks:
            - New path exists
            - Old path missing if require_old_missing=True
            - Optional hash/size metadata evidence
        """

        context = self._validate_task_context(user_id, workspace_id, task_id)
        if not context["success"]:
            return context

        old_snap_result = self.snapshot_path(
            path=old_path,
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            include_hash=False,
        )
        if not old_snap_result["success"]:
            return old_snap_result

        new_snap_result = self.snapshot_path(
            path=new_path,
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            include_hash=include_hash,
        )
        if not new_snap_result["success"]:
            return new_snap_result

        old_snapshot = old_snap_result["data"]["snapshot"]
        new_snapshot = new_snap_result["data"]["snapshot"]

        checks: List[Dict[str, Any]] = []

        new_exists = bool(new_snapshot.get("exists"))
        checks.append({
            "check": "new_path_exists",
            "path": str(new_path),
            "passed": new_exists,
        })

        old_missing_ok = not bool(old_snapshot.get("exists")) if require_old_missing else True
        checks.append({
            "check": "old_path_missing",
            "path": str(old_path),
            "required": require_old_missing,
            "passed": old_missing_ok,
        })

        name_changed = Path(str(old_path)).name != Path(str(new_path)).name
        parent_changed = Path(str(old_path)).parent != Path(str(new_path)).parent
        checks.append({
            "check": "path_changed",
            "name_changed": name_changed,
            "parent_changed": parent_changed,
            "passed": name_changed or parent_changed,
        })

        success = new_exists and old_missing_ok and (name_changed or parent_changed)

        verification_payload = self._prepare_verification_payload(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            verification_type="file_moved",
            target_path=new_path,
            status="moved_confirmed" if success else "moved_not_confirmed",
            confidence=0.94 if success else 0.70,
            evidence={
                "old_path": str(old_path),
                "new_path": str(new_path),
                "old_snapshot": old_snapshot,
                "new_snapshot": new_snapshot,
                "checks": checks,
            },
        )

        self._emit_agent_event("verification.file_moved", verification_payload)
        self._log_audit_event(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            action="confirm_moved",
            outcome="success" if success else "failed",
            details={
                "old_path": str(old_path),
                "new_path": str(new_path),
                "checks": checks,
            },
        )

        return self._safe_result(
            success=success,
            message=(
                "File/folder move confirmed."
                if success
                else "File/folder move could not be confirmed."
            ),
            data={
                "moved": success,
                "checks": checks,
                "old_snapshot": old_snapshot,
                "new_snapshot": new_snapshot,
                "verification_payload": verification_payload,
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "task_id": task_id,
            },
        )

    def confirm_backup(
        self,
        original_path: PathLike,
        backup_path: PathLike,
        user_id: str,
        workspace_id: str,
        task_id: Optional[str] = None,
        require_hash_match: bool = True,
        hash_algorithm: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Confirm that a backup/copy exists.

        For files:
            - Original exists
            - Backup exists
            - Size matches
            - Optional hash matches

        For folders:
            - Original folder exists
            - Backup folder exists
            - Child count comparison where available
        """

        context = self._validate_task_context(user_id, workspace_id, task_id)
        if not context["success"]:
            return context

        if self._requires_security_check(
            original_path,
            operation="backup_verification",
            include_hash=require_hash_match,
        ) or self._requires_security_check(
            backup_path,
            operation="backup_verification",
            include_hash=require_hash_match,
        ):
            approval = self._request_security_approval(
                user_id=user_id,
                workspace_id=workspace_id,
                path=backup_path,
                operation="backup_verification",
                reason="Verify file/folder backup state.",
                task_id=task_id,
                metadata={
                    "original_path": str(original_path),
                    "backup_path": str(backup_path),
                    "require_hash_match": require_hash_match,
                },
            )
            if not bool(approval.get("approved", False)):
                return self._error_result(
                    message="Security approval denied for backup verification.",
                    error="SECURITY_APPROVAL_DENIED",
                    metadata={
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                        "task_id": task_id,
                        "approval": approval,
                    },
                )

        original_result = self.snapshot_path(
            path=original_path,
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            include_hash=require_hash_match,
            hash_algorithm=hash_algorithm,
            include_children=True,
        )
        if not original_result["success"]:
            return original_result

        backup_result = self.snapshot_path(
            path=backup_path,
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            include_hash=require_hash_match,
            hash_algorithm=hash_algorithm,
            include_children=True,
        )
        if not backup_result["success"]:
            return backup_result

        original_snapshot = original_result["data"]["snapshot"]
        backup_snapshot = backup_result["data"]["snapshot"]

        checks: List[Dict[str, Any]] = []

        original_exists = bool(original_snapshot.get("exists"))
        backup_exists = bool(backup_snapshot.get("exists"))

        checks.append({
            "check": "original_exists",
            "passed": original_exists,
        })
        checks.append({
            "check": "backup_exists",
            "passed": backup_exists,
        })

        same_type = (
            bool(original_snapshot.get("is_file")) == bool(backup_snapshot.get("is_file"))
            and bool(original_snapshot.get("is_dir")) == bool(backup_snapshot.get("is_dir"))
        )
        checks.append({
            "check": "same_type",
            "passed": same_type,
            "original_is_file": original_snapshot.get("is_file"),
            "backup_is_file": backup_snapshot.get("is_file"),
            "original_is_dir": original_snapshot.get("is_dir"),
            "backup_is_dir": backup_snapshot.get("is_dir"),
        })

        size_match = None
        if original_snapshot.get("is_file") and backup_snapshot.get("is_file"):
            size_match = original_snapshot.get("size_bytes") == backup_snapshot.get("size_bytes")
            checks.append({
                "check": "file_size_match",
                "passed": size_match,
                "original_size": original_snapshot.get("size_bytes"),
                "backup_size": backup_snapshot.get("size_bytes"),
            })

        child_count_match = None
        if original_snapshot.get("is_dir") and backup_snapshot.get("is_dir"):
            child_count_match = original_snapshot.get("child_count") == backup_snapshot.get("child_count")
            checks.append({
                "check": "folder_child_count_match",
                "passed": child_count_match,
                "original_child_count": original_snapshot.get("child_count"),
                "backup_child_count": backup_snapshot.get("child_count"),
            })

        hash_match = None
        if require_hash_match and original_snapshot.get("is_file") and backup_snapshot.get("is_file"):
            original_hash = original_snapshot.get("hash_value")
            backup_hash = backup_snapshot.get("hash_value")
            hash_match = bool(original_hash) and original_hash == backup_hash
            checks.append({
                "check": "hash_match",
                "passed": hash_match,
                "original_hash": original_hash,
                "backup_hash": backup_hash,
                "algorithm": original_snapshot.get("hash_algorithm"),
            })

        required_checks = [
            original_exists,
            backup_exists,
            same_type,
        ]

        if size_match is not None:
            required_checks.append(bool(size_match))

        if require_hash_match and hash_match is not None:
            required_checks.append(bool(hash_match))

        if child_count_match is not None:
            required_checks.append(bool(child_count_match))

        success = all(required_checks)

        verification_payload = self._prepare_verification_payload(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            verification_type="file_backup",
            target_path=backup_path,
            status="backup_confirmed" if success else "backup_not_confirmed",
            confidence=0.96 if success else 0.72,
            evidence={
                "original_path": str(original_path),
                "backup_path": str(backup_path),
                "original_snapshot": original_snapshot,
                "backup_snapshot": backup_snapshot,
                "checks": checks,
            },
        )

        self._emit_agent_event("verification.file_backup", verification_payload)
        self._log_audit_event(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            action="confirm_backup",
            outcome="success" if success else "failed",
            details={
                "original_path": str(original_path),
                "backup_path": str(backup_path),
                "checks": checks,
            },
        )

        return self._safe_result(
            success=success,
            message=(
                "File/folder backup confirmed."
                if success
                else "File/folder backup could not be confirmed."
            ),
            data={
                "backup_confirmed": success,
                "checks": checks,
                "original_snapshot": original_snapshot,
                "backup_snapshot": backup_snapshot,
                "verification_payload": verification_payload,
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "task_id": task_id,
            },
        )

    def verify_expectation(
        self,
        expectation: Union[FileStateExpectation, Dict[str, Any]],
        user_id: str,
        workspace_id: str,
        task_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Verify a declarative file state expectation.

        This method is useful for Dashboard/API requests, Workflow Agent steps,
        and Master Agent structured verification tasks.
        """

        context = self._validate_task_context(user_id, workspace_id, task_id)
        if not context["success"]:
            return context

        if isinstance(expectation, dict):
            try:
                exp = FileStateExpectation(**expectation)
            except Exception as exc:
                return self._error_result(
                    message="Invalid file state expectation.",
                    error=exc,
                    metadata={
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                        "task_id": task_id,
                    },
                )
        else:
            exp = expectation

        include_hash = bool(exp.expected_hash)
        snap_result = self.snapshot_path(
            path=exp.path,
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            include_hash=include_hash,
            hash_algorithm=exp.hash_algorithm,
            include_children=bool(exp.must_contain_children),
        )
        if not snap_result["success"]:
            return snap_result

        snapshot = snap_result["data"]["snapshot"]
        checks: List[Dict[str, Any]] = []

        def add_check(name: str, passed: bool, **extra: Any) -> None:
            checks.append({
                "check": name,
                "passed": bool(passed),
                **extra,
            })

        if exp.should_exist is not None:
            add_check(
                "should_exist",
                snapshot.get("exists") is exp.should_exist,
                expected=exp.should_exist,
                actual=snapshot.get("exists"),
            )

        if exp.should_be_file is not None:
            add_check(
                "should_be_file",
                snapshot.get("is_file") is exp.should_be_file,
                expected=exp.should_be_file,
                actual=snapshot.get("is_file"),
            )

        if exp.should_be_dir is not None:
            add_check(
                "should_be_dir",
                snapshot.get("is_dir") is exp.should_be_dir,
                expected=exp.should_be_dir,
                actual=snapshot.get("is_dir"),
            )

        if exp.min_size_bytes is not None:
            actual_size = snapshot.get("size_bytes")
            add_check(
                "min_size_bytes",
                actual_size is not None and actual_size >= exp.min_size_bytes,
                expected_min=exp.min_size_bytes,
                actual=actual_size,
            )

        if exp.max_size_bytes is not None:
            actual_size = snapshot.get("size_bytes")
            add_check(
                "max_size_bytes",
                actual_size is not None and actual_size <= exp.max_size_bytes,
                expected_max=exp.max_size_bytes,
                actual=actual_size,
            )

        if exp.expected_size_bytes is not None:
            actual_size = snapshot.get("size_bytes")
            add_check(
                "expected_size_bytes",
                actual_size == exp.expected_size_bytes,
                expected=exp.expected_size_bytes,
                actual=actual_size,
            )

        if exp.expected_hash is not None:
            actual_hash = snapshot.get("hash_value")
            add_check(
                "expected_hash",
                bool(actual_hash) and actual_hash.lower() == exp.expected_hash.lower(),
                expected=exp.expected_hash,
                actual=actual_hash,
                algorithm=exp.hash_algorithm,
            )

        if exp.modified_after is not None:
            expected_dt = self._parse_datetime(exp.modified_after)
            actual_dt = self._parse_datetime(snapshot.get("modified_at"))
            add_check(
                "modified_after",
                actual_dt is not None and expected_dt is not None and actual_dt > expected_dt,
                expected_after=self._datetime_to_iso(expected_dt),
                actual=snapshot.get("modified_at"),
            )

        if exp.modified_before is not None:
            expected_dt = self._parse_datetime(exp.modified_before)
            actual_dt = self._parse_datetime(snapshot.get("modified_at"))
            add_check(
                "modified_before",
                actual_dt is not None and expected_dt is not None and actual_dt < expected_dt,
                expected_before=self._datetime_to_iso(expected_dt),
                actual=snapshot.get("modified_at"),
            )

        if exp.must_contain_children:
            sample = set(snapshot.get("children_sample") or [])
            for child_name in exp.must_contain_children:
                add_check(
                    "must_contain_child",
                    child_name in sample or self._safe_child_exists(exp.path, child_name),
                    expected_child=child_name,
                    sample_checked=list(sample),
                )

        success = all(check["passed"] for check in checks) if checks else False

        verification_payload = self._prepare_verification_payload(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            verification_type="file_expectation",
            target_path=exp.path,
            status="expectation_met" if success else "expectation_failed",
            confidence=0.95 if success else 0.70,
            evidence={
                "expectation": asdict(exp),
                "snapshot": snapshot,
                "checks": checks,
            },
        )

        self._emit_agent_event("verification.file_expectation", verification_payload)
        self._log_audit_event(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            action="verify_expectation",
            outcome="success" if success else "failed",
            details={
                "path": exp.path,
                "checks": checks,
            },
        )

        return self._safe_result(
            success=success,
            message=(
                "File state expectation verified successfully."
                if success
                else "File state expectation was not met."
            ),
            data={
                "expectation_met": success,
                "checks": checks,
                "snapshot": snapshot,
                "verification_payload": verification_payload,
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "task_id": task_id,
            },
        )

    def compare_snapshots(
        self,
        old_snapshot: Dict[str, Any],
        new_snapshot: Dict[str, Any],
        user_id: str,
        workspace_id: str,
        task_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Compare two file/folder snapshots and return a structured diff.
        """

        context = self._validate_task_context(user_id, workspace_id, task_id)
        if not context["success"]:
            return context

        try:
            diff = self._diff_snapshot_dicts(old_snapshot, new_snapshot)
        except Exception as exc:
            return self._error_result(
                message="Failed to compare file snapshots.",
                error=exc,
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "task_id": task_id,
                },
            )

        changed = bool(diff.changes)

        verification_payload = self._prepare_verification_payload(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            verification_type="file_snapshot_diff",
            target_path=new_snapshot.get("path") or old_snapshot.get("path"),
            status="changed" if changed else "unchanged",
            confidence=0.95,
            evidence=asdict(diff),
        )

        return self._safe_result(
            success=True,
            message="File snapshots compared successfully.",
            data={
                "changed": changed,
                "diff": asdict(diff),
                "verification_payload": verification_payload,
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "task_id": task_id,
            },
        )

    def batch_verify(
        self,
        expectations: Iterable[Union[FileStateExpectation, Dict[str, Any]]],
        user_id: str,
        workspace_id: str,
        task_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Verify multiple file state expectations in one batch.

        This is helpful for Workflow Agent and Verification Agent reports.
        """

        context = self._validate_task_context(user_id, workspace_id, task_id)
        if not context["success"]:
            return context

        results: List[Dict[str, Any]] = []
        total = 0
        passed = 0
        failed = 0

        for expectation in expectations:
            total += 1
            result = self.verify_expectation(
                expectation=expectation,
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
            )
            results.append(result)
            if result.get("success"):
                passed += 1
            else:
                failed += 1

        success = failed == 0 and total > 0

        verification_payload = self._prepare_verification_payload(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            verification_type="file_batch_verification",
            target_path=None,
            status="all_passed" if success else "some_failed",
            confidence=0.94 if success else 0.74,
            evidence={
                "total": total,
                "passed": passed,
                "failed": failed,
                "results": results,
            },
        )

        self._emit_agent_event("verification.file_batch", verification_payload)
        self._log_audit_event(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            action="batch_verify",
            outcome="success" if success else "partial_or_failed",
            details={
                "total": total,
                "passed": passed,
                "failed": failed,
            },
        )

        return self._safe_result(
            success=success,
            message=(
                "All file state expectations passed."
                if success
                else "One or more file state expectations failed."
            ),
            data={
                "total": total,
                "passed": passed,
                "failed": failed,
                "results": results,
                "verification_payload": verification_payload,
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "task_id": task_id,
            },
        )

    def get_registry_metadata(self) -> Dict[str, Any]:
        """
        Agent Registry / Loader metadata.

        This lets the Agent Registry discover this helper safely.
        """

        return {
            "agent_name": self.AGENT_NAME,
            "agent_type": self.AGENT_TYPE,
            "agent_version": self.AGENT_VERSION,
            "class_name": self.__class__.__name__,
            "module": __name__,
            "capabilities": [
                "confirm_file_created",
                "confirm_folder_created",
                "confirm_file_deleted",
                "confirm_folder_deleted",
                "confirm_file_moved",
                "confirm_folder_moved",
                "confirm_file_modified",
                "confirm_folder_modified",
                "confirm_file_backup",
                "confirm_folder_backup",
                "snapshot_file_state",
                "snapshot_folder_state",
                "compare_file_snapshots",
                "batch_file_verification",
            ],
            "safe_import": True,
            "read_only": True,
            "requires_user_context": True,
            "requires_workspace_context": True,
            "security_hooks": [
                "_requires_security_check",
                "_request_security_approval",
            ],
            "verification_hooks": [
                "_prepare_verification_payload",
            ],
            "memory_hooks": [
                "_prepare_memory_payload",
            ],
            "public_methods": [
                "snapshot_path",
                "confirm_created",
                "confirm_deleted",
                "confirm_modified",
                "confirm_moved",
                "confirm_backup",
                "verify_expectation",
                "compare_snapshots",
                "batch_verify",
                "get_registry_metadata",
            ],
        }

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    def _create_snapshot(
        self,
        path: Path,
        include_hash: bool = False,
        hash_algorithm: Optional[str] = None,
        include_children: bool = False,
        max_children_sample: int = 25,
    ) -> FileSnapshot:
        """
        Internal safe snapshot builder.
        """

        snapshot = FileSnapshot(
            path=str(path),
            exists=False,
            name=path.name,
            suffix=path.suffix,
            mime_type=mimetypes.guess_type(str(path))[0],
        )

        try:
            exists = path.exists()
            snapshot.exists = exists

            if not exists:
                return snapshot

            try:
                stat = path.lstat()
            except Exception as exc:
                snapshot.error = f"Unable to stat path: {exc}"
                return snapshot

            snapshot.is_file = path.is_file()
            snapshot.is_dir = path.is_dir()
            snapshot.is_symlink = path.is_symlink()
            snapshot.size_bytes = stat.st_size if snapshot.is_file else None
            snapshot.modified_at = self._timestamp_to_iso(stat.st_mtime)
            snapshot.created_at = self._timestamp_to_iso(stat.st_ctime)
            snapshot.accessed_at = self._timestamp_to_iso(stat.st_atime)
            snapshot.inode = getattr(stat, "st_ino", None)
            snapshot.device = getattr(stat, "st_dev", None)
            snapshot.permissions_octal = oct(stat.st_mode & 0o777)
            snapshot.owner_uid = getattr(stat, "st_uid", None)
            snapshot.group_gid = getattr(stat, "st_gid", None)

            if snapshot.is_dir and include_children:
                child_count, sample = self._folder_children_info(
                    path,
                    max_children_sample=max_children_sample,
                )
                snapshot.child_count = child_count
                snapshot.children_sample = sample

            if snapshot.is_file and include_hash:
                algorithm = hash_algorithm or getattr(
                    self.config,
                    "DEFAULT_HASH_ALGORITHM",
                    "sha256",
                )
                hash_value, skipped_reason = self._hash_file_safely(path, algorithm)
                snapshot.hash_algorithm = algorithm
                snapshot.hash_value = hash_value
                snapshot.hash_skipped_reason = skipped_reason

        except Exception as exc:
            snapshot.error = str(exc)

        return snapshot

    def _hash_file_safely(
        self,
        path: Path,
        algorithm: str,
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Hash a file safely with size limits.

        Returns:
            (hash_value, skipped_reason)
        """

        try:
            max_size = int(
                getattr(self.config, "MAX_HASH_FILE_SIZE_BYTES", 100 * 1024 * 1024)
            )
            size = path.stat().st_size

            if size > max_size:
                return None, f"File too large to hash safely: {size} bytes > {max_size} bytes."

            normalized_algorithm = algorithm.lower().strip()
            try:
                hasher = hashlib.new(normalized_algorithm)
            except Exception:
                return None, f"Unsupported hash algorithm: {algorithm}"

            with path.open("rb") as file_obj:
                for chunk in iter(lambda: file_obj.read(1024 * 1024), b""):
                    hasher.update(chunk)

            return hasher.hexdigest(), None

        except PermissionError:
            return None, "Permission denied while hashing file."
        except FileNotFoundError:
            return None, "File disappeared before hashing."
        except Exception as exc:
            return None, f"Hashing failed: {exc}"

    def _folder_children_info(
        self,
        path: Path,
        max_children_sample: int = 25,
    ) -> Tuple[Optional[int], List[str]]:
        """
        Return folder child count and a small sample of child names.
        """

        try:
            count = 0
            sample: List[str] = []
            for child in path.iterdir():
                count += 1
                if len(sample) < max_children_sample:
                    sample.append(child.name)
            return count, sample
        except PermissionError:
            return None, ["<permission denied>"]
        except Exception as exc:
            return None, [f"<error: {exc}>"]

    def _diff_snapshot_dicts(
        self,
        old_snapshot: Dict[str, Any],
        new_snapshot: Dict[str, Any],
    ) -> FileStateDiff:
        """
        Compare two snapshot dictionaries.
        """

        changes: Dict[str, Any] = {}

        def changed(field_name: str) -> bool:
            old_value = old_snapshot.get(field_name)
            new_value = new_snapshot.get(field_name)
            is_changed = old_value != new_value
            if is_changed:
                changes[field_name] = {
                    "old": old_value,
                    "new": new_value,
                }
            return is_changed

        same_path = old_snapshot.get("path") == new_snapshot.get("path")
        exists_changed = changed("exists")

        type_changed = any([
            changed("is_file"),
            changed("is_dir"),
            changed("is_symlink"),
        ])

        size_changed = changed("size_bytes")
        modified_time_changed = changed("modified_at")

        old_hash = old_snapshot.get("hash_value")
        new_hash = new_snapshot.get("hash_value")

        if old_hash is None and new_hash is None:
            hash_changed: Optional[bool] = None
        else:
            hash_changed = old_hash != new_hash
            if hash_changed:
                changes["hash_value"] = {
                    "old": old_hash,
                    "new": new_hash,
                }

        return FileStateDiff(
            same_path=same_path,
            exists_changed=exists_changed,
            type_changed=type_changed,
            size_changed=size_changed,
            modified_time_changed=modified_time_changed,
            hash_changed=hash_changed,
            old_snapshot=old_snapshot,
            new_snapshot=new_snapshot,
            changes=changes,
        )

    def _safe_child_exists(self, parent_path: PathLike, child_name: str) -> bool:
        """
        Safely check whether a named child exists inside a folder.
        """

        try:
            parent = self._normalize_path(parent_path)
            return (parent / child_name).exists()
        except Exception:
            return False

    def _normalize_path(self, path: PathLike) -> Path:
        """
        Normalize a path without forcing existence.

        expanduser is useful for local dev. resolve(strict=False) is avoided on
        some systems because it can behave differently across platforms and
        symlink setups.
        """

        return Path(str(path)).expanduser()

    def _parse_datetime(
        self,
        value: Optional[Union[str, float, int, datetime]],
    ) -> Optional[datetime]:
        """
        Parse common datetime inputs into timezone-aware UTC datetime.
        """

        if value is None:
            return None

        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc)

        if isinstance(value, (int, float)):
            try:
                return datetime.fromtimestamp(float(value), tz=timezone.utc)
            except Exception:
                return None

        if isinstance(value, str):
            raw = value.strip()
            if not raw:
                return None

            try:
                if raw.endswith("Z"):
                    raw = raw[:-1] + "+00:00"
                dt = datetime.fromisoformat(raw)
                if dt.tzinfo is None:
                    return dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
            except Exception:
                pass

            try:
                return datetime.fromtimestamp(float(raw), tz=timezone.utc)
            except Exception:
                return None

        return None

    def _datetime_to_iso(self, value: Optional[datetime]) -> Optional[str]:
        """
        Convert datetime to ISO UTC string.
        """

        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat()

    def _timestamp_to_iso(self, timestamp: Union[int, float]) -> str:
        """
        Convert POSIX timestamp to ISO UTC string.
        """

        return datetime.fromtimestamp(float(timestamp), tz=timezone.utc).isoformat()

    def _utc_now(self) -> str:
        """
        Current UTC timestamp.
        """

        return datetime.now(timezone.utc).isoformat()

    def _clamp_confidence(self, value: Union[int, float]) -> float:
        """
        Keep confidence inside 0.0 - 1.0.
        """

        try:
            return max(0.0, min(1.0, float(value)))
        except Exception:
            return 0.0


# ---------------------------------------------------------------------------
# Module-level convenience factory
# ---------------------------------------------------------------------------

def create_file_state_checker(**kwargs: Any) -> FileStateChecker:
    """
    Factory used by Agent Loader / Registry when dynamic construction is needed.
    """

    return FileStateChecker(**kwargs)


# ---------------------------------------------------------------------------
# Lightweight self-test helper
# ---------------------------------------------------------------------------

def self_test() -> Dict[str, Any]:
    """
    Non-destructive import/runtime smoke test.

    This does not create or delete files. It snapshots this module file.
    """

    checker = FileStateChecker()
    current_file = Path(__file__)
    return checker.snapshot_path(
        path=current_file,
        user_id="self_test_user",
        workspace_id="self_test_workspace",
        task_id="self_test_file_state_checker",
        include_hash=False,
    )


__all__ = [
    "FileStateChecker",
    "FileSnapshot",
    "FileStateExpectation",
    "FileStateDiff",
    "create_file_state_checker",
    "self_test",
]


if __name__ == "__main__":
    # Safe manual smoke test. Read-only.
    result = self_test()
    print(json.dumps(result, indent=2, default=str))


# FILE COMPLETE