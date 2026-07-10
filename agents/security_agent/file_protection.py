"""
agents/security_agent/file_protection.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
Security Agent - File Protection

Purpose:
    Protect folders and files from accidental deletion, unsafe modification,
    overwriting, and other risky filesystem operations. Create verified backups
    before approved high-risk operations.

Architecture compatibility:
    - BaseAgent
    - Master Agent
    - Agent Registry
    - Agent Loader
    - Agent Router
    - Security Agent
    - Verification Agent
    - Memory Agent
    - Dashboard / FastAPI integration
    - SaaS user/workspace isolation

Security principles:
    1. Safety and permission validation always come first.
    2. Every filesystem operation is isolated by user_id and workspace_id.
    3. Paths outside configured tenant roots are rejected.
    4. Protected files cannot be deleted or overwritten without approval.
    5. Risky operations create backups before execution.
    6. Deletion defaults to quarantine rather than permanent deletion.
    7. Permanent deletion requires explicit Security Agent approval.
    8. Audit, verification, and memory payloads are prepared for every action.
    9. No secrets are hardcoded.
    10. The module remains import-safe if future William modules do not exist.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import logging
import os
import re
import shutil
import stat
import tempfile
import threading
import uuid
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
)


# =============================================================================
# Safe optional William imports
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Import-safe fallback BaseAgent.

        The real William BaseAgent can replace this class automatically when
        agents.base_agent becomes available.
        """

        agent_name = "BaseAgent"
        agent_type = "base"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get(
                "agent_name",
                getattr(self, "agent_name", self.__class__.__name__),
            )
            self.agent_type = kwargs.get(
                "agent_type",
                getattr(self, "agent_type", "unknown"),
            )
            self.logger = kwargs.get(
                "logger",
                logging.getLogger(self.agent_name),
            )

        async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
            raise NotImplementedError


try:
    from agents.security_agent.security_agent import SecurityAgent  # type: ignore
except Exception:  # pragma: no cover
    SecurityAgent = None  # type: ignore


try:
    from agents.security_agent.permission_checker import PermissionChecker  # type: ignore
except Exception:  # pragma: no cover
    PermissionChecker = None  # type: ignore


try:
    from agents.security_agent.approval_manager import ApprovalManager  # type: ignore
except Exception:  # pragma: no cover
    ApprovalManager = None  # type: ignore


try:
    from agents.security_agent.audit_logger import AuditLogger  # type: ignore
except Exception:  # pragma: no cover
    AuditLogger = None  # type: ignore


try:
    from agents.verification_agent.verification_agent import VerificationAgent  # type: ignore
except Exception:  # pragma: no cover
    VerificationAgent = None  # type: ignore


# =============================================================================
# Logging
# =============================================================================

LOGGER = logging.getLogger("FileProtection")

if not LOGGER.handlers:
    logging.basicConfig(
        level=os.getenv("WILLIAM_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


# =============================================================================
# Constants and environment-safe defaults
# =============================================================================

DEFAULT_DATA_ROOT = Path(
    os.getenv(
        "WILLIAM_DATA_ROOT",
        str(Path.cwd() / ".william_data"),
    )
).expanduser()

DEFAULT_TENANT_ROOT = Path(
    os.getenv(
        "WILLIAM_TENANT_FILES_ROOT",
        str(DEFAULT_DATA_ROOT / "tenant_files"),
    )
).expanduser()

DEFAULT_PROTECTION_ROOT = Path(
    os.getenv(
        "WILLIAM_FILE_PROTECTION_ROOT",
        str(DEFAULT_DATA_ROOT / "security_agent" / "file_protection"),
    )
).expanduser()

DEFAULT_BACKUP_ROOT = Path(
    os.getenv(
        "WILLIAM_FILE_BACKUP_ROOT",
        str(DEFAULT_PROTECTION_ROOT / "backups"),
    )
).expanduser()

DEFAULT_QUARANTINE_ROOT = Path(
    os.getenv(
        "WILLIAM_FILE_QUARANTINE_ROOT",
        str(DEFAULT_PROTECTION_ROOT / "quarantine"),
    )
).expanduser()

DEFAULT_POLICY_ROOT = Path(
    os.getenv(
        "WILLIAM_FILE_POLICY_ROOT",
        str(DEFAULT_PROTECTION_ROOT / "policies"),
    )
).expanduser()

DEFAULT_MANIFEST_ROOT = Path(
    os.getenv(
        "WILLIAM_FILE_MANIFEST_ROOT",
        str(DEFAULT_PROTECTION_ROOT / "manifests"),
    )
).expanduser()

MAX_PATH_LENGTH = 4096
MAX_REASON_LENGTH = 2_000
MAX_METADATA_BYTES = 128 * 1024
MAX_BACKUP_FILE_COUNT = 100_000
MAX_BACKUP_SIZE_BYTES = 10 * 1024 * 1024 * 1024
DEFAULT_HASH_CHUNK_SIZE = 1024 * 1024
DEFAULT_BACKUP_RETENTION = 25
DEFAULT_QUARANTINE_RETENTION = 25
SCHEMA_VERSION = 1

FORBIDDEN_PATH_PARTS = {
    "..",
    "~",
}

COMMON_HIGH_RISK_NAMES = {
    ".git",
    ".env",
    ".env.production",
    ".env.local",
    "config.py",
    "settings.py",
    "requirements.txt",
    "pyproject.toml",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "docker-compose.yml",
    "docker-compose.yaml",
    "Dockerfile",
    "alembic.ini",
    "migrations",
    "database",
    "backups",
    "agents",
    "core",
}

DEFAULT_PROTECTED_GLOBS = [
    "**/.env",
    "**/.env.*",
    "**/.git/**",
    "**/config.py",
    "**/settings.py",
    "**/requirements*.txt",
    "**/pyproject.toml",
    "**/package.json",
    "**/package-lock.json",
    "**/yarn.lock",
    "**/docker-compose.yml",
    "**/docker-compose.yaml",
    "**/Dockerfile",
    "**/migrations/**",
    "**/database/**",
    "**/agents/**",
    "**/core/**",
]


# =============================================================================
# Enums
# =============================================================================

class FileRiskLevel(str, Enum):
    """Filesystem operation risk levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FileAction(str, Enum):
    """Supported filesystem actions."""

    INSPECT = "inspect"
    PROTECT = "protect"
    UNPROTECT = "unprotect"
    CREATE_BACKUP = "create_backup"
    VERIFY_BACKUP = "verify_backup"
    LIST_BACKUPS = "list_backups"
    RESTORE_BACKUP = "restore_backup"
    DELETE = "delete"
    QUARANTINE = "quarantine"
    PERMANENT_DELETE = "permanent_delete"
    OVERWRITE = "overwrite"
    MOVE = "move"
    RENAME = "rename"
    MODIFY = "modify"
    RESTORE_QUARANTINE = "restore_quarantine"
    LIST_PROTECTED = "list_protected"
    GET_POLICY = "get_policy"
    CHECK_INTEGRITY = "check_integrity"


class ProtectionMode(str, Enum):
    """Protection behavior for a path."""

    MONITOR = "monitor"
    BACKUP_REQUIRED = "backup_required"
    APPROVAL_REQUIRED = "approval_required"
    LOCKED = "locked"


class BackupFormat(str, Enum):
    """Supported backup formats."""

    COPY = "copy"
    ZIP = "zip"


# =============================================================================
# Utility helpers
# =============================================================================

def _utc_now() -> str:
    """Return a timezone-aware UTC ISO timestamp."""
    return datetime.now(timezone.utc).isoformat()


def _new_id(prefix: str = "") -> str:
    """Return a safe unique identifier."""
    identifier = uuid.uuid4().hex
    return f"{prefix}_{identifier}" if prefix else identifier


def _normalize_identifier(value: Any, max_length: int = 160) -> str:
    """Normalize tenant, actor, and resource identifiers."""
    if value is None:
        return ""

    text = str(value).replace("\x00", "").strip()
    text = re.sub(r"[^a-zA-Z0-9_.:@\-]", "_", text)
    text = text.strip("._-/\\ ")

    return text[:max_length]


def _normalize_reason(value: Any) -> str:
    """Normalize an operation reason."""
    if value is None:
        return ""

    text = str(value).replace("\x00", "").strip()
    return text[:MAX_REASON_LENGTH]


def _json_safe(value: Any) -> Any:
    """Convert a value into JSON-compatible data."""
    try:
        return json.loads(json.dumps(value, default=str))
    except Exception:
        return str(value)


def _metadata_is_safe(metadata: Optional[Mapping[str, Any]]) -> bool:
    """Check metadata size before storing it in audit/manifests."""
    if metadata is None:
        return True

    try:
        encoded = json.dumps(metadata, default=str).encode("utf-8")
        return len(encoded) <= MAX_METADATA_BYTES
    except Exception:
        return False


def _safe_metadata(metadata: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    """Return normalized bounded metadata."""
    if metadata is None:
        return {}

    if not _metadata_is_safe(metadata):
        return {
            "metadata_truncated": True,
            "message": "Original metadata exceeded safe storage limit.",
        }

    return dict(_json_safe(dict(metadata)))


def _is_relative_to(path: Path, parent: Path) -> bool:
    """Python-version-safe Path.is_relative_to equivalent."""
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _write_json_atomic(path: Path, payload: Mapping[str, Any]) -> None:
    """Write JSON atomically to reduce corruption risk."""
    path.parent.mkdir(parents=True, exist_ok=True)

    temporary = path.with_name(
        f".{path.name}.{uuid.uuid4().hex}.tmp"
    )

    with temporary.open("w", encoding="utf-8") as file_handle:
        json.dump(
            payload,
            file_handle,
            ensure_ascii=False,
            indent=2,
            default=str,
        )
        file_handle.flush()
        os.fsync(file_handle.fileno())

    temporary.replace(path)


def _read_json(path: Path, default: Any) -> Any:
    """Read JSON safely."""
    if not path.exists():
        return default

    try:
        with path.open("r", encoding="utf-8") as file_handle:
            return json.load(file_handle)
    except (OSError, json.JSONDecodeError):
        return default


def _file_sha256(path: Path, chunk_size: int = DEFAULT_HASH_CHUNK_SIZE) -> str:
    """Calculate a file SHA-256 digest."""
    digest = hashlib.sha256()

    with path.open("rb") as file_handle:
        while True:
            chunk = file_handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)

    return digest.hexdigest()


def _directory_tree_digest(entries: Sequence[Mapping[str, Any]]) -> str:
    """Create deterministic digest from manifest entries."""
    digest = hashlib.sha256()

    for entry in sorted(
        entries,
        key=lambda item: str(item.get("relative_path", "")),
    ):
        digest.update(
            json.dumps(
                dict(entry),
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            ).encode("utf-8")
        )

    return digest.hexdigest()


def _call_maybe_async(
    callable_object: Callable[..., Any],
    *args: Any,
    **kwargs: Any,
) -> Any:
    """
    Call a sync or async integration hook.

    When already inside an active event loop, async handlers are not executed
    synchronously because blocking the same loop is unsafe.
    """
    result = callable_object(*args, **kwargs)

    if not inspect.isawaitable(result):
        return result

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(result)

    raise RuntimeError(
        "Async integration hook cannot be synchronously awaited inside an "
        "active event loop. Use the async FileProtection.run() interface."
    )


# =============================================================================
# Data structures
# =============================================================================

@dataclass
class FileProtectionConfig:
    """Configuration for FileProtection."""

    tenant_root: Path = DEFAULT_TENANT_ROOT
    protection_root: Path = DEFAULT_PROTECTION_ROOT
    backup_root: Path = DEFAULT_BACKUP_ROOT
    quarantine_root: Path = DEFAULT_QUARANTINE_ROOT
    policy_root: Path = DEFAULT_POLICY_ROOT
    manifest_root: Path = DEFAULT_MANIFEST_ROOT

    backup_format: BackupFormat = BackupFormat.ZIP
    backup_before_delete: bool = True
    backup_before_overwrite: bool = True
    backup_before_move: bool = True
    backup_before_rename: bool = True
    backup_before_modify: bool = False

    default_protection_mode: ProtectionMode = ProtectionMode.BACKUP_REQUIRED
    protected_globs: List[str] = field(
        default_factory=lambda: list(DEFAULT_PROTECTED_GLOBS)
    )

    allow_symlinks: bool = False
    preserve_file_metadata: bool = True
    verify_backup_after_creation: bool = True
    quarantine_instead_of_delete: bool = True

    max_backup_size_bytes: int = MAX_BACKUP_SIZE_BYTES
    max_backup_file_count: int = MAX_BACKUP_FILE_COUNT
    backup_retention_count: int = DEFAULT_BACKUP_RETENTION
    quarantine_retention_count: int = DEFAULT_QUARANTINE_RETENTION

    require_reason_for_sensitive_actions: bool = True
    permanent_delete_requires_approval: bool = True
    unprotect_requires_approval: bool = True
    restore_overwrite_requires_approval: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """Return configuration as JSON-compatible data."""
        data = asdict(self)

        for key in {
            "tenant_root",
            "protection_root",
            "backup_root",
            "quarantine_root",
            "policy_root",
            "manifest_root",
        }:
            data[key] = str(data[key])

        data["backup_format"] = self.backup_format.value
        data["default_protection_mode"] = self.default_protection_mode.value

        return data


@dataclass
class ProtectedPathRule:
    """Tenant-specific file protection rule."""

    rule_id: str
    user_id: str
    workspace_id: str
    relative_path: str
    mode: ProtectionMode
    recursive: bool = True
    enabled: bool = True
    reason: str = ""
    created_by: str = ""
    created_at: str = field(default_factory=_utc_now)
    updated_at: str = field(default_factory=_utc_now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Return rule as JSON-compatible data."""
        data = asdict(self)
        data["mode"] = self.mode.value
        return data

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ProtectedPathRule":
        """Create a rule safely from stored data."""
        mode_value = str(
            payload.get("mode", ProtectionMode.BACKUP_REQUIRED.value)
        )

        try:
            mode = ProtectionMode(mode_value)
        except ValueError:
            mode = ProtectionMode.BACKUP_REQUIRED

        return cls(
            rule_id=_normalize_identifier(
                payload.get("rule_id") or _new_id("rule")
            ),
            user_id=_normalize_identifier(payload.get("user_id")),
            workspace_id=_normalize_identifier(payload.get("workspace_id")),
            relative_path=str(payload.get("relative_path", "")).strip(),
            mode=mode,
            recursive=bool(payload.get("recursive", True)),
            enabled=bool(payload.get("enabled", True)),
            reason=_normalize_reason(payload.get("reason")),
            created_by=_normalize_identifier(payload.get("created_by")),
            created_at=str(payload.get("created_at") or _utc_now()),
            updated_at=str(payload.get("updated_at") or _utc_now()),
            metadata=_safe_metadata(payload.get("metadata")),
        )


@dataclass
class FileRiskAssessment:
    """Risk assessment for a filesystem action."""

    action: FileAction
    risk_level: FileRiskLevel
    path: str
    exists: bool
    is_file: bool
    is_directory: bool
    is_symlink: bool
    protected: bool
    protection_mode: Optional[ProtectionMode]
    backup_required: bool
    approval_required: bool
    destructive: bool
    reasons: List[str] = field(default_factory=list)
    matched_rule_ids: List[str] = field(default_factory=list)
    size_bytes: int = 0
    file_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Return assessment as JSON-compatible data."""
        data = asdict(self)
        data["action"] = self.action.value
        data["risk_level"] = self.risk_level.value
        data["protection_mode"] = (
            self.protection_mode.value
            if self.protection_mode is not None
            else None
        )
        return data


@dataclass
class BackupManifest:
    """Backup manifest and verification metadata."""

    backup_id: str
    user_id: str
    workspace_id: str
    source_relative_path: str
    source_absolute_path: str
    backup_path: str
    backup_format: BackupFormat
    action_reason: str
    operation: str
    created_by: str
    created_at: str
    source_type: str
    source_size_bytes: int
    source_file_count: int
    source_digest: str
    backup_digest: str
    verified: bool
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Return manifest as JSON-compatible data."""
        data = asdict(self)
        data["backup_format"] = self.backup_format.value
        return data

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "BackupManifest":
        """Create manifest from stored data."""
        format_value = str(
            payload.get("backup_format", BackupFormat.ZIP.value)
        )

        try:
            backup_format = BackupFormat(format_value)
        except ValueError:
            backup_format = BackupFormat.ZIP

        return cls(
            backup_id=_normalize_identifier(payload.get("backup_id")),
            user_id=_normalize_identifier(payload.get("user_id")),
            workspace_id=_normalize_identifier(payload.get("workspace_id")),
            source_relative_path=str(
                payload.get("source_relative_path", "")
            ),
            source_absolute_path=str(
                payload.get("source_absolute_path", "")
            ),
            backup_path=str(payload.get("backup_path", "")),
            backup_format=backup_format,
            action_reason=_normalize_reason(
                payload.get("action_reason")
            ),
            operation=str(payload.get("operation", "")),
            created_by=_normalize_identifier(payload.get("created_by")),
            created_at=str(payload.get("created_at") or _utc_now()),
            source_type=str(payload.get("source_type", "unknown")),
            source_size_bytes=int(
                payload.get("source_size_bytes", 0) or 0
            ),
            source_file_count=int(
                payload.get("source_file_count", 0) or 0
            ),
            source_digest=str(payload.get("source_digest", "")),
            backup_digest=str(payload.get("backup_digest", "")),
            verified=bool(payload.get("verified", False)),
            metadata=_safe_metadata(payload.get("metadata")),
        )


@dataclass
class QuarantineRecord:
    """Metadata for a quarantined file or directory."""

    quarantine_id: str
    user_id: str
    workspace_id: str
    original_relative_path: str
    original_absolute_path: str
    quarantine_path: str
    backup_id: Optional[str]
    action_reason: str
    created_by: str
    created_at: str
    source_type: str
    size_bytes: int
    file_count: int
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Return quarantine record as JSON-compatible data."""
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "QuarantineRecord":
        """Create quarantine record from stored data."""
        return cls(
            quarantine_id=_normalize_identifier(
                payload.get("quarantine_id")
            ),
            user_id=_normalize_identifier(payload.get("user_id")),
            workspace_id=_normalize_identifier(payload.get("workspace_id")),
            original_relative_path=str(
                payload.get("original_relative_path", "")
            ),
            original_absolute_path=str(
                payload.get("original_absolute_path", "")
            ),
            quarantine_path=str(payload.get("quarantine_path", "")),
            backup_id=(
                _normalize_identifier(payload.get("backup_id"))
                if payload.get("backup_id")
                else None
            ),
            action_reason=_normalize_reason(
                payload.get("action_reason")
            ),
            created_by=_normalize_identifier(payload.get("created_by")),
            created_at=str(payload.get("created_at") or _utc_now()),
            source_type=str(payload.get("source_type", "unknown")),
            size_bytes=int(payload.get("size_bytes", 0) or 0),
            file_count=int(payload.get("file_count", 0) or 0),
            metadata=_safe_metadata(payload.get("metadata")),
        )


# =============================================================================
# FileProtection
# =============================================================================

class FileProtection(BaseAgent):
    """
    Protect files and directories from accidental or unauthorized destruction.

    Public capabilities:
        - inspect_path()
        - assess_risk()
        - protect_path()
        - unprotect_path()
        - list_protected_paths()
        - create_backup()
        - verify_backup()
        - list_backups()
        - prepare_risky_action()
        - safe_delete()
        - restore_backup()
        - restore_quarantine()
        - check_integrity()
        - get_policy()

    Master Agent integration:
        Master Agent or Agent Router can call await run(task).

    Security Agent integration:
        Sensitive operations call _request_security_approval().

    Verification Agent integration:
        Every completed operation prepares a verification payload.

    Memory Agent integration:
        Useful protection, backup, deletion, and restoration context is exposed
        through _prepare_memory_payload().

    Dashboard/API integration:
        All public methods return structured dict results containing:
            success
            message
            data
            error
            metadata
    """

    agent_name = "FileProtection"
    agent_type = "security_agent"
    module_name = "file_protection"
    registry_key = "security.file_protection"

    def __init__(
        self,
        config: Optional[FileProtectionConfig] = None,
        security_agent: Optional[Any] = None,
        permission_checker: Optional[Any] = None,
        approval_manager: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        event_emitter: Optional[Callable[..., Any]] = None,
        logger: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize FileProtection.

        Args:
            config:
                Optional FileProtectionConfig.
            security_agent:
                Optional William SecurityAgent integration.
            permission_checker:
                Optional permission validation integration.
            approval_manager:
                Optional approval workflow integration.
            audit_logger:
                Optional central audit logger integration.
            verification_agent:
                Optional Verification Agent integration.
            event_emitter:
                Optional internal event bus callback.
            logger:
                Optional logger.
        """
        try:
            super().__init__(
                agent_name=self.agent_name,
                agent_type=self.agent_type,
                logger=logger,
                **kwargs,
            )
        except TypeError:
            try:
                super().__init__()
            except Exception:
                pass

        self.config = config or FileProtectionConfig()
        self.logger = logger or logging.getLogger(self.agent_name)

        self.security_agent = security_agent
        self.permission_checker = permission_checker
        self.approval_manager = approval_manager
        self.audit_logger = audit_logger
        self.verification_agent = verification_agent
        self.event_emitter = event_emitter

        self._lock = threading.RLock()
        self._ensure_storage_directories()

        self._emit_agent_event(
            event_type="file_protection_initialized",
            payload={
                "agent": self.agent_name,
                "registry_key": self.registry_key,
                "config": self.config.to_dict(),
            },
        )

    # =========================================================================
    # Master Agent / Agent Router interface
    # =========================================================================

    async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Master Agent and Agent Router compatible entrypoint.

        Expected task format:
            {
                "action": "inspect" | "protect" | "backup" | "safe_delete" | ...,
                "user_id": "user_123",
                "workspace_id": "workspace_123",
                "actor_id": "user_123",
                "payload": {
                    "path": "projects/example/file.txt"
                }
            }
        """
        if not isinstance(task, dict):
            return self._error_result(
                message="Task must be a dictionary.",
                error="INVALID_TASK",
            )

        action = str(task.get("action", "")).strip().lower()
        payload = task.get("payload") or {}

        if not isinstance(payload, dict):
            return self._error_result(
                message="Task payload must be a dictionary.",
                error="INVALID_PAYLOAD",
                metadata={"action": action},
            )

        parameters = dict(payload)
        parameters.setdefault("user_id", task.get("user_id"))
        parameters.setdefault("workspace_id", task.get("workspace_id"))
        parameters.setdefault(
            "actor_id",
            task.get("actor_id") or task.get("user_id"),
        )

        action_map: Dict[str, Callable[..., Dict[str, Any]]] = {
            "inspect": self.inspect_path,
            "inspect_path": self.inspect_path,
            "assess_risk": self.assess_risk,
            "protect": self.protect_path,
            "protect_path": self.protect_path,
            "unprotect": self.unprotect_path,
            "unprotect_path": self.unprotect_path,
            "list_protected": self.list_protected_paths,
            "list_protected_paths": self.list_protected_paths,
            "backup": self.create_backup,
            "create_backup": self.create_backup,
            "verify_backup": self.verify_backup,
            "list_backups": self.list_backups,
            "prepare_risky_action": self.prepare_risky_action,
            "safe_delete": self.safe_delete,
            "delete": self.safe_delete,
            "restore_backup": self.restore_backup,
            "restore_quarantine": self.restore_quarantine,
            "list_quarantine": self.list_quarantine,
            "check_integrity": self.check_integrity,
            "get_policy": self.get_policy,
        }

        handler = action_map.get(action)

        if handler is None:
            return self._error_result(
                message=f"Unsupported FileProtection action: {action}",
                error="UNSUPPORTED_ACTION",
                metadata={
                    "action": action,
                    "available_actions": sorted(action_map.keys()),
                },
            )

        try:
            result = handler(**parameters)
            if inspect.isawaitable(result):
                result = await result
            return result
        except TypeError as exc:
            return self._error_result(
                message="Invalid arguments for FileProtection action.",
                error=str(exc),
                metadata={"action": action},
            )
        except Exception as exc:
            self.logger.exception(
                "Unhandled FileProtection action error: %s",
                action,
            )
            return self._error_result(
                message="FileProtection action failed.",
                error=str(exc),
                metadata={"action": action},
            )

    # =========================================================================
    # Public inspection and policy methods
    # =========================================================================

    def inspect_path(
        self,
        user_id: str,
        workspace_id: str,
        path: Union[str, Path],
        actor_id: Optional[str] = None,
        calculate_hash: bool = False,
        **_: Any,
    ) -> Dict[str, Any]:
        """Inspect a tenant-isolated file or directory."""
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id,
        )

        if not context_result["success"]:
            return context_result

        resolved_result = self._resolve_tenant_path(
            user_id=user_id,
            workspace_id=workspace_id,
            requested_path=path,
            must_exist=False,
        )

        if not resolved_result["success"]:
            return resolved_result

        absolute_path = Path(resolved_result["data"]["absolute_path"])
        relative_path = resolved_result["data"]["relative_path"]

        exists = absolute_path.exists() or absolute_path.is_symlink()

        path_data: Dict[str, Any] = {
            "relative_path": relative_path,
            "absolute_path": str(absolute_path),
            "exists": exists,
            "is_file": False,
            "is_directory": False,
            "is_symlink": absolute_path.is_symlink(),
            "size_bytes": 0,
            "file_count": 0,
            "modified_at": None,
            "created_at": None,
            "permissions": None,
            "sha256": None,
        }

        if exists:
            path_data["is_file"] = absolute_path.is_file()
            path_data["is_directory"] = absolute_path.is_dir()

            try:
                stats = absolute_path.lstat()
                path_data["size_bytes"] = (
                    stats.st_size
                    if absolute_path.is_file()
                    else self._calculate_path_metrics(
                        absolute_path
                    )[0]
                )
                path_data["file_count"] = (
                    1
                    if absolute_path.is_file()
                    else self._calculate_path_metrics(
                        absolute_path
                    )[1]
                )
                path_data["modified_at"] = datetime.fromtimestamp(
                    stats.st_mtime,
                    tz=timezone.utc,
                ).isoformat()
                path_data["created_at"] = datetime.fromtimestamp(
                    stats.st_ctime,
                    tz=timezone.utc,
                ).isoformat()
                path_data["permissions"] = stat.filemode(stats.st_mode)
            except OSError as exc:
                path_data["inspection_warning"] = str(exc)

            if (
                calculate_hash
                and absolute_path.is_file()
                and not absolute_path.is_symlink()
            ):
                try:
                    path_data["sha256"] = _file_sha256(absolute_path)
                except OSError as exc:
                    path_data["hash_warning"] = str(exc)

        protection_result = self._evaluate_protection(
            user_id=user_id,
            workspace_id=workspace_id,
            absolute_path=absolute_path,
        )

        path_data["protection"] = protection_result

        return self._safe_result(
            message="Path inspection completed.",
            data=path_data,
            metadata={
                "verification": self._prepare_verification_payload(
                    action=FileAction.INSPECT.value,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    path=relative_path,
                    expected_exists=exists,
                ),
            },
        )

    def assess_risk(
        self,
        user_id: str,
        workspace_id: str,
        path: Union[str, Path],
        action: Union[str, FileAction],
        actor_id: Optional[str] = None,
        destination_path: Optional[Union[str, Path]] = None,
        **_: Any,
    ) -> Dict[str, Any]:
        """Assess the risk of a filesystem action."""
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id,
        )

        if not context_result["success"]:
            return context_result

        try:
            normalized_action = (
                action
                if isinstance(action, FileAction)
                else FileAction(str(action).strip().lower())
            )
        except ValueError:
            return self._error_result(
                message="Unsupported filesystem action.",
                error="INVALID_FILE_ACTION",
                metadata={"action": str(action)},
            )

        resolved_result = self._resolve_tenant_path(
            user_id=user_id,
            workspace_id=workspace_id,
            requested_path=path,
            must_exist=False,
        )

        if not resolved_result["success"]:
            return resolved_result

        absolute_path = Path(resolved_result["data"]["absolute_path"])
        relative_path = resolved_result["data"]["relative_path"]

        destination_absolute: Optional[Path] = None

        if destination_path is not None:
            destination_result = self._resolve_tenant_path(
                user_id=user_id,
                workspace_id=workspace_id,
                requested_path=destination_path,
                must_exist=False,
            )

            if not destination_result["success"]:
                return destination_result

            destination_absolute = Path(
                destination_result["data"]["absolute_path"]
            )

        assessment = self._build_risk_assessment(
            user_id=user_id,
            workspace_id=workspace_id,
            path=absolute_path,
            relative_path=relative_path,
            action=normalized_action,
            destination_path=destination_absolute,
        )

        return self._safe_result(
            message="Filesystem risk assessment completed.",
            data={"assessment": assessment.to_dict()},
            metadata={
                "verification": self._prepare_verification_payload(
                    action="assess_risk",
                    user_id=user_id,
                    workspace_id=workspace_id,
                    path=relative_path,
                    risk_level=assessment.risk_level.value,
                ),
            },
        )

    def get_policy(
        self,
        user_id: str,
        workspace_id: str,
        actor_id: Optional[str] = None,
        **_: Any,
    ) -> Dict[str, Any]:
        """Return effective file protection policy for a tenant."""
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id,
        )

        if not context_result["success"]:
            return context_result

        rules = [
            rule.to_dict()
            for rule in self._load_rules(user_id, workspace_id)
        ]

        return self._safe_result(
            message="Effective file protection policy retrieved.",
            data={
                "configuration": self.config.to_dict(),
                "tenant_rules": rules,
                "default_protected_globs": list(
                    self.config.protected_globs
                ),
                "high_risk_names": sorted(COMMON_HIGH_RISK_NAMES),
            },
            metadata={
                "verification": self._prepare_verification_payload(
                    action=FileAction.GET_POLICY.value,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    rule_count=len(rules),
                ),
            },
        )

    # =========================================================================
    # Protected path management
    # =========================================================================

    def protect_path(
        self,
        user_id: str,
        workspace_id: str,
        path: Union[str, Path],
        mode: Union[str, ProtectionMode] = ProtectionMode.BACKUP_REQUIRED,
        recursive: bool = True,
        reason: str = "",
        actor_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        **_: Any,
    ) -> Dict[str, Any]:
        """Add or update a protected-path rule."""
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id,
        )

        if not context_result["success"]:
            return context_result

        try:
            normalized_mode = (
                mode
                if isinstance(mode, ProtectionMode)
                else ProtectionMode(str(mode).strip().lower())
            )
        except ValueError:
            return self._error_result(
                message="Invalid protection mode.",
                error="INVALID_PROTECTION_MODE",
                metadata={
                    "allowed_modes": [
                        item.value for item in ProtectionMode
                    ]
                },
            )

        resolved_result = self._resolve_tenant_path(
            user_id=user_id,
            workspace_id=workspace_id,
            requested_path=path,
            must_exist=False,
        )

        if not resolved_result["success"]:
            return resolved_result

        relative_path = resolved_result["data"]["relative_path"]
        safe_reason = _normalize_reason(reason)

        rules = self._load_rules(user_id, workspace_id)
        existing_rule: Optional[ProtectedPathRule] = None

        for rule in rules:
            if rule.relative_path == relative_path:
                existing_rule = rule
                break

        now = _utc_now()
        safe_actor = _normalize_identifier(actor_id or user_id)

        if existing_rule:
            existing_rule.mode = normalized_mode
            existing_rule.recursive = bool(recursive)
            existing_rule.enabled = True
            existing_rule.reason = safe_reason
            existing_rule.updated_at = now
            existing_rule.metadata = _safe_metadata(metadata)
            rule = existing_rule
        else:
            rule = ProtectedPathRule(
                rule_id=_new_id("rule"),
                user_id=_normalize_identifier(user_id),
                workspace_id=_normalize_identifier(workspace_id),
                relative_path=relative_path,
                mode=normalized_mode,
                recursive=bool(recursive),
                enabled=True,
                reason=safe_reason,
                created_by=safe_actor,
                created_at=now,
                updated_at=now,
                metadata=_safe_metadata(metadata),
            )
            rules.append(rule)

        self._save_rules(user_id, workspace_id, rules)

        self._log_audit_event(
            action=FileAction.PROTECT.value,
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=safe_actor,
            resource_id=rule.rule_id,
            metadata={
                "path": relative_path,
                "mode": normalized_mode.value,
                "recursive": recursive,
            },
        )

        self._emit_agent_event(
            event_type="file_path_protected",
            payload={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "rule": rule.to_dict(),
            },
        )

        return self._safe_result(
            message="Path protection rule saved successfully.",
            data={"rule": rule.to_dict()},
            metadata={
                "memory_payload": self._prepare_memory_payload(
                    action=FileAction.PROTECT.value,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    resource=rule.to_dict(),
                ),
                "verification": self._prepare_verification_payload(
                    action=FileAction.PROTECT.value,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    path=relative_path,
                    rule_id=rule.rule_id,
                ),
            },
        )

    def unprotect_path(
        self,
        user_id: str,
        workspace_id: str,
        path: Optional[Union[str, Path]] = None,
        rule_id: Optional[str] = None,
        reason: str = "",
        actor_id: Optional[str] = None,
        approval_context: Optional[Mapping[str, Any]] = None,
        **_: Any,
    ) -> Dict[str, Any]:
        """Disable a protected-path rule after required approval."""
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id,
        )

        if not context_result["success"]:
            return context_result

        if not rule_id and path is None:
            return self._error_result(
                message="Either rule_id or path is required.",
                error="MISSING_RULE_SELECTOR",
            )

        safe_reason = _normalize_reason(reason)

        if self.config.require_reason_for_sensitive_actions and not safe_reason:
            return self._error_result(
                message="A reason is required to remove file protection.",
                error="REASON_REQUIRED",
            )

        rules = self._load_rules(user_id, workspace_id)
        target_relative_path: Optional[str] = None

        if path is not None:
            resolved_result = self._resolve_tenant_path(
                user_id=user_id,
                workspace_id=workspace_id,
                requested_path=path,
                must_exist=False,
            )

            if not resolved_result["success"]:
                return resolved_result

            target_relative_path = resolved_result["data"]["relative_path"]

        matched_rule: Optional[ProtectedPathRule] = None

        for rule in rules:
            if rule_id and rule.rule_id == _normalize_identifier(rule_id):
                matched_rule = rule
                break

            if (
                target_relative_path is not None
                and rule.relative_path == target_relative_path
            ):
                matched_rule = rule
                break

        if matched_rule is None:
            return self._error_result(
                message="Protection rule not found.",
                error="RULE_NOT_FOUND",
            )

        if self.config.unprotect_requires_approval:
            approval_result = self._request_security_approval(
                action=FileAction.UNPROTECT.value,
                user_id=user_id,
                workspace_id=workspace_id,
                actor_id=actor_id or user_id,
                resource_id=matched_rule.rule_id,
                reason=safe_reason,
                approval_context=approval_context,
                risk_level=FileRiskLevel.HIGH,
            )

            if not approval_result["success"]:
                return approval_result

        matched_rule.enabled = False
        matched_rule.updated_at = _utc_now()
        matched_rule.metadata = {
            **matched_rule.metadata,
            "disabled_reason": safe_reason,
            "disabled_by": _normalize_identifier(actor_id or user_id),
            "disabled_at": _utc_now(),
        }

        self._save_rules(user_id, workspace_id, rules)

        self._log_audit_event(
            action=FileAction.UNPROTECT.value,
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id or user_id,
            resource_id=matched_rule.rule_id,
            metadata={
                "path": matched_rule.relative_path,
                "reason": safe_reason,
            },
        )

        return self._safe_result(
            message="Path protection rule disabled successfully.",
            data={"rule": matched_rule.to_dict()},
            metadata={
                "memory_payload": self._prepare_memory_payload(
                    action=FileAction.UNPROTECT.value,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    resource=matched_rule.to_dict(),
                ),
                "verification": self._prepare_verification_payload(
                    action=FileAction.UNPROTECT.value,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    rule_id=matched_rule.rule_id,
                    expected_enabled=False,
                ),
            },
        )

    def list_protected_paths(
        self,
        user_id: str,
        workspace_id: str,
        include_disabled: bool = False,
        actor_id: Optional[str] = None,
        **_: Any,
    ) -> Dict[str, Any]:
        """List tenant-specific protection rules."""
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id,
        )

        if not context_result["success"]:
            return context_result

        rules = self._load_rules(user_id, workspace_id)

        if not include_disabled:
            rules = [rule for rule in rules if rule.enabled]

        return self._safe_result(
            message="Protected paths retrieved successfully.",
            data={
                "rules": [rule.to_dict() for rule in rules],
                "count": len(rules),
            },
            metadata={
                "verification": self._prepare_verification_payload(
                    action=FileAction.LIST_PROTECTED.value,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    rule_count=len(rules),
                ),
            },
        )

    # =========================================================================
    # Backup operations
    # =========================================================================

    def create_backup(
        self,
        user_id: str,
        workspace_id: str,
        path: Union[str, Path],
        reason: str,
        operation: str = "manual_backup",
        actor_id: Optional[str] = None,
        backup_format: Optional[Union[str, BackupFormat]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        **_: Any,
    ) -> Dict[str, Any]:
        """Create and optionally verify a tenant-isolated backup."""
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id,
        )

        if not context_result["success"]:
            return context_result

        safe_reason = _normalize_reason(reason)

        if not safe_reason:
            return self._error_result(
                message="A backup reason is required.",
                error="REASON_REQUIRED",
            )

        resolved_result = self._resolve_tenant_path(
            user_id=user_id,
            workspace_id=workspace_id,
            requested_path=path,
            must_exist=True,
        )

        if not resolved_result["success"]:
            return resolved_result

        source_path = Path(resolved_result["data"]["absolute_path"])
        relative_path = resolved_result["data"]["relative_path"]

        if source_path.is_symlink() and not self.config.allow_symlinks:
            return self._error_result(
                message="Symlink backups are disabled by policy.",
                error="SYMLINK_NOT_ALLOWED",
                metadata={"path": relative_path},
            )

        selected_format = self.config.backup_format

        if backup_format is not None:
            try:
                selected_format = (
                    backup_format
                    if isinstance(backup_format, BackupFormat)
                    else BackupFormat(str(backup_format).strip().lower())
                )
            except ValueError:
                return self._error_result(
                    message="Unsupported backup format.",
                    error="INVALID_BACKUP_FORMAT",
                )

        try:
            source_size, source_file_count = self._calculate_path_metrics(
                source_path
            )
        except OSError as exc:
            return self._error_result(
                message="Unable to calculate source path size.",
                error=str(exc),
                metadata={"path": relative_path},
            )

        if source_size > self.config.max_backup_size_bytes:
            return self._error_result(
                message="Backup size exceeds configured safety limit.",
                error="BACKUP_SIZE_LIMIT_EXCEEDED",
                metadata={
                    "size_bytes": source_size,
                    "maximum_bytes": self.config.max_backup_size_bytes,
                },
            )

        if source_file_count > self.config.max_backup_file_count:
            return self._error_result(
                message="Backup file count exceeds configured safety limit.",
                error="BACKUP_FILE_COUNT_LIMIT_EXCEEDED",
                metadata={
                    "file_count": source_file_count,
                    "maximum_file_count": self.config.max_backup_file_count,
                },
            )

        backup_id = _new_id("backup")
        tenant_backup_root = self._tenant_backup_root(
            user_id,
            workspace_id,
        )
        tenant_backup_root.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        safe_name = self._safe_backup_name(source_path.name or "root")

        if selected_format == BackupFormat.ZIP:
            backup_path = tenant_backup_root / (
                f"{timestamp}_{backup_id}_{safe_name}.zip"
            )
        else:
            backup_path = tenant_backup_root / (
                f"{timestamp}_{backup_id}_{safe_name}"
            )

        try:
            source_entries = self._build_source_manifest(source_path)
            source_digest = _directory_tree_digest(source_entries)

            with self._lock:
                if selected_format == BackupFormat.ZIP:
                    self._create_zip_backup(
                        source_path=source_path,
                        destination=backup_path,
                    )
                else:
                    self._create_copy_backup(
                        source_path=source_path,
                        destination=backup_path,
                    )

            backup_digest = self._calculate_backup_digest(
                backup_path,
                selected_format,
            )

            manifest = BackupManifest(
                backup_id=backup_id,
                user_id=_normalize_identifier(user_id),
                workspace_id=_normalize_identifier(workspace_id),
                source_relative_path=relative_path,
                source_absolute_path=str(source_path),
                backup_path=str(backup_path),
                backup_format=selected_format,
                action_reason=safe_reason,
                operation=str(operation)[:160],
                created_by=_normalize_identifier(actor_id or user_id),
                created_at=_utc_now(),
                source_type=(
                    "directory"
                    if source_path.is_dir()
                    else "file"
                ),
                source_size_bytes=source_size,
                source_file_count=source_file_count,
                source_digest=source_digest,
                backup_digest=backup_digest,
                verified=False,
                metadata=_safe_metadata(metadata),
            )

            self._save_backup_manifest(manifest)

            if self.config.verify_backup_after_creation:
                verification_result = self.verify_backup(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    backup_id=backup_id,
                    actor_id=actor_id,
                )

                if not verification_result["success"]:
                    return self._error_result(
                        message=(
                            "Backup was created but verification failed."
                        ),
                        error="BACKUP_VERIFICATION_FAILED",
                        data={
                            "backup_id": backup_id,
                            "backup_path": str(backup_path),
                        },
                        metadata={
                            "verification_result": verification_result,
                        },
                    )

                manifest.verified = True
                self._save_backup_manifest(manifest)

            self._enforce_backup_retention(
                user_id=user_id,
                workspace_id=workspace_id,
            )

            self._log_audit_event(
                action=FileAction.CREATE_BACKUP.value,
                user_id=user_id,
                workspace_id=workspace_id,
                actor_id=actor_id or user_id,
                resource_id=backup_id,
                metadata={
                    "source_path": relative_path,
                    "backup_path": str(backup_path),
                    "size_bytes": source_size,
                    "file_count": source_file_count,
                    "operation": operation,
                },
            )

            self._emit_agent_event(
                event_type="file_backup_created",
                payload={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "manifest": manifest.to_dict(),
                },
            )

            return self._safe_result(
                message="Backup created successfully.",
                data={"backup": manifest.to_dict()},
                metadata={
                    "memory_payload": self._prepare_memory_payload(
                        action=FileAction.CREATE_BACKUP.value,
                        user_id=user_id,
                        workspace_id=workspace_id,
                        resource=manifest.to_dict(),
                    ),
                    "verification": self._prepare_verification_payload(
                        action=FileAction.CREATE_BACKUP.value,
                        user_id=user_id,
                        workspace_id=workspace_id,
                        backup_id=backup_id,
                        expected_backup_path=str(backup_path),
                        expected_verified=manifest.verified,
                    ),
                },
            )

        except Exception as exc:
            self.logger.exception(
                "Failed to create backup for %s",
                relative_path,
            )

            try:
                if backup_path.exists():
                    self._remove_path_internal(backup_path)
            except Exception:
                pass

            return self._error_result(
                message="Backup creation failed.",
                error=str(exc),
                metadata={
                    "path": relative_path,
                    "backup_id": backup_id,
                },
            )

    def verify_backup(
        self,
        user_id: str,
        workspace_id: str,
        backup_id: str,
        actor_id: Optional[str] = None,
        **_: Any,
    ) -> Dict[str, Any]:
        """Verify backup existence, readability, and digest."""
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id,
        )

        if not context_result["success"]:
            return context_result

        manifest = self._load_backup_manifest(
            user_id=user_id,
            workspace_id=workspace_id,
            backup_id=backup_id,
        )

        if manifest is None:
            return self._error_result(
                message="Backup manifest not found.",
                error="BACKUP_NOT_FOUND",
                metadata={"backup_id": backup_id},
            )

        backup_path = Path(manifest.backup_path)

        if not backup_path.exists():
            return self._error_result(
                message="Backup file or directory does not exist.",
                error="BACKUP_DATA_MISSING",
                metadata={
                    "backup_id": backup_id,
                    "backup_path": str(backup_path),
                },
            )

        try:
            if manifest.backup_format == BackupFormat.ZIP:
                with zipfile.ZipFile(backup_path, "r") as archive:
                    corrupt_member = archive.testzip()

                    if corrupt_member is not None:
                        return self._error_result(
                            message="Backup archive contains a corrupt member.",
                            error="BACKUP_ARCHIVE_CORRUPT",
                            metadata={
                                "backup_id": backup_id,
                                "corrupt_member": corrupt_member,
                            },
                        )

            calculated_digest = self._calculate_backup_digest(
                backup_path,
                manifest.backup_format,
            )
            digest_matches = (
                calculated_digest == manifest.backup_digest
            )

            if digest_matches:
                manifest.verified = True
                self._save_backup_manifest(manifest)

            verification_data = {
                "backup_id": backup_id,
                "exists": True,
                "readable": True,
                "digest_matches": digest_matches,
                "stored_digest": manifest.backup_digest,
                "calculated_digest": calculated_digest,
                "verified": digest_matches,
            }

            if not digest_matches:
                return self._error_result(
                    message="Backup digest verification failed.",
                    error="BACKUP_DIGEST_MISMATCH",
                    data=verification_data,
                )

            return self._safe_result(
                message="Backup verified successfully.",
                data=verification_data,
                metadata={
                    "verification": self._prepare_verification_payload(
                        action=FileAction.VERIFY_BACKUP.value,
                        user_id=user_id,
                        workspace_id=workspace_id,
                        backup_id=backup_id,
                        expected_digest=manifest.backup_digest,
                    ),
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Backup verification failed.",
                error=str(exc),
                metadata={"backup_id": backup_id},
            )

    def list_backups(
        self,
        user_id: str,
        workspace_id: str,
        source_path: Optional[Union[str, Path]] = None,
        limit: int = 100,
        actor_id: Optional[str] = None,
        **_: Any,
    ) -> Dict[str, Any]:
        """List backup manifests for one tenant."""
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id,
        )

        if not context_result["success"]:
            return context_result

        normalized_source: Optional[str] = None

        if source_path is not None:
            resolved_result = self._resolve_tenant_path(
                user_id=user_id,
                workspace_id=workspace_id,
                requested_path=source_path,
                must_exist=False,
            )

            if not resolved_result["success"]:
                return resolved_result

            normalized_source = resolved_result["data"]["relative_path"]

        manifests = self._load_all_backup_manifests(
            user_id,
            workspace_id,
        )

        if normalized_source is not None:
            manifests = [
                manifest
                for manifest in manifests
                if manifest.source_relative_path == normalized_source
            ]

        manifests.sort(
            key=lambda manifest: manifest.created_at,
            reverse=True,
        )

        safe_limit = max(1, min(int(limit or 100), 1_000))
        manifests = manifests[:safe_limit]

        return self._safe_result(
            message="Backups retrieved successfully.",
            data={
                "backups": [
                    manifest.to_dict() for manifest in manifests
                ],
                "count": len(manifests),
            },
            metadata={
                "verification": self._prepare_verification_payload(
                    action=FileAction.LIST_BACKUPS.value,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    backup_count=len(manifests),
                ),
            },
        )

    # =========================================================================
    # Risk preparation and safe deletion
    # =========================================================================

    def prepare_risky_action(
        self,
        user_id: str,
        workspace_id: str,
        path: Union[str, Path],
        action: Union[str, FileAction],
        reason: str,
        actor_id: Optional[str] = None,
        destination_path: Optional[Union[str, Path]] = None,
        approval_context: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        **_: Any,
    ) -> Dict[str, Any]:
        """
        Prepare a risky filesystem action.

        This method:
            1. Validates tenant context.
            2. Resolves and validates the path.
            3. Calculates risk.
            4. Requests approval where required.
            5. Creates a verified backup where required.
            6. Returns an authorization/preparation token.

        It does not execute the destructive action itself.
        """
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id,
        )

        if not context_result["success"]:
            return context_result

        safe_reason = _normalize_reason(reason)

        if self.config.require_reason_for_sensitive_actions and not safe_reason:
            return self._error_result(
                message="A reason is required for risky file actions.",
                error="REASON_REQUIRED",
            )

        risk_result = self.assess_risk(
            user_id=user_id,
            workspace_id=workspace_id,
            path=path,
            action=action,
            actor_id=actor_id,
            destination_path=destination_path,
        )

        if not risk_result["success"]:
            return risk_result

        assessment = risk_result["data"]["assessment"]
        risk_level = FileRiskLevel(assessment["risk_level"])
        normalized_action = FileAction(assessment["action"])

        approval_data: Optional[Dict[str, Any]] = None

        if assessment["approval_required"]:
            approval_result = self._request_security_approval(
                action=normalized_action.value,
                user_id=user_id,
                workspace_id=workspace_id,
                actor_id=actor_id or user_id,
                resource_id=assessment["path"],
                reason=safe_reason,
                approval_context=approval_context,
                risk_level=risk_level,
            )

            if not approval_result["success"]:
                return approval_result

            approval_data = approval_result["data"]

        backup_data: Optional[Dict[str, Any]] = None

        if assessment["backup_required"]:
            backup_result = self.create_backup(
                user_id=user_id,
                workspace_id=workspace_id,
                path=path,
                reason=safe_reason,
                operation=normalized_action.value,
                actor_id=actor_id,
                metadata={
                    **_safe_metadata(metadata),
                    "risk_assessment": assessment,
                },
            )

            if not backup_result["success"]:
                return self._error_result(
                    message=(
                        "Risky action preparation stopped because the "
                        "required backup failed."
                    ),
                    error="REQUIRED_BACKUP_FAILED",
                    metadata={
                        "assessment": assessment,
                        "backup_result": backup_result,
                    },
                )

            backup_data = backup_result["data"]["backup"]

        preparation_id = _new_id("preparation")
        preparation_payload = {
            "preparation_id": preparation_id,
            "user_id": _normalize_identifier(user_id),
            "workspace_id": _normalize_identifier(workspace_id),
            "actor_id": _normalize_identifier(actor_id or user_id),
            "action": normalized_action.value,
            "path": assessment["path"],
            "destination_path": (
                str(destination_path)
                if destination_path is not None
                else None
            ),
            "reason": safe_reason,
            "risk_assessment": assessment,
            "approval": approval_data,
            "backup": backup_data,
            "prepared_at": _utc_now(),
            "metadata": _safe_metadata(metadata),
        }

        self._save_preparation(
            user_id=user_id,
            workspace_id=workspace_id,
            payload=preparation_payload,
        )

        self._log_audit_event(
            action="prepare_risky_file_action",
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id or user_id,
            resource_id=preparation_id,
            metadata={
                "action": normalized_action.value,
                "path": assessment["path"],
                "risk_level": assessment["risk_level"],
                "backup_id": (
                    backup_data.get("backup_id")
                    if backup_data
                    else None
                ),
            },
        )

        return self._safe_result(
            message="Risky filesystem action prepared successfully.",
            data=preparation_payload,
            metadata={
                "memory_payload": self._prepare_memory_payload(
                    action="prepare_risky_action",
                    user_id=user_id,
                    workspace_id=workspace_id,
                    resource=preparation_payload,
                ),
                "verification": self._prepare_verification_payload(
                    action="prepare_risky_action",
                    user_id=user_id,
                    workspace_id=workspace_id,
                    preparation_id=preparation_id,
                    backup_required=assessment["backup_required"],
                    approval_required=assessment["approval_required"],
                ),
            },
        )

    def safe_delete(
        self,
        user_id: str,
        workspace_id: str,
        path: Union[str, Path],
        reason: str,
        actor_id: Optional[str] = None,
        permanent: bool = False,
        approval_context: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        **_: Any,
    ) -> Dict[str, Any]:
        """
        Safely delete a file or directory.

        Default:
            Move the resource into tenant quarantine.

        Permanent deletion:
            Requires explicit approval and a verified backup when policy requires.
        """
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id,
        )

        if not context_result["success"]:
            return context_result

        safe_reason = _normalize_reason(reason)

        if not safe_reason:
            return self._error_result(
                message="A deletion reason is required.",
                error="REASON_REQUIRED",
            )

        action = (
            FileAction.PERMANENT_DELETE
            if permanent
            else FileAction.DELETE
        )

        resolved_result = self._resolve_tenant_path(
            user_id=user_id,
            workspace_id=workspace_id,
            requested_path=path,
            must_exist=True,
        )

        if not resolved_result["success"]:
            return resolved_result

        absolute_path = Path(resolved_result["data"]["absolute_path"])
        relative_path = resolved_result["data"]["relative_path"]

        if absolute_path == self._tenant_root(user_id, workspace_id):
            return self._error_result(
                message="Deleting the tenant workspace root is prohibited.",
                error="TENANT_ROOT_DELETE_PROHIBITED",
                metadata={"path": relative_path},
            )

        preparation_result = self.prepare_risky_action(
            user_id=user_id,
            workspace_id=workspace_id,
            path=relative_path,
            action=action,
            reason=safe_reason,
            actor_id=actor_id,
            approval_context=approval_context,
            metadata=metadata,
        )

        if not preparation_result["success"]:
            return preparation_result

        preparation = preparation_result["data"]
        backup = preparation.get("backup")
        backup_id = backup.get("backup_id") if backup else None

        try:
            size_bytes, file_count = self._calculate_path_metrics(
                absolute_path
            )
            source_type = (
                "directory"
                if absolute_path.is_dir()
                else "file"
            )

            if permanent:
                if self.config.permanent_delete_requires_approval:
                    if not preparation.get("approval"):
                        return self._error_result(
                            message=(
                                "Permanent deletion requires explicit "
                                "security approval."
                            ),
                            error="SECURITY_APPROVAL_REQUIRED",
                        )

                self._remove_path_internal(absolute_path)

                result_data = {
                    "action": FileAction.PERMANENT_DELETE.value,
                    "path": relative_path,
                    "permanent": True,
                    "backup_id": backup_id,
                    "deleted_at": _utc_now(),
                }

                event_type = "file_permanently_deleted"
                message = "Path permanently deleted after security preparation."

            else:
                quarantine_record = self._move_to_quarantine(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    source_path=absolute_path,
                    relative_path=relative_path,
                    backup_id=backup_id,
                    reason=safe_reason,
                    actor_id=actor_id or user_id,
                    source_type=source_type,
                    size_bytes=size_bytes,
                    file_count=file_count,
                    metadata=metadata,
                )

                result_data = {
                    "action": FileAction.QUARANTINE.value,
                    "path": relative_path,
                    "permanent": False,
                    "backup_id": backup_id,
                    "quarantine": quarantine_record.to_dict(),
                }

                event_type = "file_moved_to_quarantine"
                message = "Path moved to quarantine successfully."

                self._enforce_quarantine_retention(
                    user_id=user_id,
                    workspace_id=workspace_id,
                )

            self._log_audit_event(
                action=action.value,
                user_id=user_id,
                workspace_id=workspace_id,
                actor_id=actor_id or user_id,
                resource_id=relative_path,
                metadata={
                    "reason": safe_reason,
                    "permanent": permanent,
                    "backup_id": backup_id,
                    "size_bytes": size_bytes,
                    "file_count": file_count,
                },
            )

            self._emit_agent_event(
                event_type=event_type,
                payload={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    **result_data,
                },
            )

            return self._safe_result(
                message=message,
                data=result_data,
                metadata={
                    "memory_payload": self._prepare_memory_payload(
                        action=action.value,
                        user_id=user_id,
                        workspace_id=workspace_id,
                        resource=result_data,
                    ),
                    "verification": self._prepare_verification_payload(
                        action=action.value,
                        user_id=user_id,
                        workspace_id=workspace_id,
                        path=relative_path,
                        expected_exists=False,
                        backup_id=backup_id,
                    ),
                },
            )

        except Exception as exc:
            self.logger.exception(
                "Safe delete failed for %s",
                relative_path,
            )
            return self._error_result(
                message="Safe deletion failed.",
                error=str(exc),
                metadata={
                    "path": relative_path,
                    "backup_id": backup_id,
                    "preparation_id": preparation.get("preparation_id"),
                },
            )

    # =========================================================================
    # Restore operations
    # =========================================================================

    def restore_backup(
        self,
        user_id: str,
        workspace_id: str,
        backup_id: str,
        destination_path: Optional[Union[str, Path]] = None,
        overwrite: bool = False,
        reason: str = "",
        actor_id: Optional[str] = None,
        approval_context: Optional[Mapping[str, Any]] = None,
        **_: Any,
    ) -> Dict[str, Any]:
        """Restore a backup into the tenant workspace."""
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id,
        )

        if not context_result["success"]:
            return context_result

        manifest = self._load_backup_manifest(
            user_id=user_id,
            workspace_id=workspace_id,
            backup_id=backup_id,
        )

        if manifest is None:
            return self._error_result(
                message="Backup manifest not found.",
                error="BACKUP_NOT_FOUND",
                metadata={"backup_id": backup_id},
            )

        verification_result = self.verify_backup(
            user_id=user_id,
            workspace_id=workspace_id,
            backup_id=backup_id,
            actor_id=actor_id,
        )

        if not verification_result["success"]:
            return self._error_result(
                message="Backup restoration stopped because verification failed.",
                error="BACKUP_VERIFICATION_FAILED",
                metadata={
                    "backup_id": backup_id,
                    "verification_result": verification_result,
                },
            )

        target_request = (
            destination_path
            if destination_path is not None
            else manifest.source_relative_path
        )

        destination_result = self._resolve_tenant_path(
            user_id=user_id,
            workspace_id=workspace_id,
            requested_path=target_request,
            must_exist=False,
        )

        if not destination_result["success"]:
            return destination_result

        destination = Path(destination_result["data"]["absolute_path"])
        destination_relative = destination_result["data"]["relative_path"]
        safe_reason = _normalize_reason(reason) or "Restore verified backup"

        destination_exists = (
            destination.exists() or destination.is_symlink()
        )

        if destination_exists and not overwrite:
            return self._error_result(
                message=(
                    "Restore destination already exists. Set overwrite=True "
                    "only after appropriate approval."
                ),
                error="DESTINATION_EXISTS",
                metadata={"destination_path": destination_relative},
            )

        pre_restore_backup: Optional[Dict[str, Any]] = None

        if destination_exists and overwrite:
            if self.config.restore_overwrite_requires_approval:
                approval_result = self._request_security_approval(
                    action="restore_backup_overwrite",
                    user_id=user_id,
                    workspace_id=workspace_id,
                    actor_id=actor_id or user_id,
                    resource_id=destination_relative,
                    reason=safe_reason,
                    approval_context=approval_context,
                    risk_level=FileRiskLevel.HIGH,
                )

                if not approval_result["success"]:
                    return approval_result

            existing_backup_result = self.create_backup(
                user_id=user_id,
                workspace_id=workspace_id,
                path=destination_relative,
                reason=(
                    f"Pre-restore backup before overwriting "
                    f"{destination_relative}"
                ),
                operation="restore_backup_overwrite",
                actor_id=actor_id,
            )

            if not existing_backup_result["success"]:
                return self._error_result(
                    message=(
                        "Restore stopped because the existing destination "
                        "could not be backed up."
                    ),
                    error="PRE_RESTORE_BACKUP_FAILED",
                    metadata={
                        "destination_path": destination_relative,
                        "backup_result": existing_backup_result,
                    },
                )

            pre_restore_backup = existing_backup_result["data"]["backup"]
            self._remove_path_internal(destination)

        backup_path = Path(manifest.backup_path)

        try:
            destination.parent.mkdir(parents=True, exist_ok=True)

            if manifest.backup_format == BackupFormat.ZIP:
                self._restore_zip_backup(
                    archive_path=backup_path,
                    destination=destination,
                    source_type=manifest.source_type,
                )
            else:
                self._restore_copy_backup(
                    backup_path=backup_path,
                    destination=destination,
                )

            restored_exists = destination.exists()

            if not restored_exists:
                raise RuntimeError(
                    "Restore completed without creating destination."
                )

            integrity_result = self._build_source_manifest(destination)
            restored_digest = _directory_tree_digest(integrity_result)
            digest_matches = restored_digest == manifest.source_digest

            result_data = {
                "backup_id": backup_id,
                "destination_path": destination_relative,
                "restored": True,
                "source_digest": manifest.source_digest,
                "restored_digest": restored_digest,
                "digest_matches": digest_matches,
                "pre_restore_backup": pre_restore_backup,
                "restored_at": _utc_now(),
            }

            self._log_audit_event(
                action=FileAction.RESTORE_BACKUP.value,
                user_id=user_id,
                workspace_id=workspace_id,
                actor_id=actor_id or user_id,
                resource_id=backup_id,
                metadata={
                    "destination_path": destination_relative,
                    "overwrite": overwrite,
                    "digest_matches": digest_matches,
                    "pre_restore_backup_id": (
                        pre_restore_backup.get("backup_id")
                        if pre_restore_backup
                        else None
                    ),
                },
            )

            return self._safe_result(
                message="Backup restored successfully.",
                data=result_data,
                metadata={
                    "memory_payload": self._prepare_memory_payload(
                        action=FileAction.RESTORE_BACKUP.value,
                        user_id=user_id,
                        workspace_id=workspace_id,
                        resource=result_data,
                    ),
                    "verification": self._prepare_verification_payload(
                        action=FileAction.RESTORE_BACKUP.value,
                        user_id=user_id,
                        workspace_id=workspace_id,
                        backup_id=backup_id,
                        destination_path=destination_relative,
                        expected_exists=True,
                        expected_digest=manifest.source_digest,
                    ),
                },
            )

        except Exception as exc:
            self.logger.exception(
                "Backup restoration failed for %s",
                backup_id,
            )
            return self._error_result(
                message="Backup restoration failed.",
                error=str(exc),
                metadata={
                    "backup_id": backup_id,
                    "destination_path": destination_relative,
                    "pre_restore_backup": pre_restore_backup,
                },
            )

    def list_quarantine(
        self,
        user_id: str,
        workspace_id: str,
        limit: int = 100,
        actor_id: Optional[str] = None,
        **_: Any,
    ) -> Dict[str, Any]:
        """List tenant quarantine records."""
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id,
        )

        if not context_result["success"]:
            return context_result

        records = self._load_quarantine_records(
            user_id,
            workspace_id,
        )
        records.sort(
            key=lambda record: record.created_at,
            reverse=True,
        )

        safe_limit = max(1, min(int(limit or 100), 1_000))
        records = records[:safe_limit]

        return self._safe_result(
            message="Quarantine records retrieved successfully.",
            data={
                "records": [record.to_dict() for record in records],
                "count": len(records),
            },
        )

    def restore_quarantine(
        self,
        user_id: str,
        workspace_id: str,
        quarantine_id: str,
        overwrite: bool = False,
        reason: str = "",
        actor_id: Optional[str] = None,
        approval_context: Optional[Mapping[str, Any]] = None,
        **_: Any,
    ) -> Dict[str, Any]:
        """Restore a quarantined path to its original tenant location."""
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id,
        )

        if not context_result["success"]:
            return context_result

        record = self._load_quarantine_record(
            user_id=user_id,
            workspace_id=workspace_id,
            quarantine_id=quarantine_id,
        )

        if record is None:
            return self._error_result(
                message="Quarantine record not found.",
                error="QUARANTINE_RECORD_NOT_FOUND",
                metadata={"quarantine_id": quarantine_id},
            )

        quarantine_path = Path(record.quarantine_path)

        if not quarantine_path.exists():
            return self._error_result(
                message="Quarantined data is missing.",
                error="QUARANTINE_DATA_MISSING",
                metadata={
                    "quarantine_id": quarantine_id,
                    "quarantine_path": str(quarantine_path),
                },
            )

        destination_result = self._resolve_tenant_path(
            user_id=user_id,
            workspace_id=workspace_id,
            requested_path=record.original_relative_path,
            must_exist=False,
        )

        if not destination_result["success"]:
            return destination_result

        destination = Path(destination_result["data"]["absolute_path"])
        destination_relative = destination_result["data"]["relative_path"]
        safe_reason = _normalize_reason(reason) or "Restore quarantined path"

        pre_restore_backup: Optional[Dict[str, Any]] = None

        if destination.exists() or destination.is_symlink():
            if not overwrite:
                return self._error_result(
                    message=(
                        "Original destination already exists. "
                        "Set overwrite=True after approval."
                    ),
                    error="DESTINATION_EXISTS",
                    metadata={"destination_path": destination_relative},
                )

            approval_result = self._request_security_approval(
                action="restore_quarantine_overwrite",
                user_id=user_id,
                workspace_id=workspace_id,
                actor_id=actor_id or user_id,
                resource_id=destination_relative,
                reason=safe_reason,
                approval_context=approval_context,
                risk_level=FileRiskLevel.HIGH,
            )

            if not approval_result["success"]:
                return approval_result

            backup_result = self.create_backup(
                user_id=user_id,
                workspace_id=workspace_id,
                path=destination_relative,
                reason=(
                    "Pre-restore backup before replacing destination "
                    "with quarantined data"
                ),
                operation="restore_quarantine_overwrite",
                actor_id=actor_id,
            )

            if not backup_result["success"]:
                return self._error_result(
                    message=(
                        "Quarantine restoration stopped because the "
                        "existing destination backup failed."
                    ),
                    error="PRE_RESTORE_BACKUP_FAILED",
                    metadata={"backup_result": backup_result},
                )

            pre_restore_backup = backup_result["data"]["backup"]
            self._remove_path_internal(destination)

        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(quarantine_path), str(destination))

            self._delete_quarantine_record(
                user_id=user_id,
                workspace_id=workspace_id,
                quarantine_id=record.quarantine_id,
            )

            result_data = {
                "quarantine_id": record.quarantine_id,
                "destination_path": destination_relative,
                "restored": True,
                "pre_restore_backup": pre_restore_backup,
                "restored_at": _utc_now(),
            }

            self._log_audit_event(
                action=FileAction.RESTORE_QUARANTINE.value,
                user_id=user_id,
                workspace_id=workspace_id,
                actor_id=actor_id or user_id,
                resource_id=record.quarantine_id,
                metadata=result_data,
            )

            return self._safe_result(
                message="Quarantined path restored successfully.",
                data=result_data,
                metadata={
                    "memory_payload": self._prepare_memory_payload(
                        action=FileAction.RESTORE_QUARANTINE.value,
                        user_id=user_id,
                        workspace_id=workspace_id,
                        resource=result_data,
                    ),
                    "verification": self._prepare_verification_payload(
                        action=FileAction.RESTORE_QUARANTINE.value,
                        user_id=user_id,
                        workspace_id=workspace_id,
                        quarantine_id=record.quarantine_id,
                        destination_path=destination_relative,
                        expected_exists=True,
                    ),
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Quarantine restoration failed.",
                error=str(exc),
                metadata={
                    "quarantine_id": record.quarantine_id,
                    "destination_path": destination_relative,
                },
            )

    # =========================================================================
    # Integrity operations
    # =========================================================================

    def check_integrity(
        self,
        user_id: str,
        workspace_id: str,
        path: Union[str, Path],
        backup_id: Optional[str] = None,
        expected_digest: Optional[str] = None,
        actor_id: Optional[str] = None,
        **_: Any,
    ) -> Dict[str, Any]:
        """Check current path integrity against a backup or digest."""
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id,
        )

        if not context_result["success"]:
            return context_result

        resolved_result = self._resolve_tenant_path(
            user_id=user_id,
            workspace_id=workspace_id,
            requested_path=path,
            must_exist=True,
        )

        if not resolved_result["success"]:
            return resolved_result

        absolute_path = Path(resolved_result["data"]["absolute_path"])
        relative_path = resolved_result["data"]["relative_path"]

        comparison_digest = expected_digest
        comparison_source = "provided_digest"

        if backup_id:
            manifest = self._load_backup_manifest(
                user_id=user_id,
                workspace_id=workspace_id,
                backup_id=backup_id,
            )

            if manifest is None:
                return self._error_result(
                    message="Backup manifest not found.",
                    error="BACKUP_NOT_FOUND",
                    metadata={"backup_id": backup_id},
                )

            comparison_digest = manifest.source_digest
            comparison_source = "backup_manifest"

        entries = self._build_source_manifest(absolute_path)
        current_digest = _directory_tree_digest(entries)

        matches = (
            current_digest == comparison_digest
            if comparison_digest
            else None
        )

        return self._safe_result(
            message="Path integrity check completed.",
            data={
                "path": relative_path,
                "current_digest": current_digest,
                "expected_digest": comparison_digest,
                "comparison_source": comparison_source,
                "matches": matches,
                "file_count": len(
                    [
                        entry
                        for entry in entries
                        if entry.get("type") == "file"
                    ]
                ),
            },
            metadata={
                "verification": self._prepare_verification_payload(
                    action=FileAction.CHECK_INTEGRITY.value,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    path=relative_path,
                    expected_digest=comparison_digest,
                ),
            },
        )

    # =========================================================================
    # Required compatibility hooks
    # =========================================================================

    def _validate_task_context(
        self,
        user_id: Optional[str],
        workspace_id: Optional[str],
        actor_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Validate user/workspace isolation context.

        No user-specific filesystem action may proceed without this context.
        """
        safe_user_id = _normalize_identifier(user_id)
        safe_workspace_id = _normalize_identifier(workspace_id)
        safe_actor_id = _normalize_identifier(actor_id or user_id)

        if not safe_user_id:
            return self._error_result(
                message="user_id is required for filesystem isolation.",
                error="MISSING_USER_ID",
            )

        if not safe_workspace_id:
            return self._error_result(
                message="workspace_id is required for filesystem isolation.",
                error="MISSING_WORKSPACE_ID",
            )

        if not safe_actor_id:
            return self._error_result(
                message="actor_id is required for security auditing.",
                error="MISSING_ACTOR_ID",
            )

        tenant_root = self._tenant_root(
            safe_user_id,
            safe_workspace_id,
        )
        tenant_root.mkdir(parents=True, exist_ok=True)

        permission_result = self._check_context_permission(
            user_id=safe_user_id,
            workspace_id=safe_workspace_id,
            actor_id=safe_actor_id,
        )

        if not permission_result["success"]:
            return permission_result

        return self._safe_result(
            message="Task context validated.",
            data={
                "user_id": safe_user_id,
                "workspace_id": safe_workspace_id,
                "actor_id": safe_actor_id,
                "tenant_root": str(tenant_root),
            },
        )

    def _requires_security_check(
        self,
        action: Union[str, FileAction],
        risk_level: Optional[FileRiskLevel] = None,
        protected: bool = False,
    ) -> bool:
        """Determine whether an operation requires Security Agent approval."""
        action_value = (
            action.value
            if isinstance(action, FileAction)
            else str(action).strip().lower()
        )

        sensitive_actions = {
            FileAction.UNPROTECT.value,
            FileAction.DELETE.value,
            FileAction.PERMANENT_DELETE.value,
            FileAction.OVERWRITE.value,
            FileAction.MOVE.value,
            FileAction.RENAME.value,
            FileAction.MODIFY.value,
            FileAction.RESTORE_BACKUP.value,
            FileAction.RESTORE_QUARANTINE.value,
            "restore_backup_overwrite",
            "restore_quarantine_overwrite",
        }

        if action_value == FileAction.PERMANENT_DELETE.value:
            return True

        if protected:
            return True

        if risk_level in {
            FileRiskLevel.HIGH,
            FileRiskLevel.CRITICAL,
        }:
            return True

        return action_value in sensitive_actions

    def _request_security_approval(
        self,
        action: str,
        user_id: str,
        workspace_id: str,
        actor_id: str,
        resource_id: str,
        reason: str,
        approval_context: Optional[Mapping[str, Any]] = None,
        risk_level: FileRiskLevel = FileRiskLevel.HIGH,
    ) -> Dict[str, Any]:
        """
        Request approval through Security Agent or Approval Manager.

        Safe fallback:
            No approval is automatically granted for destructive operations.
            The caller must provide approval_context={"approved": True, ...}
            when Security Agent modules are not available.
        """
        context = _safe_metadata(approval_context)

        if context.get("approved") is True:
            approved_by = _normalize_identifier(
                context.get("approved_by") or actor_id
            )
            approval_id = _normalize_identifier(
                context.get("approval_id") or _new_id("approval")
            )

            return self._safe_result(
                message="Security approval accepted from approval context.",
                data={
                    "approved": True,
                    "approval_id": approval_id,
                    "approved_by": approved_by,
                    "source": "approval_context",
                    "action": action,
                    "risk_level": risk_level.value,
                },
            )

        approval_payload = {
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "actor_id": actor_id,
            "resource_id": resource_id,
            "reason": reason,
            "risk_level": risk_level.value,
            "context": context,
            "requested_at": _utc_now(),
        }

        integration_candidates: List[Tuple[Any, Sequence[str], str]] = [
            (
                self.approval_manager,
                (
                    "request_approval",
                    "approve_action",
                    "check_approval",
                ),
                "approval_manager",
            ),
            (
                self.security_agent,
                (
                    "request_approval",
                    "approve_action",
                    "authorize_action",
                    "check_action",
                ),
                "security_agent",
            ),
        ]

        for integration, method_names, source_name in integration_candidates:
            if integration is None:
                continue

            for method_name in method_names:
                method = getattr(integration, method_name, None)

                if not callable(method):
                    continue

                try:
                    response = _call_maybe_async(
                        method,
                        **approval_payload,
                    )

                    if isinstance(response, bool):
                        approved = response
                        response_data: Dict[str, Any] = {
                            "approved": approved
                        }
                    elif isinstance(response, dict):
                        approved = bool(
                            response.get("approved")
                            or (
                                response.get("success")
                                and response.get(
                                    "data",
                                    {},
                                ).get("approved")
                            )
                        )
                        response_data = _json_safe(response)
                    else:
                        approved = False
                        response_data = {
                            "raw_response": str(response)
                        }

                    if approved:
                        return self._safe_result(
                            message="Security Agent approved the action.",
                            data={
                                "approved": True,
                                "source": source_name,
                                "response": response_data,
                            },
                        )

                    return self._error_result(
                        message="Security Agent did not approve the action.",
                        error="SECURITY_APPROVAL_DENIED",
                        metadata={
                            "source": source_name,
                            "response": response_data,
                            "request": approval_payload,
                        },
                    )

                except Exception as exc:
                    self.logger.warning(
                        "Security approval integration failed: %s.%s: %s",
                        source_name,
                        method_name,
                        exc,
                    )

        return self._error_result(
            message=(
                "Security approval is required. No approving Security Agent "
                "or approved approval_context was available."
            ),
            error="SECURITY_APPROVAL_REQUIRED",
            metadata={
                "request": approval_payload,
                "approval_context_example": {
                    "approved": True,
                    "approval_id": "approval_reference",
                    "approved_by": actor_id,
                },
            },
        )

    def _prepare_verification_payload(
        self,
        action: str,
        **context: Any,
    ) -> Dict[str, Any]:
        """Prepare a Verification Agent compatible payload."""
        return {
            "source_agent": self.agent_name,
            "source_module": self.module_name,
            "registry_key": self.registry_key,
            "action": action,
            "timestamp": _utc_now(),
            "verification_type": "filesystem_security",
            "checks": {
                "tenant_isolation_required": True,
                "path_boundary_validation_required": True,
                "backup_verification_supported": True,
                "structured_result_expected": True,
            },
            "context": _json_safe(context),
        }

    def _prepare_memory_payload(
        self,
        action: str,
        user_id: str,
        workspace_id: str,
        resource: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Prepare Memory Agent compatible context."""
        return {
            "source_agent": self.agent_name,
            "source_module": self.module_name,
            "memory_type": "security_file_protection_event",
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "timestamp": _utc_now(),
            "privacy_level": "restricted",
            "retention_hint": "security_audit",
            "resource": _json_safe(resource),
        }

    def _emit_agent_event(
        self,
        event_type: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """Emit an event to the future William event bus."""
        event = {
            "event_id": _new_id("event"),
            "event_type": event_type,
            "agent": self.agent_name,
            "module": self.module_name,
            "timestamp": _utc_now(),
            "payload": _json_safe(payload or {}),
        }

        if callable(self.event_emitter):
            try:
                _call_maybe_async(self.event_emitter, event)
                return
            except Exception as exc:
                self.logger.warning(
                    "FileProtection event emitter failed: %s",
                    exc,
                )

        self.logger.debug(
            "AGENT_EVENT %s",
            json.dumps(event, default=str),
        )

    def _log_audit_event(
        self,
        action: str,
        user_id: str,
        workspace_id: str,
        actor_id: str,
        resource_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """Record a structured audit event."""
        event = {
            "audit_id": _new_id("audit"),
            "agent": self.agent_name,
            "module": self.module_name,
            "action": action,
            "user_id": _normalize_identifier(user_id),
            "workspace_id": _normalize_identifier(workspace_id),
            "actor_id": _normalize_identifier(actor_id),
            "resource_id": (
                _normalize_identifier(resource_id, MAX_PATH_LENGTH)
                if resource_id
                else None
            ),
            "metadata": _safe_metadata(metadata),
            "timestamp": _utc_now(),
        }

        if self.audit_logger is not None:
            for method_name in (
                "log_event",
                "write",
                "record",
                "log_audit_event",
            ):
                method = getattr(self.audit_logger, method_name, None)

                if callable(method):
                    try:
                        _call_maybe_async(method, event)
                        return
                    except Exception as exc:
                        self.logger.warning(
                            "Audit logger failed via %s: %s",
                            method_name,
                            exc,
                        )

        self.logger.info(
            "AUDIT %s",
            json.dumps(event, default=str),
        )

    def _safe_result(
        self,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return a standard successful result."""
        return {
            "success": True,
            "message": message,
            "data": _json_safe(data or {}),
            "error": None,
            "metadata": _json_safe(metadata or {}),
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Union[str, Exception]] = None,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return a standard failed result."""
        return {
            "success": False,
            "message": message,
            "data": _json_safe(data or {}),
            "error": (
                str(error)
                if error is not None
                else message
            ),
            "metadata": _json_safe(metadata or {}),
        }

    # =========================================================================
    # Internal permission and path security
    # =========================================================================

    def _check_context_permission(
        self,
        user_id: str,
        workspace_id: str,
        actor_id: str,
    ) -> Dict[str, Any]:
        """Validate actor access through optional PermissionChecker."""
        if self.permission_checker is None:
            return self._safe_result(
                message="Permission fallback accepted tenant context.",
                data={
                    "allowed": True,
                    "source": "context_isolation_fallback",
                },
            )

        method_candidates = (
            "check_permission",
            "has_permission",
            "authorize",
            "can_access_workspace",
        )

        for method_name in method_candidates:
            method = getattr(
                self.permission_checker,
                method_name,
                None,
            )

            if not callable(method):
                continue

            try:
                response = _call_maybe_async(
                    method,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    actor_id=actor_id,
                    permission="files.protect",
                    resource="workspace_files",
                )

                if isinstance(response, bool):
                    allowed = response
                elif isinstance(response, dict):
                    allowed = bool(
                        response.get("allowed")
                        or response.get("approved")
                        or response.get("success")
                    )
                else:
                    allowed = False

                if allowed:
                    return self._safe_result(
                        message="Workspace file permission approved.",
                        data={
                            "allowed": True,
                            "source": method_name,
                        },
                    )

                return self._error_result(
                    message="Actor lacks workspace file protection permission.",
                    error="PERMISSION_DENIED",
                    metadata={
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                        "actor_id": actor_id,
                    },
                )

            except Exception as exc:
                self.logger.warning(
                    "Permission checker failed via %s: %s",
                    method_name,
                    exc,
                )

        return self._error_result(
            message="Permission checker could not validate access.",
            error="PERMISSION_VALIDATION_FAILED",
        )

    def _resolve_tenant_path(
        self,
        user_id: str,
        workspace_id: str,
        requested_path: Union[str, Path],
        must_exist: bool,
    ) -> Dict[str, Any]:
        """
        Resolve a path inside the tenant root.

        Absolute paths are accepted only when already inside the tenant root.
        Relative paths are resolved beneath the tenant root.
        """
        if requested_path is None:
            return self._error_result(
                message="A file or directory path is required.",
                error="MISSING_PATH",
            )

        raw_path = str(requested_path).replace("\x00", "").strip()

        if not raw_path:
            return self._error_result(
                message="A non-empty path is required.",
                error="EMPTY_PATH",
            )

        if len(raw_path) > MAX_PATH_LENGTH:
            return self._error_result(
                message="Path exceeds the maximum allowed length.",
                error="PATH_TOO_LONG",
            )

        tenant_root = self._tenant_root(
            user_id,
            workspace_id,
        ).resolve(strict=False)

        candidate = Path(raw_path).expanduser()

        if candidate.is_absolute():
            resolved = candidate.resolve(strict=False)
        else:
            resolved = (tenant_root / candidate).resolve(strict=False)

        if not _is_relative_to(resolved, tenant_root):
            return self._error_result(
                message="Path is outside the tenant workspace boundary.",
                error="PATH_OUTSIDE_TENANT_ROOT",
                metadata={
                    "requested_path": raw_path,
                    "tenant_root": str(tenant_root),
                },
            )

        relative = resolved.relative_to(tenant_root)

        for part in relative.parts:
            if part in FORBIDDEN_PATH_PARTS:
                return self._error_result(
                    message="Unsafe path component detected.",
                    error="UNSAFE_PATH_COMPONENT",
                    metadata={"component": part},
                )

        if must_exist and not (
            resolved.exists() or resolved.is_symlink()
        ):
            return self._error_result(
                message="Requested path does not exist.",
                error="PATH_NOT_FOUND",
                metadata={"path": str(relative)},
            )

        if resolved.is_symlink() and not self.config.allow_symlinks:
            return self._error_result(
                message="Symlink access is disabled by file protection policy.",
                error="SYMLINK_NOT_ALLOWED",
                metadata={"path": str(relative)},
            )

        return self._safe_result(
            message="Tenant path resolved safely.",
            data={
                "absolute_path": str(resolved),
                "relative_path": (
                    "."
                    if str(relative) == "."
                    else relative.as_posix()
                ),
                "tenant_root": str(tenant_root),
            },
        )

    def _tenant_root(
        self,
        user_id: str,
        workspace_id: str,
    ) -> Path:
        """Return isolated tenant filesystem root."""
        safe_user = _normalize_identifier(user_id)
        safe_workspace = _normalize_identifier(workspace_id)

        if not safe_user or not safe_workspace:
            raise ValueError(
                "user_id and workspace_id are required."
            )

        return (
            Path(self.config.tenant_root)
            / safe_user
            / safe_workspace
        )

    # =========================================================================
    # Internal risk and protection evaluation
    # =========================================================================

    def _build_risk_assessment(
        self,
        user_id: str,
        workspace_id: str,
        path: Path,
        relative_path: str,
        action: FileAction,
        destination_path: Optional[Path] = None,
    ) -> FileRiskAssessment:
        """Build a complete filesystem risk assessment."""
        exists = path.exists() or path.is_symlink()
        is_file = path.is_file() if exists else False
        is_directory = path.is_dir() if exists else False
        is_symlink = path.is_symlink()

        size_bytes = 0
        file_count = 0

        if exists:
            try:
                size_bytes, file_count = self._calculate_path_metrics(path)
            except OSError:
                pass

        protection = self._evaluate_protection(
            user_id=user_id,
            workspace_id=workspace_id,
            absolute_path=path,
        )

        protected = bool(protection["protected"])
        protection_mode = (
            ProtectionMode(protection["mode"])
            if protection.get("mode")
            else None
        )

        destructive_actions = {
            FileAction.DELETE,
            FileAction.PERMANENT_DELETE,
            FileAction.OVERWRITE,
            FileAction.MOVE,
            FileAction.RENAME,
            FileAction.MODIFY,
        }

        destructive = action in destructive_actions
        reasons: List[str] = []
        backup_required = False
        approval_required = False
        risk_level = FileRiskLevel.LOW

        if destructive:
            risk_level = FileRiskLevel.MEDIUM
            reasons.append("The requested action can change or remove data.")

        if action == FileAction.DELETE:
            backup_required = self.config.backup_before_delete
            reasons.append(
                "Deletion can make the original path unavailable."
            )

        elif action == FileAction.PERMANENT_DELETE:
            backup_required = True
            approval_required = True
            risk_level = FileRiskLevel.CRITICAL
            reasons.append(
                "Permanent deletion bypasses quarantine and is irreversible."
            )

        elif action == FileAction.OVERWRITE:
            backup_required = self.config.backup_before_overwrite
            reasons.append(
                "Overwrite can destroy the current version."
            )

        elif action == FileAction.MOVE:
            backup_required = self.config.backup_before_move
            reasons.append(
                "Move can make the original location unavailable."
            )

        elif action == FileAction.RENAME:
            backup_required = self.config.backup_before_rename
            reasons.append(
                "Rename can break references to the original path."
            )

        elif action == FileAction.MODIFY:
            backup_required = self.config.backup_before_modify

        if protected:
            risk_level = max(
                risk_level,
                FileRiskLevel.HIGH,
                key=self._risk_rank,
            )
            reasons.append(
                "The path matches an active protection policy."
            )

        if protection_mode == ProtectionMode.BACKUP_REQUIRED:
            backup_required = True

        elif protection_mode == ProtectionMode.APPROVAL_REQUIRED:
            backup_required = True
            approval_required = True

        elif protection_mode == ProtectionMode.LOCKED:
            backup_required = True
            approval_required = True
            risk_level = FileRiskLevel.CRITICAL
            reasons.append(
                "The path is locked by protection policy."
            )

        if is_directory and file_count > 100:
            risk_level = max(
                risk_level,
                FileRiskLevel.HIGH,
                key=self._risk_rank,
            )
            reasons.append(
                "The directory contains many files."
            )

        if size_bytes > 1024 * 1024 * 1024:
            risk_level = max(
                risk_level,
                FileRiskLevel.HIGH,
                key=self._risk_rank,
            )
            reasons.append(
                "The path contains more than 1 GiB of data."
            )

        if path.name in COMMON_HIGH_RISK_NAMES:
            risk_level = max(
                risk_level,
                FileRiskLevel.HIGH,
                key=self._risk_rank,
            )
            backup_required = True
            reasons.append(
                "The path name is classified as operationally sensitive."
            )

        if is_symlink:
            risk_level = FileRiskLevel.CRITICAL
            approval_required = True
            reasons.append(
                "Symlink operations can affect unexpected filesystem targets."
            )

        if destination_path is not None and destination_path.exists():
            backup_required = True
            approval_required = True
            risk_level = max(
                risk_level,
                FileRiskLevel.HIGH,
                key=self._risk_rank,
            )
            reasons.append(
                "The destination exists and may be overwritten."
            )

        if self._requires_security_check(
            action=action,
            risk_level=risk_level,
            protected=protected,
        ):
            approval_required = True

        return FileRiskAssessment(
            action=action,
            risk_level=risk_level,
            path=relative_path,
            exists=exists,
            is_file=is_file,
            is_directory=is_directory,
            is_symlink=is_symlink,
            protected=protected,
            protection_mode=protection_mode,
            backup_required=backup_required and exists,
            approval_required=approval_required,
            destructive=destructive,
            reasons=reasons,
            matched_rule_ids=protection["matched_rule_ids"],
            size_bytes=size_bytes,
            file_count=file_count,
        )

    def _evaluate_protection(
        self,
        user_id: str,
        workspace_id: str,
        absolute_path: Path,
    ) -> Dict[str, Any]:
        """Evaluate tenant rules and default protected globs."""
        tenant_root = self._tenant_root(
            user_id,
            workspace_id,
        ).resolve(strict=False)

        resolved = absolute_path.resolve(strict=False)

        if not _is_relative_to(resolved, tenant_root):
            return {
                "protected": True,
                "mode": ProtectionMode.LOCKED.value,
                "matched_rule_ids": [],
                "matched_sources": ["outside_tenant_root"],
            }

        relative = resolved.relative_to(tenant_root)
        relative_posix = (
            "."
            if str(relative) == "."
            else relative.as_posix()
        )

        matched_rules: List[ProtectedPathRule] = []

        for rule in self._load_rules(user_id, workspace_id):
            if not rule.enabled:
                continue

            rule_path = Path(rule.relative_path)

            if relative == rule_path:
                matched_rules.append(rule)
                continue

            if rule.recursive:
                try:
                    relative.relative_to(rule_path)
                    matched_rules.append(rule)
                except ValueError:
                    pass

        matched_sources: List[str] = []
        effective_mode: Optional[ProtectionMode] = None

        if matched_rules:
            effective_mode = max(
                (rule.mode for rule in matched_rules),
                key=self._protection_rank,
            )
            matched_sources.append("tenant_rule")

        for pattern in self.config.protected_globs:
            if Path(relative_posix).match(pattern):
                matched_sources.append(f"default_glob:{pattern}")

                default_mode = self.config.default_protection_mode

                if (
                    effective_mode is None
                    or self._protection_rank(default_mode)
                    > self._protection_rank(effective_mode)
                ):
                    effective_mode = default_mode

        if absolute_path.name in COMMON_HIGH_RISK_NAMES:
            matched_sources.append("high_risk_name")

            if effective_mode is None:
                effective_mode = ProtectionMode.BACKUP_REQUIRED

        return {
            "protected": effective_mode is not None,
            "mode": (
                effective_mode.value
                if effective_mode is not None
                else None
            ),
            "matched_rule_ids": [
                rule.rule_id for rule in matched_rules
            ],
            "matched_sources": matched_sources,
        }

    @staticmethod
    def _risk_rank(level: FileRiskLevel) -> int:
        """Return sortable risk level rank."""
        return {
            FileRiskLevel.LOW: 1,
            FileRiskLevel.MEDIUM: 2,
            FileRiskLevel.HIGH: 3,
            FileRiskLevel.CRITICAL: 4,
        }[level]

    @staticmethod
    def _protection_rank(mode: ProtectionMode) -> int:
        """Return sortable protection mode rank."""
        return {
            ProtectionMode.MONITOR: 1,
            ProtectionMode.BACKUP_REQUIRED: 2,
            ProtectionMode.APPROVAL_REQUIRED: 3,
            ProtectionMode.LOCKED: 4,
        }[mode]

    # =========================================================================
    # Internal storage paths
    # =========================================================================

    def _ensure_storage_directories(self) -> None:
        """Create required non-tenant storage directories."""
        for directory in (
            self.config.tenant_root,
            self.config.protection_root,
            self.config.backup_root,
            self.config.quarantine_root,
            self.config.policy_root,
            self.config.manifest_root,
        ):
            Path(directory).mkdir(parents=True, exist_ok=True)

    def _tenant_backup_root(
        self,
        user_id: str,
        workspace_id: str,
    ) -> Path:
        """Return tenant backup root."""
        return (
            Path(self.config.backup_root)
            / _normalize_identifier(user_id)
            / _normalize_identifier(workspace_id)
        )

    def _tenant_quarantine_root(
        self,
        user_id: str,
        workspace_id: str,
    ) -> Path:
        """Return tenant quarantine root."""
        return (
            Path(self.config.quarantine_root)
            / _normalize_identifier(user_id)
            / _normalize_identifier(workspace_id)
        )

    def _tenant_manifest_root(
        self,
        user_id: str,
        workspace_id: str,
    ) -> Path:
        """Return tenant backup manifest root."""
        return (
            Path(self.config.manifest_root)
            / _normalize_identifier(user_id)
            / _normalize_identifier(workspace_id)
            / "backups"
        )

    def _tenant_quarantine_manifest_root(
        self,
        user_id: str,
        workspace_id: str,
    ) -> Path:
        """Return tenant quarantine manifest root."""
        return (
            Path(self.config.manifest_root)
            / _normalize_identifier(user_id)
            / _normalize_identifier(workspace_id)
            / "quarantine"
        )

    def _tenant_preparation_root(
        self,
        user_id: str,
        workspace_id: str,
    ) -> Path:
        """Return tenant risky-action preparation root."""
        return (
            Path(self.config.manifest_root)
            / _normalize_identifier(user_id)
            / _normalize_identifier(workspace_id)
            / "preparations"
        )

    def _policy_file(
        self,
        user_id: str,
        workspace_id: str,
    ) -> Path:
        """Return tenant protection policy file."""
        return (
            Path(self.config.policy_root)
            / _normalize_identifier(user_id)
            / f"{_normalize_identifier(workspace_id)}.json"
        )

    # =========================================================================
    # Internal rule persistence
    # =========================================================================

    def _load_rules(
        self,
        user_id: str,
        workspace_id: str,
    ) -> List[ProtectedPathRule]:
        """Load tenant protection rules."""
        payload = _read_json(
            self._policy_file(user_id, workspace_id),
            default={},
        )

        raw_rules = payload.get("rules", []) if isinstance(payload, dict) else []
        rules: List[ProtectedPathRule] = []

        for raw_rule in raw_rules:
            if not isinstance(raw_rule, dict):
                continue

            rule = ProtectedPathRule.from_dict(raw_rule)

            if (
                rule.user_id == _normalize_identifier(user_id)
                and rule.workspace_id
                == _normalize_identifier(workspace_id)
            ):
                rules.append(rule)

        return rules

    def _save_rules(
        self,
        user_id: str,
        workspace_id: str,
        rules: Sequence[ProtectedPathRule],
    ) -> None:
        """Persist tenant protection rules atomically."""
        payload = {
            "schema_version": SCHEMA_VERSION,
            "user_id": _normalize_identifier(user_id),
            "workspace_id": _normalize_identifier(workspace_id),
            "updated_at": _utc_now(),
            "rules": [rule.to_dict() for rule in rules],
        }

        with self._lock:
            _write_json_atomic(
                self._policy_file(user_id, workspace_id),
                payload,
            )

    # =========================================================================
    # Internal backup persistence
    # =========================================================================

    def _save_backup_manifest(
        self,
        manifest: BackupManifest,
    ) -> None:
        """Persist backup manifest."""
        manifest_root = self._tenant_manifest_root(
            manifest.user_id,
            manifest.workspace_id,
        )
        manifest_root.mkdir(parents=True, exist_ok=True)

        manifest_file = manifest_root / f"{manifest.backup_id}.json"

        with self._lock:
            _write_json_atomic(
                manifest_file,
                {
                    "schema_version": SCHEMA_VERSION,
                    "manifest": manifest.to_dict(),
                },
            )

    def _load_backup_manifest(
        self,
        user_id: str,
        workspace_id: str,
        backup_id: str,
    ) -> Optional[BackupManifest]:
        """Load one tenant backup manifest."""
        safe_backup_id = _normalize_identifier(backup_id)
        manifest_file = (
            self._tenant_manifest_root(user_id, workspace_id)
            / f"{safe_backup_id}.json"
        )

        payload = _read_json(manifest_file, default={})

        if not isinstance(payload, dict):
            return None

        raw_manifest = payload.get("manifest")

        if not isinstance(raw_manifest, dict):
            return None

        manifest = BackupManifest.from_dict(raw_manifest)

        if (
            manifest.user_id != _normalize_identifier(user_id)
            or manifest.workspace_id
            != _normalize_identifier(workspace_id)
        ):
            return None

        return manifest

    def _load_all_backup_manifests(
        self,
        user_id: str,
        workspace_id: str,
    ) -> List[BackupManifest]:
        """Load all tenant backup manifests."""
        root = self._tenant_manifest_root(
            user_id,
            workspace_id,
        )

        if not root.exists():
            return []

        manifests: List[BackupManifest] = []

        for manifest_file in root.glob("*.json"):
            payload = _read_json(manifest_file, default={})

            if not isinstance(payload, dict):
                continue

            raw_manifest = payload.get("manifest")

            if not isinstance(raw_manifest, dict):
                continue

            manifest = BackupManifest.from_dict(raw_manifest)

            if (
                manifest.user_id == _normalize_identifier(user_id)
                and manifest.workspace_id
                == _normalize_identifier(workspace_id)
            ):
                manifests.append(manifest)

        return manifests

    # =========================================================================
    # Internal quarantine persistence
    # =========================================================================

    def _save_quarantine_record(
        self,
        record: QuarantineRecord,
    ) -> None:
        """Persist quarantine record."""
        root = self._tenant_quarantine_manifest_root(
            record.user_id,
            record.workspace_id,
        )
        root.mkdir(parents=True, exist_ok=True)

        with self._lock:
            _write_json_atomic(
                root / f"{record.quarantine_id}.json",
                {
                    "schema_version": SCHEMA_VERSION,
                    "record": record.to_dict(),
                },
            )

    def _load_quarantine_record(
        self,
        user_id: str,
        workspace_id: str,
        quarantine_id: str,
    ) -> Optional[QuarantineRecord]:
        """Load one quarantine record."""
        safe_id = _normalize_identifier(quarantine_id)
        path = (
            self._tenant_quarantine_manifest_root(
                user_id,
                workspace_id,
            )
            / f"{safe_id}.json"
        )

        payload = _read_json(path, default={})

        if not isinstance(payload, dict):
            return None

        raw_record = payload.get("record")

        if not isinstance(raw_record, dict):
            return None

        record = QuarantineRecord.from_dict(raw_record)

        if (
            record.user_id != _normalize_identifier(user_id)
            or record.workspace_id
            != _normalize_identifier(workspace_id)
        ):
            return None

        return record

    def _load_quarantine_records(
        self,
        user_id: str,
        workspace_id: str,
    ) -> List[QuarantineRecord]:
        """Load all tenant quarantine records."""
        root = self._tenant_quarantine_manifest_root(
            user_id,
            workspace_id,
        )

        if not root.exists():
            return []

        records: List[QuarantineRecord] = []

        for manifest_file in root.glob("*.json"):
            payload = _read_json(manifest_file, default={})

            if not isinstance(payload, dict):
                continue

            raw_record = payload.get("record")

            if not isinstance(raw_record, dict):
                continue

            record = QuarantineRecord.from_dict(raw_record)

            if (
                record.user_id == _normalize_identifier(user_id)
                and record.workspace_id
                == _normalize_identifier(workspace_id)
            ):
                records.append(record)

        return records

    def _delete_quarantine_record(
        self,
        user_id: str,
        workspace_id: str,
        quarantine_id: str,
    ) -> None:
        """Delete quarantine manifest after successful restoration."""
        path = (
            self._tenant_quarantine_manifest_root(
                user_id,
                workspace_id,
            )
            / f"{_normalize_identifier(quarantine_id)}.json"
        )

        if path.exists():
            path.unlink()

    def _save_preparation(
        self,
        user_id: str,
        workspace_id: str,
        payload: Mapping[str, Any],
    ) -> None:
        """Store a risky-action preparation record."""
        preparation_id = _normalize_identifier(
            payload.get("preparation_id")
        )
        root = self._tenant_preparation_root(
            user_id,
            workspace_id,
        )
        root.mkdir(parents=True, exist_ok=True)

        with self._lock:
            _write_json_atomic(
                root / f"{preparation_id}.json",
                {
                    "schema_version": SCHEMA_VERSION,
                    "preparation": _json_safe(payload),
                },
            )

    # =========================================================================
    # Internal backup implementation
    # =========================================================================

    def _calculate_path_metrics(
        self,
        path: Path,
    ) -> Tuple[int, int]:
        """Calculate total bytes and file count."""
        if path.is_symlink():
            return path.lstat().st_size, 1

        if path.is_file():
            return path.stat().st_size, 1

        total_size = 0
        file_count = 0

        for root, directories, files in os.walk(
            path,
            followlinks=False,
        ):
            root_path = Path(root)

            for directory_name in list(directories):
                directory_path = root_path / directory_name

                if directory_path.is_symlink():
                    if not self.config.allow_symlinks:
                        directories.remove(directory_name)
                        continue

            for file_name in files:
                file_path = root_path / file_name

                if file_path.is_symlink() and not self.config.allow_symlinks:
                    continue

                try:
                    total_size += file_path.lstat().st_size
                    file_count += 1
                except OSError:
                    continue

                if file_count > self.config.max_backup_file_count:
                    break

            if file_count > self.config.max_backup_file_count:
                break

        return total_size, file_count

    def _build_source_manifest(
        self,
        path: Path,
    ) -> List[Dict[str, Any]]:
        """Build deterministic source manifest with hashes."""
        entries: List[Dict[str, Any]] = []

        if path.is_symlink():
            entries.append(
                {
                    "relative_path": path.name,
                    "type": "symlink",
                    "target": os.readlink(path),
                }
            )
            return entries

        if path.is_file():
            stats = path.stat()
            entries.append(
                {
                    "relative_path": path.name,
                    "type": "file",
                    "size_bytes": stats.st_size,
                    "sha256": _file_sha256(path),
                }
            )
            return entries

        entries.append(
            {
                "relative_path": ".",
                "type": "directory",
            }
        )

        for item in sorted(
            path.rglob("*"),
            key=lambda child: child.as_posix(),
        ):
            relative = item.relative_to(path).as_posix()

            if item.is_symlink():
                if not self.config.allow_symlinks:
                    continue

                entries.append(
                    {
                        "relative_path": relative,
                        "type": "symlink",
                        "target": os.readlink(item),
                    }
                )

            elif item.is_dir():
                entries.append(
                    {
                        "relative_path": relative,
                        "type": "directory",
                    }
                )

            elif item.is_file():
                stats = item.stat()
                entries.append(
                    {
                        "relative_path": relative,
                        "type": "file",
                        "size_bytes": stats.st_size,
                        "sha256": _file_sha256(item),
                    }
                )

            if len(entries) > self.config.max_backup_file_count + 1:
                raise ValueError(
                    "Source manifest exceeds configured file count limit."
                )

        return entries

    def _create_zip_backup(
        self,
        source_path: Path,
        destination: Path,
    ) -> None:
        """Create ZIP backup safely."""
        destination.parent.mkdir(parents=True, exist_ok=True)

        compression = zipfile.ZIP_DEFLATED

        with zipfile.ZipFile(
            destination,
            mode="w",
            compression=compression,
            allowZip64=True,
        ) as archive:
            if source_path.is_file():
                archive.write(
                    source_path,
                    arcname=source_path.name,
                )
                return

            root_name = source_path.name or "root"

            for item in sorted(
                source_path.rglob("*"),
                key=lambda child: child.as_posix(),
            ):
                if item.is_symlink() and not self.config.allow_symlinks:
                    continue

                relative = item.relative_to(source_path)
                archive_name = Path(root_name) / relative

                if item.is_dir():
                    archive.writestr(
                        archive_name.as_posix().rstrip("/") + "/",
                        "",
                    )
                elif item.is_file():
                    archive.write(
                        item,
                        arcname=archive_name.as_posix(),
                    )

    def _create_copy_backup(
        self,
        source_path: Path,
        destination: Path,
    ) -> None:
        """Create direct-copy backup."""
        destination.parent.mkdir(parents=True, exist_ok=True)

        if source_path.is_dir():
            shutil.copytree(
                source_path,
                destination,
                symlinks=self.config.allow_symlinks,
                copy_function=(
                    shutil.copy2
                    if self.config.preserve_file_metadata
                    else shutil.copy
                ),
            )
        else:
            copy_function = (
                shutil.copy2
                if self.config.preserve_file_metadata
                else shutil.copy
            )
            copy_function(source_path, destination)

    def _calculate_backup_digest(
        self,
        backup_path: Path,
        backup_format: BackupFormat,
    ) -> str:
        """Calculate deterministic backup digest."""
        if backup_format == BackupFormat.ZIP:
            return _file_sha256(backup_path)

        entries = self._build_source_manifest(backup_path)
        return _directory_tree_digest(entries)

    def _restore_zip_backup(
        self,
        archive_path: Path,
        destination: Path,
        source_type: str,
    ) -> None:
        """Restore ZIP backup with path traversal protection."""
        with tempfile.TemporaryDirectory(
            prefix="william_restore_"
        ) as temporary_directory:
            temporary_root = Path(temporary_directory)

            with zipfile.ZipFile(archive_path, "r") as archive:
                for member in archive.infolist():
                    member_path = (
                        temporary_root / member.filename
                    ).resolve(strict=False)

                    if not _is_relative_to(
                        member_path,
                        temporary_root.resolve(strict=False),
                    ):
                        raise ValueError(
                            "Unsafe archive member path detected."
                        )

                archive.extractall(temporary_root)

            extracted_items = list(temporary_root.iterdir())

            if source_type == "file":
                files = [
                    item
                    for item in temporary_root.rglob("*")
                    if item.is_file()
                ]

                if len(files) != 1:
                    raise ValueError(
                        "File backup archive contains an unexpected structure."
                    )

                destination.parent.mkdir(
                    parents=True,
                    exist_ok=True,
                )
                shutil.copy2(files[0], destination)
                return

            if len(extracted_items) == 1 and extracted_items[0].is_dir():
                shutil.copytree(
                    extracted_items[0],
                    destination,
                    copy_function=shutil.copy2,
                )
            else:
                destination.mkdir(parents=True, exist_ok=True)

                for item in extracted_items:
                    target = destination / item.name

                    if item.is_dir():
                        shutil.copytree(
                            item,
                            target,
                            copy_function=shutil.copy2,
                        )
                    else:
                        shutil.copy2(item, target)

    def _restore_copy_backup(
        self,
        backup_path: Path,
        destination: Path,
    ) -> None:
        """Restore direct-copy backup."""
        if backup_path.is_dir():
            shutil.copytree(
                backup_path,
                destination,
                copy_function=shutil.copy2,
            )
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(backup_path, destination)

    # =========================================================================
    # Internal quarantine and deletion implementation
    # =========================================================================

    def _move_to_quarantine(
        self,
        user_id: str,
        workspace_id: str,
        source_path: Path,
        relative_path: str,
        backup_id: Optional[str],
        reason: str,
        actor_id: str,
        source_type: str,
        size_bytes: int,
        file_count: int,
        metadata: Optional[Mapping[str, Any]],
    ) -> QuarantineRecord:
        """Move a path into isolated tenant quarantine."""
        quarantine_id = _new_id("quarantine")
        tenant_quarantine_root = self._tenant_quarantine_root(
            user_id,
            workspace_id,
        )
        tenant_quarantine_root.mkdir(
            parents=True,
            exist_ok=True,
        )

        timestamp = datetime.now(timezone.utc).strftime(
            "%Y%m%dT%H%M%S%fZ"
        )
        safe_name = self._safe_backup_name(
            source_path.name or "resource"
        )
        quarantine_path = tenant_quarantine_root / (
            f"{timestamp}_{quarantine_id}_{safe_name}"
        )

        shutil.move(
            str(source_path),
            str(quarantine_path),
        )

        record = QuarantineRecord(
            quarantine_id=quarantine_id,
            user_id=_normalize_identifier(user_id),
            workspace_id=_normalize_identifier(workspace_id),
            original_relative_path=relative_path,
            original_absolute_path=str(source_path),
            quarantine_path=str(quarantine_path),
            backup_id=backup_id,
            action_reason=reason,
            created_by=_normalize_identifier(actor_id),
            created_at=_utc_now(),
            source_type=source_type,
            size_bytes=size_bytes,
            file_count=file_count,
            metadata=_safe_metadata(metadata),
        )

        self._save_quarantine_record(record)
        return record

    def _remove_path_internal(self, path: Path) -> None:
        """
        Internal removal primitive.

        This method must only be called after caller-side policy, approval, and
        backup checks have completed.
        """
        if not (path.exists() or path.is_symlink()):
            return

        if path.is_symlink() or path.is_file():
            path.unlink()
            return

        if path.is_dir():
            shutil.rmtree(path)
            return

        raise ValueError(
            f"Unsupported filesystem object: {path}"
        )

    # =========================================================================
    # Internal retention
    # =========================================================================

    def _enforce_backup_retention(
        self,
        user_id: str,
        workspace_id: str,
    ) -> None:
        """Retain only the configured number of tenant backups."""
        retention = max(
            1,
            int(self.config.backup_retention_count),
        )
        manifests = self._load_all_backup_manifests(
            user_id,
            workspace_id,
        )
        manifests.sort(
            key=lambda manifest: manifest.created_at,
            reverse=True,
        )

        for manifest in manifests[retention:]:
            try:
                backup_path = Path(manifest.backup_path)

                if backup_path.exists():
                    self._remove_path_internal(backup_path)

                manifest_file = (
                    self._tenant_manifest_root(
                        user_id,
                        workspace_id,
                    )
                    / f"{manifest.backup_id}.json"
                )

                if manifest_file.exists():
                    manifest_file.unlink()

            except Exception as exc:
                self.logger.warning(
                    "Failed to remove expired backup %s: %s",
                    manifest.backup_id,
                    exc,
                )

    def _enforce_quarantine_retention(
        self,
        user_id: str,
        workspace_id: str,
    ) -> None:
        """Retain only the configured number of quarantine records."""
        retention = max(
            1,
            int(self.config.quarantine_retention_count),
        )
        records = self._load_quarantine_records(
            user_id,
            workspace_id,
        )
        records.sort(
            key=lambda record: record.created_at,
            reverse=True,
        )

        for record in records[retention:]:
            try:
                quarantine_path = Path(record.quarantine_path)

                if quarantine_path.exists():
                    self._remove_path_internal(quarantine_path)

                self._delete_quarantine_record(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    quarantine_id=record.quarantine_id,
                )

            except Exception as exc:
                self.logger.warning(
                    "Failed to remove expired quarantine record %s: %s",
                    record.quarantine_id,
                    exc,
                )

    # =========================================================================
    # Miscellaneous helpers
    # =========================================================================

    @staticmethod
    def _safe_backup_name(name: str) -> str:
        """Create a filesystem-safe backup label."""
        cleaned = re.sub(
            r"[^a-zA-Z0-9_.\-]",
            "_",
            str(name),
        )
        cleaned = cleaned.strip("._")

        return cleaned[:120] or "resource"


# =============================================================================
# Self-test
# =============================================================================

def _self_test() -> Dict[str, Any]:
    """
    Run a safe temporary-directory self-test.

    This test:
        - creates isolated test storage
        - creates a tenant file
        - protects it
        - creates and verifies a backup
        - quarantines it with explicit approval context
        - restores it from quarantine

    It does not touch real project files.
    """
    with tempfile.TemporaryDirectory(
        prefix="william_file_protection_test_"
    ) as temporary_directory:
        root = Path(temporary_directory)

        config = FileProtectionConfig(
            tenant_root=root / "tenant_files",
            protection_root=root / "protection",
            backup_root=root / "protection" / "backups",
            quarantine_root=root / "protection" / "quarantine",
            policy_root=root / "protection" / "policies",
            manifest_root=root / "protection" / "manifests",
            backup_format=BackupFormat.ZIP,
            backup_retention_count=5,
            quarantine_retention_count=5,
        )

        protection = FileProtection(config=config)

        user_id = "test_user"
        workspace_id = "test_workspace"
        actor_id = "test_user"

        tenant_root = protection._tenant_root(
            user_id,
            workspace_id,
        )
        tenant_root.mkdir(parents=True, exist_ok=True)

        test_file = tenant_root / "important.txt"
        test_file.write_text(
            "William FileProtection self-test.",
            encoding="utf-8",
        )

        protect_result = protection.protect_path(
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id,
            path="important.txt",
            mode=ProtectionMode.APPROVAL_REQUIRED,
            reason="Self-test protected resource",
        )

        backup_result = protection.create_backup(
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id,
            path="important.txt",
            reason="Self-test backup",
        )

        delete_result = protection.safe_delete(
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id,
            path="important.txt",
            reason="Self-test quarantine",
            permanent=False,
            approval_context={
                "approved": True,
                "approval_id": "self_test_approval",
                "approved_by": actor_id,
            },
        )

        restore_result: Dict[str, Any]

        if delete_result["success"]:
            quarantine_id = delete_result["data"]["quarantine"][
                "quarantine_id"
            ]

            restore_result = protection.restore_quarantine(
                user_id=user_id,
                workspace_id=workspace_id,
                actor_id=actor_id,
                quarantine_id=quarantine_id,
                reason="Self-test restore",
            )
        else:
            restore_result = {
                "success": False,
                "message": "Restore skipped.",
                "data": {},
                "error": "DELETE_FAILED",
                "metadata": {},
            }

        success = all(
            [
                protect_result["success"],
                backup_result["success"],
                delete_result["success"],
                restore_result["success"],
                test_file.exists(),
            ]
        )

        return {
            "success": success,
            "message": (
                "FileProtection self-test completed successfully."
                if success
                else "FileProtection self-test failed."
            ),
            "data": {
                "protect_result": protect_result,
                "backup_result": backup_result,
                "delete_result": delete_result,
                "restore_result": restore_result,
                "restored_file_exists": test_file.exists(),
            },
            "error": None if success else "SELF_TEST_FAILED",
            "metadata": {
                "tested_at": _utc_now(),
                "temporary_root": str(root),
            },
        }


if __name__ == "__main__":
    print(
        json.dumps(
            _self_test(),
            indent=2,
            default=str,
        )
    )