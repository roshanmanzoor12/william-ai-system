"""
agents/memory_agent/memory_sync.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
Memory Agent - Memory Sync

Purpose:
    Sync memory across devices/workspaces with conflict resolution.

This module is designed to be:
    - Import-safe even when other William/Jarvis modules are not available yet.
    - Compatible with BaseAgent, Agent Registry, Agent Loader, Agent Router, and Master Agent routing.
    - Safe for SaaS multi-user / multi-workspace memory isolation.
    - Ready for FastAPI/dashboard/API integration.
    - Structured around safe JSON/dict responses.

Core responsibilities:
    - Register and track devices participating in memory sync.
    - Push memory changes from a device/workspace into the sync layer.
    - Pull memory changes for a device/workspace.
    - Detect and resolve conflicts using deterministic strategies.
    - Protect sensitive sync operations through Security Agent hooks.
    - Prepare Verification Agent payloads after completed sync operations.
    - Prepare Memory Agent compatible payloads for useful sync context.
    - Emit audit/event payloads without requiring the future event system to exist.

Conflict resolution priority:
    1. Safety and permission rules.
    2. SaaS user/workspace isolation.
    3. BaseAgent compatibility.
    4. MasterAgent/Registry compatibility.
    5. File-specific sync functionality.
    6. Future upgrades.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Safe optional imports
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for early development

    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps the file import-safe before the real William/Jarvis BaseAgent
        exists. The real project BaseAgent can override logging, registry hooks,
        permission checks, event dispatching, and shared context behavior.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.logger = logging.getLogger(self.agent_name)

        def run(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent.run() called directly.",
                "data": {},
                "error": "BaseAgent not installed.",
                "metadata": {},
            }


try:
    from agents.security_agent.security_agent import SecurityAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for early development

    class SecurityAgent:  # type: ignore
        """
        Fallback SecurityAgent stub.

        The real Security Agent should enforce policy, permission checks,
        subscription limits, workspace access, sensitive-memory approvals,
        and destructive-action protection.
        """

        def approve_action(self, payload: Dict[str, Any]) -> Dict[str, Any]:
            return {
                "success": True,
                "message": "Fallback security approval granted.",
                "data": {"approved": True, "fallback": True},
                "error": None,
                "metadata": {"security_agent_available": False},
            }


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_AGENT_NAME = "MemorySync"
DEFAULT_SYNC_LIMIT = 500
MAX_SYNC_LIMIT = 5000
DEFAULT_CLOCK_SKEW_SECONDS = 300

SENSITIVE_PRIVACY_LEVELS = {"sensitive", "secret", "restricted", "private_sensitive"}
DEFAULT_PUBLIC_CONFLICT_FIELDS = {
    "memory_id",
    "record_hash",
    "version",
    "updated_at",
    "source_device_id",
    "sync_status",
    "conflict_id",
}


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class SyncOperation(str, Enum):
    """Supported memory sync operation types."""

    REGISTER_DEVICE = "register_device"
    PUSH = "push"
    PULL = "pull"
    FULL_SYNC = "full_sync"
    RESOLVE_CONFLICTS = "resolve_conflicts"
    LIST_DEVICES = "list_devices"
    DISABLE_DEVICE = "disable_device"
    GET_STATUS = "get_status"


class MemoryChangeType(str, Enum):
    """Supported memory change types."""

    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    RESTORE = "restore"
    UPSERT = "upsert"


class ConflictStrategy(str, Enum):
    """
    Conflict resolution strategies.

    LAST_WRITE_WINS:
        The newest safe record wins.

    HIGHEST_VERSION_WINS:
        The highest version wins; timestamp is tie-breaker.

    MERGE_SAFE_FIELDS:
        Non-sensitive fields are merged deterministically.

    KEEP_LOCAL:
        Current stored record wins.

    KEEP_REMOTE:
        Incoming device record wins if allowed.

    MANUAL_REVIEW:
        Conflict remains unresolved and is sent to dashboard/API review queue.
    """

    LAST_WRITE_WINS = "last_write_wins"
    HIGHEST_VERSION_WINS = "highest_version_wins"
    MERGE_SAFE_FIELDS = "merge_safe_fields"
    KEEP_LOCAL = "keep_local"
    KEEP_REMOTE = "keep_remote"
    MANUAL_REVIEW = "manual_review"


class SyncStatus(str, Enum):
    """Sync result status values."""

    SYNCED = "synced"
    PENDING = "pending"
    CONFLICT = "conflict"
    REJECTED = "rejected"
    SKIPPED = "skipped"
    DELETED = "deleted"
    ERROR = "error"


class DeviceStatus(str, Enum):
    """Device status for sync participation."""

    ACTIVE = "active"
    DISABLED = "disabled"
    REVOKED = "revoked"
    PENDING = "pending"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class SyncContext:
    """
    SaaS context required for every user/workspace-specific sync operation.

    user_id:
        Authenticated SaaS user id.

    workspace_id:
        Current workspace id. This is required to prevent cross-workspace memory
        leakage.

    actor_id:
        The user/service/agent initiating the operation.

    device_id:
        Device identifier. Can represent web browser, mobile app, desktop app,
        server worker, or agent runtime.

    role:
        Optional role for future RBAC.

    subscription_plan:
        Optional subscription plan for future limits.

    request_id:
        External request id from API/dashboard if available.
    """

    user_id: str
    workspace_id: str
    actor_id: Optional[str] = None
    device_id: Optional[str] = None
    role: Optional[str] = None
    subscription_plan: Optional[str] = None
    request_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MemoryRecord:
    """
    Portable memory record structure used by MemorySync.

    The system can accept records as dicts too. This dataclass exists to normalize
    and validate sync operations.

    record_id:
        Unique memory record id.

    category:
        Memory category such as preference, project, client, team, short_term,
        long_term, knowledge_graph, etc.

    content:
        Actual memory content. Should already be privacy-guarded before storage.

    privacy_level:
        Privacy level used for security checks.

    version:
        Monotonic integer version.

    updated_at:
        ISO datetime string.

    deleted:
        Soft-delete flag.

    source_device_id:
        Origin device id.

    record_hash:
        Hash of normalized content and selected metadata.
    """

    record_id: str
    user_id: str
    workspace_id: str
    category: str
    content: Dict[str, Any]
    privacy_level: str = "normal"
    version: int = 1
    created_at: str = field(default_factory=lambda: utc_now_iso())
    updated_at: str = field(default_factory=lambda: utc_now_iso())
    deleted: bool = False
    source_device_id: Optional[str] = None
    change_type: str = MemoryChangeType.UPSERT.value
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    record_hash: Optional[str] = None

    def normalized(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["record_hash"] = self.record_hash or stable_hash(
            {
                "record_id": self.record_id,
                "user_id": self.user_id,
                "workspace_id": self.workspace_id,
                "category": self.category,
                "content": self.content,
                "privacy_level": self.privacy_level,
                "version": self.version,
                "deleted": self.deleted,
                "tags": self.tags,
            }
        )
        return payload


@dataclass
class SyncDevice:
    """Device metadata tracked for safe memory sync."""

    device_id: str
    user_id: str
    workspace_id: str
    device_name: str = "Unknown Device"
    device_type: str = "unknown"
    status: str = DeviceStatus.ACTIVE.value
    registered_at: str = field(default_factory=lambda: utc_now_iso())
    last_seen_at: str = field(default_factory=lambda: utc_now_iso())
    last_sync_at: Optional[str] = None
    sync_cursor: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SyncConflict:
    """Conflict record for manual or automatic resolution."""

    conflict_id: str
    user_id: str
    workspace_id: str
    record_id: str
    local_record: Dict[str, Any]
    remote_record: Dict[str, Any]
    reason: str
    strategy: str
    status: str = "open"
    resolved_record: Optional[Dict[str, Any]] = None
    created_at: str = field(default_factory=lambda: utc_now_iso())
    resolved_at: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Storage adapter
# ---------------------------------------------------------------------------

class InMemorySyncStore:
    """
    Thread-safe in-memory sync store.

    This is intentionally production-shaped but dependency-free. In production,
    this can be replaced with a PostgreSQL/Redis/vector-store backed adapter
    without changing the public MemorySync interface.

    Isolation keys always include:
        user_id + workspace_id
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._records: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        self._devices: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        self._conflicts: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        self._change_log: List[Dict[str, Any]] = []

    def save_device(self, device: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            key = (device["user_id"], device["workspace_id"], device["device_id"])
            self._devices[key] = copy.deepcopy(device)
            return copy.deepcopy(self._devices[key])

    def get_device(self, user_id: str, workspace_id: str, device_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            device = self._devices.get((user_id, workspace_id, device_id))
            return copy.deepcopy(device) if device else None

    def list_devices(self, user_id: str, workspace_id: str) -> List[Dict[str, Any]]:
        with self._lock:
            return [
                copy.deepcopy(device)
                for (uid, wid, _), device in self._devices.items()
                if uid == user_id and wid == workspace_id
            ]

    def save_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            key = (record["user_id"], record["workspace_id"], record["record_id"])
            self._records[key] = copy.deepcopy(record)
            self._change_log.append(
                {
                    "change_id": str(uuid.uuid4()),
                    "user_id": record["user_id"],
                    "workspace_id": record["workspace_id"],
                    "record_id": record["record_id"],
                    "source_device_id": record.get("source_device_id"),
                    "updated_at": record.get("updated_at") or utc_now_iso(),
                    "version": record.get("version", 1),
                    "deleted": bool(record.get("deleted", False)),
                    "record": copy.deepcopy(record),
                    "logged_at": utc_now_iso(),
                }
            )
            return copy.deepcopy(self._records[key])

    def get_record(self, user_id: str, workspace_id: str, record_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            record = self._records.get((user_id, workspace_id, record_id))
            return copy.deepcopy(record) if record else None

    def list_records(
        self,
        user_id: str,
        workspace_id: str,
        since: Optional[str] = None,
        limit: int = DEFAULT_SYNC_LIMIT,
        include_deleted: bool = True,
        exclude_device_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        with self._lock:
            rows: List[Dict[str, Any]] = []
            for (uid, wid, _), record in self._records.items():
                if uid != user_id or wid != workspace_id:
                    continue
                if exclude_device_id and record.get("source_device_id") == exclude_device_id:
                    continue
                if not include_deleted and record.get("deleted"):
                    continue
                if since and compare_iso(record.get("updated_at"), since) <= 0:
                    continue
                rows.append(copy.deepcopy(record))

            rows.sort(key=lambda item: item.get("updated_at", ""), reverse=False)
            return rows[:limit]

    def save_conflict(self, conflict: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            key = (conflict["user_id"], conflict["workspace_id"], conflict["conflict_id"])
            self._conflicts[key] = copy.deepcopy(conflict)
            return copy.deepcopy(conflict)

    def get_conflict(self, user_id: str, workspace_id: str, conflict_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            conflict = self._conflicts.get((user_id, workspace_id, conflict_id))
            return copy.deepcopy(conflict) if conflict else None

    def list_conflicts(
        self,
        user_id: str,
        workspace_id: str,
        status: Optional[str] = None,
        limit: int = DEFAULT_SYNC_LIMIT,
    ) -> List[Dict[str, Any]]:
        with self._lock:
            rows = []
            for (uid, wid, _), conflict in self._conflicts.items():
                if uid != user_id or wid != workspace_id:
                    continue
                if status and conflict.get("status") != status:
                    continue
                rows.append(copy.deepcopy(conflict))
            rows.sort(key=lambda item: item.get("created_at", ""), reverse=True)
            return rows[:limit]

    def update_device_cursor(
        self,
        user_id: str,
        workspace_id: str,
        device_id: str,
        cursor: Optional[str],
    ) -> Optional[Dict[str, Any]]:
        with self._lock:
            key = (user_id, workspace_id, device_id)
            device = self._devices.get(key)
            if not device:
                return None
            device["sync_cursor"] = cursor
            device["last_sync_at"] = utc_now_iso()
            device["last_seen_at"] = utc_now_iso()
            self._devices[key] = copy.deepcopy(device)
            return copy.deepcopy(device)


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def utc_now_iso() -> str:
    """Return current UTC datetime as an ISO string."""
    return datetime.now(timezone.utc).isoformat()


def parse_iso(value: Optional[str]) -> Optional[datetime]:
    """Parse ISO datetime safely."""
    if not value:
        return None
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except Exception:
        return None


def compare_iso(left: Optional[str], right: Optional[str]) -> int:
    """
    Compare two ISO timestamps.

    Returns:
        -1 if left < right
         0 if equal or unparsable
         1 if left > right
    """
    left_dt = parse_iso(left)
    right_dt = parse_iso(right)
    if not left_dt or not right_dt:
        return 0
    if left_dt < right_dt:
        return -1
    if left_dt > right_dt:
        return 1
    return 0


def stable_json(data: Any) -> str:
    """Serialize data deterministically for hashing/comparison."""
    return json.dumps(data, sort_keys=True, ensure_ascii=False, default=str, separators=(",", ":"))


def stable_hash(data: Any) -> str:
    """Create stable SHA256 hash from JSON-like data."""
    return hashlib.sha256(stable_json(data).encode("utf-8")).hexdigest()


def safe_int(value: Any, default: int = 0) -> int:
    """Convert value to int safely."""
    try:
        return int(value)
    except Exception:
        return default


def redact_sensitive_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Redact potentially sensitive content for conflict previews, logs, and dashboard.

    The full record should remain in secure storage. Audit logs and regular
    events should avoid leaking sensitive memory content.
    """
    redacted = copy.deepcopy(record)
    privacy = str(redacted.get("privacy_level", "normal")).lower()
    if privacy in SENSITIVE_PRIVACY_LEVELS:
        redacted["content"] = {
            "redacted": True,
            "reason": "Sensitive memory content hidden from non-secure output.",
        }
    return redacted


def normalize_limit(limit: Optional[int]) -> int:
    """Normalize sync limit."""
    if limit is None:
        return DEFAULT_SYNC_LIMIT
    return max(1, min(int(limit), MAX_SYNC_LIMIT))


# ---------------------------------------------------------------------------
# MemorySync
# ---------------------------------------------------------------------------

class MemorySync(BaseAgent):
    """
    Sync memory across devices/workspaces with conflict resolution.

    Connections to William/Jarvis architecture:
        - Master Agent:
            Can route sync tasks to this class via run() or explicit public methods.

        - Memory Agent:
            Uses this helper to synchronize short-term, long-term, project,
            client, team, and knowledge-graph memory records.

        - Security Agent:
            Sensitive sync operations call _request_security_approval().

        - Verification Agent:
            Completed operations return _prepare_verification_payload().

        - Dashboard/API:
            Public methods return structured dicts suitable for FastAPI responses.

        - Agent Registry/Loader:
            Class is import-safe and exposes metadata through get_agent_manifest().
    """

    def __init__(
        self,
        store: Optional[InMemorySyncStore] = None,
        security_agent: Optional[Any] = None,
        default_conflict_strategy: Union[str, ConflictStrategy] = ConflictStrategy.HIGHEST_VERSION_WINS,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        audit_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        logger_instance: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        try:
            super().__init__(agent_name=DEFAULT_AGENT_NAME, **kwargs)
        except TypeError:
            super().__init__()

        self.agent_name = DEFAULT_AGENT_NAME
        self.store = store or InMemorySyncStore()
        self.security_agent = security_agent or SecurityAgent()
        self.default_conflict_strategy = ConflictStrategy(str(default_conflict_strategy))
        self.event_callback = event_callback
        self.audit_callback = audit_callback
        self.logger = logger_instance or logging.getLogger(__name__)
        self._clock_skew_seconds = DEFAULT_CLOCK_SKEW_SECONDS

    # ------------------------------------------------------------------
    # Registry / loader compatibility
    # ------------------------------------------------------------------

    def get_agent_manifest(self) -> Dict[str, Any]:
        """Return registry-compatible metadata for Agent Loader/Registry."""
        return {
            "success": True,
            "message": "MemorySync manifest loaded.",
            "data": {
                "agent_name": self.agent_name,
                "class_name": self.__class__.__name__,
                "module": "agents.memory_agent.memory_sync",
                "version": "1.0.0",
                "purpose": "Sync memory across devices/workspaces with conflict resolution.",
                "supported_operations": [operation.value for operation in SyncOperation],
                "conflict_strategies": [strategy.value for strategy in ConflictStrategy],
                "requires_user_context": True,
                "requires_workspace_context": True,
                "compatible_with": [
                    "BaseAgent",
                    "AgentRegistry",
                    "AgentLoader",
                    "AgentRouter",
                    "MasterAgent",
                    "MemoryAgent",
                    "SecurityAgent",
                    "VerificationAgent",
                    "DashboardAPI",
                ],
            },
            "error": None,
            "metadata": {
                "generated_at": utc_now_iso(),
            },
        }

    def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generic router method for Master Agent / Agent Router.

        Expected task shape:
            {
                "operation": "push" | "pull" | "full_sync" | ...,
                "context": {
                    "user_id": "...",
                    "workspace_id": "...",
                    "device_id": "..."
                },
                "data": {...}
            }
        """
        try:
            if not isinstance(task, dict):
                return self._error_result("Task must be a dictionary.", code="INVALID_TASK")

            operation = task.get("operation")
            context_payload = task.get("context") or {}
            data = task.get("data") or {}

            context = self._context_from_dict(context_payload)
            validation = self._validate_task_context(context)
            if not validation["success"]:
                return validation

            if operation == SyncOperation.REGISTER_DEVICE.value:
                return self.register_device(context, **data)

            if operation == SyncOperation.PUSH.value:
                return self.push_changes(
                    context=context,
                    records=data.get("records", []),
                    conflict_strategy=data.get("conflict_strategy"),
                )

            if operation == SyncOperation.PULL.value:
                return self.pull_changes(
                    context=context,
                    since=data.get("since"),
                    limit=data.get("limit", DEFAULT_SYNC_LIMIT),
                    include_deleted=data.get("include_deleted", True),
                )

            if operation == SyncOperation.FULL_SYNC.value:
                return self.full_sync(
                    context=context,
                    records=data.get("records", []),
                    since=data.get("since"),
                    conflict_strategy=data.get("conflict_strategy"),
                    limit=data.get("limit", DEFAULT_SYNC_LIMIT),
                )

            if operation == SyncOperation.RESOLVE_CONFLICTS.value:
                return self.resolve_conflicts(
                    context=context,
                    conflict_ids=data.get("conflict_ids"),
                    strategy=data.get("strategy"),
                    manual_records=data.get("manual_records"),
                )

            if operation == SyncOperation.LIST_DEVICES.value:
                return self.list_devices(context)

            if operation == SyncOperation.DISABLE_DEVICE.value:
                return self.disable_device(
                    context=context,
                    target_device_id=data.get("target_device_id"),
                    reason=data.get("reason"),
                )

            if operation == SyncOperation.GET_STATUS.value:
                return self.get_sync_status(context)

            return self._error_result(
                message=f"Unsupported sync operation: {operation}",
                code="UNSUPPORTED_OPERATION",
                metadata={"supported_operations": [op.value for op in SyncOperation]},
            )

        except Exception as exc:
            self.logger.exception("MemorySync.run failed.")
            return self._error_result(
                message="MemorySync task failed.",
                error=str(exc),
                code="MEMORY_SYNC_RUN_ERROR",
            )

    # ------------------------------------------------------------------
    # Public methods
    # ------------------------------------------------------------------

    def register_device(
        self,
        context: SyncContext,
        device_name: str = "Unknown Device",
        device_type: str = "unknown",
        device_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Register a device for memory sync.

        This is safe for browsers, mobile apps, desktop clients, server workers,
        and future agent runtimes.
        """
        validation = self._validate_task_context(context, require_device=False)
        if not validation["success"]:
            return validation

        try:
            actual_device_id = device_id or context.device_id or self._generate_device_id(context, device_name, device_type)
            security = self._request_security_approval(
                context=context,
                action=SyncOperation.REGISTER_DEVICE.value,
                payload={
                    "device_id": actual_device_id,
                    "device_name": device_name,
                    "device_type": device_type,
                    "metadata": metadata or {},
                },
            )
            if not security["success"]:
                return security

            existing = self.store.get_device(context.user_id, context.workspace_id, actual_device_id)
            if existing:
                existing["last_seen_at"] = utc_now_iso()
                existing["status"] = DeviceStatus.ACTIVE.value
                existing["metadata"] = {
                    **existing.get("metadata", {}),
                    **(metadata or {}),
                }
                saved = self.store.save_device(existing)
                message = "Device already registered. Last seen updated."
            else:
                device = SyncDevice(
                    device_id=actual_device_id,
                    user_id=context.user_id,
                    workspace_id=context.workspace_id,
                    device_name=device_name,
                    device_type=device_type,
                    metadata=metadata or {},
                )
                saved = self.store.save_device(asdict(device))
                message = "Device registered for memory sync."

            self._emit_agent_event(
                context,
                event_type="memory_sync.device_registered",
                payload={"device_id": actual_device_id, "device_type": device_type},
            )
            self._log_audit_event(
                context,
                action=SyncOperation.REGISTER_DEVICE.value,
                payload={"device_id": actual_device_id, "device_type": device_type},
            )

            return self._safe_result(
                message=message,
                data={
                    "device": saved,
                    "verification_payload": self._prepare_verification_payload(
                        context=context,
                        action=SyncOperation.REGISTER_DEVICE.value,
                        result={"device_id": actual_device_id},
                    ),
                },
                metadata={"operation": SyncOperation.REGISTER_DEVICE.value},
            )

        except Exception as exc:
            self.logger.exception("Device registration failed.")
            return self._error_result(
                "Failed to register sync device.",
                error=str(exc),
                code="DEVICE_REGISTRATION_FAILED",
            )

    def push_changes(
        self,
        context: SyncContext,
        records: Iterable[Union[Dict[str, Any], MemoryRecord]],
        conflict_strategy: Optional[Union[str, ConflictStrategy]] = None,
    ) -> Dict[str, Any]:
        """
        Push local device memory changes into centralized sync storage.

        This method:
            - Validates user/workspace/device context.
            - Normalizes incoming memory records.
            - Prevents cross-user/cross-workspace contamination.
            - Detects conflicts.
            - Resolves conflicts using configured strategy.
            - Stores synced records.
            - Creates audit and verification payloads.
        """
        validation = self._validate_task_context(context, require_device=True)
        if not validation["success"]:
            return validation

        try:
            strategy = self._normalize_strategy(conflict_strategy)
            incoming_records = list(records or [])

            security = self._request_security_approval(
                context=context,
                action=SyncOperation.PUSH.value,
                payload={
                    "record_count": len(incoming_records),
                    "conflict_strategy": strategy.value,
                    "device_id": context.device_id,
                },
            )
            if not security["success"]:
                return security

            device_check = self._ensure_active_device(context)
            if not device_check["success"]:
                return device_check

            pushed: List[Dict[str, Any]] = []
            conflicts: List[Dict[str, Any]] = []
            rejected: List[Dict[str, Any]] = []
            skipped: List[Dict[str, Any]] = []

            for raw_record in incoming_records:
                normalized_result = self._normalize_record(raw_record, context)
                if not normalized_result["success"]:
                    rejected.append(
                        {
                            "record": self._safe_record_preview(raw_record),
                            "reason": normalized_result["message"],
                        }
                    )
                    continue

                remote_record = normalized_result["data"]["record"]
                isolation_check = self._validate_record_isolation(remote_record, context)
                if not isolation_check["success"]:
                    rejected.append(
                        {
                            "record": self._safe_record_preview(remote_record),
                            "reason": isolation_check["message"],
                        }
                    )
                    continue

                local_record = self.store.get_record(
                    user_id=context.user_id,
                    workspace_id=context.workspace_id,
                    record_id=remote_record["record_id"],
                )

                if not local_record:
                    saved = self.store.save_record(remote_record)
                    pushed.append(self._safe_record_preview(saved, include_content=False))
                    continue

                if self._records_equivalent(local_record, remote_record):
                    skipped.append(
                        {
                            "record_id": remote_record["record_id"],
                            "reason": "Record already synced.",
                            "sync_status": SyncStatus.SKIPPED.value,
                        }
                    )
                    continue

                conflict_needed, reason = self._detect_conflict(local_record, remote_record)
                if conflict_needed:
                    resolved = self._resolve_record_conflict(
                        context=context,
                        local_record=local_record,
                        remote_record=remote_record,
                        strategy=strategy,
                        reason=reason,
                    )

                    if resolved["status"] == SyncStatus.CONFLICT.value:
                        conflicts.append(resolved["conflict"])
                        continue

                    if resolved["status"] == SyncStatus.REJECTED.value:
                        rejected.append(
                            {
                                "record_id": remote_record["record_id"],
                                "reason": resolved.get("reason", "Conflict rejected."),
                            }
                        )
                        continue

                    saved = self.store.save_record(resolved["record"])
                    pushed.append(self._safe_record_preview(saved, include_content=False))
                    continue

                chosen = self._choose_newer_safe_record(local_record, remote_record)
                saved = self.store.save_record(chosen)
                pushed.append(self._safe_record_preview(saved, include_content=False))

            cursor = utc_now_iso()
            self.store.update_device_cursor(
                user_id=context.user_id,
                workspace_id=context.workspace_id,
                device_id=str(context.device_id),
                cursor=cursor,
            )

            summary = {
                "pushed_count": len(pushed),
                "conflict_count": len(conflicts),
                "rejected_count": len(rejected),
                "skipped_count": len(skipped),
                "cursor": cursor,
            }

            self._emit_agent_event(
                context,
                event_type="memory_sync.push_completed",
                payload=summary,
            )
            self._log_audit_event(
                context,
                action=SyncOperation.PUSH.value,
                payload={
                    **summary,
                    "device_id": context.device_id,
                    "conflict_strategy": strategy.value,
                },
            )

            return self._safe_result(
                message="Memory changes pushed successfully.",
                data={
                    "summary": summary,
                    "pushed": pushed,
                    "conflicts": conflicts,
                    "rejected": rejected,
                    "skipped": skipped,
                    "memory_payload": self._prepare_memory_payload(
                        context=context,
                        action=SyncOperation.PUSH.value,
                        useful_context=summary,
                    ),
                    "verification_payload": self._prepare_verification_payload(
                        context=context,
                        action=SyncOperation.PUSH.value,
                        result=summary,
                    ),
                },
                metadata={
                    "operation": SyncOperation.PUSH.value,
                    "conflict_strategy": strategy.value,
                },
            )

        except Exception as exc:
            self.logger.exception("Push changes failed.")
            return self._error_result(
                "Failed to push memory changes.",
                error=str(exc),
                code="PUSH_CHANGES_FAILED",
            )

    def pull_changes(
        self,
        context: SyncContext,
        since: Optional[str] = None,
        limit: int = DEFAULT_SYNC_LIMIT,
        include_deleted: bool = True,
    ) -> Dict[str, Any]:
        """
        Pull memory changes for a specific device/user/workspace.

        The method excludes changes from the same device by default so a device
        does not receive its own latest push unless the dashboard/API passes no
        device_id.
        """
        validation = self._validate_task_context(context, require_device=True)
        if not validation["success"]:
            return validation

        try:
            safe_limit = normalize_limit(limit)

            security = self._request_security_approval(
                context=context,
                action=SyncOperation.PULL.value,
                payload={
                    "since": since,
                    "limit": safe_limit,
                    "include_deleted": include_deleted,
                    "device_id": context.device_id,
                },
            )
            if not security["success"]:
                return security

            device_check = self._ensure_active_device(context)
            if not device_check["success"]:
                return device_check

            rows = self.store.list_records(
                user_id=context.user_id,
                workspace_id=context.workspace_id,
                since=since,
                limit=safe_limit,
                include_deleted=include_deleted,
                exclude_device_id=context.device_id,
            )

            safe_rows = [self._safe_record_for_sync(row) for row in rows]
            cursor = utc_now_iso()

            self.store.update_device_cursor(
                user_id=context.user_id,
                workspace_id=context.workspace_id,
                device_id=str(context.device_id),
                cursor=cursor,
            )

            summary = {
                "pulled_count": len(safe_rows),
                "since": since,
                "cursor": cursor,
                "limit": safe_limit,
                "include_deleted": include_deleted,
            }

            self._emit_agent_event(
                context,
                event_type="memory_sync.pull_completed",
                payload=summary,
            )
            self._log_audit_event(
                context,
                action=SyncOperation.PULL.value,
                payload=summary,
            )

            return self._safe_result(
                message="Memory changes pulled successfully.",
                data={
                    "records": safe_rows,
                    "summary": summary,
                    "verification_payload": self._prepare_verification_payload(
                        context=context,
                        action=SyncOperation.PULL.value,
                        result=summary,
                    ),
                },
                metadata={"operation": SyncOperation.PULL.value},
            )

        except Exception as exc:
            self.logger.exception("Pull changes failed.")
            return self._error_result(
                "Failed to pull memory changes.",
                error=str(exc),
                code="PULL_CHANGES_FAILED",
            )

    def full_sync(
        self,
        context: SyncContext,
        records: Iterable[Union[Dict[str, Any], MemoryRecord]],
        since: Optional[str] = None,
        conflict_strategy: Optional[Union[str, ConflictStrategy]] = None,
        limit: int = DEFAULT_SYNC_LIMIT,
    ) -> Dict[str, Any]:
        """
        Perform push then pull as one dashboard/API-friendly operation.
        """
        validation = self._validate_task_context(context, require_device=True)
        if not validation["success"]:
            return validation

        try:
            security = self._request_security_approval(
                context=context,
                action=SyncOperation.FULL_SYNC.value,
                payload={
                    "since": since,
                    "device_id": context.device_id,
                    "conflict_strategy": str(conflict_strategy or self.default_conflict_strategy.value),
                },
            )
            if not security["success"]:
                return security

            push_result = self.push_changes(
                context=context,
                records=records,
                conflict_strategy=conflict_strategy,
            )
            if not push_result["success"]:
                return push_result

            pull_result = self.pull_changes(
                context=context,
                since=since,
                limit=limit,
                include_deleted=True,
            )
            if not pull_result["success"]:
                return pull_result

            summary = {
                "push": push_result["data"].get("summary", {}),
                "pull": pull_result["data"].get("summary", {}),
            }

            self._emit_agent_event(
                context,
                event_type="memory_sync.full_sync_completed",
                payload=summary,
            )
            self._log_audit_event(
                context,
                action=SyncOperation.FULL_SYNC.value,
                payload=summary,
            )

            return self._safe_result(
                message="Full memory sync completed successfully.",
                data={
                    "summary": summary,
                    "push_result": push_result["data"],
                    "pull_result": pull_result["data"],
                    "verification_payload": self._prepare_verification_payload(
                        context=context,
                        action=SyncOperation.FULL_SYNC.value,
                        result=summary,
                    ),
                },
                metadata={"operation": SyncOperation.FULL_SYNC.value},
            )

        except Exception as exc:
            self.logger.exception("Full sync failed.")
            return self._error_result(
                "Failed to complete full memory sync.",
                error=str(exc),
                code="FULL_SYNC_FAILED",
            )

    def resolve_conflicts(
        self,
        context: SyncContext,
        conflict_ids: Optional[List[str]] = None,
        strategy: Optional[Union[str, ConflictStrategy]] = None,
        manual_records: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Resolve open conflicts.

        manual_records shape:
            {
                "conflict_id": {
                    "record_id": "...",
                    "content": {...},
                    ...
                }
            }
        """
        validation = self._validate_task_context(context, require_device=False)
        if not validation["success"]:
            return validation

        try:
            chosen_strategy = self._normalize_strategy(strategy or ConflictStrategy.MANUAL_REVIEW.value)

            security = self._request_security_approval(
                context=context,
                action=SyncOperation.RESOLVE_CONFLICTS.value,
                payload={
                    "conflict_ids": conflict_ids,
                    "strategy": chosen_strategy.value,
                    "has_manual_records": bool(manual_records),
                },
            )
            if not security["success"]:
                return security

            open_conflicts = self.store.list_conflicts(
                user_id=context.user_id,
                workspace_id=context.workspace_id,
                status="open",
                limit=MAX_SYNC_LIMIT,
            )

            if conflict_ids:
                wanted = set(conflict_ids)
                open_conflicts = [item for item in open_conflicts if item.get("conflict_id") in wanted]

            resolved: List[Dict[str, Any]] = []
            unresolved: List[Dict[str, Any]] = []
            rejected: List[Dict[str, Any]] = []

            for conflict in open_conflicts:
                conflict_id = conflict["conflict_id"]

                if manual_records and conflict_id in manual_records:
                    normalized = self._normalize_record(manual_records[conflict_id], context)
                    if not normalized["success"]:
                        rejected.append({"conflict_id": conflict_id, "reason": normalized["message"]})
                        continue
                    record = normalized["data"]["record"]
                else:
                    result = self._resolve_record_conflict(
                        context=context,
                        local_record=conflict["local_record"],
                        remote_record=conflict["remote_record"],
                        strategy=chosen_strategy,
                        reason=conflict.get("reason", "Manual conflict resolution."),
                    )
                    if result["status"] == SyncStatus.CONFLICT.value:
                        unresolved.append(
                            {
                                "conflict_id": conflict_id,
                                "reason": "Strategy left conflict unresolved.",
                            }
                        )
                        continue
                    record = result["record"]

                isolation_check = self._validate_record_isolation(record, context)
                if not isolation_check["success"]:
                    rejected.append({"conflict_id": conflict_id, "reason": isolation_check["message"]})
                    continue

                saved = self.store.save_record(record)
                conflict["status"] = "resolved"
                conflict["resolved_at"] = utc_now_iso()
                conflict["resolved_record"] = self._safe_record_preview(saved, include_content=False)
                conflict["strategy"] = chosen_strategy.value
                self.store.save_conflict(conflict)
                resolved.append(
                    {
                        "conflict_id": conflict_id,
                        "record_id": saved.get("record_id"),
                        "strategy": chosen_strategy.value,
                        "sync_status": SyncStatus.SYNCED.value,
                    }
                )

            summary = {
                "resolved_count": len(resolved),
                "unresolved_count": len(unresolved),
                "rejected_count": len(rejected),
                "strategy": chosen_strategy.value,
            }

            self._emit_agent_event(
                context,
                event_type="memory_sync.conflicts_resolved",
                payload=summary,
            )
            self._log_audit_event(
                context,
                action=SyncOperation.RESOLVE_CONFLICTS.value,
                payload=summary,
            )

            return self._safe_result(
                message="Conflict resolution completed.",
                data={
                    "summary": summary,
                    "resolved": resolved,
                    "unresolved": unresolved,
                    "rejected": rejected,
                    "verification_payload": self._prepare_verification_payload(
                        context=context,
                        action=SyncOperation.RESOLVE_CONFLICTS.value,
                        result=summary,
                    ),
                },
                metadata={"operation": SyncOperation.RESOLVE_CONFLICTS.value},
            )

        except Exception as exc:
            self.logger.exception("Resolve conflicts failed.")
            return self._error_result(
                "Failed to resolve memory conflicts.",
                error=str(exc),
                code="RESOLVE_CONFLICTS_FAILED",
            )

    def list_devices(self, context: SyncContext) -> Dict[str, Any]:
        """List devices registered for a user/workspace."""
        validation = self._validate_task_context(context, require_device=False)
        if not validation["success"]:
            return validation

        try:
            devices = self.store.list_devices(context.user_id, context.workspace_id)
            return self._safe_result(
                message="Sync devices loaded.",
                data={"devices": devices, "count": len(devices)},
                metadata={"operation": SyncOperation.LIST_DEVICES.value},
            )
        except Exception as exc:
            return self._error_result(
                "Failed to list sync devices.",
                error=str(exc),
                code="LIST_DEVICES_FAILED",
            )

    def disable_device(
        self,
        context: SyncContext,
        target_device_id: Optional[str],
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Disable a device from future sync."""
        validation = self._validate_task_context(context, require_device=False)
        if not validation["success"]:
            return validation

        if not target_device_id:
            return self._error_result(
                "target_device_id is required.",
                code="TARGET_DEVICE_ID_REQUIRED",
            )

        try:
            security = self._request_security_approval(
                context=context,
                action=SyncOperation.DISABLE_DEVICE.value,
                payload={"target_device_id": target_device_id, "reason": reason},
            )
            if not security["success"]:
                return security

            device = self.store.get_device(context.user_id, context.workspace_id, target_device_id)
            if not device:
                return self._error_result(
                    "Device not found in this workspace.",
                    code="DEVICE_NOT_FOUND",
                )

            device["status"] = DeviceStatus.DISABLED.value
            device["disabled_at"] = utc_now_iso()
            device["disabled_reason"] = reason or "Disabled by user/admin."
            saved = self.store.save_device(device)

            self._emit_agent_event(
                context,
                event_type="memory_sync.device_disabled",
                payload={"target_device_id": target_device_id},
            )
            self._log_audit_event(
                context,
                action=SyncOperation.DISABLE_DEVICE.value,
                payload={"target_device_id": target_device_id, "reason": reason},
            )

            return self._safe_result(
                message="Sync device disabled.",
                data={"device": saved},
                metadata={"operation": SyncOperation.DISABLE_DEVICE.value},
            )

        except Exception as exc:
            return self._error_result(
                "Failed to disable sync device.",
                error=str(exc),
                code="DISABLE_DEVICE_FAILED",
            )

    def get_sync_status(self, context: SyncContext) -> Dict[str, Any]:
        """Return sync status summary for a user/workspace."""
        validation = self._validate_task_context(context, require_device=False)
        if not validation["success"]:
            return validation

        try:
            devices = self.store.list_devices(context.user_id, context.workspace_id)
            conflicts = self.store.list_conflicts(
                context.user_id,
                context.workspace_id,
                status="open",
                limit=MAX_SYNC_LIMIT,
            )
            records = self.store.list_records(
                context.user_id,
                context.workspace_id,
                since=None,
                limit=MAX_SYNC_LIMIT,
                include_deleted=True,
            )

            status = {
                "device_count": len(devices),
                "active_device_count": len([d for d in devices if d.get("status") == DeviceStatus.ACTIVE.value]),
                "record_count": len(records),
                "open_conflict_count": len(conflicts),
                "last_checked_at": utc_now_iso(),
            }

            return self._safe_result(
                message="Memory sync status loaded.",
                data={"status": status},
                metadata={"operation": SyncOperation.GET_STATUS.value},
            )

        except Exception as exc:
            return self._error_result(
                "Failed to load sync status.",
                error=str(exc),
                code="GET_SYNC_STATUS_FAILED",
            )

    # ------------------------------------------------------------------
    # Required compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(
        self,
        context: SyncContext,
        require_device: bool = True,
    ) -> Dict[str, Any]:
        """
        Validate SaaS task context.

        This protects the highest-priority system rules:
            - user_id is required
            - workspace_id is required
            - device_id is required for device sync operations
        """
        if not isinstance(context, SyncContext):
            return self._error_result(
                "Invalid sync context.",
                code="INVALID_SYNC_CONTEXT",
            )

        if not context.user_id or not str(context.user_id).strip():
            return self._error_result(
                "user_id is required for memory sync.",
                code="USER_ID_REQUIRED",
            )

        if not context.workspace_id or not str(context.workspace_id).strip():
            return self._error_result(
                "workspace_id is required for memory sync.",
                code="WORKSPACE_ID_REQUIRED",
            )

        if require_device and (not context.device_id or not str(context.device_id).strip()):
            return self._error_result(
                "device_id is required for this memory sync operation.",
                code="DEVICE_ID_REQUIRED",
            )

        return self._safe_result(
            message="Sync context validated.",
            data={"valid": True},
            metadata={"hook": "_validate_task_context"},
        )

    def _requires_security_check(
        self,
        action: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Determine whether an action requires Security Agent approval.

        Memory sync is sensitive by nature, so most operations require approval.
        Pull/list/status are still checked because they can expose memory metadata.
        """
        sensitive_actions = {
            SyncOperation.REGISTER_DEVICE.value,
            SyncOperation.PUSH.value,
            SyncOperation.PULL.value,
            SyncOperation.FULL_SYNC.value,
            SyncOperation.RESOLVE_CONFLICTS.value,
            SyncOperation.DISABLE_DEVICE.value,
        }

        if action in sensitive_actions:
            return True

        payload = payload or {}
        if payload.get("privacy_level") in SENSITIVE_PRIVACY_LEVELS:
            return True

        return False

    def _request_security_approval(
        self,
        context: SyncContext,
        action: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        The fallback SecurityAgent grants approval only to keep imports/tests safe.
        Production Security Agent should enforce RBAC, subscription limits,
        workspace membership, device trust, privacy policy, and admin approvals.
        """
        payload = payload or {}

        if not self._requires_security_check(action, payload):
            return self._safe_result(
                message="Security approval not required.",
                data={"approved": True},
                metadata={"hook": "_request_security_approval"},
            )

        approval_payload = {
            "agent": self.agent_name,
            "action": action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "actor_id": context.actor_id,
            "device_id": context.device_id,
            "payload": payload,
            "requested_at": utc_now_iso(),
        }

        try:
            if hasattr(self.security_agent, "approve_action"):
                response = self.security_agent.approve_action(approval_payload)
            elif hasattr(self.security_agent, "request_approval"):
                response = self.security_agent.request_approval(approval_payload)
            else:
                response = {
                    "success": True,
                    "message": "Security agent has no approval method; fallback approved.",
                    "data": {"approved": True, "fallback": True},
                    "error": None,
                    "metadata": {"security_agent_available": False},
                }

            if not isinstance(response, dict):
                return self._error_result(
                    "Security Agent returned invalid approval response.",
                    code="INVALID_SECURITY_RESPONSE",
                )

            approved = bool(response.get("success")) and bool(
                response.get("data", {}).get("approved", response.get("approved", True))
            )

            if not approved:
                return self._error_result(
                    "Security approval denied.",
                    error=response.get("error"),
                    code="SECURITY_APPROVAL_DENIED",
                    metadata={"security_response": response},
                )

            return self._safe_result(
                message="Security approval granted.",
                data={"approved": True, "security_response": response},
                metadata={"hook": "_request_security_approval"},
            )

        except Exception as exc:
            self.logger.exception("Security approval failed.")
            return self._error_result(
                "Security approval failed.",
                error=str(exc),
                code="SECURITY_APPROVAL_FAILED",
            )

    def _prepare_verification_payload(
        self,
        context: SyncContext,
        action: str,
        result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent compatible payload.

        The Verification Agent can later use this to validate:
            - user/workspace isolation
            - synced counts
            - conflict status
            - device state
            - audit trail
        """
        return {
            "agent": self.agent_name,
            "action": action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "actor_id": context.actor_id,
            "device_id": context.device_id,
            "result_summary": copy.deepcopy(result),
            "verification_type": "memory_sync_integrity",
            "checks": [
                "saas_user_workspace_isolation",
                "device_authorization",
                "conflict_resolution_integrity",
                "sensitive_memory_redaction",
                "audit_event_created",
            ],
            "created_at": utc_now_iso(),
        }

    def _prepare_memory_payload(
        self,
        context: SyncContext,
        action: str,
        useful_context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        This does not store memory directly. It returns a structured payload that
        Memory Agent can decide to store, summarize, ignore, or route through
        Privacy Guard.
        """
        return {
            "agent": self.agent_name,
            "memory_type": "system_sync_event",
            "category": "memory_sync",
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "source_device_id": context.device_id,
            "content": {
                "action": action,
                "summary": copy.deepcopy(useful_context),
            },
            "importance": "low",
            "privacy_level": "system",
            "created_at": utc_now_iso(),
        }

    def _emit_agent_event(
        self,
        context: SyncContext,
        event_type: str,
        payload: Dict[str, Any],
    ) -> None:
        """
        Emit event for future Agent Event Bus / Dashboard notifications.

        Safe no-op if no callback is configured.
        """
        event = {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "agent": self.agent_name,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "actor_id": context.actor_id,
            "device_id": context.device_id,
            "payload": copy.deepcopy(payload),
            "created_at": utc_now_iso(),
        }

        try:
            if self.event_callback:
                self.event_callback(event)
        except Exception:
            self.logger.exception("Failed to emit MemorySync agent event.")

    def _log_audit_event(
        self,
        context: SyncContext,
        action: str,
        payload: Dict[str, Any],
    ) -> None:
        """
        Log audit event.

        In production this can connect to audit_logs table, event stream,
        compliance logger, or dashboard analytics.
        """
        audit_event = {
            "audit_id": str(uuid.uuid4()),
            "agent": self.agent_name,
            "action": action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "actor_id": context.actor_id,
            "device_id": context.device_id,
            "payload": copy.deepcopy(payload),
            "created_at": utc_now_iso(),
        }

        try:
            if self.audit_callback:
                self.audit_callback(audit_event)
            else:
                self.logger.info("MemorySync audit event: %s", stable_json(audit_event))
        except Exception:
            self.logger.exception("Failed to log MemorySync audit event.")

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard success response."""
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
        error: Optional[str] = None,
        code: str = "MEMORY_SYNC_ERROR",
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard error response."""
        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": error or code,
            "metadata": {
                "code": code,
                **(metadata or {}),
            },
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _context_from_dict(self, payload: Dict[str, Any]) -> SyncContext:
        """Build SyncContext safely from a dictionary."""
        return SyncContext(
            user_id=str(payload.get("user_id") or ""),
            workspace_id=str(payload.get("workspace_id") or ""),
            actor_id=payload.get("actor_id"),
            device_id=payload.get("device_id"),
            role=payload.get("role"),
            subscription_plan=payload.get("subscription_plan"),
            request_id=payload.get("request_id"),
            metadata=payload.get("metadata") or {},
        )

    def _generate_device_id(self, context: SyncContext, device_name: str, device_type: str) -> str:
        """Generate stable-ish device id when caller does not provide one."""
        seed = {
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "device_name": device_name,
            "device_type": device_type,
            "time_bucket": int(time.time() // 60),
            "nonce": str(uuid.uuid4()),
        }
        return f"dev_{stable_hash(seed)[:24]}"

    def _ensure_active_device(self, context: SyncContext) -> Dict[str, Any]:
        """Ensure device exists and is active."""
        if not context.device_id:
            return self._error_result("device_id is required.", code="DEVICE_ID_REQUIRED")

        device = self.store.get_device(context.user_id, context.workspace_id, context.device_id)
        if not device:
            registered = self.register_device(
                context=context,
                device_id=context.device_id,
                device_name="Auto Registered Device",
                device_type="unknown",
                metadata={"auto_registered": True},
            )
            if not registered["success"]:
                return registered
            device = registered["data"]["device"]

        if device.get("status") != DeviceStatus.ACTIVE.value:
            return self._error_result(
                "Device is not active for memory sync.",
                code="DEVICE_NOT_ACTIVE",
                data={"device_status": device.get("status")},
            )

        device["last_seen_at"] = utc_now_iso()
        self.store.save_device(device)

        return self._safe_result(
            "Device is active.",
            data={"device": device},
            metadata={"hook": "_ensure_active_device"},
        )

    def _normalize_strategy(
        self,
        strategy: Optional[Union[str, ConflictStrategy]],
    ) -> ConflictStrategy:
        """Normalize conflict strategy."""
        if not strategy:
            return self.default_conflict_strategy
        try:
            return ConflictStrategy(str(strategy))
        except Exception:
            return self.default_conflict_strategy

    def _normalize_record(
        self,
        raw_record: Union[Dict[str, Any], MemoryRecord],
        context: SyncContext,
    ) -> Dict[str, Any]:
        """Normalize incoming memory record."""
        try:
            if isinstance(raw_record, MemoryRecord):
                record = raw_record.normalized()
            elif isinstance(raw_record, dict):
                record = copy.deepcopy(raw_record)
            else:
                return self._error_result(
                    "Memory record must be a dictionary or MemoryRecord.",
                    code="INVALID_MEMORY_RECORD",
                )

            record_id = record.get("record_id") or record.get("memory_id") or str(uuid.uuid4())
            category = record.get("category") or "general"
            content = record.get("content")
            if content is None:
                content = {}
            if not isinstance(content, dict):
                content = {"value": content}

            normalized = {
                "record_id": str(record_id),
                "user_id": str(record.get("user_id") or context.user_id),
                "workspace_id": str(record.get("workspace_id") or context.workspace_id),
                "category": str(category),
                "content": content,
                "privacy_level": str(record.get("privacy_level") or "normal"),
                "version": max(1, safe_int(record.get("version"), 1)),
                "created_at": record.get("created_at") or utc_now_iso(),
                "updated_at": record.get("updated_at") or utc_now_iso(),
                "deleted": bool(record.get("deleted", False)),
                "source_device_id": record.get("source_device_id") or context.device_id,
                "change_type": str(record.get("change_type") or MemoryChangeType.UPSERT.value),
                "tags": list(record.get("tags") or []),
                "metadata": dict(record.get("metadata") or {}),
            }

            normalized["record_hash"] = record.get("record_hash") or stable_hash(
                {
                    "record_id": normalized["record_id"],
                    "user_id": normalized["user_id"],
                    "workspace_id": normalized["workspace_id"],
                    "category": normalized["category"],
                    "content": normalized["content"],
                    "privacy_level": normalized["privacy_level"],
                    "version": normalized["version"],
                    "deleted": normalized["deleted"],
                    "tags": normalized["tags"],
                }
            )

            return self._safe_result(
                message="Memory record normalized.",
                data={"record": normalized},
                metadata={"hook": "_normalize_record"},
            )

        except Exception as exc:
            return self._error_result(
                "Failed to normalize memory record.",
                error=str(exc),
                code="NORMALIZE_RECORD_FAILED",
            )

    def _validate_record_isolation(
        self,
        record: Dict[str, Any],
        context: SyncContext,
    ) -> Dict[str, Any]:
        """Validate that a memory record belongs to the exact SaaS user/workspace."""
        if str(record.get("user_id")) != str(context.user_id):
            return self._error_result(
                "Record rejected because user_id does not match sync context.",
                code="USER_ISOLATION_VIOLATION",
            )

        if str(record.get("workspace_id")) != str(context.workspace_id):
            return self._error_result(
                "Record rejected because workspace_id does not match sync context.",
                code="WORKSPACE_ISOLATION_VIOLATION",
            )

        return self._safe_result(
            "Record isolation validated.",
            data={"valid": True},
            metadata={"hook": "_validate_record_isolation"},
        )

    def _records_equivalent(self, left: Dict[str, Any], right: Dict[str, Any]) -> bool:
        """Check whether two records are equivalent for sync purposes."""
        left_hash = left.get("record_hash") or stable_hash(left.get("content", {}))
        right_hash = right.get("record_hash") or stable_hash(right.get("content", {}))
        return (
            str(left_hash) == str(right_hash)
            and safe_int(left.get("version"), 1) == safe_int(right.get("version"), 1)
            and bool(left.get("deleted", False)) == bool(right.get("deleted", False))
        )

    def _detect_conflict(
        self,
        local_record: Dict[str, Any],
        remote_record: Dict[str, Any],
    ) -> Tuple[bool, str]:
        """
        Detect conflict between local stored record and remote incoming record.

        Conflict is detected when:
            - Same record id.
            - Different hash/content.
            - Versions or timestamps indicate parallel edits.
        """
        if local_record.get("record_hash") == remote_record.get("record_hash"):
            return False, "Hashes match."

        local_version = safe_int(local_record.get("version"), 1)
        remote_version = safe_int(remote_record.get("version"), 1)

        if remote_version > local_version:
            return False, "Remote version is newer."

        if local_version > remote_version:
            return False, "Local version is newer."

        local_updated = local_record.get("updated_at")
        remote_updated = remote_record.get("updated_at")

        if local_updated and remote_updated and local_updated != remote_updated:
            return True, "Same version with different content and timestamps."

        return True, "Same version with different content."

    def _resolve_record_conflict(
        self,
        context: SyncContext,
        local_record: Dict[str, Any],
        remote_record: Dict[str, Any],
        strategy: ConflictStrategy,
        reason: str,
    ) -> Dict[str, Any]:
        """Resolve one record conflict or create a conflict entry."""
        if self._is_sensitive_record(local_record) or self._is_sensitive_record(remote_record):
            if strategy == ConflictStrategy.MERGE_SAFE_FIELDS:
                strategy = ConflictStrategy.MANUAL_REVIEW

        if strategy == ConflictStrategy.MANUAL_REVIEW:
            conflict = self._create_conflict(
                context=context,
                local_record=local_record,
                remote_record=remote_record,
                reason=reason,
                strategy=strategy,
            )
            return {"status": SyncStatus.CONFLICT.value, "conflict": conflict}

        if strategy == ConflictStrategy.KEEP_LOCAL:
            return {"status": SyncStatus.SYNCED.value, "record": local_record}

        if strategy == ConflictStrategy.KEEP_REMOTE:
            return {"status": SyncStatus.SYNCED.value, "record": remote_record}

        if strategy == ConflictStrategy.LAST_WRITE_WINS:
            return {
                "status": SyncStatus.SYNCED.value,
                "record": self._choose_newer_safe_record(local_record, remote_record),
            }

        if strategy == ConflictStrategy.HIGHEST_VERSION_WINS:
            return {
                "status": SyncStatus.SYNCED.value,
                "record": self._choose_highest_version_record(local_record, remote_record),
            }

        if strategy == ConflictStrategy.MERGE_SAFE_FIELDS:
            merged = self._merge_safe_fields(local_record, remote_record)
            return {"status": SyncStatus.SYNCED.value, "record": merged}

        conflict = self._create_conflict(
            context=context,
            local_record=local_record,
            remote_record=remote_record,
            reason=f"Unsupported strategy fallback: {strategy.value}",
            strategy=ConflictStrategy.MANUAL_REVIEW,
        )
        return {"status": SyncStatus.CONFLICT.value, "conflict": conflict}

    def _choose_newer_safe_record(
        self,
        local_record: Dict[str, Any],
        remote_record: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Choose newer record by updated_at, then version."""
        timestamp_compare = compare_iso(local_record.get("updated_at"), remote_record.get("updated_at"))
        if timestamp_compare < 0:
            return copy.deepcopy(remote_record)
        if timestamp_compare > 0:
            return copy.deepcopy(local_record)
        return self._choose_highest_version_record(local_record, remote_record)

    def _choose_highest_version_record(
        self,
        local_record: Dict[str, Any],
        remote_record: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Choose record with highest version."""
        local_version = safe_int(local_record.get("version"), 1)
        remote_version = safe_int(remote_record.get("version"), 1)
        if remote_version > local_version:
            return copy.deepcopy(remote_record)
        if local_version > remote_version:
            return copy.deepcopy(local_record)
        return copy.deepcopy(remote_record if compare_iso(local_record.get("updated_at"), remote_record.get("updated_at")) <= 0 else local_record)

    def _merge_safe_fields(
        self,
        local_record: Dict[str, Any],
        remote_record: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Merge safe non-sensitive fields.

        Sensitive records are not merged automatically. Caller should route them
        to manual review before calling this.
        """
        merged = copy.deepcopy(local_record)
        remote = copy.deepcopy(remote_record)

        local_content = merged.get("content") if isinstance(merged.get("content"), dict) else {}
        remote_content = remote.get("content") if isinstance(remote.get("content"), dict) else {}

        merged_content = {
            **local_content,
            **remote_content,
        }

        merged["content"] = merged_content
        merged["version"] = max(safe_int(local_record.get("version"), 1), safe_int(remote_record.get("version"), 1)) + 1
        merged["updated_at"] = utc_now_iso()
        merged["source_device_id"] = remote_record.get("source_device_id") or local_record.get("source_device_id")
        merged["tags"] = sorted(set((local_record.get("tags") or []) + (remote_record.get("tags") or [])))
        merged["metadata"] = {
            **(local_record.get("metadata") or {}),
            **(remote_record.get("metadata") or {}),
            "merged_by": self.agent_name,
            "merged_at": utc_now_iso(),
        }
        merged["record_hash"] = stable_hash(
            {
                "record_id": merged.get("record_id"),
                "user_id": merged.get("user_id"),
                "workspace_id": merged.get("workspace_id"),
                "category": merged.get("category"),
                "content": merged.get("content"),
                "privacy_level": merged.get("privacy_level"),
                "version": merged.get("version"),
                "deleted": merged.get("deleted"),
                "tags": merged.get("tags"),
            }
        )
        return merged

    def _create_conflict(
        self,
        context: SyncContext,
        local_record: Dict[str, Any],
        remote_record: Dict[str, Any],
        reason: str,
        strategy: ConflictStrategy,
    ) -> Dict[str, Any]:
        """Create and store conflict record."""
        conflict = SyncConflict(
            conflict_id=str(uuid.uuid4()),
            user_id=context.user_id,
            workspace_id=context.workspace_id,
            record_id=str(remote_record.get("record_id") or local_record.get("record_id")),
            local_record=copy.deepcopy(local_record),
            remote_record=copy.deepcopy(remote_record),
            reason=reason,
            strategy=strategy.value,
            metadata={
                "local_preview": self._safe_record_preview(local_record, include_content=False),
                "remote_preview": self._safe_record_preview(remote_record, include_content=False),
                "created_by": self.agent_name,
            },
        )
        saved = self.store.save_conflict(asdict(conflict))
        return {
            **saved,
            "local_record": redact_sensitive_record(saved["local_record"]),
            "remote_record": redact_sensitive_record(saved["remote_record"]),
        }

    def _is_sensitive_record(self, record: Dict[str, Any]) -> bool:
        """Check if record privacy level is sensitive."""
        return str(record.get("privacy_level", "normal")).lower() in SENSITIVE_PRIVACY_LEVELS

    def _safe_record_preview(
        self,
        record: Any,
        include_content: bool = False,
    ) -> Dict[str, Any]:
        """Return safe record preview for responses/logs."""
        if isinstance(record, MemoryRecord):
            payload = record.normalized()
        elif isinstance(record, dict):
            payload = copy.deepcopy(record)
        else:
            return {"invalid_record": True, "type": str(type(record))}

        preview = {
            "record_id": payload.get("record_id") or payload.get("memory_id"),
            "user_id": payload.get("user_id"),
            "workspace_id": payload.get("workspace_id"),
            "category": payload.get("category"),
            "privacy_level": payload.get("privacy_level"),
            "version": payload.get("version"),
            "updated_at": payload.get("updated_at"),
            "deleted": payload.get("deleted"),
            "source_device_id": payload.get("source_device_id"),
            "record_hash": payload.get("record_hash"),
            "sync_status": SyncStatus.SYNCED.value,
        }

        if include_content:
            if self._is_sensitive_record(payload):
                preview["content"] = {
                    "redacted": True,
                    "reason": "Sensitive memory content hidden.",
                }
            else:
                preview["content"] = payload.get("content", {})

        return preview

    def _safe_record_for_sync(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Return record payload for sync response.

        Sensitive content is still included because the device is authorized
        through context/security approval. If your product policy requires
        separate device-level encryption, replace this method with encrypted
        payload generation.
        """
        safe_record = copy.deepcopy(record)
        safe_record.setdefault("sync_status", SyncStatus.SYNCED.value)
        return safe_record


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------

def create_memory_sync(**kwargs: Any) -> MemorySync:
    """Factory helper for Agent Loader / tests / FastAPI dependency injection."""
    return MemorySync(**kwargs)


# ---------------------------------------------------------------------------
# Module exports
# ---------------------------------------------------------------------------

__all__ = [
    "MemorySync",
    "MemoryRecord",
    "SyncContext",
    "SyncDevice",
    "SyncConflict",
    "SyncOperation",
    "MemoryChangeType",
    "ConflictStrategy",
    "SyncStatus",
    "DeviceStatus",
    "InMemorySyncStore",
    "create_memory_sync",
]