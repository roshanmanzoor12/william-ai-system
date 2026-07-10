"""
agents/system_agent/system_memory.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Remembers common folders, apps, device settings, and workflow preferences
    for the System Agent while preserving SaaS user/workspace isolation.

This module is designed to be:
    - Import-safe even if the full William system is not created yet.
    - Compatible with BaseAgent, Agent Registry, Agent Loader, Agent Router,
      Master Agent routing, Security Agent, Memory Agent, Verification Agent,
      Dashboard/API, and future FastAPI integration.
    - Safe by default: no real OS mutation, financial action, browser action,
      message sending, call action, or destructive action is executed here.

Main Class:
    SystemMemory

Responsibilities:
    - Store and retrieve common folders per user/workspace.
    - Store and retrieve frequently used apps per user/workspace.
    - Store and retrieve device settings preferences per user/workspace.
    - Store and retrieve workflow preferences per user/workspace.
    - Export/import structured memory safely.
    - Prepare Memory Agent payloads.
    - Prepare Verification Agent payloads.
    - Emit events and audit logs where possible.
"""

from __future__ import annotations

import copy
import json
import logging
import os
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Optional William BaseAgent compatibility
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:
    try:
        from agents.base_agent.base_agent import BaseAgent  # type: ignore
    except Exception:

        class BaseAgent:  # type: ignore
            """
            Fallback BaseAgent stub.

            This fallback exists so this file can be imported and tested even
            before the full William/Jarvis agent system is generated.
            """

            def __init__(
                self,
                agent_name: str = "system_memory",
                agent_type: str = "system",
                **kwargs: Any,
            ) -> None:
                self.agent_name = agent_name
                self.agent_type = agent_type
                self.agent_id = kwargs.get("agent_id", f"{agent_type}:{agent_name}")

            def emit_event(self, event_type: str, payload: Dict[str, Any]) -> None:
                return None

            def log(self, level: str, message: str, **kwargs: Any) -> None:
                return None


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_AGENT_NAME = "system_memory"
DEFAULT_AGENT_TYPE = "system_agent"

DEFAULT_STORAGE_DIR = os.environ.get(
    "WILLIAM_SYSTEM_MEMORY_DIR",
    os.path.join(".william_data", "system_memory"),
)

SUPPORTED_MEMORY_TYPES = {
    "folder",
    "app",
    "device_setting",
    "workflow_preference",
}

SENSITIVE_SETTING_KEYS = {
    "password",
    "secret",
    "token",
    "api_key",
    "private_key",
    "credential",
    "cookie",
    "session",
    "bearer",
    "oauth",
}

DEFAULT_MEMORY_LIMIT = 5000


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

@dataclass
class MemoryRecord:
    """
    Represents one isolated System Memory record.

    Each record always belongs to exactly one user_id and workspace_id.
    """

    record_id: str
    user_id: str
    workspace_id: str
    memory_type: str
    key: str
    value: Any
    label: Optional[str] = None
    description: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    confidence: float = 1.0
    source: str = "system_agent"
    created_at: str = field(default_factory=lambda: utc_now_iso())
    updated_at: str = field(default_factory=lambda: utc_now_iso())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["tags"] = list(self.tags or [])
        data["metadata"] = dict(self.metadata or {})
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MemoryRecord":
        safe_data = dict(data or {})
        safe_data.setdefault("record_id", generate_id("sysmem"))
        safe_data.setdefault("user_id", "")
        safe_data.setdefault("workspace_id", "")
        safe_data.setdefault("memory_type", "")
        safe_data.setdefault("key", "")
        safe_data.setdefault("value", None)
        safe_data.setdefault("tags", [])
        safe_data.setdefault("confidence", 1.0)
        safe_data.setdefault("source", "system_agent")
        safe_data.setdefault("created_at", utc_now_iso())
        safe_data.setdefault("updated_at", utc_now_iso())
        safe_data.setdefault("metadata", {})
        return cls(**safe_data)


@dataclass
class SystemMemoryContext:
    """
    Normalized execution context used by SystemMemory.

    The Master Agent / Router / Dashboard should pass user_id and workspace_id
    for every user-specific task.
    """

    user_id: str
    workspace_id: str
    request_id: str = field(default_factory=lambda: generate_id("req"))
    actor_id: Optional[str] = None
    role: Optional[str] = None
    session_id: Optional[str] = None
    source: str = "system_memory"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Utility Functions
# ---------------------------------------------------------------------------

def utc_now_iso() -> str:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def generate_id(prefix: str = "id") -> str:
    """Generate a readable unique ID."""
    return f"{prefix}_{uuid.uuid4().hex}"


def normalize_key(value: Any) -> str:
    """
    Normalize dictionary keys used for memory records.

    Keeps names predictable for Dashboard/API use.
    """
    text = str(value or "").strip().lower()
    text = text.replace("\\", "/")
    text = " ".join(text.split())
    text = text.replace(" ", "_")
    return text


def safe_json_dumps(data: Any) -> str:
    """Safely serialize data for logs/storage."""
    try:
        return json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True, default=str)
    except Exception:
        return json.dumps(str(data), ensure_ascii=False)


def deep_copy(data: Any) -> Any:
    """Best-effort deep copy."""
    try:
        return copy.deepcopy(data)
    except Exception:
        return data


def is_sensitive_key(key: str) -> bool:
    """Detect sensitive setting keys that should not be stored casually."""
    lowered = str(key or "").lower()
    return any(token in lowered for token in SENSITIVE_SETTING_KEYS)


def sanitize_tags(tags: Optional[Iterable[Any]]) -> List[str]:
    """Normalize tags into a clean list."""
    if not tags:
        return []

    cleaned: List[str] = []
    for tag in tags:
        text = str(tag or "").strip()
        if text and text not in cleaned:
            cleaned.append(text[:80])

    return cleaned[:30]


def sanitize_path_for_display(path_value: Any) -> str:
    """
    Normalize folder path values for safe memory display.

    This does not verify or create folders. It only stores the preference.
    """
    raw = str(path_value or "").strip()
    if not raw:
        return ""

    return raw.replace("\\", "/")


def ensure_dict(value: Any) -> Dict[str, Any]:
    """Return value if dict, otherwise empty dict."""
    return dict(value) if isinstance(value, dict) else {}


# ---------------------------------------------------------------------------
# File Storage Adapter
# ---------------------------------------------------------------------------

class JsonSystemMemoryStore:
    """
    Lightweight JSON storage adapter.

    This is intentionally simple and import-safe. In production SaaS, this
    adapter can be replaced with PostgreSQL, Redis, encrypted object storage,
    or a workspace-scoped memory service.

    File structure:
        .william_data/system_memory/
            user_<user_id>/
                workspace_<workspace_id>.json

    No user/workspace data is mixed in the same storage file.
    """

    def __init__(self, storage_dir: Union[str, Path] = DEFAULT_STORAGE_DIR) -> None:
        self.storage_dir = Path(storage_dir)
        self._lock = threading.RLock()

    def _safe_segment(self, value: str) -> str:
        text = str(value or "").strip()
        if not text:
            text = "unknown"

        allowed = []
        for char in text:
            if char.isalnum() or char in ("-", "_", "."):
                allowed.append(char)
            else:
                allowed.append("_")

        return "".join(allowed)[:120]

    def _workspace_file(self, user_id: str, workspace_id: str) -> Path:
        safe_user = self._safe_segment(user_id)
        safe_workspace = self._safe_segment(workspace_id)
        return self.storage_dir / f"user_{safe_user}" / f"workspace_{safe_workspace}.json"

    def load_records(self, user_id: str, workspace_id: str) -> List[MemoryRecord]:
        """Load isolated memory records for one user/workspace."""
        with self._lock:
            file_path = self._workspace_file(user_id, workspace_id)

            if not file_path.exists():
                return []

            try:
                raw = json.loads(file_path.read_text(encoding="utf-8"))
                records_data = raw.get("records", [])
                records: List[MemoryRecord] = []

                for item in records_data:
                    try:
                        record = MemoryRecord.from_dict(item)
                        if (
                            str(record.user_id) == str(user_id)
                            and str(record.workspace_id) == str(workspace_id)
                        ):
                            records.append(record)
                    except Exception as exc:
                        logger.warning("Skipping invalid system memory record: %s", exc)

                return records
            except Exception as exc:
                logger.exception("Failed to load system memory file: %s", exc)
                return []

    def save_records(
        self,
        user_id: str,
        workspace_id: str,
        records: List[MemoryRecord],
    ) -> None:
        """Save isolated memory records for one user/workspace."""
        with self._lock:
            file_path = self._workspace_file(user_id, workspace_id)
            file_path.parent.mkdir(parents=True, exist_ok=True)

            isolated_records = [
                record
                for record in records
                if str(record.user_id) == str(user_id)
                and str(record.workspace_id) == str(workspace_id)
            ]

            payload = {
                "schema": "william.system_memory.v1",
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
                "updated_at": utc_now_iso(),
                "records": [record.to_dict() for record in isolated_records],
            }

            tmp_path = file_path.with_suffix(".json.tmp")
            tmp_path.write_text(safe_json_dumps(payload), encoding="utf-8")
            tmp_path.replace(file_path)


# ---------------------------------------------------------------------------
# SystemMemory
# ---------------------------------------------------------------------------

class SystemMemory(BaseAgent):
    """
    System Agent memory component.

    This class helps the System Agent remember useful user/workspace-specific
    system context such as common folders, frequently used apps, preferred
    device settings, and workflow preferences.

    It does not execute system actions directly. It only stores and retrieves
    preferences that other agents may use after Security Agent approval.
    """

    def __init__(
        self,
        storage_dir: Union[str, Path] = DEFAULT_STORAGE_DIR,
        storage: Optional[JsonSystemMemoryStore] = None,
        security_checker: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], None]] = None,
        event_emitter: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        memory_limit: int = DEFAULT_MEMORY_LIMIT,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            agent_name=kwargs.pop("agent_name", DEFAULT_AGENT_NAME),
            agent_type=kwargs.pop("agent_type", DEFAULT_AGENT_TYPE),
            **kwargs,
        )

        self.storage = storage or JsonSystemMemoryStore(storage_dir=storage_dir)
        self.security_checker = security_checker
        self.audit_logger = audit_logger
        self.event_emitter = event_emitter
        self.memory_limit = max(100, int(memory_limit or DEFAULT_MEMORY_LIMIT))
        self._cache: Dict[Tuple[str, str], List[MemoryRecord]] = {}
        self._lock = threading.RLock()

    # -----------------------------------------------------------------------
    # Compatibility Hooks
    # -----------------------------------------------------------------------

    def _validate_task_context(
        self,
        context: Union[SystemMemoryContext, Dict[str, Any], None],
    ) -> Dict[str, Any]:
        """
        Validate task context.

        Every user-specific operation must include user_id and workspace_id.
        """
        if isinstance(context, SystemMemoryContext):
            context_dict = context.to_dict()
        elif isinstance(context, dict):
            context_dict = dict(context)
        else:
            context_dict = {}

        user_id = str(context_dict.get("user_id") or "").strip()
        workspace_id = str(context_dict.get("workspace_id") or "").strip()

        if not user_id:
            return self._error_result(
                message="Missing required user_id in task context.",
                error_code="MISSING_USER_ID",
                metadata={"hook": "_validate_task_context"},
            )

        if not workspace_id:
            return self._error_result(
                message="Missing required workspace_id in task context.",
                error_code="MISSING_WORKSPACE_ID",
                metadata={"hook": "_validate_task_context"},
            )

        context_dict.setdefault("request_id", generate_id("req"))
        context_dict.setdefault("source", "system_memory")
        context_dict.setdefault("metadata", {})
        context_dict["user_id"] = user_id
        context_dict["workspace_id"] = workspace_id

        return self._safe_result(
            message="Task context validated.",
            data=context_dict,
            metadata={"hook": "_validate_task_context"},
        )

    def _requires_security_check(
        self,
        action: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Decide whether an operation needs Security Agent approval.

        Reading normal preferences is safe. Storing sensitive keys, importing
        memory, exporting memory, bulk deletion, or storing executable-looking
        workflow data should go through security.
        """
        action_name = str(action or "").lower().strip()
        payload = payload or {}

        if action_name in {
            "import_memory",
            "export_memory",
            "clear_memory",
            "delete_record",
            "bulk_update",
        }:
            return True

        key = str(payload.get("key") or payload.get("setting_key") or "").lower()
        memory_type = str(payload.get("memory_type") or "").lower()

        if is_sensitive_key(key):
            return True

        if memory_type == "device_setting" and is_sensitive_key(key):
            return True

        if memory_type == "workflow_preference":
            value = payload.get("value")
            if isinstance(value, dict):
                dangerous_tokens = {
                    "execute",
                    "shell",
                    "terminal",
                    "cmd",
                    "powershell",
                    "delete",
                    "format",
                    "transfer",
                    "payment",
                }
                serialized = safe_json_dumps(value).lower()
                if any(token in serialized for token in dangerous_tokens):
                    return True

        return False

    def _request_security_approval(
        self,
        action: str,
        context: Dict[str, Any],
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request approval from Security Agent if available.

        If no security checker is wired yet, safe low-risk actions continue.
        Sensitive actions are denied by default without checker approval.
        """
        payload = payload or {}
        requires_check = self._requires_security_check(action, payload)

        security_payload = {
            "agent": DEFAULT_AGENT_NAME,
            "action": action,
            "requires_security_check": requires_check,
            "context": self._public_context(context),
            "payload_summary": self._summarize_payload(payload),
            "created_at": utc_now_iso(),
        }

        if not requires_check:
            return self._safe_result(
                message="Security approval not required.",
                data={
                    "approved": True,
                    "security_payload": security_payload,
                },
                metadata={"hook": "_request_security_approval"},
            )

        if self.security_checker is None:
            return self._error_result(
                message=(
                    "Security approval is required, but no Security Agent "
                    "checker is configured."
                ),
                error_code="SECURITY_CHECKER_NOT_CONFIGURED",
                data={
                    "approved": False,
                    "security_payload": security_payload,
                },
                metadata={"hook": "_request_security_approval"},
            )

        try:
            approval = self.security_checker(security_payload)
            approved = bool(approval.get("approved") or approval.get("success"))

            if not approved:
                return self._error_result(
                    message="Security Agent denied this SystemMemory action.",
                    error_code="SECURITY_DENIED",
                    data={
                        "approved": False,
                        "approval": approval,
                        "security_payload": security_payload,
                    },
                    metadata={"hook": "_request_security_approval"},
                )

            return self._safe_result(
                message="Security Agent approved this SystemMemory action.",
                data={
                    "approved": True,
                    "approval": approval,
                    "security_payload": security_payload,
                },
                metadata={"hook": "_request_security_approval"},
            )

        except Exception as exc:
            logger.exception("Security approval failed: %s", exc)
            return self._error_result(
                message="Security approval failed.",
                error_code="SECURITY_APPROVAL_EXCEPTION",
                error=str(exc),
                data={
                    "approved": False,
                    "security_payload": security_payload,
                },
                metadata={"hook": "_request_security_approval"},
            )

    def _prepare_verification_payload(
        self,
        action: str,
        context: Dict[str, Any],
        result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare a Verification Agent payload.

        The Verification Agent can use this to confirm memory changes,
        ownership isolation, and expected output structure.
        """
        return {
            "verification_type": "system_memory_action",
            "agent": DEFAULT_AGENT_NAME,
            "action": action,
            "success": bool(result.get("success")),
            "message": result.get("message"),
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "request_id": context.get("request_id"),
            "record_count": self.count_records(context).get("data", {}).get("count"),
            "result_metadata": result.get("metadata", {}),
            "created_at": utc_now_iso(),
        }

    def _prepare_memory_payload(
        self,
        action: str,
        context: Dict[str, Any],
        record: Optional[MemoryRecord] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent-compatible payload.

        Useful context can later be forwarded to the global Memory Agent while
        preserving per-user/per-workspace boundaries.
        """
        payload: Dict[str, Any] = {
            "memory_scope": "system_agent",
            "memory_component": "system_memory",
            "action": action,
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "request_id": context.get("request_id"),
            "created_at": utc_now_iso(),
            "data": data or {},
        }

        if record is not None:
            payload["record"] = record.to_dict()

        return payload

    def _emit_agent_event(
        self,
        event_type: str,
        payload: Dict[str, Any],
    ) -> None:
        """
        Emit event to Dashboard/API/Agent event bus if configured.
        """
        safe_payload = deep_copy(payload)
        safe_payload.setdefault("event_id", generate_id("evt"))
        safe_payload.setdefault("agent", DEFAULT_AGENT_NAME)
        safe_payload.setdefault("created_at", utc_now_iso())

        try:
            if self.event_emitter:
                self.event_emitter(event_type, safe_payload)
                return

            if hasattr(super(), "emit_event"):
                try:
                    super().emit_event(event_type, safe_payload)  # type: ignore
                    return
                except Exception:
                    pass

            logger.debug("SystemMemory event emitted: %s %s", event_type, safe_payload)
        except Exception as exc:
            logger.warning("Failed to emit SystemMemory event: %s", exc)

    def _log_audit_event(
        self,
        action: str,
        context: Dict[str, Any],
        payload: Optional[Dict[str, Any]] = None,
        success: bool = True,
        error: Optional[str] = None,
    ) -> None:
        """
        Log audit event for Dashboard/API and compliance.

        This does not store secrets. Payload is summarized.
        """
        audit_payload = {
            "audit_id": generate_id("audit"),
            "agent": DEFAULT_AGENT_NAME,
            "action": action,
            "success": success,
            "error": error,
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "actor_id": context.get("actor_id"),
            "role": context.get("role"),
            "request_id": context.get("request_id"),
            "payload_summary": self._summarize_payload(payload or {}),
            "created_at": utc_now_iso(),
        }

        try:
            if self.audit_logger:
                self.audit_logger(audit_payload)
            else:
                logger.info("SystemMemory audit: %s", safe_json_dumps(audit_payload))
        except Exception as exc:
            logger.warning("Failed to write SystemMemory audit event: %s", exc)

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return a standard success result."""
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
        error_code: str = "SYSTEM_MEMORY_ERROR",
        error: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return a standard error result."""
        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": {
                "code": error_code,
                "detail": error or message,
            },
            "metadata": metadata or {},
        }

    # -----------------------------------------------------------------------
    # Public Folder Memory Methods
    # -----------------------------------------------------------------------

    def remember_folder(
        self,
        context: Union[SystemMemoryContext, Dict[str, Any]],
        folder_key: str,
        folder_path: str,
        label: Optional[str] = None,
        description: Optional[str] = None,
        tags: Optional[Iterable[Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Remember a commonly used folder path.

        Example:
            folder_key = "downloads"
            folder_path = "C:/Users/Roshan/Downloads"
        """
        return self._upsert_memory(
            context=context,
            memory_type="folder",
            key=folder_key,
            value=sanitize_path_for_display(folder_path),
            label=label,
            description=description,
            tags=tags,
            metadata=metadata,
            action="remember_folder",
        )

    def get_folder(
        self,
        context: Union[SystemMemoryContext, Dict[str, Any]],
        folder_key: str,
    ) -> Dict[str, Any]:
        """Retrieve one remembered folder by key."""
        return self.get_memory(
            context=context,
            memory_type="folder",
            key=folder_key,
            action="get_folder",
        )

    def list_folders(
        self,
        context: Union[SystemMemoryContext, Dict[str, Any]],
        tags: Optional[Iterable[Any]] = None,
    ) -> Dict[str, Any]:
        """List remembered folders for this user/workspace."""
        return self.list_memory(
            context=context,
            memory_type="folder",
            tags=tags,
            action="list_folders",
        )

    def forget_folder(
        self,
        context: Union[SystemMemoryContext, Dict[str, Any]],
        folder_key: str,
    ) -> Dict[str, Any]:
        """Forget one remembered folder."""
        return self.delete_memory(
            context=context,
            memory_type="folder",
            key=folder_key,
            action="forget_folder",
        )

    # -----------------------------------------------------------------------
    # Public App Memory Methods
    # -----------------------------------------------------------------------

    def remember_app(
        self,
        context: Union[SystemMemoryContext, Dict[str, Any]],
        app_key: str,
        app_info: Union[str, Dict[str, Any]],
        label: Optional[str] = None,
        description: Optional[str] = None,
        tags: Optional[Iterable[Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Remember a commonly used app.

        app_info may be a string or dict:
            "Chrome"
            {
                "name": "Chrome",
                "package": "com.android.chrome",
                "platform": "android"
            }
        """
        value = app_info
        if isinstance(app_info, str):
            value = {
                "name": app_info.strip(),
                "platform": "unknown",
            }

        return self._upsert_memory(
            context=context,
            memory_type="app",
            key=app_key,
            value=value,
            label=label,
            description=description,
            tags=tags,
            metadata=metadata,
            action="remember_app",
        )

    def get_app(
        self,
        context: Union[SystemMemoryContext, Dict[str, Any]],
        app_key: str,
    ) -> Dict[str, Any]:
        """Retrieve one remembered app by key."""
        return self.get_memory(
            context=context,
            memory_type="app",
            key=app_key,
            action="get_app",
        )

    def list_apps(
        self,
        context: Union[SystemMemoryContext, Dict[str, Any]],
        tags: Optional[Iterable[Any]] = None,
    ) -> Dict[str, Any]:
        """List remembered apps for this user/workspace."""
        return self.list_memory(
            context=context,
            memory_type="app",
            tags=tags,
            action="list_apps",
        )

    def forget_app(
        self,
        context: Union[SystemMemoryContext, Dict[str, Any]],
        app_key: str,
    ) -> Dict[str, Any]:
        """Forget one remembered app."""
        return self.delete_memory(
            context=context,
            memory_type="app",
            key=app_key,
            action="forget_app",
        )

    # -----------------------------------------------------------------------
    # Public Device Setting Memory Methods
    # -----------------------------------------------------------------------

    def remember_device_setting(
        self,
        context: Union[SystemMemoryContext, Dict[str, Any]],
        setting_key: str,
        setting_value: Any,
        label: Optional[str] = None,
        description: Optional[str] = None,
        tags: Optional[Iterable[Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Remember a preferred device setting.

        This does not apply the setting to a real device. It only stores the
        preference so the System Agent can request approval later.
        """
        if is_sensitive_key(setting_key):
            return self._error_result(
                message="Sensitive device setting keys cannot be stored here.",
                error_code="SENSITIVE_DEVICE_SETTING_BLOCKED",
                metadata={"setting_key": setting_key},
            )

        return self._upsert_memory(
            context=context,
            memory_type="device_setting",
            key=setting_key,
            value=setting_value,
            label=label,
            description=description,
            tags=tags,
            metadata=metadata,
            action="remember_device_setting",
        )

    def get_device_setting(
        self,
        context: Union[SystemMemoryContext, Dict[str, Any]],
        setting_key: str,
    ) -> Dict[str, Any]:
        """Retrieve one remembered device setting."""
        return self.get_memory(
            context=context,
            memory_type="device_setting",
            key=setting_key,
            action="get_device_setting",
        )

    def list_device_settings(
        self,
        context: Union[SystemMemoryContext, Dict[str, Any]],
        tags: Optional[Iterable[Any]] = None,
    ) -> Dict[str, Any]:
        """List remembered device settings."""
        return self.list_memory(
            context=context,
            memory_type="device_setting",
            tags=tags,
            action="list_device_settings",
        )

    def forget_device_setting(
        self,
        context: Union[SystemMemoryContext, Dict[str, Any]],
        setting_key: str,
    ) -> Dict[str, Any]:
        """Forget one remembered device setting."""
        return self.delete_memory(
            context=context,
            memory_type="device_setting",
            key=setting_key,
            action="forget_device_setting",
        )

    # -----------------------------------------------------------------------
    # Public Workflow Preference Memory Methods
    # -----------------------------------------------------------------------

    def remember_workflow_preference(
        self,
        context: Union[SystemMemoryContext, Dict[str, Any]],
        preference_key: str,
        preference_value: Any,
        label: Optional[str] = None,
        description: Optional[str] = None,
        tags: Optional[Iterable[Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Remember workflow preferences.

        Examples:
            - preferred_download_folder
            - browser_profile
            - file_naming_style
            - default_export_format
            - preferred_device_mode
        """
        return self._upsert_memory(
            context=context,
            memory_type="workflow_preference",
            key=preference_key,
            value=preference_value,
            label=label,
            description=description,
            tags=tags,
            metadata=metadata,
            action="remember_workflow_preference",
        )

    def get_workflow_preference(
        self,
        context: Union[SystemMemoryContext, Dict[str, Any]],
        preference_key: str,
    ) -> Dict[str, Any]:
        """Retrieve one workflow preference."""
        return self.get_memory(
            context=context,
            memory_type="workflow_preference",
            key=preference_key,
            action="get_workflow_preference",
        )

    def list_workflow_preferences(
        self,
        context: Union[SystemMemoryContext, Dict[str, Any]],
        tags: Optional[Iterable[Any]] = None,
    ) -> Dict[str, Any]:
        """List workflow preferences."""
        return self.list_memory(
            context=context,
            memory_type="workflow_preference",
            tags=tags,
            action="list_workflow_preferences",
        )

    def forget_workflow_preference(
        self,
        context: Union[SystemMemoryContext, Dict[str, Any]],
        preference_key: str,
    ) -> Dict[str, Any]:
        """Forget one workflow preference."""
        return self.delete_memory(
            context=context,
            memory_type="workflow_preference",
            key=preference_key,
            action="forget_workflow_preference",
        )

    # -----------------------------------------------------------------------
    # Generic Public Methods
    # -----------------------------------------------------------------------

    def get_memory(
        self,
        context: Union[SystemMemoryContext, Dict[str, Any]],
        memory_type: str,
        key: str,
        action: str = "get_memory",
    ) -> Dict[str, Any]:
        """Retrieve a single memory record by type/key."""
        context_result = self._validate_task_context(context)
        if not context_result["success"]:
            return context_result

        ctx = context_result["data"]
        memory_type = self._validate_memory_type(memory_type)
        if not memory_type:
            return self._error_result(
                message="Invalid memory_type.",
                error_code="INVALID_MEMORY_TYPE",
                metadata={"allowed": sorted(SUPPORTED_MEMORY_TYPES)},
            )

        normalized_key = normalize_key(key)
        if not normalized_key:
            return self._error_result(
                message="Missing memory key.",
                error_code="MISSING_MEMORY_KEY",
            )

        records = self._load(ctx)
        record = self._find_record(records, memory_type, normalized_key)

        if not record:
            result = self._error_result(
                message="System memory record not found.",
                error_code="MEMORY_RECORD_NOT_FOUND",
                metadata={
                    "memory_type": memory_type,
                    "key": normalized_key,
                },
            )
            self._log_audit_event(action, ctx, {"memory_type": memory_type, "key": normalized_key}, False)
            return result

        result = self._safe_result(
            message="System memory record retrieved.",
            data={
                "record": record.to_dict(),
                "memory_payload": self._prepare_memory_payload(action, ctx, record),
            },
            metadata={
                "memory_type": memory_type,
                "key": normalized_key,
            },
        )

        self._log_audit_event(action, ctx, {"memory_type": memory_type, "key": normalized_key}, True)
        return result

    def list_memory(
        self,
        context: Union[SystemMemoryContext, Dict[str, Any]],
        memory_type: Optional[str] = None,
        tags: Optional[Iterable[Any]] = None,
        action: str = "list_memory",
    ) -> Dict[str, Any]:
        """List memory records for the current user/workspace."""
        context_result = self._validate_task_context(context)
        if not context_result["success"]:
            return context_result

        ctx = context_result["data"]
        normalized_type = self._validate_memory_type(memory_type) if memory_type else None
        if memory_type and not normalized_type:
            return self._error_result(
                message="Invalid memory_type.",
                error_code="INVALID_MEMORY_TYPE",
                metadata={"allowed": sorted(SUPPORTED_MEMORY_TYPES)},
            )

        tag_filter = set(sanitize_tags(tags))
        records = self._load(ctx)

        filtered: List[MemoryRecord] = []
        for record in records:
            if normalized_type and record.memory_type != normalized_type:
                continue

            if tag_filter and not tag_filter.intersection(set(record.tags or [])):
                continue

            filtered.append(record)

        filtered.sort(key=lambda item: item.updated_at, reverse=True)

        result = self._safe_result(
            message="System memory records listed.",
            data={
                "records": [record.to_dict() for record in filtered],
                "count": len(filtered),
                "memory_payload": self._prepare_memory_payload(
                    action,
                    ctx,
                    data={
                        "count": len(filtered),
                        "memory_type": normalized_type,
                        "tags": sorted(tag_filter),
                    },
                ),
            },
            metadata={
                "memory_type": normalized_type,
                "tags": sorted(tag_filter),
            },
        )

        self._log_audit_event(
            action,
            ctx,
            {
                "memory_type": normalized_type,
                "tags": sorted(tag_filter),
                "count": len(filtered),
            },
            True,
        )

        return result

    def delete_memory(
        self,
        context: Union[SystemMemoryContext, Dict[str, Any]],
        memory_type: str,
        key: str,
        action: str = "delete_memory",
    ) -> Dict[str, Any]:
        """Delete one memory record by type/key."""
        context_result = self._validate_task_context(context)
        if not context_result["success"]:
            return context_result

        ctx = context_result["data"]
        memory_type = self._validate_memory_type(memory_type)
        if not memory_type:
            return self._error_result(
                message="Invalid memory_type.",
                error_code="INVALID_MEMORY_TYPE",
                metadata={"allowed": sorted(SUPPORTED_MEMORY_TYPES)},
            )

        normalized_key = normalize_key(key)
        if not normalized_key:
            return self._error_result(
                message="Missing memory key.",
                error_code="MISSING_MEMORY_KEY",
            )

        security_result = self._request_security_approval(
            action=action,
            context=ctx,
            payload={
                "memory_type": memory_type,
                "key": normalized_key,
            },
        )
        if not security_result["success"]:
            self._log_audit_event(action, ctx, {"memory_type": memory_type, "key": normalized_key}, False)
            return security_result

        with self._lock:
            records = self._load(ctx)
            before_count = len(records)

            deleted_record: Optional[MemoryRecord] = None
            remaining: List[MemoryRecord] = []

            for record in records:
                if record.memory_type == memory_type and record.key == normalized_key:
                    deleted_record = record
                else:
                    remaining.append(record)

            if deleted_record is None:
                result = self._error_result(
                    message="System memory record not found.",
                    error_code="MEMORY_RECORD_NOT_FOUND",
                    metadata={
                        "memory_type": memory_type,
                        "key": normalized_key,
                    },
                )
                self._log_audit_event(action, ctx, {"memory_type": memory_type, "key": normalized_key}, False)
                return result

            self._save(ctx, remaining)

        result = self._safe_result(
            message="System memory record deleted.",
            data={
                "deleted_record": deleted_record.to_dict(),
                "before_count": before_count,
                "after_count": len(remaining),
                "verification_payload": self._prepare_verification_payload(
                    action,
                    ctx,
                    {"success": True, "message": "System memory record deleted.", "metadata": {}},
                ),
            },
            metadata={
                "memory_type": memory_type,
                "key": normalized_key,
            },
        )

        self._emit_agent_event(
            "system_memory.deleted",
            {
                "context": self._public_context(ctx),
                "memory_type": memory_type,
                "key": normalized_key,
                "record_id": deleted_record.record_id,
            },
        )
        self._log_audit_event(action, ctx, {"memory_type": memory_type, "key": normalized_key}, True)

        return result

    def clear_memory(
        self,
        context: Union[SystemMemoryContext, Dict[str, Any]],
        memory_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Clear all SystemMemory records for a user/workspace.

        If memory_type is provided, only that type is cleared.
        Requires Security Agent approval.
        """
        action = "clear_memory"
        context_result = self._validate_task_context(context)
        if not context_result["success"]:
            return context_result

        ctx = context_result["data"]
        normalized_type = self._validate_memory_type(memory_type) if memory_type else None

        if memory_type and not normalized_type:
            return self._error_result(
                message="Invalid memory_type.",
                error_code="INVALID_MEMORY_TYPE",
                metadata={"allowed": sorted(SUPPORTED_MEMORY_TYPES)},
            )

        security_result = self._request_security_approval(
            action=action,
            context=ctx,
            payload={"memory_type": normalized_type},
        )
        if not security_result["success"]:
            self._log_audit_event(action, ctx, {"memory_type": normalized_type}, False)
            return security_result

        with self._lock:
            records = self._load(ctx)
            before_count = len(records)

            if normalized_type:
                remaining = [record for record in records if record.memory_type != normalized_type]
                deleted_count = before_count - len(remaining)
            else:
                remaining = []
                deleted_count = before_count

            self._save(ctx, remaining)

        result = self._safe_result(
            message="System memory cleared.",
            data={
                "deleted_count": deleted_count,
                "remaining_count": len(remaining),
                "verification_payload": self._prepare_verification_payload(
                    action,
                    ctx,
                    {"success": True, "message": "System memory cleared.", "metadata": {}},
                ),
            },
            metadata={"memory_type": normalized_type},
        )

        self._emit_agent_event(
            "system_memory.cleared",
            {
                "context": self._public_context(ctx),
                "memory_type": normalized_type,
                "deleted_count": deleted_count,
            },
        )
        self._log_audit_event(action, ctx, {"memory_type": normalized_type, "deleted_count": deleted_count}, True)

        return result

    def count_records(
        self,
        context: Union[SystemMemoryContext, Dict[str, Any]],
        memory_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Count records for a user/workspace."""
        context_result = self._validate_task_context(context)
        if not context_result["success"]:
            return context_result

        ctx = context_result["data"]
        normalized_type = self._validate_memory_type(memory_type) if memory_type else None

        records = self._load(ctx)
        if normalized_type:
            records = [record for record in records if record.memory_type == normalized_type]

        return self._safe_result(
            message="System memory record count prepared.",
            data={
                "count": len(records),
                "memory_type": normalized_type,
            },
            metadata={"memory_type": normalized_type},
        )

    # -----------------------------------------------------------------------
    # Snapshot / Import / Export
    # -----------------------------------------------------------------------

    def export_memory(
        self,
        context: Union[SystemMemoryContext, Dict[str, Any]],
        include_metadata: bool = True,
    ) -> Dict[str, Any]:
        """
        Export isolated memory for this user/workspace.

        Requires Security Agent approval because it can expose private user
        workflow preferences.
        """
        action = "export_memory"
        context_result = self._validate_task_context(context)
        if not context_result["success"]:
            return context_result

        ctx = context_result["data"]

        security_result = self._request_security_approval(
            action=action,
            context=ctx,
            payload={"include_metadata": include_metadata},
        )
        if not security_result["success"]:
            self._log_audit_event(action, ctx, {"include_metadata": include_metadata}, False)
            return security_result

        records = self._load(ctx)
        records_data = []

        for record in records:
            item = record.to_dict()
            if not include_metadata:
                item["metadata"] = {}
            records_data.append(item)

        export_payload = {
            "schema": "william.system_memory.export.v1",
            "export_id": generate_id("sysmem_export"),
            "user_id": ctx["user_id"],
            "workspace_id": ctx["workspace_id"],
            "created_at": utc_now_iso(),
            "records": records_data,
            "count": len(records_data),
        }

        result = self._safe_result(
            message="System memory exported.",
            data={
                "export": export_payload,
                "verification_payload": self._prepare_verification_payload(
                    action,
                    ctx,
                    {"success": True, "message": "System memory exported.", "metadata": {}},
                ),
            },
            metadata={"count": len(records_data)},
        )

        self._log_audit_event(action, ctx, {"count": len(records_data)}, True)
        return result

    def import_memory(
        self,
        context: Union[SystemMemoryContext, Dict[str, Any]],
        import_payload: Dict[str, Any],
        merge: bool = True,
        overwrite_existing: bool = False,
    ) -> Dict[str, Any]:
        """
        Import isolated SystemMemory records.

        Security approval is required. Imported records are forced into the
        current user_id/workspace_id to prevent cross-tenant data leakage.
        """
        action = "import_memory"
        context_result = self._validate_task_context(context)
        if not context_result["success"]:
            return context_result

        ctx = context_result["data"]

        security_result = self._request_security_approval(
            action=action,
            context=ctx,
            payload={
                "merge": merge,
                "overwrite_existing": overwrite_existing,
                "record_count": len(import_payload.get("records", []))
                if isinstance(import_payload, dict)
                else 0,
            },
        )
        if not security_result["success"]:
            self._log_audit_event(action, ctx, {"merge": merge}, False)
            return security_result

        if not isinstance(import_payload, dict):
            return self._error_result(
                message="Import payload must be a dictionary.",
                error_code="INVALID_IMPORT_PAYLOAD",
            )

        incoming_items = import_payload.get("records", [])
        if not isinstance(incoming_items, list):
            return self._error_result(
                message="Import payload records must be a list.",
                error_code="INVALID_IMPORT_RECORDS",
            )

        imported: List[MemoryRecord] = []
        skipped: List[Dict[str, Any]] = []

        for item in incoming_items:
            try:
                if not isinstance(item, dict):
                    skipped.append({"reason": "record_not_dict"})
                    continue

                memory_type = self._validate_memory_type(item.get("memory_type"))
                key = normalize_key(item.get("key"))

                if not memory_type or not key:
                    skipped.append({
                        "reason": "invalid_type_or_key",
                        "record": self._summarize_payload(item),
                    })
                    continue

                if is_sensitive_key(key):
                    skipped.append({
                        "reason": "sensitive_key_blocked",
                        "key": key,
                    })
                    continue

                record = MemoryRecord.from_dict(item)
                record.record_id = record.record_id or generate_id("sysmem")
                record.user_id = ctx["user_id"]
                record.workspace_id = ctx["workspace_id"]
                record.memory_type = memory_type
                record.key = key
                record.updated_at = utc_now_iso()

                imported.append(record)
            except Exception as exc:
                skipped.append({
                    "reason": "exception",
                    "error": str(exc),
                })

        with self._lock:
            existing = self._load(ctx)
            if not merge:
                existing = []

            existing_map: Dict[Tuple[str, str], MemoryRecord] = {
                (record.memory_type, record.key): record for record in existing
            }

            for record in imported:
                record_key = (record.memory_type, record.key)

                if record_key in existing_map and not overwrite_existing:
                    skipped.append({
                        "reason": "record_exists",
                        "memory_type": record.memory_type,
                        "key": record.key,
                    })
                    continue

                existing_map[record_key] = record

            merged_records = list(existing_map.values())
            merged_records = self._enforce_memory_limit(merged_records)
            self._save(ctx, merged_records)

        result = self._safe_result(
            message="System memory imported.",
            data={
                "imported_count": len(imported),
                "skipped_count": len(skipped),
                "skipped": skipped,
                "total_count": len(merged_records),
                "verification_payload": self._prepare_verification_payload(
                    action,
                    ctx,
                    {"success": True, "message": "System memory imported.", "metadata": {}},
                ),
            },
            metadata={
                "merge": merge,
                "overwrite_existing": overwrite_existing,
            },
        )

        self._emit_agent_event(
            "system_memory.imported",
            {
                "context": self._public_context(ctx),
                "imported_count": len(imported),
                "skipped_count": len(skipped),
            },
        )
        self._log_audit_event(
            action,
            ctx,
            {
                "imported_count": len(imported),
                "skipped_count": len(skipped),
            },
            True,
        )

        return result

    def build_profile_snapshot(
        self,
        context: Union[SystemMemoryContext, Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Build a clean System Agent profile snapshot.

        Master Agent can use this to route tasks with better context.
        """
        context_result = self._validate_task_context(context)
        if not context_result["success"]:
            return context_result

        ctx = context_result["data"]
        records = self._load(ctx)

        snapshot = {
            "folders": {},
            "apps": {},
            "device_settings": {},
            "workflow_preferences": {},
        }

        for record in records:
            if record.memory_type == "folder":
                snapshot["folders"][record.key] = record.to_dict()
            elif record.memory_type == "app":
                snapshot["apps"][record.key] = record.to_dict()
            elif record.memory_type == "device_setting":
                snapshot["device_settings"][record.key] = record.to_dict()
            elif record.memory_type == "workflow_preference":
                snapshot["workflow_preferences"][record.key] = record.to_dict()

        return self._safe_result(
            message="System memory profile snapshot prepared.",
            data={
                "snapshot": snapshot,
                "counts": {
                    "folders": len(snapshot["folders"]),
                    "apps": len(snapshot["apps"]),
                    "device_settings": len(snapshot["device_settings"]),
                    "workflow_preferences": len(snapshot["workflow_preferences"]),
                    "total": len(records),
                },
                "memory_payload": self._prepare_memory_payload(
                    "build_profile_snapshot",
                    ctx,
                    data={"counts": {"total": len(records)}},
                ),
            },
            metadata={"record_count": len(records)},
        )

    # -----------------------------------------------------------------------
    # Router / Agent Entry Point
    # -----------------------------------------------------------------------

    def handle_task(
        self,
        task: Dict[str, Any],
        context: Optional[Union[SystemMemoryContext, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Router-compatible entry point.

        The Agent Router / Master Agent can call this with:
            {
                "action": "remember_folder",
                "payload": {...}
            }
        """
        if not isinstance(task, dict):
            return self._error_result(
                message="Task must be a dictionary.",
                error_code="INVALID_TASK",
            )

        action = str(task.get("action") or "").strip()
        payload = ensure_dict(task.get("payload"))

        merged_context: Dict[str, Any] = {}
        if isinstance(context, SystemMemoryContext):
            merged_context.update(context.to_dict())
        elif isinstance(context, dict):
            merged_context.update(context)

        if isinstance(task.get("context"), dict):
            merged_context.update(task["context"])

        if not action:
            return self._error_result(
                message="Missing task action.",
                error_code="MISSING_TASK_ACTION",
            )

        route_map: Dict[str, Callable[..., Dict[str, Any]]] = {
            "remember_folder": self.remember_folder,
            "get_folder": self.get_folder,
            "list_folders": self.list_folders,
            "forget_folder": self.forget_folder,
            "remember_app": self.remember_app,
            "get_app": self.get_app,
            "list_apps": self.list_apps,
            "forget_app": self.forget_app,
            "remember_device_setting": self.remember_device_setting,
            "get_device_setting": self.get_device_setting,
            "list_device_settings": self.list_device_settings,
            "forget_device_setting": self.forget_device_setting,
            "remember_workflow_preference": self.remember_workflow_preference,
            "get_workflow_preference": self.get_workflow_preference,
            "list_workflow_preferences": self.list_workflow_preferences,
            "forget_workflow_preference": self.forget_workflow_preference,
            "list_memory": self.list_memory,
            "count_records": self.count_records,
            "clear_memory": self.clear_memory,
            "export_memory": self.export_memory,
            "import_memory": self.import_memory,
            "build_profile_snapshot": self.build_profile_snapshot,
        }

        handler = route_map.get(action)
        if handler is None:
            return self._error_result(
                message=f"Unsupported SystemMemory action: {action}",
                error_code="UNSUPPORTED_ACTION",
                metadata={"supported_actions": sorted(route_map.keys())},
            )

        try:
            if action == "remember_folder":
                return handler(
                    merged_context,
                    payload.get("folder_key") or payload.get("key"),
                    payload.get("folder_path") or payload.get("path") or payload.get("value"),
                    label=payload.get("label"),
                    description=payload.get("description"),
                    tags=payload.get("tags"),
                    metadata=payload.get("metadata"),
                )

            if action in {"get_folder", "forget_folder"}:
                return handler(
                    merged_context,
                    payload.get("folder_key") or payload.get("key"),
                )

            if action == "list_folders":
                return handler(merged_context, tags=payload.get("tags"))

            if action == "remember_app":
                return handler(
                    merged_context,
                    payload.get("app_key") or payload.get("key"),
                    payload.get("app_info") or payload.get("value"),
                    label=payload.get("label"),
                    description=payload.get("description"),
                    tags=payload.get("tags"),
                    metadata=payload.get("metadata"),
                )

            if action in {"get_app", "forget_app"}:
                return handler(
                    merged_context,
                    payload.get("app_key") or payload.get("key"),
                )

            if action == "list_apps":
                return handler(merged_context, tags=payload.get("tags"))

            if action == "remember_device_setting":
                return handler(
                    merged_context,
                    payload.get("setting_key") or payload.get("key"),
                    payload.get("setting_value") if "setting_value" in payload else payload.get("value"),
                    label=payload.get("label"),
                    description=payload.get("description"),
                    tags=payload.get("tags"),
                    metadata=payload.get("metadata"),
                )

            if action in {"get_device_setting", "forget_device_setting"}:
                return handler(
                    merged_context,
                    payload.get("setting_key") or payload.get("key"),
                )

            if action == "list_device_settings":
                return handler(merged_context, tags=payload.get("tags"))

            if action == "remember_workflow_preference":
                return handler(
                    merged_context,
                    payload.get("preference_key") or payload.get("key"),
                    payload.get("preference_value") if "preference_value" in payload else payload.get("value"),
                    label=payload.get("label"),
                    description=payload.get("description"),
                    tags=payload.get("tags"),
                    metadata=payload.get("metadata"),
                )

            if action in {"get_workflow_preference", "forget_workflow_preference"}:
                return handler(
                    merged_context,
                    payload.get("preference_key") or payload.get("key"),
                )

            if action == "list_workflow_preferences":
                return handler(merged_context, tags=payload.get("tags"))

            if action == "list_memory":
                return handler(
                    merged_context,
                    memory_type=payload.get("memory_type"),
                    tags=payload.get("tags"),
                )

            if action == "count_records":
                return handler(
                    merged_context,
                    memory_type=payload.get("memory_type"),
                )

            if action == "clear_memory":
                return handler(
                    merged_context,
                    memory_type=payload.get("memory_type"),
                )

            if action == "export_memory":
                return handler(
                    merged_context,
                    include_metadata=bool(payload.get("include_metadata", True)),
                )

            if action == "import_memory":
                return handler(
                    merged_context,
                    import_payload=payload.get("import_payload") or payload.get("export") or {},
                    merge=bool(payload.get("merge", True)),
                    overwrite_existing=bool(payload.get("overwrite_existing", False)),
                )

            if action == "build_profile_snapshot":
                return handler(merged_context)

            return self._error_result(
                message=f"Action mapping exists but execution is not configured: {action}",
                error_code="ACTION_EXECUTION_NOT_CONFIGURED",
            )

        except TypeError as exc:
            logger.exception("SystemMemory task parameter error: %s", exc)
            return self._error_result(
                message="Invalid parameters for SystemMemory task.",
                error_code="INVALID_TASK_PARAMETERS",
                error=str(exc),
                metadata={
                    "action": action,
                    "payload_keys": sorted(payload.keys()),
                },
            )
        except Exception as exc:
            logger.exception("SystemMemory task failed: %s", exc)
            return self._error_result(
                message="SystemMemory task failed.",
                error_code="TASK_FAILED",
                error=str(exc),
                metadata={"action": action},
            )

    # -----------------------------------------------------------------------
    # Internal Upsert / Load / Save Helpers
    # -----------------------------------------------------------------------

    def _upsert_memory(
        self,
        context: Union[SystemMemoryContext, Dict[str, Any]],
        memory_type: str,
        key: str,
        value: Any,
        label: Optional[str] = None,
        description: Optional[str] = None,
        tags: Optional[Iterable[Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        action: str = "upsert_memory",
    ) -> Dict[str, Any]:
        """Create or update one SystemMemory record."""
        context_result = self._validate_task_context(context)
        if not context_result["success"]:
            return context_result

        ctx = context_result["data"]
        normalized_type = self._validate_memory_type(memory_type)
        normalized_key = normalize_key(key)

        if not normalized_type:
            return self._error_result(
                message="Invalid memory_type.",
                error_code="INVALID_MEMORY_TYPE",
                metadata={"allowed": sorted(SUPPORTED_MEMORY_TYPES)},
            )

        if not normalized_key:
            return self._error_result(
                message="Missing memory key.",
                error_code="MISSING_MEMORY_KEY",
            )

        if value is None or value == "":
            return self._error_result(
                message="Missing memory value.",
                error_code="MISSING_MEMORY_VALUE",
            )

        payload = {
            "memory_type": normalized_type,
            "key": normalized_key,
            "value": value,
            "label": label,
            "description": description,
            "tags": list(tags or []),
            "metadata": metadata or {},
        }

        security_result = self._request_security_approval(
            action=action,
            context=ctx,
            payload=payload,
        )
        if not security_result["success"]:
            self._log_audit_event(action, ctx, payload, False)
            return security_result

        now = utc_now_iso()

        with self._lock:
            records = self._load(ctx)
            existing = self._find_record(records, normalized_type, normalized_key)

            if existing:
                existing.value = deep_copy(value)
                existing.label = label if label is not None else existing.label
                existing.description = (
                    description if description is not None else existing.description
                )
                existing.tags = sanitize_tags(tags) if tags is not None else existing.tags
                existing.metadata = {
                    **(existing.metadata or {}),
                    **(metadata or {}),
                }
                existing.updated_at = now
                record = existing
                operation = "updated"
            else:
                record = MemoryRecord(
                    record_id=generate_id("sysmem"),
                    user_id=ctx["user_id"],
                    workspace_id=ctx["workspace_id"],
                    memory_type=normalized_type,
                    key=normalized_key,
                    value=deep_copy(value),
                    label=label,
                    description=description,
                    tags=sanitize_tags(tags),
                    source="system_agent",
                    created_at=now,
                    updated_at=now,
                    metadata=metadata or {},
                )
                records.append(record)
                operation = "created"

            records = self._enforce_memory_limit(records)
            self._save(ctx, records)

        base_result = self._safe_result(
            message=f"System memory record {operation}.",
            data={
                "operation": operation,
                "record": record.to_dict(),
                "memory_payload": self._prepare_memory_payload(action, ctx, record),
            },
            metadata={
                "memory_type": normalized_type,
                "key": normalized_key,
            },
        )

        verification_payload = self._prepare_verification_payload(action, ctx, base_result)
        base_result["data"]["verification_payload"] = verification_payload

        self._emit_agent_event(
            "system_memory.upserted",
            {
                "context": self._public_context(ctx),
                "operation": operation,
                "memory_type": normalized_type,
                "key": normalized_key,
                "record_id": record.record_id,
            },
        )

        self._log_audit_event(action, ctx, payload, True)

        return base_result

    def _load(self, context: Dict[str, Any]) -> List[MemoryRecord]:
        """Load records from cache/storage."""
        cache_key = (str(context["user_id"]), str(context["workspace_id"]))

        with self._lock:
            if cache_key not in self._cache:
                self._cache[cache_key] = self.storage.load_records(
                    user_id=cache_key[0],
                    workspace_id=cache_key[1],
                )

            return [MemoryRecord.from_dict(record.to_dict()) for record in self._cache[cache_key]]

    def _save(self, context: Dict[str, Any], records: List[MemoryRecord]) -> None:
        """Save records to cache/storage."""
        user_id = str(context["user_id"])
        workspace_id = str(context["workspace_id"])
        cache_key = (user_id, workspace_id)

        isolated = [
            record
            for record in records
            if str(record.user_id) == user_id
            and str(record.workspace_id) == workspace_id
        ]

        self._cache[cache_key] = [MemoryRecord.from_dict(record.to_dict()) for record in isolated]
        self.storage.save_records(user_id, workspace_id, isolated)

    def _find_record(
        self,
        records: List[MemoryRecord],
        memory_type: str,
        key: str,
    ) -> Optional[MemoryRecord]:
        """Find one memory record by type/key."""
        normalized_type = self._validate_memory_type(memory_type)
        normalized_key = normalize_key(key)

        for record in records:
            if record.memory_type == normalized_type and record.key == normalized_key:
                return record

        return None

    def _validate_memory_type(self, memory_type: Any) -> Optional[str]:
        """Validate memory_type against supported types."""
        normalized = str(memory_type or "").strip().lower()
        return normalized if normalized in SUPPORTED_MEMORY_TYPES else None

    def _enforce_memory_limit(self, records: List[MemoryRecord]) -> List[MemoryRecord]:
        """
        Keep memory size bounded.

        The newest updated records are kept first.
        """
        if len(records) <= self.memory_limit:
            return records

        sorted_records = sorted(records, key=lambda item: item.updated_at, reverse=True)
        return sorted_records[: self.memory_limit]

    # -----------------------------------------------------------------------
    # Safety / Display Helpers
    # -----------------------------------------------------------------------

    def _public_context(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Return non-sensitive context fields for event/audit payloads."""
        return {
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "request_id": context.get("request_id"),
            "actor_id": context.get("actor_id"),
            "role": context.get("role"),
            "source": context.get("source"),
        }

    def _summarize_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Summarize payload without exposing sensitive values.
        """
        summary: Dict[str, Any] = {}

        for key, value in (payload or {}).items():
            key_text = str(key)

            if is_sensitive_key(key_text):
                summary[key_text] = "[REDACTED]"
                continue

            if key_text in {"value", "setting_value", "preference_value", "app_info"}:
                if isinstance(value, dict):
                    summary[key_text] = {
                        "type": "dict",
                        "keys": sorted([str(k) for k in value.keys()])[:30],
                    }
                elif isinstance(value, list):
                    summary[key_text] = {
                        "type": "list",
                        "count": len(value),
                    }
                else:
                    text = str(value)
                    summary[key_text] = text[:120] + ("..." if len(text) > 120 else "")
                continue

            if isinstance(value, (str, int, float, bool)) or value is None:
                text = str(value)
                summary[key_text] = text[:160] + ("..." if len(text) > 160 else "")
            elif isinstance(value, list):
                summary[key_text] = {
                    "type": "list",
                    "count": len(value),
                }
            elif isinstance(value, dict):
                summary[key_text] = {
                    "type": "dict",
                    "keys": sorted([str(k) for k in value.keys()])[:30],
                }
            else:
                summary[key_text] = {
                    "type": type(value).__name__,
                }

        return summary


# ---------------------------------------------------------------------------
# Convenience Factory
# ---------------------------------------------------------------------------

def create_system_memory(**kwargs: Any) -> SystemMemory:
    """
    Factory used by Agent Loader / Registry.

    Example:
        registry.register("system_memory", create_system_memory())
    """
    return SystemMemory(**kwargs)


# ---------------------------------------------------------------------------
# Simple Manual Test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    memory = SystemMemory(storage_dir=os.path.join(".william_data_test", "system_memory"))

    test_context = {
        "user_id": "demo_user",
        "workspace_id": "demo_workspace",
        "actor_id": "demo_actor",
        "role": "owner",
    }

    print(
        safe_json_dumps(
            memory.remember_folder(
                test_context,
                folder_key="downloads",
                folder_path="C:/Users/Demo/Downloads",
                label="Downloads Folder",
                description="Default downloads folder for this workspace.",
                tags=["files", "downloads"],
            )
        )
    )

    print(
        safe_json_dumps(
            memory.remember_app(
                test_context,
                app_key="chrome",
                app_info={
                    "name": "Google Chrome",
                    "platform": "desktop",
                    "package": "com.google.chrome",
                },
                tags=["browser"],
            )
        )
    )

    print(
        safe_json_dumps(
            memory.remember_device_setting(
                test_context,
                setting_key="preferred_brightness",
                setting_value="70%",
                tags=["device", "display"],
            )
        )
    )

    print(
        safe_json_dumps(
            memory.remember_workflow_preference(
                test_context,
                preference_key="default_export_format",
                preference_value="xlsx",
                tags=["workflow", "exports"],
            )
        )
    )

    print(safe_json_dumps(memory.build_profile_snapshot(test_context)))