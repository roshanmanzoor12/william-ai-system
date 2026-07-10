"""
agents/memory_agent/client_memory.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
Memory Agent - Client Memory Store

Purpose:
    Stores and manages client/business notes, proposals, campaigns, and deadlines
    with strict SaaS user/workspace isolation.

This module is import-safe, production-ready, and designed to integrate with:
    - Master Agent routing
    - Memory Agent
    - Security Agent
    - Verification Agent
    - Dashboard/API layer
    - Agent Registry / Agent Loader
    - Future database/vector-memory backends

Core guarantees:
    - Every user-specific operation requires user_id and workspace_id.
    - Data is never mixed across users/workspaces.
    - Sensitive/destructive operations are security-gated.
    - Every result uses structured dict format.
    - File can import even if other William modules are not created yet.
"""

from __future__ import annotations

import copy
import json
import logging
import os
import re
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Literal, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Safe optional imports / fallback stubs
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps the file import-safe before the full William/Jarvis agent
        framework is generated.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_type = kwargs.get("agent_type", "memory_agent")
            self.logger = logging.getLogger(self.agent_name)

        async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
            raise NotImplementedError("Fallback BaseAgent does not implement run().")


try:
    from agents.security_agent.security_agent import SecurityAgent  # type: ignore
except Exception:  # pragma: no cover
    SecurityAgent = None  # type: ignore


try:
    from agents.verification_agent.verification_agent import VerificationAgent  # type: ignore
except Exception:  # pragma: no cover
    VerificationAgent = None  # type: ignore


# ---------------------------------------------------------------------------
# Logger setup
# ---------------------------------------------------------------------------

LOGGER = logging.getLogger("ClientMemory")
if not LOGGER.handlers:
    logging.basicConfig(level=logging.INFO)


# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

MemoryKind = Literal["note", "proposal", "campaign", "deadline"]
MemoryStatus = Literal["active", "archived", "deleted", "completed", "cancelled"]
Priority = Literal["low", "normal", "medium", "high", "urgent"]
PrivacyLevel = Literal["public", "internal", "private", "restricted"]
ProposalStatus = Literal["draft", "sent", "accepted", "rejected", "expired", "archived"]
CampaignStatus = Literal["planned", "active", "paused", "completed", "cancelled", "archived"]
DeadlineStatus = Literal["pending", "completed", "overdue", "cancelled", "archived"]


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_STORAGE_DIR = Path(
    os.getenv(
        "WILLIAM_CLIENT_MEMORY_DIR",
        str(Path.cwd() / ".william_data" / "memory_agent" / "client_memory"),
    )
)

MAX_TITLE_LENGTH = 180
MAX_BODY_LENGTH = 50_000
MAX_TAG_LENGTH = 64
MAX_TAGS = 30
MAX_CLIENT_NAME_LENGTH = 180
MAX_SEARCH_LIMIT = 200
DEFAULT_SEARCH_LIMIT = 50

SENSITIVE_ACTIONS = {
    "delete",
    "bulk_delete",
    "export",
    "mark_deleted",
    "purge_deleted",
    "restore",
}

DESTRUCTIVE_ACTIONS = {
    "delete",
    "bulk_delete",
    "mark_deleted",
    "purge_deleted",
}


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    """Return timezone-aware UTC timestamp in ISO format."""
    return datetime.now(timezone.utc).isoformat()


def _safe_uuid() -> str:
    """Return a stable UUID string."""
    return str(uuid.uuid4())


def _normalize_text(value: Any, max_length: int = MAX_BODY_LENGTH) -> str:
    """Normalize user-provided text safely."""
    if value is None:
        return ""
    text = str(value).replace("\x00", "").strip()
    if len(text) > max_length:
        text = text[:max_length]
    return text


def _normalize_key(value: Any, max_length: int = 160) -> str:
    """
    Normalize identifiers such as user_id, workspace_id, client_id.

    Keeps IDs readable while removing dangerous path/control characters.
    """
    text = _normalize_text(value, max_length=max_length)
    text = re.sub(r"[^a-zA-Z0-9_.:@\-]", "_", text)
    text = text.strip("._-/\\ ")
    return text[:max_length]


def _normalize_tags(tags: Optional[Iterable[Any]]) -> List[str]:
    """Normalize a tag list."""
    if not tags:
        return []

    cleaned: List[str] = []
    seen = set()

    for tag in tags:
        value = _normalize_text(tag, max_length=MAX_TAG_LENGTH).lower()
        value = re.sub(r"\s+", "-", value)
        value = re.sub(r"[^a-z0-9_\-]", "", value)
        if not value or value in seen:
            continue
        cleaned.append(value)
        seen.add(value)
        if len(cleaned) >= MAX_TAGS:
            break

    return cleaned


def _parse_datetime(value: Optional[Any]) -> Optional[str]:
    """
    Parse date/datetime-like values into ISO string.

    Accepts:
        - None
        - datetime
        - ISO string
        - plain date string YYYY-MM-DD
    """
    if value in (None, ""):
        return None

    if isinstance(value, datetime):
        dt = value
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()

    text = _normalize_text(value, max_length=80)
    if not text:
        return None

    # YYYY-MM-DD fallback
    try:
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
            dt = datetime.fromisoformat(text + "T00:00:00+00:00")
            return dt.isoformat()

        normalized = text.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    except Exception:
        return text


def _deepcopy_jsonable(value: Any) -> Any:
    """Return a JSON-safe deep copy."""
    try:
        return json.loads(json.dumps(value, default=str))
    except Exception:
        return copy.deepcopy(value)


def _is_overdue(due_at: Optional[str], status: str) -> bool:
    """Check if a deadline date is overdue."""
    if not due_at or status in {"completed", "cancelled", "archived", "deleted"}:
        return False
    try:
        dt = datetime.fromisoformat(due_at.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt < datetime.now(timezone.utc)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class ClientMemoryRecord:
    """
    Generic client memory record.

    Used for notes, proposals, campaigns, and deadlines.
    """

    id: str
    kind: MemoryKind
    user_id: str
    workspace_id: str

    client_id: str = ""
    client_name: str = ""
    project_id: str = ""

    title: str = ""
    body: str = ""
    summary: str = ""

    status: str = "active"
    priority: Priority = "normal"
    privacy_level: PrivacyLevel = "internal"
    tags: List[str] = field(default_factory=list)

    amount: Optional[float] = None
    currency: str = "USD"

    proposal_status: Optional[ProposalStatus] = None
    campaign_status: Optional[CampaignStatus] = None
    deadline_status: Optional[DeadlineStatus] = None

    starts_at: Optional[str] = None
    ends_at: Optional[str] = None
    due_at: Optional[str] = None
    completed_at: Optional[str] = None

    assigned_to: List[str] = field(default_factory=list)
    related_ids: List[str] = field(default_factory=list)

    metadata: Dict[str, Any] = field(default_factory=dict)

    created_by: str = ""
    updated_by: str = ""
    created_at: str = field(default_factory=_utc_now)
    updated_at: str = field(default_factory=_utc_now)
    archived_at: Optional[str] = None
    deleted_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert record to JSON-style dict."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ClientMemoryRecord":
        """Create record from dict with safe defaults."""
        raw = dict(data or {})
        allowed = {field_name for field_name in cls.__dataclass_fields__.keys()}
        filtered = {key: value for key, value in raw.items() if key in allowed}

        if "id" not in filtered:
            filtered["id"] = _safe_uuid()
        if "kind" not in filtered:
            filtered["kind"] = "note"
        if "user_id" not in filtered:
            filtered["user_id"] = ""
        if "workspace_id" not in filtered:
            filtered["workspace_id"] = ""

        return cls(**filtered)


@dataclass
class ClientMemoryQuery:
    """Search/list query model for client memory."""

    user_id: str
    workspace_id: str
    kind: Optional[MemoryKind] = None
    client_id: Optional[str] = None
    client_name: Optional[str] = None
    project_id: Optional[str] = None
    status: Optional[str] = None
    tag: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    privacy_level: Optional[PrivacyLevel] = None
    priority: Optional[Priority] = None
    search: Optional[str] = None
    include_archived: bool = False
    include_deleted: bool = False
    due_before: Optional[str] = None
    due_after: Optional[str] = None
    limit: int = DEFAULT_SEARCH_LIMIT
    offset: int = 0
    sort_by: str = "updated_at"
    sort_dir: Literal["asc", "desc"] = "desc"


# ---------------------------------------------------------------------------
# Storage backend
# ---------------------------------------------------------------------------

class JsonClientMemoryStore:
    """
    Lightweight JSON storage backend.

    This is safe for development, local testing, and early dashboard/API
    integration. It is intentionally isolated by user_id/workspace_id.

    Future upgrade path:
        Replace this store with Postgres, Redis, Supabase, MongoDB, S3/R2,
        or encrypted object storage without changing ClientMemory public methods.
    """

    def __init__(self, storage_dir: Union[str, Path] = DEFAULT_STORAGE_DIR) -> None:
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    def _workspace_file(self, user_id: str, workspace_id: str) -> Path:
        safe_user = _normalize_key(user_id)
        safe_workspace = _normalize_key(workspace_id)
        if not safe_user or not safe_workspace:
            raise ValueError("user_id and workspace_id are required for storage isolation.")

        folder = self.storage_dir / safe_user
        folder.mkdir(parents=True, exist_ok=True)
        return folder / f"{safe_workspace}.json"

    def _load_workspace(self, user_id: str, workspace_id: str) -> Dict[str, Any]:
        path = self._workspace_file(user_id, workspace_id)

        if not path.exists():
            return {
                "schema_version": 1,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "records": [],
                "created_at": _utc_now(),
                "updated_at": _utc_now(),
            }

        with self._lock:
            try:
                with path.open("r", encoding="utf-8") as file:
                    data = json.load(file)
                if not isinstance(data, dict):
                    raise ValueError("Invalid client memory file format.")
                data.setdefault("records", [])
                data.setdefault("schema_version", 1)
                return data
            except json.JSONDecodeError as exc:
                raise ValueError(f"Client memory JSON is corrupted: {path}") from exc

    def _save_workspace(self, user_id: str, workspace_id: str, data: Dict[str, Any]) -> None:
        path = self._workspace_file(user_id, workspace_id)
        tmp_path = path.with_suffix(".tmp")

        data["user_id"] = user_id
        data["workspace_id"] = workspace_id
        data["updated_at"] = _utc_now()
        data.setdefault("schema_version", 1)
        data.setdefault("records", [])

        with self._lock:
            with tmp_path.open("w", encoding="utf-8") as file:
                json.dump(data, file, ensure_ascii=False, indent=2, default=str)
            tmp_path.replace(path)

    def list_records(self, user_id: str, workspace_id: str) -> List[Dict[str, Any]]:
        """List all records for isolated user/workspace."""
        data = self._load_workspace(user_id, workspace_id)
        records = data.get("records", [])
        return list(records if isinstance(records, list) else [])

    def upsert_record(self, record: ClientMemoryRecord) -> Dict[str, Any]:
        """Insert or update a record."""
        data = self._load_workspace(record.user_id, record.workspace_id)
        records = data.setdefault("records", [])
        record_dict = record.to_dict()

        replaced = False
        for index, existing in enumerate(records):
            if existing.get("id") == record.id:
                records[index] = record_dict
                replaced = True
                break

        if not replaced:
            records.append(record_dict)

        self._save_workspace(record.user_id, record.workspace_id, data)
        return record_dict

    def get_record(self, user_id: str, workspace_id: str, record_id: str) -> Optional[Dict[str, Any]]:
        """Get a record by ID within isolated user/workspace."""
        for record in self.list_records(user_id, workspace_id):
            if record.get("id") == record_id:
                return record
        return None

    def replace_records(
        self,
        user_id: str,
        workspace_id: str,
        records: List[Dict[str, Any]],
    ) -> None:
        """Replace the full isolated record set."""
        data = self._load_workspace(user_id, workspace_id)
        data["records"] = records
        self._save_workspace(user_id, workspace_id, data)


# ---------------------------------------------------------------------------
# ClientMemory
# ---------------------------------------------------------------------------

class ClientMemory(BaseAgent):
    """
    Client/business memory manager for William/Jarvis Memory Agent.

    Responsibilities:
        - Store client notes.
        - Store proposal data and proposal statuses.
        - Store campaign records and campaign statuses.
        - Store deadlines and deadline statuses.
        - Search and filter client/business memory.
        - Maintain strict SaaS user/workspace isolation.
        - Prepare Memory Agent and Verification Agent payloads.
        - Gate sensitive operations through Security Agent hooks.

    This class is intentionally API/dashboard friendly:
        - every public method returns structured dicts.
        - no hardcoded secrets.
        - no direct external destructive/system action.
    """

    agent_name = "ClientMemory"
    agent_type = "memory_agent"
    module_name = "client_memory"

    def __init__(
        self,
        storage_dir: Union[str, Path] = DEFAULT_STORAGE_DIR,
        security_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        logger: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        try:
            super().__init__(
                agent_name=self.agent_name,
                agent_type=self.agent_type,
                **kwargs,
            )
        except TypeError:
            super().__init__()

        self.logger = logger or logging.getLogger(self.agent_name)
        self.store = JsonClientMemoryStore(storage_dir=storage_dir)
        self.security_agent = security_agent
        self.verification_agent = verification_agent

        self._emit_agent_event(
            event_type="module_initialized",
            payload={
                "module": self.module_name,
                "storage_dir": str(storage_dir),
                "import_safe": True,
            },
        )

    # ------------------------------------------------------------------
    # Base / router entrypoint
    # ------------------------------------------------------------------

    async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Agent Router / Master Agent compatible async entrypoint.

        Expected task format:
            {
                "action": "add_note" | "list" | "search" | ...,
                "user_id": "...",
                "workspace_id": "...",
                "payload": {...}
            }
        """
        action = _normalize_text(task.get("action"), max_length=80)
        payload = task.get("payload") or {}

        if not isinstance(payload, dict):
            return self._error_result(
                message="Invalid task payload. Expected dict.",
                error="INVALID_PAYLOAD",
                metadata={"action": action},
            )

        merged = dict(payload)
        merged.setdefault("user_id", task.get("user_id"))
        merged.setdefault("workspace_id", task.get("workspace_id"))
        merged.setdefault("actor_id", task.get("actor_id") or task.get("user_id"))

        action_map = {
            "add_note": self.add_note,
            "create_note": self.add_note,
            "add_proposal": self.add_proposal,
            "create_proposal": self.add_proposal,
            "add_campaign": self.add_campaign,
            "create_campaign": self.add_campaign,
            "add_deadline": self.add_deadline,
            "create_deadline": self.add_deadline,
            "get": self.get_record,
            "get_record": self.get_record,
            "list": self.list_records,
            "list_records": self.list_records,
            "search": self.search_records,
            "update": self.update_record,
            "update_record": self.update_record,
            "archive": self.archive_record,
            "archive_record": self.archive_record,
            "restore": self.restore_record,
            "restore_record": self.restore_record,
            "delete": self.delete_record,
            "delete_record": self.delete_record,
            "complete_deadline": self.complete_deadline,
            "mark_deadline_completed": self.complete_deadline,
            "upcoming_deadlines": self.upcoming_deadlines,
            "overdue_deadlines": self.overdue_deadlines,
            "client_summary": self.get_client_summary,
            "get_client_summary": self.get_client_summary,
            "export": self.export_records,
            "export_records": self.export_records,
        }

        handler = action_map.get(action)
        if not handler:
            return self._error_result(
                message=f"Unsupported ClientMemory action: {action}",
                error="UNSUPPORTED_ACTION",
                metadata={"available_actions": sorted(action_map.keys())},
            )

        try:
            result = handler(**merged)
            return result
        except TypeError as exc:
            return self._error_result(
                message="Invalid arguments for ClientMemory action.",
                error=str(exc),
                metadata={"action": action},
            )
        except Exception as exc:
            self.logger.exception("ClientMemory run() failed.")
            return self._error_result(
                message="ClientMemory action failed.",
                error=str(exc),
                metadata={"action": action},
            )

    # ------------------------------------------------------------------
    # Public create methods
    # ------------------------------------------------------------------

    def add_note(
        self,
        user_id: str,
        workspace_id: str,
        title: str,
        body: str,
        client_id: str = "",
        client_name: str = "",
        project_id: str = "",
        tags: Optional[Iterable[Any]] = None,
        priority: Priority = "normal",
        privacy_level: PrivacyLevel = "internal",
        actor_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **_: Any,
    ) -> Dict[str, Any]:
        """Create a client/business note."""
        context = self._validate_task_context(user_id, workspace_id, actor_id)
        if not context["success"]:
            return context

        record = self._build_record(
            kind="note",
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id or user_id,
            title=title,
            body=body,
            client_id=client_id,
            client_name=client_name,
            project_id=project_id,
            tags=tags,
            priority=priority,
            privacy_level=privacy_level,
            status="active",
            metadata=metadata or {},
        )

        return self._save_and_return(
            record=record,
            action="add_note",
            message="Client note stored successfully.",
        )

    def add_proposal(
        self,
        user_id: str,
        workspace_id: str,
        title: str,
        body: str,
        client_id: str = "",
        client_name: str = "",
        project_id: str = "",
        amount: Optional[Union[int, float, str]] = None,
        currency: str = "USD",
        proposal_status: ProposalStatus = "draft",
        due_at: Optional[Any] = None,
        tags: Optional[Iterable[Any]] = None,
        priority: Priority = "normal",
        privacy_level: PrivacyLevel = "internal",
        actor_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **_: Any,
    ) -> Dict[str, Any]:
        """Create a client proposal memory record."""
        context = self._validate_task_context(user_id, workspace_id, actor_id)
        if not context["success"]:
            return context

        amount_value = self._safe_amount(amount)

        record = self._build_record(
            kind="proposal",
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id or user_id,
            title=title,
            body=body,
            client_id=client_id,
            client_name=client_name,
            project_id=project_id,
            tags=tags,
            priority=priority,
            privacy_level=privacy_level,
            status="active",
            due_at=due_at,
            metadata=metadata or {},
        )
        record.amount = amount_value
        record.currency = _normalize_text(currency, max_length=12).upper() or "USD"
        record.proposal_status = proposal_status

        return self._save_and_return(
            record=record,
            action="add_proposal",
            message="Client proposal stored successfully.",
        )

    def add_campaign(
        self,
        user_id: str,
        workspace_id: str,
        title: str,
        body: str = "",
        client_id: str = "",
        client_name: str = "",
        project_id: str = "",
        campaign_status: CampaignStatus = "planned",
        starts_at: Optional[Any] = None,
        ends_at: Optional[Any] = None,
        tags: Optional[Iterable[Any]] = None,
        priority: Priority = "normal",
        privacy_level: PrivacyLevel = "internal",
        actor_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **_: Any,
    ) -> Dict[str, Any]:
        """Create a marketing/sales/business campaign memory record."""
        context = self._validate_task_context(user_id, workspace_id, actor_id)
        if not context["success"]:
            return context

        record = self._build_record(
            kind="campaign",
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id or user_id,
            title=title,
            body=body,
            client_id=client_id,
            client_name=client_name,
            project_id=project_id,
            tags=tags,
            priority=priority,
            privacy_level=privacy_level,
            status="active",
            starts_at=starts_at,
            ends_at=ends_at,
            metadata=metadata or {},
        )
        record.campaign_status = campaign_status

        return self._save_and_return(
            record=record,
            action="add_campaign",
            message="Client campaign stored successfully.",
        )

    def add_deadline(
        self,
        user_id: str,
        workspace_id: str,
        title: str,
        due_at: Any,
        body: str = "",
        client_id: str = "",
        client_name: str = "",
        project_id: str = "",
        assigned_to: Optional[Iterable[Any]] = None,
        tags: Optional[Iterable[Any]] = None,
        priority: Priority = "normal",
        privacy_level: PrivacyLevel = "internal",
        actor_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **_: Any,
    ) -> Dict[str, Any]:
        """Create a client/project deadline memory record."""
        context = self._validate_task_context(user_id, workspace_id, actor_id)
        if not context["success"]:
            return context

        parsed_due = _parse_datetime(due_at)
        if not parsed_due:
            return self._error_result(
                message="Deadline requires a valid due_at value.",
                error="INVALID_DUE_AT",
            )

        record = self._build_record(
            kind="deadline",
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id or user_id,
            title=title,
            body=body,
            client_id=client_id,
            client_name=client_name,
            project_id=project_id,
            tags=tags,
            priority=priority,
            privacy_level=privacy_level,
            status="active",
            due_at=parsed_due,
            metadata=metadata or {},
        )
        record.deadline_status = "pending"
        record.assigned_to = [
            _normalize_key(value, max_length=120)
            for value in (assigned_to or [])
            if _normalize_key(value, max_length=120)
        ]

        return self._save_and_return(
            record=record,
            action="add_deadline",
            message="Client deadline stored successfully.",
        )

    # ------------------------------------------------------------------
    # Public read/search methods
    # ------------------------------------------------------------------

    def get_record(
        self,
        user_id: str,
        workspace_id: str,
        record_id: str,
        actor_id: Optional[str] = None,
        **_: Any,
    ) -> Dict[str, Any]:
        """Get one record by ID with strict user/workspace isolation."""
        context = self._validate_task_context(user_id, workspace_id, actor_id)
        if not context["success"]:
            return context

        safe_id = _normalize_key(record_id, max_length=80)
        if not safe_id:
            return self._error_result(
                message="record_id is required.",
                error="MISSING_RECORD_ID",
            )

        record = self.store.get_record(user_id, workspace_id, safe_id)
        if not record or record.get("deleted_at"):
            return self._error_result(
                message="Client memory record not found.",
                error="NOT_FOUND",
                metadata={"record_id": safe_id},
            )

        return self._safe_result(
            message="Client memory record found.",
            data={"record": record},
            metadata={
                "verification": self._prepare_verification_payload(
                    action="get_record",
                    user_id=user_id,
                    workspace_id=workspace_id,
                    record_id=safe_id,
                )
            },
        )

    def list_records(
        self,
        user_id: str,
        workspace_id: str,
        kind: Optional[MemoryKind] = None,
        client_id: Optional[str] = None,
        status: Optional[str] = None,
        include_archived: bool = False,
        include_deleted: bool = False,
        limit: int = DEFAULT_SEARCH_LIMIT,
        offset: int = 0,
        actor_id: Optional[str] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """List records with common filters."""
        return self.search_records(
            user_id=user_id,
            workspace_id=workspace_id,
            kind=kind,
            client_id=client_id,
            status=status,
            include_archived=include_archived,
            include_deleted=include_deleted,
            limit=limit,
            offset=offset,
            actor_id=actor_id,
            **kwargs,
        )

    def search_records(
        self,
        user_id: str,
        workspace_id: str,
        kind: Optional[MemoryKind] = None,
        client_id: Optional[str] = None,
        client_name: Optional[str] = None,
        project_id: Optional[str] = None,
        status: Optional[str] = None,
        tag: Optional[str] = None,
        tags: Optional[Iterable[Any]] = None,
        privacy_level: Optional[PrivacyLevel] = None,
        priority: Optional[Priority] = None,
        search: Optional[str] = None,
        include_archived: bool = False,
        include_deleted: bool = False,
        due_before: Optional[Any] = None,
        due_after: Optional[Any] = None,
        limit: int = DEFAULT_SEARCH_LIMIT,
        offset: int = 0,
        sort_by: str = "updated_at",
        sort_dir: Literal["asc", "desc"] = "desc",
        actor_id: Optional[str] = None,
        **_: Any,
    ) -> Dict[str, Any]:
        """Search client memory records."""
        context = self._validate_task_context(user_id, workspace_id, actor_id)
        if not context["success"]:
            return context

        query = ClientMemoryQuery(
            user_id=user_id,
            workspace_id=workspace_id,
            kind=kind,
            client_id=_normalize_key(client_id, 160) if client_id else None,
            client_name=_normalize_text(client_name, MAX_CLIENT_NAME_LENGTH).lower() if client_name else None,
            project_id=_normalize_key(project_id, 160) if project_id else None,
            status=_normalize_text(status, 40) if status else None,
            tag=_normalize_tags([tag])[0] if tag else None,
            tags=_normalize_tags(tags),
            privacy_level=privacy_level,
            priority=priority,
            search=_normalize_text(search, 500).lower() if search else None,
            include_archived=bool(include_archived),
            include_deleted=bool(include_deleted),
            due_before=_parse_datetime(due_before),
            due_after=_parse_datetime(due_after),
            limit=self._safe_limit(limit),
            offset=max(0, int(offset or 0)),
            sort_by=_normalize_text(sort_by, 50) or "updated_at",
            sort_dir=sort_dir if sort_dir in {"asc", "desc"} else "desc",
        )

        records = [
            ClientMemoryRecord.from_dict(record).to_dict()
            for record in self.store.list_records(user_id, workspace_id)
        ]

        filtered = [record for record in records if self._record_matches_query(record, query)]
        filtered = self._sort_records(filtered, query.sort_by, query.sort_dir)

        total = len(filtered)
        page = filtered[query.offset: query.offset + query.limit]

        self._emit_agent_event(
            event_type="client_memory_search",
            payload={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "kind": kind,
                "total": total,
                "returned": len(page),
            },
        )

        return self._safe_result(
            message="Client memory records retrieved successfully.",
            data={
                "records": page,
                "total": total,
                "limit": query.limit,
                "offset": query.offset,
            },
            metadata={
                "query": _deepcopy_jsonable(asdict(query)),
                "memory_payload": self._prepare_memory_payload(
                    action="search_records",
                    user_id=user_id,
                    workspace_id=workspace_id,
                    records=page,
                ),
                "verification": self._prepare_verification_payload(
                    action="search_records",
                    user_id=user_id,
                    workspace_id=workspace_id,
                    record_count=len(page),
                ),
            },
        )

    # ------------------------------------------------------------------
    # Public update/status methods
    # ------------------------------------------------------------------

    def update_record(
        self,
        user_id: str,
        workspace_id: str,
        record_id: str,
        updates: Optional[Dict[str, Any]] = None,
        actor_id: Optional[str] = None,
        **direct_updates: Any,
    ) -> Dict[str, Any]:
        """Update an existing client memory record."""
        context = self._validate_task_context(user_id, workspace_id, actor_id)
        if not context["success"]:
            return context

        safe_id = _normalize_key(record_id, max_length=80)
        payload = dict(updates or {})
        payload.update({k: v for k, v in direct_updates.items() if k not in {"_", "kwargs"}})

        existing = self.store.get_record(user_id, workspace_id, safe_id)
        if not existing or existing.get("deleted_at"):
            return self._error_result(
                message="Client memory record not found.",
                error="NOT_FOUND",
                metadata={"record_id": safe_id},
            )

        record = ClientMemoryRecord.from_dict(existing)
        allowed_fields = {
            "title",
            "body",
            "summary",
            "client_id",
            "client_name",
            "project_id",
            "status",
            "priority",
            "privacy_level",
            "tags",
            "amount",
            "currency",
            "proposal_status",
            "campaign_status",
            "deadline_status",
            "starts_at",
            "ends_at",
            "due_at",
            "completed_at",
            "assigned_to",
            "related_ids",
            "metadata",
        }

        changed_fields: List[str] = []

        for key, value in payload.items():
            if key not in allowed_fields:
                continue

            normalized = self._normalize_field_update(key, value)
            setattr(record, key, normalized)
            changed_fields.append(key)

        record.updated_at = _utc_now()
        record.updated_by = _normalize_key(actor_id or user_id, 160)

        if record.kind == "deadline":
            if record.deadline_status == "completed" and not record.completed_at:
                record.completed_at = _utc_now()
            elif record.deadline_status in {"pending", "overdue"}:
                record.completed_at = None

        saved = self.store.upsert_record(record)

        self._log_audit_event(
            action="update_record",
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id or user_id,
            resource_id=record.id,
            metadata={"changed_fields": changed_fields},
        )

        return self._safe_result(
            message="Client memory record updated successfully.",
            data={"record": saved, "changed_fields": changed_fields},
            metadata={
                "memory_payload": self._prepare_memory_payload(
                    action="update_record",
                    user_id=user_id,
                    workspace_id=workspace_id,
                    record=saved,
                ),
                "verification": self._prepare_verification_payload(
                    action="update_record",
                    user_id=user_id,
                    workspace_id=workspace_id,
                    record_id=record.id,
                    changed_fields=changed_fields,
                ),
            },
        )

    def archive_record(
        self,
        user_id: str,
        workspace_id: str,
        record_id: str,
        actor_id: Optional[str] = None,
        **_: Any,
    ) -> Dict[str, Any]:
        """Archive a record without deleting it."""
        return self.update_record(
            user_id=user_id,
            workspace_id=workspace_id,
            record_id=record_id,
            updates={
                "status": "archived",
                "metadata": {"archived_reason": "Archived by user/system request."},
            },
            actor_id=actor_id,
        )

    def restore_record(
        self,
        user_id: str,
        workspace_id: str,
        record_id: str,
        actor_id: Optional[str] = None,
        security_context: Optional[Dict[str, Any]] = None,
        **_: Any,
    ) -> Dict[str, Any]:
        """Restore archived or soft-deleted record."""
        context = self._validate_task_context(user_id, workspace_id, actor_id)
        if not context["success"]:
            return context

        if self._requires_security_check("restore"):
            approval = self._request_security_approval(
                action="restore",
                user_id=user_id,
                workspace_id=workspace_id,
                actor_id=actor_id or user_id,
                resource_id=record_id,
                security_context=security_context,
            )
            if not approval["success"]:
                return approval

        safe_id = _normalize_key(record_id, 80)
        existing = self.store.get_record(user_id, workspace_id, safe_id)
        if not existing:
            return self._error_result(
                message="Client memory record not found.",
                error="NOT_FOUND",
                metadata={"record_id": safe_id},
            )

        record = ClientMemoryRecord.from_dict(existing)
        record.status = "active"
        record.archived_at = None
        record.deleted_at = None
        record.updated_at = _utc_now()
        record.updated_by = _normalize_key(actor_id or user_id, 160)

        saved = self.store.upsert_record(record)

        self._log_audit_event(
            action="restore_record",
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id or user_id,
            resource_id=record.id,
        )

        return self._safe_result(
            message="Client memory record restored successfully.",
            data={"record": saved},
            metadata={
                "verification": self._prepare_verification_payload(
                    action="restore_record",
                    user_id=user_id,
                    workspace_id=workspace_id,
                    record_id=record.id,
                )
            },
        )

    def delete_record(
        self,
        user_id: str,
        workspace_id: str,
        record_id: str,
        actor_id: Optional[str] = None,
        hard_delete: bool = False,
        security_context: Optional[Dict[str, Any]] = None,
        **_: Any,
    ) -> Dict[str, Any]:
        """
        Delete a record.

        Default behavior is soft delete.
        Hard delete requires security approval and should normally be reserved
        for privacy/compliance tools.
        """
        context = self._validate_task_context(user_id, workspace_id, actor_id)
        if not context["success"]:
            return context

        action = "purge_deleted" if hard_delete else "delete"

        if self._requires_security_check(action):
            approval = self._request_security_approval(
                action=action,
                user_id=user_id,
                workspace_id=workspace_id,
                actor_id=actor_id or user_id,
                resource_id=record_id,
                security_context=security_context,
            )
            if not approval["success"]:
                return approval

        safe_id = _normalize_key(record_id, 80)
        records = self.store.list_records(user_id, workspace_id)

        existing_index = None
        existing_record = None
        for index, item in enumerate(records):
            if item.get("id") == safe_id:
                existing_index = index
                existing_record = item
                break

        if existing_index is None or existing_record is None:
            return self._error_result(
                message="Client memory record not found.",
                error="NOT_FOUND",
                metadata={"record_id": safe_id},
            )

        if hard_delete:
            records.pop(existing_index)
            self.store.replace_records(user_id, workspace_id, records)
            deleted_data = {"record_id": safe_id, "hard_deleted": True}
        else:
            record = ClientMemoryRecord.from_dict(existing_record)
            record.status = "deleted"
            record.deleted_at = _utc_now()
            record.updated_at = _utc_now()
            record.updated_by = _normalize_key(actor_id or user_id, 160)
            records[existing_index] = record.to_dict()
            self.store.replace_records(user_id, workspace_id, records)
            deleted_data = {"record": record.to_dict(), "hard_deleted": False}

        self._log_audit_event(
            action="delete_record",
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id or user_id,
            resource_id=safe_id,
            metadata={"hard_delete": hard_delete},
        )

        return self._safe_result(
            message="Client memory record deleted successfully.",
            data=deleted_data,
            metadata={
                "verification": self._prepare_verification_payload(
                    action="delete_record",
                    user_id=user_id,
                    workspace_id=workspace_id,
                    record_id=safe_id,
                    hard_delete=hard_delete,
                )
            },
        )

    def complete_deadline(
        self,
        user_id: str,
        workspace_id: str,
        record_id: str,
        actor_id: Optional[str] = None,
        completion_note: str = "",
        **_: Any,
    ) -> Dict[str, Any]:
        """Mark a deadline record as completed."""
        existing = self.store.get_record(user_id, workspace_id, _normalize_key(record_id, 80))
        if not existing:
            return self._error_result(
                message="Deadline record not found.",
                error="NOT_FOUND",
                metadata={"record_id": record_id},
            )

        if existing.get("kind") != "deadline":
            return self._error_result(
                message="Record is not a deadline.",
                error="INVALID_RECORD_KIND",
                metadata={"record_id": record_id, "kind": existing.get("kind")},
            )

        metadata = dict(existing.get("metadata") or {})
        if completion_note:
            metadata["completion_note"] = _normalize_text(completion_note, 5000)

        return self.update_record(
            user_id=user_id,
            workspace_id=workspace_id,
            record_id=record_id,
            updates={
                "deadline_status": "completed",
                "status": "completed",
                "completed_at": _utc_now(),
                "metadata": metadata,
            },
            actor_id=actor_id,
        )

    # ------------------------------------------------------------------
    # Deadline helpers
    # ------------------------------------------------------------------

    def upcoming_deadlines(
        self,
        user_id: str,
        workspace_id: str,
        client_id: Optional[str] = None,
        project_id: Optional[str] = None,
        limit: int = DEFAULT_SEARCH_LIMIT,
        actor_id: Optional[str] = None,
        **_: Any,
    ) -> Dict[str, Any]:
        """Return pending future deadlines."""
        result = self.search_records(
            user_id=user_id,
            workspace_id=workspace_id,
            kind="deadline",
            client_id=client_id,
            project_id=project_id,
            include_archived=False,
            include_deleted=False,
            limit=MAX_SEARCH_LIMIT,
            sort_by="due_at",
            sort_dir="asc",
            actor_id=actor_id,
        )

        if not result["success"]:
            return result

        now = datetime.now(timezone.utc)
        upcoming: List[Dict[str, Any]] = []

        for record in result["data"]["records"]:
            due_at = record.get("due_at")
            status = record.get("deadline_status") or record.get("status")
            if status in {"completed", "cancelled", "archived", "deleted"}:
                continue
            try:
                due_dt = datetime.fromisoformat(str(due_at).replace("Z", "+00:00"))
                if due_dt.tzinfo is None:
                    due_dt = due_dt.replace(tzinfo=timezone.utc)
                if due_dt >= now:
                    upcoming.append(record)
            except Exception:
                continue

        safe_limit = self._safe_limit(limit)
        return self._safe_result(
            message="Upcoming client deadlines retrieved successfully.",
            data={
                "records": upcoming[:safe_limit],
                "total": len(upcoming),
                "limit": safe_limit,
            },
        )

    def overdue_deadlines(
        self,
        user_id: str,
        workspace_id: str,
        client_id: Optional[str] = None,
        project_id: Optional[str] = None,
        limit: int = DEFAULT_SEARCH_LIMIT,
        actor_id: Optional[str] = None,
        **_: Any,
    ) -> Dict[str, Any]:
        """Return overdue deadlines and mark their derived status in response."""
        result = self.search_records(
            user_id=user_id,
            workspace_id=workspace_id,
            kind="deadline",
            client_id=client_id,
            project_id=project_id,
            include_archived=False,
            include_deleted=False,
            limit=MAX_SEARCH_LIMIT,
            sort_by="due_at",
            sort_dir="asc",
            actor_id=actor_id,
        )

        if not result["success"]:
            return result

        overdue: List[Dict[str, Any]] = []

        for record in result["data"]["records"]:
            if _is_overdue(record.get("due_at"), record.get("deadline_status") or record.get("status")):
                item = dict(record)
                item["derived_status"] = "overdue"
                overdue.append(item)

        safe_limit = self._safe_limit(limit)
        return self._safe_result(
            message="Overdue client deadlines retrieved successfully.",
            data={
                "records": overdue[:safe_limit],
                "total": len(overdue),
                "limit": safe_limit,
            },
        )

    # ------------------------------------------------------------------
    # Summary/export methods
    # ------------------------------------------------------------------

    def get_client_summary(
        self,
        user_id: str,
        workspace_id: str,
        client_id: Optional[str] = None,
        client_name: Optional[str] = None,
        actor_id: Optional[str] = None,
        **_: Any,
    ) -> Dict[str, Any]:
        """Return dashboard/API-friendly client summary."""
        result = self.search_records(
            user_id=user_id,
            workspace_id=workspace_id,
            client_id=client_id,
            client_name=client_name,
            include_archived=True,
            include_deleted=False,
            limit=MAX_SEARCH_LIMIT,
            actor_id=actor_id,
        )

        if not result["success"]:
            return result

        records = result["data"]["records"]
        summary = {
            "client_id": client_id or "",
            "client_name": client_name or "",
            "total_records": len(records),
            "notes": 0,
            "proposals": {
                "total": 0,
                "draft": 0,
                "sent": 0,
                "accepted": 0,
                "rejected": 0,
                "expired": 0,
                "archived": 0,
                "total_amount": 0.0,
            },
            "campaigns": {
                "total": 0,
                "planned": 0,
                "active": 0,
                "paused": 0,
                "completed": 0,
                "cancelled": 0,
                "archived": 0,
            },
            "deadlines": {
                "total": 0,
                "pending": 0,
                "completed": 0,
                "overdue": 0,
                "cancelled": 0,
                "archived": 0,
            },
            "recent_records": records[:10],
            "updated_at": _utc_now(),
        }

        for record in records:
            kind = record.get("kind")
            if kind == "note":
                summary["notes"] += 1

            elif kind == "proposal":
                summary["proposals"]["total"] += 1
                proposal_status = record.get("proposal_status") or "draft"
                if proposal_status in summary["proposals"]:
                    summary["proposals"][proposal_status] += 1
                if isinstance(record.get("amount"), (int, float)):
                    summary["proposals"]["total_amount"] += float(record["amount"])

            elif kind == "campaign":
                summary["campaigns"]["total"] += 1
                campaign_status = record.get("campaign_status") or "planned"
                if campaign_status in summary["campaigns"]:
                    summary["campaigns"][campaign_status] += 1

            elif kind == "deadline":
                summary["deadlines"]["total"] += 1
                deadline_status = record.get("deadline_status") or "pending"
                if _is_overdue(record.get("due_at"), deadline_status):
                    summary["deadlines"]["overdue"] += 1
                elif deadline_status in summary["deadlines"]:
                    summary["deadlines"][deadline_status] += 1

        return self._safe_result(
            message="Client summary generated successfully.",
            data={"summary": summary},
            metadata={
                "memory_payload": self._prepare_memory_payload(
                    action="get_client_summary",
                    user_id=user_id,
                    workspace_id=workspace_id,
                    records=records,
                    summary=summary,
                ),
                "verification": self._prepare_verification_payload(
                    action="get_client_summary",
                    user_id=user_id,
                    workspace_id=workspace_id,
                    record_count=len(records),
                ),
            },
        )

    def export_records(
        self,
        user_id: str,
        workspace_id: str,
        actor_id: Optional[str] = None,
        security_context: Optional[Dict[str, Any]] = None,
        **filters: Any,
    ) -> Dict[str, Any]:
        """
        Export filtered client memory records.

        Security gated because exports may expose client/business-sensitive data.
        This method returns data only; it does not write external files or send data.
        """
        context = self._validate_task_context(user_id, workspace_id, actor_id)
        if not context["success"]:
            return context

        if self._requires_security_check("export"):
            approval = self._request_security_approval(
                action="export",
                user_id=user_id,
                workspace_id=workspace_id,
                actor_id=actor_id or user_id,
                resource_id="client_memory_export",
                security_context=security_context,
            )
            if not approval["success"]:
                return approval

        result = self.search_records(
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id,
            include_archived=bool(filters.pop("include_archived", True)),
            include_deleted=bool(filters.pop("include_deleted", False)),
            limit=MAX_SEARCH_LIMIT,
            **filters,
        )

        if not result["success"]:
            return result

        export_payload = {
            "schema_version": 1,
            "exported_at": _utc_now(),
            "user_id": user_id,
            "workspace_id": workspace_id,
            "record_count": result["data"]["total"],
            "records": result["data"]["records"],
        }

        self._log_audit_event(
            action="export_records",
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id or user_id,
            metadata={"record_count": result["data"]["total"]},
        )

        return self._safe_result(
            message="Client memory export prepared successfully.",
            data={"export": export_payload},
            metadata={
                "verification": self._prepare_verification_payload(
                    action="export_records",
                    user_id=user_id,
                    workspace_id=workspace_id,
                    record_count=result["data"]["total"],
                )
            },
        )

    # ------------------------------------------------------------------
    # Compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(
        self,
        user_id: Optional[str],
        workspace_id: Optional[str],
        actor_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Validate SaaS context.

        This is the main isolation gate. Every user-specific operation must
        pass through this method.
        """
        safe_user = _normalize_key(user_id, 160)
        safe_workspace = _normalize_key(workspace_id, 160)
        safe_actor = _normalize_key(actor_id or user_id, 160)

        if not safe_user:
            return self._error_result(
                message="user_id is required for client memory isolation.",
                error="MISSING_USER_ID",
            )

        if not safe_workspace:
            return self._error_result(
                message="workspace_id is required for client memory isolation.",
                error="MISSING_WORKSPACE_ID",
            )

        return self._safe_result(
            message="Task context validated.",
            data={
                "user_id": safe_user,
                "workspace_id": safe_workspace,
                "actor_id": safe_actor,
            },
        )

    def _requires_security_check(self, action: str) -> bool:
        """Return whether an action must be approved by Security Agent."""
        normalized = _normalize_text(action, 80).lower()
        return normalized in SENSITIVE_ACTIONS or normalized in DESTRUCTIVE_ACTIONS

    def _request_security_approval(
        self,
        action: str,
        user_id: str,
        workspace_id: str,
        actor_id: str,
        resource_id: str = "",
        security_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        Fallback behavior:
            If no Security Agent exists yet, allow soft operations but deny
            hard destructive operations unless explicitly marked approved in
            security_context.
        """
        security_context = dict(security_context or {})

        if security_context.get("approved") is True:
            return self._safe_result(
                message="Security approval already provided.",
                data={"approved": True, "source": "security_context"},
            )

        if self.security_agent and hasattr(self.security_agent, "approve_action"):
            try:
                approval = self.security_agent.approve_action(
                    action=action,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    actor_id=actor_id,
                    resource_id=resource_id,
                    context=security_context,
                )
                if isinstance(approval, dict) and approval.get("success"):
                    return self._safe_result(
                        message="Security Agent approved action.",
                        data={"approved": True, "source": "security_agent"},
                    )
                return self._error_result(
                    message="Security Agent rejected or failed the action.",
                    error="SECURITY_REJECTED",
                    metadata={"approval": approval},
                )
            except Exception as exc:
                self.logger.warning("Security approval failed: %s", exc)
                return self._error_result(
                    message="Security approval failed.",
                    error=str(exc),
                )

        if action in {"purge_deleted", "bulk_delete"}:
            return self._error_result(
                message=(
                    "Security Agent is not available. Hard destructive client "
                    "memory actions require explicit security_context approved=True."
                ),
                error="SECURITY_AGENT_REQUIRED",
                metadata={
                    "action": action,
                    "resource_id": resource_id,
                },
            )

        return self._safe_result(
            message="Security approval fallback allowed this guarded operation.",
            data={
                "approved": True,
                "source": "fallback_policy",
                "warning": "Security Agent not available yet.",
            },
        )

    def _prepare_verification_payload(self, action: str, **kwargs: Any) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        This file does not call the Verification Agent directly by default.
        The Master Agent or API layer can forward this payload after completion.
        """
        return {
            "agent": self.agent_name,
            "module": self.module_name,
            "action": action,
            "timestamp": _utc_now(),
            "checks": {
                "saaS_isolation": bool(kwargs.get("user_id") and kwargs.get("workspace_id")),
                "structured_result": True,
                "security_checked_if_required": self._requires_security_check(action),
            },
            "context": _deepcopy_jsonable(kwargs),
        }

    def _prepare_memory_payload(self, action: str, **kwargs: Any) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        Used by the Memory Agent to index useful client/business context into
        short-term, long-term, project memory, embeddings, or knowledge graph.
        """
        return {
            "source_agent": self.agent_name,
            "source_module": self.module_name,
            "action": action,
            "timestamp": _utc_now(),
            "memory_type": "client_business_memory",
            "privacy_level": kwargs.get("privacy_level", "internal"),
            "user_id": kwargs.get("user_id"),
            "workspace_id": kwargs.get("workspace_id"),
            "payload": _deepcopy_jsonable(kwargs),
        }

    def _emit_agent_event(self, event_type: str, payload: Optional[Dict[str, Any]] = None) -> None:
        """
        Emit/log internal agent event.

        Future integrations can replace this with:
            - event bus
            - WebSocket dashboard stream
            - audit/event table
            - OpenTelemetry span
        """
        safe_payload = _deepcopy_jsonable(payload or {})
        self.logger.debug(
            "ClientMemory event=%s payload=%s",
            event_type,
            safe_payload,
        )

    def _log_audit_event(
        self,
        action: str,
        user_id: str,
        workspace_id: str,
        actor_id: Optional[str] = None,
        resource_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log audit event.

        This method intentionally does not write to external systems directly.
        Dashboard/API can later connect this to audit_logs table.
        """
        event = {
            "agent": self.agent_name,
            "module": self.module_name,
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "actor_id": actor_id or user_id,
            "resource_id": resource_id,
            "metadata": _deepcopy_jsonable(metadata or {}),
            "timestamp": _utc_now(),
        }
        self.logger.info("AUDIT %s", json.dumps(event, default=str))

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return successful structured result."""
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
        error: Union[str, Exception, None] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return failed structured result."""
        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": str(error) if error is not None else message,
            "metadata": metadata or {},
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_record(
        self,
        kind: MemoryKind,
        user_id: str,
        workspace_id: str,
        actor_id: str,
        title: str,
        body: str = "",
        client_id: str = "",
        client_name: str = "",
        project_id: str = "",
        tags: Optional[Iterable[Any]] = None,
        priority: Priority = "normal",
        privacy_level: PrivacyLevel = "internal",
        status: str = "active",
        starts_at: Optional[Any] = None,
        ends_at: Optional[Any] = None,
        due_at: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ClientMemoryRecord:
        """Build and normalize a ClientMemoryRecord."""
        safe_user = _normalize_key(user_id, 160)
        safe_workspace = _normalize_key(workspace_id, 160)
        safe_actor = _normalize_key(actor_id or user_id, 160)

        clean_title = _normalize_text(title, MAX_TITLE_LENGTH)
        clean_body = _normalize_text(body, MAX_BODY_LENGTH)

        if not clean_title:
            raise ValueError("title is required.")

        record = ClientMemoryRecord(
            id=_safe_uuid(),
            kind=kind,
            user_id=safe_user,
            workspace_id=safe_workspace,
            client_id=_normalize_key(client_id, 160),
            client_name=_normalize_text(client_name, MAX_CLIENT_NAME_LENGTH),
            project_id=_normalize_key(project_id, 160),
            title=clean_title,
            body=clean_body,
            summary=self._make_summary(clean_body or clean_title),
            status=_normalize_text(status, 40) or "active",
            priority=priority if priority in {"low", "normal", "medium", "high", "urgent"} else "normal",
            privacy_level=privacy_level if privacy_level in {"public", "internal", "private", "restricted"} else "internal",
            tags=_normalize_tags(tags),
            starts_at=_parse_datetime(starts_at),
            ends_at=_parse_datetime(ends_at),
            due_at=_parse_datetime(due_at),
            metadata=_deepcopy_jsonable(metadata or {}),
            created_by=safe_actor,
            updated_by=safe_actor,
            created_at=_utc_now(),
            updated_at=_utc_now(),
        )

        return record

    def _save_and_return(
        self,
        record: ClientMemoryRecord,
        action: str,
        message: str,
    ) -> Dict[str, Any]:
        """Save record and return structured response with hooks."""
        try:
            saved = self.store.upsert_record(record)

            self._log_audit_event(
                action=action,
                user_id=record.user_id,
                workspace_id=record.workspace_id,
                actor_id=record.created_by,
                resource_id=record.id,
                metadata={"kind": record.kind, "client_id": record.client_id},
            )

            self._emit_agent_event(
                event_type=f"client_memory_{record.kind}_created",
                payload={
                    "user_id": record.user_id,
                    "workspace_id": record.workspace_id,
                    "record_id": record.id,
                    "kind": record.kind,
                },
            )

            return self._safe_result(
                message=message,
                data={"record": saved},
                metadata={
                    "memory_payload": self._prepare_memory_payload(
                        action=action,
                        user_id=record.user_id,
                        workspace_id=record.workspace_id,
                        record=saved,
                        privacy_level=record.privacy_level,
                    ),
                    "verification": self._prepare_verification_payload(
                        action=action,
                        user_id=record.user_id,
                        workspace_id=record.workspace_id,
                        record_id=record.id,
                        kind=record.kind,
                    ),
                },
            )
        except Exception as exc:
            self.logger.exception("Failed to save client memory record.")
            return self._error_result(
                message="Failed to save client memory record.",
                error=exc,
                metadata={"action": action, "record_id": record.id},
            )

    def _record_matches_query(self, record: Dict[str, Any], query: ClientMemoryQuery) -> bool:
        """Return whether a record matches query filters."""
        if record.get("user_id") != query.user_id:
            return False
        if record.get("workspace_id") != query.workspace_id:
            return False

        if not query.include_deleted and record.get("deleted_at"):
            return False
        if not query.include_archived and record.get("status") == "archived":
            return False

        if query.kind and record.get("kind") != query.kind:
            return False
        if query.client_id and record.get("client_id") != query.client_id:
            return False
        if query.client_name and query.client_name not in str(record.get("client_name", "")).lower():
            return False
        if query.project_id and record.get("project_id") != query.project_id:
            return False
        if query.status and record.get("status") != query.status:
            specific_statuses = {
                record.get("proposal_status"),
                record.get("campaign_status"),
                record.get("deadline_status"),
            }
            if query.status not in specific_statuses:
                return False
        if query.privacy_level and record.get("privacy_level") != query.privacy_level:
            return False
        if query.priority and record.get("priority") != query.priority:
            return False

        record_tags = set(record.get("tags") or [])
        if query.tag and query.tag not in record_tags:
            return False
        if query.tags and not set(query.tags).issubset(record_tags):
            return False

        if query.search:
            haystack = " ".join(
                [
                    str(record.get("title", "")),
                    str(record.get("body", "")),
                    str(record.get("summary", "")),
                    str(record.get("client_name", "")),
                    str(record.get("client_id", "")),
                    str(record.get("project_id", "")),
                    " ".join(record.get("tags") or []),
                    json.dumps(record.get("metadata") or {}, default=str),
                ]
            ).lower()
            if query.search not in haystack:
                return False

        if query.due_before or query.due_after:
            due_at = record.get("due_at")
            if not due_at:
                return False
            try:
                due_dt = datetime.fromisoformat(str(due_at).replace("Z", "+00:00"))
                if due_dt.tzinfo is None:
                    due_dt = due_dt.replace(tzinfo=timezone.utc)

                if query.due_before:
                    before_dt = datetime.fromisoformat(query.due_before.replace("Z", "+00:00"))
                    if before_dt.tzinfo is None:
                        before_dt = before_dt.replace(tzinfo=timezone.utc)
                    if due_dt > before_dt:
                        return False

                if query.due_after:
                    after_dt = datetime.fromisoformat(query.due_after.replace("Z", "+00:00"))
                    if after_dt.tzinfo is None:
                        after_dt = after_dt.replace(tzinfo=timezone.utc)
                    if due_dt < after_dt:
                        return False
            except Exception:
                return False

        return True

    def _sort_records(
        self,
        records: List[Dict[str, Any]],
        sort_by: str,
        sort_dir: Literal["asc", "desc"] = "desc",
    ) -> List[Dict[str, Any]]:
        """Sort records safely."""
        allowed_sort_fields = {
            "created_at",
            "updated_at",
            "due_at",
            "starts_at",
            "ends_at",
            "title",
            "client_name",
            "priority",
            "kind",
            "status",
        }
        field_name = sort_by if sort_by in allowed_sort_fields else "updated_at"

        def sort_key(item: Dict[str, Any]) -> Tuple[int, str]:
            value = item.get(field_name)
            if value in (None, ""):
                return (1, "")
            return (0, str(value).lower())

        return sorted(records, key=sort_key, reverse=(sort_dir == "desc"))

    def _normalize_field_update(self, key: str, value: Any) -> Any:
        """Normalize update fields according to schema."""
        if key in {"title"}:
            return _normalize_text(value, MAX_TITLE_LENGTH)
        if key in {"body"}:
            return _normalize_text(value, MAX_BODY_LENGTH)
        if key in {"summary"}:
            return _normalize_text(value, 1000)
        if key in {"client_id", "project_id"}:
            return _normalize_key(value, 160)
        if key in {"client_name"}:
            return _normalize_text(value, MAX_CLIENT_NAME_LENGTH)
        if key == "status":
            return _normalize_text(value, 40)
        if key == "priority":
            return value if value in {"low", "normal", "medium", "high", "urgent"} else "normal"
        if key == "privacy_level":
            return value if value in {"public", "internal", "private", "restricted"} else "internal"
        if key == "tags":
            return _normalize_tags(value)
        if key == "amount":
            return self._safe_amount(value)
        if key == "currency":
            return _normalize_text(value, 12).upper() or "USD"
        if key in {"proposal_status", "campaign_status", "deadline_status"}:
            return _normalize_text(value, 40)
        if key in {"starts_at", "ends_at", "due_at", "completed_at"}:
            return _parse_datetime(value)
        if key in {"assigned_to", "related_ids"}:
            if not isinstance(value, Iterable) or isinstance(value, (str, bytes)):
                return []
            return [
                _normalize_key(item, 160)
                for item in value
                if _normalize_key(item, 160)
            ]
        if key == "metadata":
            return _deepcopy_jsonable(value if isinstance(value, dict) else {})
        return value

    def _make_summary(self, text: str, limit: int = 280) -> str:
        """Create a short summary from body/title."""
        clean = re.sub(r"\s+", " ", _normalize_text(text, MAX_BODY_LENGTH)).strip()
        if len(clean) <= limit:
            return clean
        return clean[: max(0, limit - 3)].rstrip() + "..."

    def _safe_amount(self, amount: Optional[Union[int, float, str]]) -> Optional[float]:
        """Normalize numeric proposal/campaign amount."""
        if amount in (None, ""):
            return None
        try:
            value = float(str(amount).replace(",", "").strip())
            if value < 0:
                return None
            return round(value, 2)
        except Exception:
            return None

    def _safe_limit(self, limit: Any) -> int:
        """Normalize pagination limit."""
        try:
            parsed = int(limit)
        except Exception:
            parsed = DEFAULT_SEARCH_LIMIT
        return max(1, min(parsed, MAX_SEARCH_LIMIT))


# ---------------------------------------------------------------------------
# Module self-test helper
# ---------------------------------------------------------------------------

def _self_test() -> Dict[str, Any]:
    """
    Lightweight import/runtime test.

    Can be used manually:
        python -m agents.memory_agent.client_memory
    """
    memory = ClientMemory(storage_dir=DEFAULT_STORAGE_DIR / "_self_test")

    created = memory.add_note(
        user_id="test_user",
        workspace_id="test_workspace",
        actor_id="test_user",
        client_id="client_001",
        client_name="Demo Client",
        title="Discovery call notes",
        body="Client wants SEO, PPC, and AI automation proposal.",
        tags=["seo", "ppc", "ai-automation"],
    )

    if not created["success"]:
        return created

    proposal = memory.add_proposal(
        user_id="test_user",
        workspace_id="test_workspace",
        actor_id="test_user",
        client_id="client_001",
        client_name="Demo Client",
        title="Growth Proposal",
        body="SEO + Google Ads + AI Automation implementation.",
        amount=1500,
        currency="USD",
        proposal_status="draft",
    )

    deadline = memory.add_deadline(
        user_id="test_user",
        workspace_id="test_workspace",
        actor_id="test_user",
        client_id="client_001",
        client_name="Demo Client",
        title="Send final proposal",
        due_at="2030-01-01",
        priority="high",
    )

    summary = memory.get_client_summary(
        user_id="test_user",
        workspace_id="test_workspace",
        client_id="client_001",
    )

    return {
        "success": all([created["success"], proposal["success"], deadline["success"], summary["success"]]),
        "message": "ClientMemory self-test completed.",
        "data": {
            "created_note": created,
            "created_proposal": proposal,
            "created_deadline": deadline,
            "summary": summary,
        },
        "error": None,
        "metadata": {"tested_at": _utc_now()},
    }


if __name__ == "__main__":
    print(json.dumps(_self_test(), indent=2, default=str))