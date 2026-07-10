"""
agents/super_agents/call_agent/call_memory.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Stores approved call notes, preferences, leads, and summaries for the Call Agent.

Responsibilities:
    - Store only approved call-related memory.
    - Keep strict user_id/workspace_id SaaS isolation.
    - Provide structured JSON/dict results.
    - Prepare Memory Agent compatible payloads.
    - Prepare Verification Agent compatible payloads.
    - Emit audit/event metadata for dashboard/API integration.
    - Stay import-safe even when other William/Jarvis modules do not exist yet.

Connections:
    - Master Agent / Router:
        Can call `route_task()` or public methods directly.
    - Security Agent:
        Sensitive write/delete/export actions pass through `_request_security_approval()`.
    - Memory Agent:
        Memory-compatible payloads are prepared through `_prepare_memory_payload()`.
    - Verification Agent:
        Every completed useful action prepares `_prepare_verification_payload()`.
    - Dashboard/API:
        Public methods return structured dicts ready for FastAPI responses.
    - Registry / Loader:
        Exposes `AGENT_CLASS`, `AGENT_METADATA`, and `get_agent_metadata()`.

Important:
    This file does not perform real external calls, messaging, CRM writes, browser actions,
    or destructive system actions. Storage is local JSON by default and can be replaced by
    database-backed adapters later.
"""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
import logging
import os
import re
import threading
import time
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Safe optional BaseAgent import
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for standalone import safety
    class BaseAgent:  # type: ignore
        """
        Minimal fallback BaseAgent so this file remains import-safe before the
        real William/Jarvis BaseAgent exists.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.logger = logging.getLogger(self.agent_name)

        async def run(self, task: Mapping[str, Any]) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent run() not implemented.",
                "data": None,
                "error": "BASE_AGENT_FALLBACK",
                "metadata": {"agent": self.__class__.__name__},
            }


# ---------------------------------------------------------------------------
# Constants / Metadata
# ---------------------------------------------------------------------------

CALL_MEMORY_VERSION = "1.0.0"

AGENT_METADATA: Dict[str, Any] = {
    "agent_name": "CallMemory",
    "module": "Call Agent",
    "file_path": "agents/super_agents/call_agent/call_memory.py",
    "version": CALL_MEMORY_VERSION,
    "purpose": "Stores approved call notes, preferences, leads, and summaries.",
    "supports_user_workspace_isolation": True,
    "requires_security_for_sensitive_actions": True,
    "compatible_with": [
        "BaseAgent",
        "Agent Registry",
        "Agent Loader",
        "Agent Router",
        "Master Agent",
        "Security Agent",
        "Memory Agent",
        "Verification Agent",
        "Dashboard/API",
    ],
    "public_methods": [
        "store_call_note",
        "store_preference",
        "store_lead",
        "store_call_summary",
        "get_record",
        "list_records",
        "search_records",
        "list_leads",
        "list_preferences",
        "list_call_notes",
        "list_call_summaries",
        "delete_record",
        "export_workspace_memory",
        "route_task",
    ],
}


class CallMemoryRecordType(str, Enum):
    CALL_NOTE = "call_note"
    PREFERENCE = "preference"
    LEAD = "lead"
    CALL_SUMMARY = "call_summary"


class CallMemorySensitivity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class CallMemoryStatus(str, Enum):
    ACTIVE = "active"
    ARCHIVED = "archived"
    DELETED = "deleted"


DEFAULT_STORAGE_DIR = Path(
    os.getenv(
        "WILLIAM_CALL_MEMORY_STORAGE_DIR",
        ".william_data/call_memory",
    )
)

SAFE_TEXT_MAX_LENGTH = 20_000
SAFE_FIELD_MAX_LENGTH = 1_000
MAX_SEARCH_RESULTS = 100
MAX_EXPORT_RECORDS = 10_000

SENSITIVE_ACTIONS = {
    "store_call_note",
    "store_preference",
    "store_lead",
    "store_call_summary",
    "delete_record",
    "export_workspace_memory",
}

PHONE_RE = re.compile(r"^[+()\-.\s0-9]{5,32}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
KEY_RE = re.compile(r"^[a-zA-Z0-9_.:\-]{1,128}$")


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class CallMemoryContext:
    """
    Required SaaS isolation context.

    Every user-specific operation must include user_id and workspace_id.
    """

    user_id: str
    workspace_id: str
    actor_id: Optional[str] = None
    role: Optional[str] = None
    request_id: Optional[str] = None
    session_id: Optional[str] = None
    source_agent: Optional[str] = None
    ip_address: Optional[str] = None

    @classmethod
    def from_mapping(cls, context: Mapping[str, Any]) -> "CallMemoryContext":
        return cls(
            user_id=str(context.get("user_id", "")).strip(),
            workspace_id=str(context.get("workspace_id", "")).strip(),
            actor_id=_optional_str(context.get("actor_id")),
            role=_optional_str(context.get("role")),
            request_id=_optional_str(context.get("request_id")) or _new_id("req"),
            session_id=_optional_str(context.get("session_id")),
            source_agent=_optional_str(context.get("source_agent")),
            ip_address=_optional_str(context.get("ip_address")),
        )


@dataclasses.dataclass
class CallMemoryRecord:
    """
    Canonical stored record.

    This structure is intentionally database-friendly so it can later map to
    SQL, document stores, vector stores, or Memory Agent payloads.
    """

    record_id: str
    record_type: str
    user_id: str
    workspace_id: str
    approved: bool
    title: str
    content: str
    data: Dict[str, Any]
    tags: List[str]
    call_id: Optional[str]
    contact_id: Optional[str]
    lead_id: Optional[str]
    sensitivity: str
    status: str
    created_at: str
    updated_at: str
    created_by: Optional[str]
    source_agent: Optional[str]
    metadata: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def _optional_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _safe_json_copy(value: Any) -> Any:
    try:
        return json.loads(json.dumps(value, ensure_ascii=False, default=str))
    except Exception:
        return str(value)


def _normalize_key(value: str, field_name: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{field_name} is required.")
    if not KEY_RE.match(text):
        raise ValueError(
            f"{field_name} contains unsupported characters. "
            "Allowed: letters, numbers, underscore, hyphen, colon, dot."
        )
    return text


def _truncate_text(value: Any, max_length: int = SAFE_TEXT_MAX_LENGTH) -> str:
    text = "" if value is None else str(value)
    text = text.replace("\x00", "").strip()
    if len(text) > max_length:
        return text[: max_length - 20] + "...[truncated]"
    return text


def _normalize_tags(tags: Optional[Iterable[Any]]) -> List[str]:
    if not tags:
        return []
    output: List[str] = []
    seen = set()
    for tag in tags:
        text = _truncate_text(tag, 80).lower()
        text = re.sub(r"\s+", "-", text)
        text = re.sub(r"[^a-z0-9_.:\-]", "", text)
        if text and text not in seen:
            seen.add(text)
            output.append(text)
    return output[:50]


def _stable_hash(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _redact_phone(phone: Optional[str]) -> Optional[str]:
    if not phone:
        return None
    digits = re.sub(r"\D", "", phone)
    if len(digits) <= 4:
        return "****"
    return f"{'*' * max(0, len(digits) - 4)}{digits[-4:]}"


def _redact_email(email: Optional[str]) -> Optional[str]:
    if not email or "@" not in email:
        return email
    name, domain = email.split("@", 1)
    if not name:
        return f"***@{domain}"
    return f"{name[:1]}***@{domain}"


def _contains_pii(data: Mapping[str, Any]) -> bool:
    text = json.dumps(data, default=str, ensure_ascii=False).lower()
    pii_indicators = [
        "phone",
        "email",
        "address",
        "card",
        "payment",
        "billing",
        "ssn",
        "passport",
        "cnic",
        "dob",
    ]
    return any(item in text for item in pii_indicators)


def _deep_merge(base: Dict[str, Any], incoming: Mapping[str, Any]) -> Dict[str, Any]:
    result = copy.deepcopy(base)
    for key, value in incoming.items():
        if (
            isinstance(result.get(key), dict)
            and isinstance(value, Mapping)
        ):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = _safe_json_copy(value)
    return result


# ---------------------------------------------------------------------------
# Storage Adapter
# ---------------------------------------------------------------------------

class JsonCallMemoryStore:
    """
    Simple JSON-backed store.

    It is intentionally conservative:
    - Records are saved per workspace file.
    - Reads and writes are protected by a process lock.
    - The file path is derived from normalized user/workspace IDs.
    - This can be replaced by a database adapter later without changing
      CallMemory public methods.
    """

    def __init__(
        self,
        storage_dir: Union[str, Path] = DEFAULT_STORAGE_DIR,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.storage_dir = Path(storage_dir)
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        self._lock = threading.RLock()
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def _workspace_path(self, user_id: str, workspace_id: str) -> Path:
        safe_user = _normalize_key(user_id, "user_id")
        safe_workspace = _normalize_key(workspace_id, "workspace_id")
        digest = hashlib.sha256(
            f"{safe_user}:{safe_workspace}".encode("utf-8")
        ).hexdigest()[:24]
        return self.storage_dir / safe_user / f"{safe_workspace}_{digest}.json"

    def _empty_document(self, user_id: str, workspace_id: str) -> Dict[str, Any]:
        return {
            "schema": "william.call_memory.v1",
            "user_id": user_id,
            "workspace_id": workspace_id,
            "created_at": _utc_now(),
            "updated_at": _utc_now(),
            "records": {},
            "audit": [],
        }

    def load_document(self, user_id: str, workspace_id: str) -> Dict[str, Any]:
        with self._lock:
            path = self._workspace_path(user_id, workspace_id)
            if not path.exists():
                return self._empty_document(user_id, workspace_id)

            try:
                with path.open("r", encoding="utf-8") as handle:
                    doc = json.load(handle)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Call memory store is corrupted: {path}") from exc

            if doc.get("user_id") != user_id or doc.get("workspace_id") != workspace_id:
                raise PermissionError("Workspace store isolation check failed.")

            if "records" not in doc or not isinstance(doc["records"], dict):
                doc["records"] = {}
            if "audit" not in doc or not isinstance(doc["audit"], list):
                doc["audit"] = []

            return doc

    def save_document(self, user_id: str, workspace_id: str, document: Mapping[str, Any]) -> None:
        with self._lock:
            path = self._workspace_path(user_id, workspace_id)
            path.parent.mkdir(parents=True, exist_ok=True)

            doc = _safe_json_copy(document)
            doc["user_id"] = user_id
            doc["workspace_id"] = workspace_id
            doc["updated_at"] = _utc_now()

            temp_path = path.with_suffix(".json.tmp")
            with temp_path.open("w", encoding="utf-8") as handle:
                json.dump(doc, handle, indent=2, ensure_ascii=False, sort_keys=True)
            temp_path.replace(path)

    def upsert_record(self, record: CallMemoryRecord) -> Dict[str, Any]:
        with self._lock:
            doc = self.load_document(record.user_id, record.workspace_id)
            doc["records"][record.record_id] = record.to_dict()
            self.save_document(record.user_id, record.workspace_id, doc)
            return record.to_dict()

    def get_record(self, user_id: str, workspace_id: str, record_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            doc = self.load_document(user_id, workspace_id)
            record = doc["records"].get(record_id)
            if not record:
                return None
            if record.get("user_id") != user_id or record.get("workspace_id") != workspace_id:
                raise PermissionError("Record isolation check failed.")
            return _safe_json_copy(record)

    def list_records(
        self,
        user_id: str,
        workspace_id: str,
        record_type: Optional[str] = None,
        status: Optional[str] = CallMemoryStatus.ACTIVE.value,
        limit: int = 100,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        with self._lock:
            doc = self.load_document(user_id, workspace_id)
            records = list(doc["records"].values())

            filtered = []
            for record in records:
                if record.get("user_id") != user_id or record.get("workspace_id") != workspace_id:
                    continue
                if record_type and record.get("record_type") != record_type:
                    continue
                if status and record.get("status") != status:
                    continue
                filtered.append(record)

            filtered.sort(key=lambda item: item.get("updated_at", ""), reverse=True)
            total = len(filtered)
            safe_offset = max(0, int(offset))
            safe_limit = max(1, min(int(limit), 500))
            return _safe_json_copy(filtered[safe_offset : safe_offset + safe_limit]), total

    def soft_delete_record(
        self,
        user_id: str,
        workspace_id: str,
        record_id: str,
        actor_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        with self._lock:
            doc = self.load_document(user_id, workspace_id)
            record = doc["records"].get(record_id)
            if not record:
                return None

            if record.get("user_id") != user_id or record.get("workspace_id") != workspace_id:
                raise PermissionError("Record isolation check failed.")

            record["status"] = CallMemoryStatus.DELETED.value
            record["updated_at"] = _utc_now()
            record.setdefault("metadata", {})
            record["metadata"]["deleted_by"] = actor_id
            record["metadata"]["deleted_at"] = _utc_now()
            doc["records"][record_id] = record

            self.save_document(user_id, workspace_id, doc)
            return _safe_json_copy(record)


# ---------------------------------------------------------------------------
# Main Agent
# ---------------------------------------------------------------------------

class CallMemory(BaseAgent):
    """
    Stores approved call notes, preferences, leads, and summaries.

    Public methods return:
        {
            "success": bool,
            "message": str,
            "data": dict/list/None,
            "error": str|dict|None,
            "metadata": dict
        }

    This class is safe for:
        - Master Agent routing
        - FastAPI endpoints
        - Dashboard integrations
        - Memory Agent handoff
        - Verification Agent handoff
    """

    agent_name = "CallMemory"
    version = CALL_MEMORY_VERSION

    def __init__(
        self,
        storage_dir: Union[str, Path] = DEFAULT_STORAGE_DIR,
        security_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        logger: Optional[logging.Logger] = None,
        require_approval_by_default: bool = True,
        allow_local_storage: bool = True,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        try:
            super().__init__(*args, agent_name=self.agent_name, **kwargs)
        except TypeError:
            super().__init__(*args, **kwargs)

        self.logger = logger or getattr(self, "logger", logging.getLogger(self.agent_name))
        self.security_agent = security_agent
        self.memory_agent = memory_agent
        self.verification_agent = verification_agent
        self.event_bus = event_bus
        self.audit_logger = audit_logger
        self.require_approval_by_default = bool(require_approval_by_default)
        self.allow_local_storage = bool(allow_local_storage)

        self.store = JsonCallMemoryStore(storage_dir=storage_dir, logger=self.logger)

    # ------------------------------------------------------------------
    # Compatibility hooks
    # ------------------------------------------------------------------

    def _safe_result(
        self,
        success: bool,
        message: str,
        data: Any = None,
        error: Any = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "success": bool(success),
            "message": str(message),
            "data": _safe_json_copy(data),
            "error": _safe_json_copy(error),
            "metadata": _safe_json_copy(
                {
                    "agent": self.agent_name,
                    "version": self.version,
                    "timestamp": _utc_now(),
                    **dict(metadata or {}),
                }
            ),
        }

    def _error_result(
        self,
        message: str,
        error: Any = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        self.logger.warning("%s: %s", message, error)
        return self._safe_result(
            success=False,
            message=message,
            data=None,
            error=error,
            metadata=metadata,
        )

    def _validate_task_context(self, context: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Validates SaaS context.

        Never store, search, export, or delete call memory without both user_id
        and workspace_id.
        """
        try:
            parsed = CallMemoryContext.from_mapping(context or {})
            user_id = _normalize_key(parsed.user_id, "user_id")
            workspace_id = _normalize_key(parsed.workspace_id, "workspace_id")

            return self._safe_result(
                success=True,
                message="Task context validated.",
                data=dataclasses.asdict(
                    CallMemoryContext(
                        user_id=user_id,
                        workspace_id=workspace_id,
                        actor_id=parsed.actor_id,
                        role=parsed.role,
                        request_id=parsed.request_id,
                        session_id=parsed.session_id,
                        source_agent=parsed.source_agent,
                        ip_address=parsed.ip_address,
                    )
                ),
                metadata={"hook": "_validate_task_context"},
            )
        except Exception as exc:
            return self._error_result(
                message="Invalid or missing user/workspace context.",
                error=str(exc),
                metadata={"hook": "_validate_task_context"},
            )

    def _requires_security_check(self, action: str, payload: Optional[Mapping[str, Any]] = None) -> bool:
        """
        Determines whether Security Agent approval is required.

        Writes, deletes, exports, and records containing likely PII are sensitive.
        """
        payload = payload or {}
        if action in SENSITIVE_ACTIONS:
            return True
        if _contains_pii(payload):
            return True
        return False

    def _request_security_approval(
        self,
        action: str,
        context: Mapping[str, Any],
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Requests approval from Security Agent when available.

        If no Security Agent is attached, this method allows safe local storage
        only when:
            - `approved=True` was explicitly supplied, or
            - `require_approval_by_default=False`.

        This prevents accidental unapproved call-memory writes.
        """
        approved_flag = bool(payload.get("approved") is True)

        security_payload = {
            "action": action,
            "agent": self.agent_name,
            "context": _safe_json_copy(context),
            "payload_hash": _stable_hash(payload),
            "sensitivity": payload.get("sensitivity", CallMemorySensitivity.MEDIUM.value),
            "contains_pii": _contains_pii(payload),
            "requested_at": _utc_now(),
        }

        if self.security_agent and hasattr(self.security_agent, "approve_action"):
            try:
                approval = self.security_agent.approve_action(security_payload)
                if isinstance(approval, Mapping):
                    is_approved = bool(approval.get("approved") or approval.get("success"))
                    return self._safe_result(
                        success=is_approved,
                        message="Security approval completed." if is_approved else "Security approval denied.",
                        data=dict(approval),
                        error=None if is_approved else approval.get("error", "SECURITY_DENIED"),
                        metadata={"hook": "_request_security_approval", "security_agent": True},
                    )
            except Exception as exc:
                return self._error_result(
                    message="Security approval request failed.",
                    error=str(exc),
                    metadata={"hook": "_request_security_approval", "security_agent": True},
                )

        if approved_flag:
            return self._safe_result(
                success=True,
                message="Security approval accepted from explicit approved=True flag.",
                data={"approved": True, "mode": "explicit_flag", "security_payload": security_payload},
                metadata={"hook": "_request_security_approval", "security_agent": False},
            )

        if not self.require_approval_by_default:
            return self._safe_result(
                success=True,
                message="Security approval allowed by local safe default.",
                data={"approved": True, "mode": "local_safe_default", "security_payload": security_payload},
                metadata={"hook": "_request_security_approval", "security_agent": False},
            )

        return self._error_result(
            message="Security approval required before storing call memory.",
            error="SECURITY_APPROVAL_REQUIRED",
            metadata={
                "hook": "_request_security_approval",
                "security_agent": False,
                "action": action,
            },
        )

    def _prepare_verification_payload(
        self,
        action: str,
        context: Mapping[str, Any],
        result_data: Any,
        success: bool = True,
    ) -> Dict[str, Any]:
        """
        Prepares payload for Verification Agent.

        The payload does not leak full content by default; it includes hashes,
        IDs, types, and audit-friendly metadata.
        """
        if isinstance(result_data, Mapping):
            record_id = result_data.get("record_id")
            record_type = result_data.get("record_type")
            status = result_data.get("status")
        else:
            record_id = None
            record_type = None
            status = None

        payload = {
            "verification_type": "call_memory_action",
            "agent": self.agent_name,
            "action": action,
            "success": bool(success),
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "actor_id": context.get("actor_id"),
            "request_id": context.get("request_id"),
            "record_id": record_id,
            "record_type": record_type,
            "record_status": status,
            "result_hash": _stable_hash(result_data),
            "created_at": _utc_now(),
        }

        if self.verification_agent and hasattr(self.verification_agent, "prepare"):
            try:
                external_payload = self.verification_agent.prepare(payload)
                if isinstance(external_payload, Mapping):
                    return dict(external_payload)
            except Exception as exc:
                self.logger.warning("Verification Agent payload preparation failed: %s", exc)

        return payload

    def _prepare_memory_payload(
        self,
        record: Mapping[str, Any],
        context: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Converts a CallMemoryRecord into a Memory Agent compatible payload.
        """
        return {
            "memory_type": "call_memory",
            "source_agent": self.agent_name,
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "actor_id": context.get("actor_id"),
            "record_id": record.get("record_id"),
            "record_type": record.get("record_type"),
            "title": record.get("title"),
            "content": record.get("content"),
            "data": _safe_json_copy(record.get("data", {})),
            "tags": list(record.get("tags", [])),
            "call_id": record.get("call_id"),
            "contact_id": record.get("contact_id"),
            "lead_id": record.get("lead_id"),
            "sensitivity": record.get("sensitivity"),
            "approved": record.get("approved"),
            "status": record.get("status"),
            "created_at": record.get("created_at"),
            "updated_at": record.get("updated_at"),
            "metadata": {
                "source_file": "agents/super_agents/call_agent/call_memory.py",
                "schema": "william.memory.call.v1",
                "record_hash": _stable_hash(record),
            },
        }

    def _emit_agent_event(
        self,
        event_name: str,
        context: Mapping[str, Any],
        payload: Mapping[str, Any],
    ) -> None:
        """
        Emits lightweight events for dashboard/API/observability.

        If no event bus exists, it logs only. It never raises to callers.
        """
        event = {
            "event_name": event_name,
            "agent": self.agent_name,
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "request_id": context.get("request_id"),
            "payload": _safe_json_copy(payload),
            "timestamp": _utc_now(),
        }

        try:
            if self.event_bus and hasattr(self.event_bus, "emit"):
                self.event_bus.emit(event_name, event)
            else:
                self.logger.info("Agent event: %s", json.dumps(event, default=str))
        except Exception as exc:
            self.logger.warning("Failed to emit agent event %s: %s", event_name, exc)

    def _log_audit_event(
        self,
        action: str,
        context: Mapping[str, Any],
        payload: Mapping[str, Any],
        success: bool,
        error: Optional[Any] = None,
    ) -> None:
        """
        Logs audit events without mixing users/workspaces.
        """
        audit_event = {
            "action": action,
            "agent": self.agent_name,
            "success": bool(success),
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "actor_id": context.get("actor_id"),
            "role": context.get("role"),
            "request_id": context.get("request_id"),
            "session_id": context.get("session_id"),
            "source_agent": context.get("source_agent"),
            "payload_hash": _stable_hash(payload),
            "error": _safe_json_copy(error),
            "created_at": _utc_now(),
        }

        try:
            if self.audit_logger and hasattr(self.audit_logger, "log"):
                self.audit_logger.log(audit_event)
            else:
                self.logger.info("Audit event: %s", json.dumps(audit_event, default=str))
        except Exception as exc:
            self.logger.warning("Failed to write audit event: %s", exc)

    # ------------------------------------------------------------------
    # Internal creation helpers
    # ------------------------------------------------------------------

    def _validated_context_or_error(self, context: Mapping[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return None, validation
        return dict(validation["data"]), None

    def _validate_approval(self, approved: bool) -> None:
        if approved is not True:
            raise PermissionError(
                "Call memory can only store approved notes, preferences, leads, or summaries."
            )

    def _validate_record_type(self, record_type: Union[str, CallMemoryRecordType]) -> str:
        value = record_type.value if isinstance(record_type, CallMemoryRecordType) else str(record_type)
        allowed = {item.value for item in CallMemoryRecordType}
        if value not in allowed:
            raise ValueError(f"Unsupported call memory record_type: {value}")
        return value

    def _normalize_sensitivity(self, sensitivity: Union[str, CallMemorySensitivity, None]) -> str:
        if isinstance(sensitivity, CallMemorySensitivity):
            return sensitivity.value
        value = str(sensitivity or CallMemorySensitivity.MEDIUM.value).lower().strip()
        allowed = {item.value for item in CallMemorySensitivity}
        if value not in allowed:
            return CallMemorySensitivity.MEDIUM.value
        return value

    def _build_record(
        self,
        *,
        context: Mapping[str, Any],
        record_type: Union[str, CallMemoryRecordType],
        title: str,
        content: str,
        data: Optional[Mapping[str, Any]] = None,
        tags: Optional[Iterable[Any]] = None,
        approved: bool = False,
        call_id: Optional[str] = None,
        contact_id: Optional[str] = None,
        lead_id: Optional[str] = None,
        sensitivity: Union[str, CallMemorySensitivity, None] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> CallMemoryRecord:
        self._validate_approval(approved)

        normalized_type = self._validate_record_type(record_type)
        safe_title = _truncate_text(title, SAFE_FIELD_MAX_LENGTH)
        safe_content = _truncate_text(content, SAFE_TEXT_MAX_LENGTH)

        if not safe_title:
            safe_title = normalized_type.replace("_", " ").title()
        if not safe_content and not data:
            raise ValueError("Either content or data is required.")

        safe_data = _safe_json_copy(dict(data or {}))
        safe_metadata = _safe_json_copy(dict(metadata or {}))

        final_sensitivity = self._normalize_sensitivity(sensitivity)
        if final_sensitivity == CallMemorySensitivity.LOW.value and _contains_pii(safe_data):
            final_sensitivity = CallMemorySensitivity.MEDIUM.value

        now = _utc_now()
        record = CallMemoryRecord(
            record_id=_new_id("cmem"),
            record_type=normalized_type,
            user_id=str(context["user_id"]),
            workspace_id=str(context["workspace_id"]),
            approved=True,
            title=safe_title,
            content=safe_content,
            data=safe_data,
            tags=_normalize_tags(tags),
            call_id=_optional_str(call_id),
            contact_id=_optional_str(contact_id),
            lead_id=_optional_str(lead_id),
            sensitivity=final_sensitivity,
            status=CallMemoryStatus.ACTIVE.value,
            created_at=now,
            updated_at=now,
            created_by=_optional_str(context.get("actor_id")),
            source_agent=_optional_str(context.get("source_agent")) or self.agent_name,
            metadata=safe_metadata,
        )
        return record

    def _store_record(
        self,
        *,
        action: str,
        context: Mapping[str, Any],
        record: CallMemoryRecord,
        original_payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        if not self.allow_local_storage:
            return self._error_result(
                message="Local call memory storage is disabled.",
                error="LOCAL_STORAGE_DISABLED",
                metadata={"action": action},
            )

        if self._requires_security_check(action, original_payload):
            approval = self._request_security_approval(action, context, original_payload)
            if not approval["success"]:
                self._log_audit_event(action, context, original_payload, success=False, error=approval["error"])
                return approval

        try:
            stored = self.store.upsert_record(record)
            memory_payload = self._prepare_memory_payload(stored, context)
            verification_payload = self._prepare_verification_payload(action, context, stored, success=True)

            data = {
                "record": stored,
                "memory_payload": memory_payload,
                "verification_payload": verification_payload,
            }

            self._emit_agent_event(
                event_name=f"call_memory.{record.record_type}.stored",
                context=context,
                payload={
                    "record_id": record.record_id,
                    "record_type": record.record_type,
                    "sensitivity": record.sensitivity,
                    "status": record.status,
                },
            )
            self._log_audit_event(action, context, original_payload, success=True)

            return self._safe_result(
                success=True,
                message=f"{record.record_type.replace('_', ' ').title()} stored successfully.",
                data=data,
                metadata={
                    "action": action,
                    "record_id": record.record_id,
                    "record_type": record.record_type,
                    "verification_ready": True,
                    "memory_ready": True,
                },
            )
        except Exception as exc:
            self._log_audit_event(action, context, original_payload, success=False, error=str(exc))
            return self._error_result(
                message="Failed to store call memory record.",
                error=str(exc),
                metadata={"action": action, "record_type": record.record_type},
            )

    # ------------------------------------------------------------------
    # Public write methods
    # ------------------------------------------------------------------

    def store_call_note(
        self,
        *,
        context: Mapping[str, Any],
        note: str,
        approved: bool,
        title: Optional[str] = None,
        call_id: Optional[str] = None,
        contact_id: Optional[str] = None,
        tags: Optional[Iterable[Any]] = None,
        sensitivity: Union[str, CallMemorySensitivity, None] = CallMemorySensitivity.MEDIUM,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Store an approved note from a call.

        Example:
            store_call_note(
                context={"user_id": "u1", "workspace_id": "w1"},
                note="Caller wants a website quote.",
                approved=True,
                call_id="call_123",
            )
        """
        action = "store_call_note"
        ctx, err = self._validated_context_or_error(context)
        if err:
            return err

        payload = {
            "note": note,
            "approved": approved,
            "title": title,
            "call_id": call_id,
            "contact_id": contact_id,
            "tags": list(tags or []),
            "sensitivity": str(sensitivity),
            "metadata": dict(metadata or {}),
        }

        try:
            record = self._build_record(
                context=ctx,
                record_type=CallMemoryRecordType.CALL_NOTE,
                title=title or "Approved Call Note",
                content=note,
                data={"note": _truncate_text(note), "note_length": len(str(note or ""))},
                tags=list(tags or []) + ["call-note"],
                approved=approved,
                call_id=call_id,
                contact_id=contact_id,
                sensitivity=sensitivity,
                metadata=metadata,
            )
            return self._store_record(action=action, context=ctx, record=record, original_payload=payload)
        except Exception as exc:
            self._log_audit_event(action, ctx, payload, success=False, error=str(exc))
            return self._error_result(
                message="Unable to store call note.",
                error=str(exc),
                metadata={"action": action},
            )

    def store_preference(
        self,
        *,
        context: Mapping[str, Any],
        preference_key: str,
        preference_value: Any,
        approved: bool,
        title: Optional[str] = None,
        call_id: Optional[str] = None,
        contact_id: Optional[str] = None,
        tags: Optional[Iterable[Any]] = None,
        sensitivity: Union[str, CallMemorySensitivity, None] = CallMemorySensitivity.MEDIUM,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Store an approved caller/client preference.

        Examples:
            - prefers morning callbacks
            - prefers WhatsApp follow-up
            - interested in SEO, web development, or AI automation
        """
        action = "store_preference"
        ctx, err = self._validated_context_or_error(context)
        if err:
            return err

        payload = {
            "preference_key": preference_key,
            "preference_value": preference_value,
            "approved": approved,
            "title": title,
            "call_id": call_id,
            "contact_id": contact_id,
            "tags": list(tags or []),
            "sensitivity": str(sensitivity),
            "metadata": dict(metadata or {}),
        }

        try:
            safe_key = _normalize_key(preference_key, "preference_key")
            safe_value = _safe_json_copy(preference_value)
            content = f"{safe_key}: {_truncate_text(safe_value, SAFE_FIELD_MAX_LENGTH)}"

            record = self._build_record(
                context=ctx,
                record_type=CallMemoryRecordType.PREFERENCE,
                title=title or f"Preference: {safe_key}",
                content=content,
                data={
                    "preference_key": safe_key,
                    "preference_value": safe_value,
                },
                tags=list(tags or []) + ["preference", safe_key],
                approved=approved,
                call_id=call_id,
                contact_id=contact_id,
                sensitivity=sensitivity,
                metadata=metadata,
            )
            return self._store_record(action=action, context=ctx, record=record, original_payload=payload)
        except Exception as exc:
            self._log_audit_event(action, ctx, payload, success=False, error=str(exc))
            return self._error_result(
                message="Unable to store caller preference.",
                error=str(exc),
                metadata={"action": action},
            )

    def store_lead(
        self,
        *,
        context: Mapping[str, Any],
        full_name: str,
        phone_number: str,
        approved: bool,
        service_interest: Optional[str] = None,
        urgency: Optional[str] = None,
        budget: Optional[Union[str, int, float]] = None,
        email: Optional[str] = None,
        company_name: Optional[str] = None,
        call_id: Optional[str] = None,
        contact_id: Optional[str] = None,
        lead_id: Optional[str] = None,
        notes: Optional[str] = None,
        qualification: Optional[Mapping[str, Any]] = None,
        tags: Optional[Iterable[Any]] = None,
        sensitivity: Union[str, CallMemorySensitivity, None] = CallMemorySensitivity.HIGH,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Store an approved lead captured from a call.

        By default this treats lead data as high sensitivity because it can
        contain names, phone numbers, emails, budget, and business details.
        """
        action = "store_lead"
        ctx, err = self._validated_context_or_error(context)
        if err:
            return err

        payload = {
            "full_name": full_name,
            "phone_number": phone_number,
            "email": email,
            "company_name": company_name,
            "service_interest": service_interest,
            "urgency": urgency,
            "budget": budget,
            "approved": approved,
            "call_id": call_id,
            "contact_id": contact_id,
            "lead_id": lead_id,
            "notes": notes,
            "qualification": dict(qualification or {}),
            "tags": list(tags or []),
            "sensitivity": str(sensitivity),
            "metadata": dict(metadata or {}),
        }

        try:
            safe_name = _truncate_text(full_name, 200)
            safe_phone = _truncate_text(phone_number, 32)

            if not safe_name:
                raise ValueError("full_name is required for lead memory.")
            if not safe_phone or not PHONE_RE.match(safe_phone):
                raise ValueError("phone_number is required and must be a valid phone-like value.")
            if email and not EMAIL_RE.match(email.strip()):
                raise ValueError("email must be valid when provided.")

            final_lead_id = lead_id or _new_id("lead")
            safe_notes = _truncate_text(notes, SAFE_TEXT_MAX_LENGTH)

            lead_data = {
                "lead_id": final_lead_id,
                "full_name": safe_name,
                "phone_number": safe_phone,
                "phone_redacted": _redact_phone(safe_phone),
                "email": _optional_str(email),
                "email_redacted": _redact_email(email),
                "company_name": _truncate_text(company_name, 300) if company_name else None,
                "service_interest": _truncate_text(service_interest, 500) if service_interest else None,
                "urgency": _truncate_text(urgency, 200) if urgency else None,
                "budget": _safe_json_copy(budget),
                "notes": safe_notes,
                "qualification": _safe_json_copy(dict(qualification or {})),
            }

            content_parts = [
                f"Lead: {safe_name}",
                f"Phone: {_redact_phone(safe_phone)}",
            ]
            if service_interest:
                content_parts.append(f"Interest: {_truncate_text(service_interest, 300)}")
            if urgency:
                content_parts.append(f"Urgency: {_truncate_text(urgency, 100)}")
            if safe_notes:
                content_parts.append(f"Notes: {safe_notes}")

            record = self._build_record(
                context=ctx,
                record_type=CallMemoryRecordType.LEAD,
                title=f"Lead: {safe_name}",
                content="\n".join(content_parts),
                data=lead_data,
                tags=list(tags or []) + ["lead"],
                approved=approved,
                call_id=call_id,
                contact_id=contact_id,
                lead_id=final_lead_id,
                sensitivity=sensitivity,
                metadata=metadata,
            )
            return self._store_record(action=action, context=ctx, record=record, original_payload=payload)
        except Exception as exc:
            self._log_audit_event(action, ctx, payload, success=False, error=str(exc))
            return self._error_result(
                message="Unable to store call lead.",
                error=str(exc),
                metadata={"action": action},
            )

    def store_call_summary(
        self,
        *,
        context: Mapping[str, Any],
        summary: str,
        approved: bool,
        title: Optional[str] = None,
        call_id: Optional[str] = None,
        contact_id: Optional[str] = None,
        lead_id: Optional[str] = None,
        action_items: Optional[Sequence[Any]] = None,
        sentiment: Optional[str] = None,
        next_steps: Optional[Sequence[Any]] = None,
        tags: Optional[Iterable[Any]] = None,
        sensitivity: Union[str, CallMemorySensitivity, None] = CallMemorySensitivity.MEDIUM,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Store an approved call summary.

        Designed to receive output from call_summarizer.py after approval.
        """
        action = "store_call_summary"
        ctx, err = self._validated_context_or_error(context)
        if err:
            return err

        payload = {
            "summary": summary,
            "approved": approved,
            "title": title,
            "call_id": call_id,
            "contact_id": contact_id,
            "lead_id": lead_id,
            "action_items": list(action_items or []),
            "sentiment": sentiment,
            "next_steps": list(next_steps or []),
            "tags": list(tags or []),
            "sensitivity": str(sensitivity),
            "metadata": dict(metadata or {}),
        }

        try:
            safe_summary = _truncate_text(summary, SAFE_TEXT_MAX_LENGTH)
            data = {
                "summary": safe_summary,
                "action_items": _safe_json_copy(list(action_items or [])),
                "sentiment": _truncate_text(sentiment, 100) if sentiment else None,
                "next_steps": _safe_json_copy(list(next_steps or [])),
            }

            record = self._build_record(
                context=ctx,
                record_type=CallMemoryRecordType.CALL_SUMMARY,
                title=title or "Approved Call Summary",
                content=safe_summary,
                data=data,
                tags=list(tags or []) + ["call-summary"],
                approved=approved,
                call_id=call_id,
                contact_id=contact_id,
                lead_id=lead_id,
                sensitivity=sensitivity,
                metadata=metadata,
            )
            return self._store_record(action=action, context=ctx, record=record, original_payload=payload)
        except Exception as exc:
            self._log_audit_event(action, ctx, payload, success=False, error=str(exc))
            return self._error_result(
                message="Unable to store call summary.",
                error=str(exc),
                metadata={"action": action},
            )

    # ------------------------------------------------------------------
    # Public read/search methods
    # ------------------------------------------------------------------

    def get_record(
        self,
        *,
        context: Mapping[str, Any],
        record_id: str,
        include_memory_payload: bool = False,
    ) -> Dict[str, Any]:
        """
        Get a single call memory record scoped to user_id/workspace_id.
        """
        action = "get_record"
        ctx, err = self._validated_context_or_error(context)
        if err:
            return err

        try:
            safe_record_id = _normalize_key(record_id, "record_id")
            record = self.store.get_record(ctx["user_id"], ctx["workspace_id"], safe_record_id)
            if not record or record.get("status") == CallMemoryStatus.DELETED.value:
                return self._safe_result(
                    success=False,
                    message="Call memory record not found.",
                    data=None,
                    error="NOT_FOUND",
                    metadata={"action": action, "record_id": safe_record_id},
                )

            data: Dict[str, Any] = {"record": record}
            if include_memory_payload:
                data["memory_payload"] = self._prepare_memory_payload(record, ctx)

            return self._safe_result(
                success=True,
                message="Call memory record retrieved.",
                data=data,
                metadata={"action": action, "record_id": safe_record_id},
            )
        except Exception as exc:
            return self._error_result(
                message="Unable to retrieve call memory record.",
                error=str(exc),
                metadata={"action": action},
            )

    def list_records(
        self,
        *,
        context: Mapping[str, Any],
        record_type: Optional[Union[str, CallMemoryRecordType]] = None,
        status: Optional[Union[str, CallMemoryStatus]] = CallMemoryStatus.ACTIVE,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """
        List records scoped to user_id/workspace_id.
        """
        action = "list_records"
        ctx, err = self._validated_context_or_error(context)
        if err:
            return err

        try:
            normalized_type = None
            if record_type:
                normalized_type = self._validate_record_type(record_type)

            normalized_status = None
            if status:
                normalized_status = status.value if isinstance(status, CallMemoryStatus) else str(status)
                allowed_statuses = {item.value for item in CallMemoryStatus}
                if normalized_status not in allowed_statuses:
                    raise ValueError(f"Unsupported status: {normalized_status}")

            records, total = self.store.list_records(
                user_id=ctx["user_id"],
                workspace_id=ctx["workspace_id"],
                record_type=normalized_type,
                status=normalized_status,
                limit=limit,
                offset=offset,
            )

            return self._safe_result(
                success=True,
                message="Call memory records listed.",
                data={
                    "records": records,
                    "total": total,
                    "limit": max(1, min(int(limit), 500)),
                    "offset": max(0, int(offset)),
                    "record_type": normalized_type,
                    "status": normalized_status,
                },
                metadata={"action": action},
            )
        except Exception as exc:
            return self._error_result(
                message="Unable to list call memory records.",
                error=str(exc),
                metadata={"action": action},
            )

    def list_leads(
        self,
        *,
        context: Mapping[str, Any],
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        return self.list_records(
            context=context,
            record_type=CallMemoryRecordType.LEAD,
            status=CallMemoryStatus.ACTIVE,
            limit=limit,
            offset=offset,
        )

    def list_preferences(
        self,
        *,
        context: Mapping[str, Any],
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        return self.list_records(
            context=context,
            record_type=CallMemoryRecordType.PREFERENCE,
            status=CallMemoryStatus.ACTIVE,
            limit=limit,
            offset=offset,
        )

    def list_call_notes(
        self,
        *,
        context: Mapping[str, Any],
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        return self.list_records(
            context=context,
            record_type=CallMemoryRecordType.CALL_NOTE,
            status=CallMemoryStatus.ACTIVE,
            limit=limit,
            offset=offset,
        )

    def list_call_summaries(
        self,
        *,
        context: Mapping[str, Any],
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        return self.list_records(
            context=context,
            record_type=CallMemoryRecordType.CALL_SUMMARY,
            status=CallMemoryStatus.ACTIVE,
            limit=limit,
            offset=offset,
        )

    def search_records(
        self,
        *,
        context: Mapping[str, Any],
        query: str,
        record_type: Optional[Union[str, CallMemoryRecordType]] = None,
        tags: Optional[Iterable[str]] = None,
        limit: int = 50,
    ) -> Dict[str, Any]:
        """
        Simple local search over title/content/tags/data.

        This is intentionally local and safe. A vector search adapter can be
        added later behind this method.
        """
        action = "search_records"
        ctx, err = self._validated_context_or_error(context)
        if err:
            return err

        try:
            safe_query = _truncate_text(query, 500).lower()
            if not safe_query:
                raise ValueError("query is required.")

            normalized_type = self._validate_record_type(record_type) if record_type else None
            wanted_tags = set(_normalize_tags(tags))
            max_results = max(1, min(int(limit), MAX_SEARCH_RESULTS))

            listed, _total = self.store.list_records(
                user_id=ctx["user_id"],
                workspace_id=ctx["workspace_id"],
                record_type=normalized_type,
                status=CallMemoryStatus.ACTIVE.value,
                limit=MAX_EXPORT_RECORDS,
                offset=0,
            )

            matches: List[Dict[str, Any]] = []
            for record in listed:
                record_tags = set(record.get("tags", []))
                if wanted_tags and not wanted_tags.issubset(record_tags):
                    continue

                haystack = " ".join(
                    [
                        str(record.get("title", "")),
                        str(record.get("content", "")),
                        json.dumps(record.get("data", {}), ensure_ascii=False, default=str),
                        " ".join(record.get("tags", [])),
                    ]
                ).lower()

                if safe_query in haystack:
                    score = haystack.count(safe_query)
                    item = _safe_json_copy(record)
                    item["_search_score"] = score
                    matches.append(item)

            matches.sort(key=lambda item: (item.get("_search_score", 0), item.get("updated_at", "")), reverse=True)
            matches = matches[:max_results]

            return self._safe_result(
                success=True,
                message="Call memory search completed.",
                data={
                    "query": safe_query,
                    "records": matches,
                    "count": len(matches),
                    "limit": max_results,
                    "record_type": normalized_type,
                    "tags": list(wanted_tags),
                },
                metadata={"action": action},
            )
        except Exception as exc:
            return self._error_result(
                message="Unable to search call memory records.",
                error=str(exc),
                metadata={"action": action},
            )

    # ------------------------------------------------------------------
    # Public delete/export methods
    # ------------------------------------------------------------------

    def delete_record(
        self,
        *,
        context: Mapping[str, Any],
        record_id: str,
        approved: bool,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Soft-delete a call memory record.

        Real destructive deletion should be implemented only behind a stronger
        Security Agent policy. This method marks status=deleted.
        """
        action = "delete_record"
        ctx, err = self._validated_context_or_error(context)
        if err:
            return err

        payload = {
            "record_id": record_id,
            "approved": approved,
            "reason": reason,
        }

        try:
            self._validate_approval(approved)
            safe_record_id = _normalize_key(record_id, "record_id")

            if self._requires_security_check(action, payload):
                approval = self._request_security_approval(action, ctx, payload)
                if not approval["success"]:
                    self._log_audit_event(action, ctx, payload, success=False, error=approval["error"])
                    return approval

            deleted = self.store.soft_delete_record(
                user_id=ctx["user_id"],
                workspace_id=ctx["workspace_id"],
                record_id=safe_record_id,
                actor_id=ctx.get("actor_id"),
            )
            if not deleted:
                return self._safe_result(
                    success=False,
                    message="Call memory record not found.",
                    data=None,
                    error="NOT_FOUND",
                    metadata={"action": action, "record_id": safe_record_id},
                )

            verification_payload = self._prepare_verification_payload(action, ctx, deleted, success=True)

            self._emit_agent_event(
                event_name="call_memory.record.deleted",
                context=ctx,
                payload={"record_id": safe_record_id, "reason": reason},
            )
            self._log_audit_event(action, ctx, payload, success=True)

            return self._safe_result(
                success=True,
                message="Call memory record deleted safely.",
                data={
                    "record": deleted,
                    "verification_payload": verification_payload,
                },
                metadata={"action": action, "record_id": safe_record_id},
            )
        except Exception as exc:
            self._log_audit_event(action, ctx, payload, success=False, error=str(exc))
            return self._error_result(
                message="Unable to delete call memory record.",
                error=str(exc),
                metadata={"action": action},
            )

    def export_workspace_memory(
        self,
        *,
        context: Mapping[str, Any],
        approved: bool,
        record_type: Optional[Union[str, CallMemoryRecordType]] = None,
        include_deleted: bool = False,
        limit: int = MAX_EXPORT_RECORDS,
    ) -> Dict[str, Any]:
        """
        Export call memory for one workspace only.

        This is useful for dashboard/API backup, Memory Agent migration, or
        Verification Agent review. It never crosses user/workspace boundaries.
        """
        action = "export_workspace_memory"
        ctx, err = self._validated_context_or_error(context)
        if err:
            return err

        payload = {
            "approved": approved,
            "record_type": str(record_type) if record_type else None,
            "include_deleted": include_deleted,
            "limit": limit,
        }

        try:
            self._validate_approval(approved)

            if self._requires_security_check(action, payload):
                approval = self._request_security_approval(action, ctx, payload)
                if not approval["success"]:
                    self._log_audit_event(action, ctx, payload, success=False, error=approval["error"])
                    return approval

            normalized_type = self._validate_record_type(record_type) if record_type else None
            export_limit = max(1, min(int(limit), MAX_EXPORT_RECORDS))

            if include_deleted:
                statuses = [None]
            else:
                statuses = [CallMemoryStatus.ACTIVE.value]

            all_records: List[Dict[str, Any]] = []
            total = 0
            for status in statuses:
                records, count = self.store.list_records(
                    user_id=ctx["user_id"],
                    workspace_id=ctx["workspace_id"],
                    record_type=normalized_type,
                    status=status,
                    limit=export_limit,
                    offset=0,
                )
                all_records.extend(records)
                total += count

            all_records = all_records[:export_limit]

            export_data = {
                "schema": "william.call_memory.export.v1",
                "agent": self.agent_name,
                "version": self.version,
                "user_id": ctx["user_id"],
                "workspace_id": ctx["workspace_id"],
                "record_type": normalized_type,
                "include_deleted": include_deleted,
                "count": len(all_records),
                "total_available": total,
                "exported_at": _utc_now(),
                "records": all_records,
            }

            verification_payload = self._prepare_verification_payload(action, ctx, export_data, success=True)

            self._emit_agent_event(
                event_name="call_memory.workspace.exported",
                context=ctx,
                payload={
                    "record_type": normalized_type,
                    "count": len(all_records),
                    "include_deleted": include_deleted,
                },
            )
            self._log_audit_event(action, ctx, payload, success=True)

            return self._safe_result(
                success=True,
                message="Workspace call memory exported.",
                data={
                    "export": export_data,
                    "verification_payload": verification_payload,
                },
                metadata={"action": action},
            )
        except Exception as exc:
            self._log_audit_event(action, ctx, payload, success=False, error=str(exc))
            return self._error_result(
                message="Unable to export workspace call memory.",
                error=str(exc),
                metadata={"action": action},
            )

    # ------------------------------------------------------------------
    # Master Agent / Router compatibility
    # ------------------------------------------------------------------

    def route_task(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Router-compatible task entrypoint.

        Expected task shape:
            {
                "action": "store_lead",
                "context": {"user_id": "...", "workspace_id": "..."},
                "payload": {...}
            }
        """
        if not isinstance(task, Mapping):
            return self._error_result(
                message="Task must be a mapping/dict.",
                error="INVALID_TASK",
                metadata={"action": "route_task"},
            )

        action = str(task.get("action", "")).strip()
        context = task.get("context") or {}
        payload = task.get("payload") or {}

        if not isinstance(context, Mapping):
            return self._error_result(
                message="Task context must be a mapping/dict.",
                error="INVALID_CONTEXT",
                metadata={"action": "route_task"},
            )

        if not isinstance(payload, Mapping):
            return self._error_result(
                message="Task payload must be a mapping/dict.",
                error="INVALID_PAYLOAD",
                metadata={"action": "route_task"},
            )

        try:
            if action == "store_call_note":
                return self.store_call_note(context=context, **dict(payload))
            if action == "store_preference":
                return self.store_preference(context=context, **dict(payload))
            if action == "store_lead":
                return self.store_lead(context=context, **dict(payload))
            if action in {"store_call_summary", "store_summary"}:
                return self.store_call_summary(context=context, **dict(payload))
            if action == "get_record":
                return self.get_record(context=context, **dict(payload))
            if action == "list_records":
                return self.list_records(context=context, **dict(payload))
            if action == "search_records":
                return self.search_records(context=context, **dict(payload))
            if action == "list_leads":
                return self.list_leads(context=context, **dict(payload))
            if action == "list_preferences":
                return self.list_preferences(context=context, **dict(payload))
            if action == "list_call_notes":
                return self.list_call_notes(context=context, **dict(payload))
            if action == "list_call_summaries":
                return self.list_call_summaries(context=context, **dict(payload))
            if action == "delete_record":
                return self.delete_record(context=context, **dict(payload))
            if action == "export_workspace_memory":
                return self.export_workspace_memory(context=context, **dict(payload))

            return self._error_result(
                message=f"Unsupported CallMemory action: {action}",
                error="UNSUPPORTED_ACTION",
                metadata={
                    "action": "route_task",
                    "requested_action": action,
                    "supported_actions": AGENT_METADATA["public_methods"],
                },
            )
        except TypeError as exc:
            return self._error_result(
                message="Task payload does not match the selected action signature.",
                error=str(exc),
                metadata={"action": "route_task", "requested_action": action},
            )
        except Exception as exc:
            return self._error_result(
                message="CallMemory route_task failed.",
                error=str(exc),
                metadata={"action": "route_task", "requested_action": action},
            )

    async def run(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Async-compatible BaseAgent entrypoint.
        """
        return self.route_task(task)

    # ------------------------------------------------------------------
    # Registry / Loader helpers
    # ------------------------------------------------------------------

    @classmethod
    def get_agent_metadata(cls) -> Dict[str, Any]:
        return _safe_json_copy(AGENT_METADATA)

    @classmethod
    def healthcheck(cls) -> Dict[str, Any]:
        return {
            "success": True,
            "message": "CallMemory import healthcheck passed.",
            "data": {
                "agent": cls.__name__,
                "version": CALL_MEMORY_VERSION,
                "time": _utc_now(),
            },
            "error": None,
            "metadata": {"module": "Call Agent"},
        }


# Registry-compatible aliases
AGENT_CLASS = CallMemory
Agent = CallMemory


def get_agent_metadata() -> Dict[str, Any]:
    """
    Module-level metadata helper for registry loaders.
    """
    return CallMemory.get_agent_metadata()


def create_agent(**kwargs: Any) -> CallMemory:
    """
    Factory helper for Agent Loader / Registry.
    """
    return CallMemory(**kwargs)


# ---------------------------------------------------------------------------
# Lightweight local test
# ---------------------------------------------------------------------------

def _self_test() -> Dict[str, Any]:
    """
    Safe local self-test. Does not call external systems.
    """
    temp_dir = Path(os.getenv("WILLIAM_CALL_MEMORY_TEST_DIR", ".william_data/test_call_memory"))
    agent = CallMemory(storage_dir=temp_dir, require_approval_by_default=True)

    context = {
        "user_id": "test_user",
        "workspace_id": "test_workspace",
        "actor_id": "tester",
        "source_agent": "self_test",
    }

    note_result = agent.store_call_note(
        context=context,
        note="Caller approved storing this note for follow-up.",
        approved=True,
        call_id="call_test_001",
        tags=["test"],
    )

    lead_result = agent.store_lead(
        context=context,
        full_name="Test Lead",
        phone_number="+1 555 0100",
        approved=True,
        service_interest="Website development",
        call_id="call_test_001",
        tags=["test", "lead"],
    )

    list_result = agent.list_records(context=context, limit=10)

    return {
        "success": bool(note_result["success"] and lead_result["success"] and list_result["success"]),
        "message": "CallMemory self-test completed.",
        "data": {
            "note_result": note_result,
            "lead_result": lead_result,
            "list_result": list_result,
        },
        "error": None,
        "metadata": {"agent": "CallMemory", "version": CALL_MEMORY_VERSION},
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print(json.dumps(_self_test(), indent=2, ensure_ascii=False))


# FILE COMPLETE