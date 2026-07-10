"""
agents/memory_agent/long_term.py

William / Jarvis Multi-Agent AI SaaS System
Memory Agent - Long Term Memory

Purpose:
    Permanent useful facts, preferences, project rules, business context,
    pinned knowledge, and long-lived recall records.

This module is designed to be:
    - SaaS-safe: user_id + workspace_id isolation is mandatory.
    - Import-safe: works even if future William modules are not created yet.
    - Production-ready: structured results, audit logs, validation, safe defaults.
    - Agent-compatible: BaseAgent, Registry, Router, Master Agent friendly.
    - Future-ready: can later swap JSON storage for DB/vector storage.

Core Responsibilities:
    - Store long-term memory records.
    - Recall long-term memory by scope/category/query/tags.
    - Update/delete/archive memories safely.
    - Track importance, confidence, source, visibility, retention, and metadata.
    - Prepare verification and memory payloads for other agents.
    - Emit agent events and audit records.
    - Support Dashboard/API integration through structured dict results.

Security Notes:
    - This file does not execute real browser/system/financial/message/call actions.
    - Sensitive memory actions can be routed through Security Agent hooks.
    - Memory isolation prevents cross-user/workspace leakage.

Author:
    Digital Promotix - William / Jarvis Architecture
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any, Dict, Iterable, List, Literal, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Safe optional imports for future William/Jarvis architecture
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for import safety
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This allows long_term.py to import safely before the real William
        BaseAgent exists. When the real BaseAgent is created, it will be used.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)

        def emit_event(self, *args: Any, **kwargs: Any) -> None:
            return None


try:
    from agents.memory_agent.config import MemoryAgentConfig  # type: ignore
except Exception:  # pragma: no cover - fallback for import safety
    class MemoryAgentConfig:  # type: ignore
        """
        Fallback config stub for standalone testing.

        Future config.py can override these values.
        """

        LONG_TERM_STORAGE_DIR = "data/memory_agent/long_term"
        LONG_TERM_BACKUP_DIR = "data/memory_agent/backups/long_term"
        MAX_LONG_TERM_RECORDS_PER_WORKSPACE = 10000
        DEFAULT_MEMORY_CONFIDENCE = 0.8
        DEFAULT_MEMORY_IMPORTANCE = 0.5
        ENABLE_AUDIT_LOGGING = True
        ENABLE_AGENT_EVENTS = True
        ENABLE_SECURITY_APPROVAL = True


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger("william.memory_agent.long_term")
if not logger.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

MemoryScope = Literal[
    "user",
    "workspace",
    "project",
    "client",
    "team",
    "agent",
    "business",
    "system",
]

MemoryCategory = Literal[
    "fact",
    "preference",
    "project_rule",
    "business_context",
    "client_context",
    "team_context",
    "agent_instruction",
    "workflow_rule",
    "safety_rule",
    "technical_context",
    "note",
]

MemoryStatus = Literal[
    "active",
    "archived",
    "deleted",
]

MemoryVisibility = Literal[
    "private",
    "workspace",
    "agent_internal",
    "system_internal",
]


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _utc_now_iso() -> str:
    """Return current UTC datetime in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def _safe_slug(value: str, default: str = "unknown") -> str:
    """
    Convert a value into a filesystem-safe slug.

    Used only for local JSON file names, never for permission decisions.
    """
    if value is None:
        return default
    value = str(value).strip()
    if not value:
        return default
    value = re.sub(r"[^a-zA-Z0-9_.-]+", "_", value)
    return value[:128] or default


def _normalize_text(value: Any) -> str:
    """Normalize text for simple matching."""
    if value is None:
        return ""
    text = str(value).lower().strip()
    text = re.sub(r"\s+", " ", text)
    return text


def _dedupe_list(values: Optional[Iterable[Any]]) -> List[str]:
    """Return clean unique string list while preserving order."""
    if not values:
        return []
    seen = set()
    output: List[str] = []
    for item in values:
        text = str(item).strip()
        if not text:
            continue
        key = text.lower()
        if key not in seen:
            output.append(text)
            seen.add(key)
    return output


def _clamp_float(value: Any, minimum: float = 0.0, maximum: float = 1.0, default: float = 0.0) -> float:
    """Safely parse and clamp float."""
    try:
        parsed = float(value)
    except Exception:
        parsed = default
    return max(minimum, min(maximum, parsed))


def _json_default(value: Any) -> Any:
    """JSON serializer fallback."""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    return str(value)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class LongTermMemoryRecord:
    """
    A single long-term memory record.

    Each record is isolated by:
        - user_id
        - workspace_id

    The Memory Agent, Master Agent, Router, and Dashboard can use this record
    to recall stable knowledge without mixing tenants.
    """

    memory_id: str
    user_id: str
    workspace_id: str

    content: str
    category: MemoryCategory = "fact"
    scope: MemoryScope = "workspace"
    visibility: MemoryVisibility = "workspace"
    status: MemoryStatus = "active"

    title: Optional[str] = None
    summary: Optional[str] = None

    tags: List[str] = field(default_factory=list)
    entities: List[str] = field(default_factory=list)
    source: Optional[str] = None
    source_agent: Optional[str] = None
    source_task_id: Optional[str] = None

    importance: float = 0.5
    confidence: float = 0.8

    project_id: Optional[str] = None
    client_id: Optional[str] = None
    team_id: Optional[str] = None
    agent_name: Optional[str] = None

    retention_policy: str = "permanent"
    pinned: bool = False
    sensitive: bool = False

    created_at: str = field(default_factory=_utc_now_iso)
    updated_at: str = field(default_factory=_utc_now_iso)
    last_accessed_at: Optional[str] = None
    access_count: int = 0

    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert record to serializable dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "LongTermMemoryRecord":
        """Create a record from dictionary safely."""
        allowed_fields = set(cls.__dataclass_fields__.keys())  # type: ignore
        clean = {key: value for key, value in payload.items() if key in allowed_fields}

        clean.setdefault("memory_id", str(uuid.uuid4()))
        clean.setdefault("user_id", "")
        clean.setdefault("workspace_id", "")
        clean.setdefault("content", "")

        clean["tags"] = _dedupe_list(clean.get("tags", []))
        clean["entities"] = _dedupe_list(clean.get("entities", []))
        clean["importance"] = _clamp_float(clean.get("importance"), default=0.5)
        clean["confidence"] = _clamp_float(clean.get("confidence"), default=0.8)
        clean["metadata"] = clean.get("metadata") or {}

        return cls(**clean)


@dataclass
class MemoryQuery:
    """
    Query object used by recall/search methods.

    This is intentionally simple and DB-independent. The future memory_search.py
    or embeddings.py module can use this query shape for vector/hybrid recall.
    """

    user_id: str
    workspace_id: str
    query: Optional[str] = None
    category: Optional[MemoryCategory] = None
    scope: Optional[MemoryScope] = None
    tags: List[str] = field(default_factory=list)
    entities: List[str] = field(default_factory=list)
    project_id: Optional[str] = None
    client_id: Optional[str] = None
    team_id: Optional[str] = None
    agent_name: Optional[str] = None
    include_archived: bool = False
    include_sensitive: bool = False
    limit: int = 25
    min_importance: Optional[float] = None
    min_confidence: Optional[float] = None


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class LongTermMemory(BaseAgent):
    """
    Long-term permanent memory manager for William / Jarvis.

    Public Methods:
        - remember()
        - recall()
        - get_memory()
        - update_memory()
        - archive_memory()
        - delete_memory()
        - list_memories()
        - search_memories()
        - export_workspace_memory()
        - import_workspace_memory()
        - backup_workspace_memory()
        - get_stats()

    Compatibility Hooks:
        - _validate_task_context()
        - _requires_security_check()
        - _request_security_approval()
        - _prepare_verification_payload()
        - _prepare_memory_payload()
        - _emit_agent_event()
        - _log_audit_event()
        - _safe_result()
        - _error_result()
    """

    AGENT_NAME = "LongTermMemory"
    AGENT_MODULE = "Memory Agent"
    FILE_PATH = "agents/memory_agent/long_term.py"

    VALID_SCOPES: Tuple[str, ...] = (
        "user",
        "workspace",
        "project",
        "client",
        "team",
        "agent",
        "business",
        "system",
    )

    VALID_CATEGORIES: Tuple[str, ...] = (
        "fact",
        "preference",
        "project_rule",
        "business_context",
        "client_context",
        "team_context",
        "agent_instruction",
        "workflow_rule",
        "safety_rule",
        "technical_context",
        "note",
    )

    VALID_VISIBILITIES: Tuple[str, ...] = (
        "private",
        "workspace",
        "agent_internal",
        "system_internal",
    )

    SENSITIVE_CATEGORIES: Tuple[str, ...] = (
        "safety_rule",
        "agent_instruction",
    )

    def __init__(
        self,
        storage_dir: Optional[Union[str, Path]] = None,
        backup_dir: Optional[Union[str, Path]] = None,
        config: Optional[Any] = None,
        security_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
    ) -> None:
        """
        Initialize long-term memory.

        Args:
            storage_dir:
                Directory for JSON memory files.
            backup_dir:
                Directory for backups.
            config:
                Optional MemoryAgentConfig-like object.
            security_agent:
                Future Security Agent integration.
            verification_agent:
                Future Verification Agent integration.
            event_bus:
                Future event bus / registry integration.
            audit_logger:
                Future centralized audit logger integration.
        """
        try:
            super().__init__(agent_name=self.AGENT_NAME)
        except TypeError:
            try:
                super().__init__()
            except Exception:
                pass

        self.config = config or MemoryAgentConfig()
        self.security_agent = security_agent
        self.verification_agent = verification_agent
        self.event_bus = event_bus
        self.audit_logger = audit_logger

        self.storage_dir = Path(
            storage_dir
            or getattr(self.config, "LONG_TERM_STORAGE_DIR", "data/memory_agent/long_term")
        )
        self.backup_dir = Path(
            backup_dir
            or getattr(self.config, "LONG_TERM_BACKUP_DIR", "data/memory_agent/backups/long_term")
        )

        self.max_records_per_workspace = int(
            getattr(self.config, "MAX_LONG_TERM_RECORDS_PER_WORKSPACE", 10000)
        )
        self.default_confidence = float(
            getattr(self.config, "DEFAULT_MEMORY_CONFIDENCE", 0.8)
        )
        self.default_importance = float(
            getattr(self.config, "DEFAULT_MEMORY_IMPORTANCE", 0.5)
        )
        self.enable_audit_logging = bool(
            getattr(self.config, "ENABLE_AUDIT_LOGGING", True)
        )
        self.enable_agent_events = bool(
            getattr(self.config, "ENABLE_AGENT_EVENTS", True)
        )
        self.enable_security_approval = bool(
            getattr(self.config, "ENABLE_SECURITY_APPROVAL", True)
        )

        self._lock = RLock()
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(parents=True, exist_ok=True)

        logger.info("LongTermMemory initialized with storage_dir=%s", self.storage_dir)

    # ---------------------------------------------------------------------
    # Public API
    # ---------------------------------------------------------------------

    def remember(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        content: str,
        category: MemoryCategory = "fact",
        scope: MemoryScope = "workspace",
        title: Optional[str] = None,
        summary: Optional[str] = None,
        tags: Optional[List[str]] = None,
        entities: Optional[List[str]] = None,
        source: Optional[str] = None,
        source_agent: Optional[str] = None,
        source_task_id: Optional[str] = None,
        importance: Optional[float] = None,
        confidence: Optional[float] = None,
        project_id: Optional[Union[str, int]] = None,
        client_id: Optional[Union[str, int]] = None,
        team_id: Optional[Union[str, int]] = None,
        agent_name: Optional[str] = None,
        visibility: MemoryVisibility = "workspace",
        pinned: bool = False,
        sensitive: bool = False,
        retention_policy: str = "permanent",
        metadata: Optional[Dict[str, Any]] = None,
        require_security: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Store a permanent long-term memory record.

        This method is used by:
            - Memory Agent to persist stable context.
            - Master Agent to save user/project/business facts.
            - Dashboard/API to pin rules and preferences.
            - Future Preference/Project/Client memory modules.

        Returns:
            Structured result dict:
                {
                    "success": bool,
                    "message": str,
                    "data": {...},
                    "error": None | {...},
                    "metadata": {...}
                }
        """
        context_result = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not context_result["success"]:
            return context_result

        user_id_str = str(user_id)
        workspace_id_str = str(workspace_id)

        content = str(content or "").strip()
        if not content:
            return self._error_result(
                message="Memory content is required.",
                code="EMPTY_MEMORY_CONTENT",
                metadata={"user_id": user_id_str, "workspace_id": workspace_id_str},
            )

        category = self._normalize_category(category)
        scope = self._normalize_scope(scope)
        visibility = self._normalize_visibility(visibility)

        sensitive = bool(sensitive or category in self.SENSITIVE_CATEGORIES)

        security_needed = self._requires_security_check(
            action="remember",
            category=category,
            scope=scope,
            visibility=visibility,
            sensitive=sensitive,
            require_security=require_security,
        )

        if security_needed:
            approval = self._request_security_approval(
                user_id=user_id_str,
                workspace_id=workspace_id_str,
                action="remember",
                payload={
                    "category": category,
                    "scope": scope,
                    "visibility": visibility,
                    "sensitive": sensitive,
                    "content_preview": content[:250],
                },
            )
            if not approval.get("approved", False):
                return self._error_result(
                    message="Security approval denied for long-term memory write.",
                    code="SECURITY_APPROVAL_DENIED",
                    metadata={
                        "user_id": user_id_str,
                        "workspace_id": workspace_id_str,
                        "approval": approval,
                    },
                )

        with self._lock:
            records = self._load_workspace_records(user_id_str, workspace_id_str)

            active_count = len([item for item in records if item.status != "deleted"])
            if active_count >= self.max_records_per_workspace:
                return self._error_result(
                    message="Long-term memory limit reached for this workspace.",
                    code="MEMORY_LIMIT_REACHED",
                    metadata={
                        "user_id": user_id_str,
                        "workspace_id": workspace_id_str,
                        "limit": self.max_records_per_workspace,
                    },
                )

            record = LongTermMemoryRecord(
                memory_id=str(uuid.uuid4()),
                user_id=user_id_str,
                workspace_id=workspace_id_str,
                content=content,
                category=category,
                scope=scope,
                visibility=visibility,
                title=title.strip() if title else None,
                summary=summary.strip() if summary else self._auto_summary(content),
                tags=_dedupe_list(tags),
                entities=_dedupe_list(entities),
                source=source,
                source_agent=source_agent,
                source_task_id=source_task_id,
                importance=_clamp_float(
                    importance,
                    default=self.default_importance,
                ),
                confidence=_clamp_float(
                    confidence,
                    default=self.default_confidence,
                ),
                project_id=str(project_id) if project_id is not None else None,
                client_id=str(client_id) if client_id is not None else None,
                team_id=str(team_id) if team_id is not None else None,
                agent_name=agent_name,
                pinned=bool(pinned),
                sensitive=sensitive,
                retention_policy=str(retention_policy or "permanent"),
                metadata=metadata or {},
            )

            records.append(record)
            self._save_workspace_records(user_id_str, workspace_id_str, records)

        verification_payload = self._prepare_verification_payload(
            action="remember",
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            memory_id=record.memory_id,
            success=True,
            data=record.to_dict(),
        )

        memory_payload = self._prepare_memory_payload(
            action="remember",
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            memory_id=record.memory_id,
            record=record.to_dict(),
        )

        self._emit_agent_event(
            event_name="memory.long_term.created",
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            payload={
                "memory_id": record.memory_id,
                "category": record.category,
                "scope": record.scope,
                "source_agent": record.source_agent,
            },
        )

        self._log_audit_event(
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            action="long_term_memory.created",
            payload={
                "memory_id": record.memory_id,
                "category": record.category,
                "scope": record.scope,
                "visibility": record.visibility,
                "sensitive": record.sensitive,
            },
        )

        return self._safe_result(
            message="Long-term memory saved successfully.",
            data={
                "memory": record.to_dict(),
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                "user_id": user_id_str,
                "workspace_id": workspace_id_str,
                "agent": self.AGENT_NAME,
            },
        )

    def recall(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        query: Optional[str] = None,
        category: Optional[MemoryCategory] = None,
        scope: Optional[MemoryScope] = None,
        tags: Optional[List[str]] = None,
        entities: Optional[List[str]] = None,
        project_id: Optional[Union[str, int]] = None,
        client_id: Optional[Union[str, int]] = None,
        team_id: Optional[Union[str, int]] = None,
        agent_name: Optional[str] = None,
        include_archived: bool = False,
        include_sensitive: bool = False,
        limit: int = 25,
        min_importance: Optional[float] = None,
        min_confidence: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Recall long-term memories using simple hybrid filtering.

        This is DB/vector independent and safe for early production. Future
        recall_engine.py and embeddings.py can wrap or replace this scoring.
        """
        context_result = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not context_result["success"]:
            return context_result

        memory_query = MemoryQuery(
            user_id=str(user_id),
            workspace_id=str(workspace_id),
            query=query,
            category=self._normalize_category(category) if category else None,
            scope=self._normalize_scope(scope) if scope else None,
            tags=_dedupe_list(tags),
            entities=_dedupe_list(entities),
            project_id=str(project_id) if project_id is not None else None,
            client_id=str(client_id) if client_id is not None else None,
            team_id=str(team_id) if team_id is not None else None,
            agent_name=agent_name,
            include_archived=include_archived,
            include_sensitive=include_sensitive,
            limit=max(1, min(int(limit or 25), 500)),
            min_importance=min_importance,
            min_confidence=min_confidence,
        )

        with self._lock:
            records = self._load_workspace_records(memory_query.user_id, memory_query.workspace_id)
            matched = self._filter_and_score_records(records, memory_query)

            for score, record in matched:
                record.last_accessed_at = _utc_now_iso()
                record.access_count += 1

            if matched:
                self._save_workspace_records(
                    memory_query.user_id,
                    memory_query.workspace_id,
                    records,
                )

        result_items = [
            {
                "score": score,
                "memory": record.to_dict(),
            }
            for score, record in matched[: memory_query.limit]
        ]

        self._emit_agent_event(
            event_name="memory.long_term.recalled",
            user_id=memory_query.user_id,
            workspace_id=memory_query.workspace_id,
            payload={
                "query": query,
                "matched_count": len(result_items),
                "category": memory_query.category,
                "scope": memory_query.scope,
            },
        )

        return self._safe_result(
            message="Long-term memories recalled successfully.",
            data={
                "items": result_items,
                "count": len(result_items),
                "query": asdict(memory_query),
            },
            metadata={
                "user_id": memory_query.user_id,
                "workspace_id": memory_query.workspace_id,
                "agent": self.AGENT_NAME,
            },
        )

    def search_memories(self, **kwargs: Any) -> Dict[str, Any]:
        """
        Alias for recall().

        Kept for Dashboard/API compatibility.
        """
        return self.recall(**kwargs)

    def list_memories(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        status: Optional[MemoryStatus] = "active",
        category: Optional[MemoryCategory] = None,
        scope: Optional[MemoryScope] = None,
        include_sensitive: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """
        List memory records for dashboard/API views.
        """
        context_result = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not context_result["success"]:
            return context_result

        user_id_str = str(user_id)
        workspace_id_str = str(workspace_id)
        limit = max(1, min(int(limit or 100), 1000))
        offset = max(0, int(offset or 0))

        with self._lock:
            records = self._load_workspace_records(user_id_str, workspace_id_str)

        filtered: List[LongTermMemoryRecord] = []
        for record in records:
            if status and record.status != status:
                continue
            if category and record.category != self._normalize_category(category):
                continue
            if scope and record.scope != self._normalize_scope(scope):
                continue
            if record.sensitive and not include_sensitive:
                continue
            filtered.append(record)

        filtered.sort(
            key=lambda item: (
                item.pinned,
                item.importance,
                item.updated_at,
            ),
            reverse=True,
        )

        paginated = filtered[offset : offset + limit]

        return self._safe_result(
            message="Long-term memories listed successfully.",
            data={
                "items": [item.to_dict() for item in paginated],
                "count": len(paginated),
                "total": len(filtered),
                "limit": limit,
                "offset": offset,
            },
            metadata={
                "user_id": user_id_str,
                "workspace_id": workspace_id_str,
            },
        )

    def get_memory(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        memory_id: str,
        include_sensitive: bool = False,
    ) -> Dict[str, Any]:
        """
        Fetch a single memory by ID with tenant isolation.
        """
        context_result = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not context_result["success"]:
            return context_result

        user_id_str = str(user_id)
        workspace_id_str = str(workspace_id)

        with self._lock:
            records = self._load_workspace_records(user_id_str, workspace_id_str)
            record = self._find_record(records, memory_id)

            if not record or record.status == "deleted":
                return self._error_result(
                    message="Memory not found.",
                    code="MEMORY_NOT_FOUND",
                    metadata={
                        "user_id": user_id_str,
                        "workspace_id": workspace_id_str,
                        "memory_id": memory_id,
                    },
                )

            if record.sensitive and not include_sensitive:
                return self._error_result(
                    message="Memory is sensitive and requires explicit access.",
                    code="SENSITIVE_MEMORY_RESTRICTED",
                    metadata={
                        "user_id": user_id_str,
                        "workspace_id": workspace_id_str,
                        "memory_id": memory_id,
                    },
                )

            record.last_accessed_at = _utc_now_iso()
            record.access_count += 1
            self._save_workspace_records(user_id_str, workspace_id_str, records)

        return self._safe_result(
            message="Memory fetched successfully.",
            data={"memory": record.to_dict()},
            metadata={
                "user_id": user_id_str,
                "workspace_id": workspace_id_str,
                "memory_id": memory_id,
            },
        )

    def update_memory(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        memory_id: str,
        updates: Dict[str, Any],
        require_security: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Update an existing memory safely.

        Only allowed fields can be updated. Tenant identifiers and memory_id
        cannot be changed.
        """
        context_result = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not context_result["success"]:
            return context_result

        if not isinstance(updates, dict) or not updates:
            return self._error_result(
                message="Updates dictionary is required.",
                code="EMPTY_UPDATES",
            )

        user_id_str = str(user_id)
        workspace_id_str = str(workspace_id)

        allowed_fields = {
            "content",
            "category",
            "scope",
            "visibility",
            "title",
            "summary",
            "tags",
            "entities",
            "source",
            "source_agent",
            "source_task_id",
            "importance",
            "confidence",
            "project_id",
            "client_id",
            "team_id",
            "agent_name",
            "retention_policy",
            "pinned",
            "sensitive",
            "metadata",
        }

        clean_updates = {
            key: value for key, value in updates.items() if key in allowed_fields
        }

        if not clean_updates:
            return self._error_result(
                message="No allowed update fields were provided.",
                code="NO_ALLOWED_UPDATE_FIELDS",
                metadata={"allowed_fields": sorted(allowed_fields)},
            )

        security_needed = self._requires_security_check(
            action="update_memory",
            category=str(clean_updates.get("category", "")),
            scope=str(clean_updates.get("scope", "")),
            visibility=str(clean_updates.get("visibility", "")),
            sensitive=bool(clean_updates.get("sensitive", False)),
            require_security=require_security,
        )

        if security_needed:
            approval = self._request_security_approval(
                user_id=user_id_str,
                workspace_id=workspace_id_str,
                action="update_memory",
                payload={
                    "memory_id": memory_id,
                    "updates": self._redact_sensitive_update_preview(clean_updates),
                },
            )
            if not approval.get("approved", False):
                return self._error_result(
                    message="Security approval denied for long-term memory update.",
                    code="SECURITY_APPROVAL_DENIED",
                    metadata={"approval": approval},
                )

        with self._lock:
            records = self._load_workspace_records(user_id_str, workspace_id_str)
            record = self._find_record(records, memory_id)

            if not record or record.status == "deleted":
                return self._error_result(
                    message="Memory not found.",
                    code="MEMORY_NOT_FOUND",
                    metadata={
                        "user_id": user_id_str,
                        "workspace_id": workspace_id_str,
                        "memory_id": memory_id,
                    },
                )

            before = record.to_dict()

            for key, value in clean_updates.items():
                if key == "content":
                    value = str(value or "").strip()
                    if not value:
                        return self._error_result(
                            message="Memory content cannot be empty.",
                            code="EMPTY_MEMORY_CONTENT",
                        )
                    setattr(record, key, value)
                elif key == "category":
                    setattr(record, key, self._normalize_category(value))
                elif key == "scope":
                    setattr(record, key, self._normalize_scope(value))
                elif key == "visibility":
                    setattr(record, key, self._normalize_visibility(value))
                elif key in {"tags", "entities"}:
                    setattr(record, key, _dedupe_list(value))
                elif key in {"importance", "confidence"}:
                    setattr(record, key, _clamp_float(value, default=getattr(record, key)))
                elif key in {"project_id", "client_id", "team_id"}:
                    setattr(record, key, str(value) if value is not None else None)
                elif key == "metadata":
                    existing = record.metadata if isinstance(record.metadata, dict) else {}
                    incoming = value if isinstance(value, dict) else {}
                    existing.update(incoming)
                    record.metadata = existing
                else:
                    setattr(record, key, value)

            record.updated_at = _utc_now_iso()

            if record.category in self.SENSITIVE_CATEGORIES:
                record.sensitive = True

            self._save_workspace_records(user_id_str, workspace_id_str, records)

        self._emit_agent_event(
            event_name="memory.long_term.updated",
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            payload={"memory_id": memory_id},
        )

        self._log_audit_event(
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            action="long_term_memory.updated",
            payload={
                "memory_id": memory_id,
                "changed_fields": sorted(clean_updates.keys()),
            },
        )

        return self._safe_result(
            message="Memory updated successfully.",
            data={
                "before": before,
                "after": record.to_dict(),
                "verification_payload": self._prepare_verification_payload(
                    action="update_memory",
                    user_id=user_id_str,
                    workspace_id=workspace_id_str,
                    memory_id=memory_id,
                    success=True,
                    data=record.to_dict(),
                ),
            },
            metadata={
                "user_id": user_id_str,
                "workspace_id": workspace_id_str,
                "memory_id": memory_id,
            },
        )

    def archive_memory(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        memory_id: str,
    ) -> Dict[str, Any]:
        """
        Archive a memory record without deleting it.
        """
        return self._set_memory_status(
            user_id=user_id,
            workspace_id=workspace_id,
            memory_id=memory_id,
            status="archived",
            action_label="archived",
        )

    def delete_memory(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        memory_id: str,
        hard_delete: bool = False,
        require_security: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Delete a memory record.

        By default, this is a soft delete. Hard delete physically removes the
        record from local storage and should be protected by Security Agent.
        """
        context_result = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not context_result["success"]:
            return context_result

        user_id_str = str(user_id)
        workspace_id_str = str(workspace_id)

        security_needed = bool(hard_delete) or self._requires_security_check(
            action="delete_memory",
            category="",
            scope="",
            visibility="",
            sensitive=False,
            require_security=require_security,
        )

        if security_needed:
            approval = self._request_security_approval(
                user_id=user_id_str,
                workspace_id=workspace_id_str,
                action="delete_memory",
                payload={"memory_id": memory_id, "hard_delete": hard_delete},
            )
            if not approval.get("approved", False):
                return self._error_result(
                    message="Security approval denied for memory delete.",
                    code="SECURITY_APPROVAL_DENIED",
                    metadata={"approval": approval},
                )

        with self._lock:
            records = self._load_workspace_records(user_id_str, workspace_id_str)
            record = self._find_record(records, memory_id)

            if not record:
                return self._error_result(
                    message="Memory not found.",
                    code="MEMORY_NOT_FOUND",
                    metadata={
                        "user_id": user_id_str,
                        "workspace_id": workspace_id_str,
                        "memory_id": memory_id,
                    },
                )

            deleted_record = record.to_dict()

            if hard_delete:
                records = [item for item in records if item.memory_id != memory_id]
            else:
                record.status = "deleted"
                record.updated_at = _utc_now_iso()

            self._save_workspace_records(user_id_str, workspace_id_str, records)

        self._emit_agent_event(
            event_name="memory.long_term.deleted",
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            payload={"memory_id": memory_id, "hard_delete": hard_delete},
        )

        self._log_audit_event(
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            action="long_term_memory.deleted",
            payload={"memory_id": memory_id, "hard_delete": hard_delete},
        )

        return self._safe_result(
            message="Memory deleted successfully." if hard_delete else "Memory soft-deleted successfully.",
            data={
                "memory": deleted_record,
                "hard_delete": hard_delete,
            },
            metadata={
                "user_id": user_id_str,
                "workspace_id": workspace_id_str,
                "memory_id": memory_id,
            },
        )

    def export_workspace_memory(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        include_deleted: bool = False,
        include_sensitive: bool = False,
    ) -> Dict[str, Any]:
        """
        Export workspace memory as a structured dict.

        Useful for dashboard export, backup, migration, and future sync.
        """
        context_result = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not context_result["success"]:
            return context_result

        user_id_str = str(user_id)
        workspace_id_str = str(workspace_id)

        with self._lock:
            records = self._load_workspace_records(user_id_str, workspace_id_str)

        exported: List[Dict[str, Any]] = []
        for record in records:
            if record.status == "deleted" and not include_deleted:
                continue
            if record.sensitive and not include_sensitive:
                continue
            exported.append(record.to_dict())

        payload = {
            "schema": "william.memory_agent.long_term.export.v1",
            "exported_at": _utc_now_iso(),
            "user_id": user_id_str,
            "workspace_id": workspace_id_str,
            "count": len(exported),
            "records": exported,
        }

        return self._safe_result(
            message="Workspace long-term memory exported successfully.",
            data=payload,
            metadata={
                "user_id": user_id_str,
                "workspace_id": workspace_id_str,
                "count": len(exported),
            },
        )

    def import_workspace_memory(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        records: List[Dict[str, Any]],
        merge: bool = True,
        require_security: Optional[bool] = True,
    ) -> Dict[str, Any]:
        """
        Import memory records into a workspace.

        Args:
            merge:
                If True, existing records are preserved and imported records
                are added/updated by memory_id.
                If False, existing active records are replaced.

        Security:
            Importing memory can alter long-term agent behavior, so it requires
            Security Agent approval by default.
        """
        context_result = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not context_result["success"]:
            return context_result

        if not isinstance(records, list):
            return self._error_result(
                message="Records must be a list of dictionaries.",
                code="INVALID_IMPORT_RECORDS",
            )

        user_id_str = str(user_id)
        workspace_id_str = str(workspace_id)

        if self._requires_security_check(
            action="import_workspace_memory",
            category="",
            scope="workspace",
            visibility="workspace",
            sensitive=True,
            require_security=require_security,
        ):
            approval = self._request_security_approval(
                user_id=user_id_str,
                workspace_id=workspace_id_str,
                action="import_workspace_memory",
                payload={"record_count": len(records), "merge": merge},
            )
            if not approval.get("approved", False):
                return self._error_result(
                    message="Security approval denied for memory import.",
                    code="SECURITY_APPROVAL_DENIED",
                    metadata={"approval": approval},
                )

        imported_records: List[LongTermMemoryRecord] = []

        for raw in records:
            if not isinstance(raw, dict):
                continue

            raw_copy = dict(raw)
            raw_copy["user_id"] = user_id_str
            raw_copy["workspace_id"] = workspace_id_str
            raw_copy.setdefault("memory_id", str(uuid.uuid4()))
            raw_copy.setdefault("created_at", _utc_now_iso())
            raw_copy["updated_at"] = _utc_now_iso()

            try:
                record = LongTermMemoryRecord.from_dict(raw_copy)
            except Exception as exc:
                logger.warning("Skipping invalid memory import record: %s", exc)
                continue

            if record.content.strip():
                imported_records.append(record)

        with self._lock:
            existing = self._load_workspace_records(user_id_str, workspace_id_str)

            if merge:
                by_id = {item.memory_id: item for item in existing}
                for imported in imported_records:
                    by_id[imported.memory_id] = imported
                final_records = list(by_id.values())
            else:
                final_records = imported_records

            if len(final_records) > self.max_records_per_workspace:
                return self._error_result(
                    message="Import exceeds workspace long-term memory limit.",
                    code="MEMORY_LIMIT_REACHED",
                    metadata={
                        "limit": self.max_records_per_workspace,
                        "attempted": len(final_records),
                    },
                )

            self._save_workspace_records(user_id_str, workspace_id_str, final_records)

        self._emit_agent_event(
            event_name="memory.long_term.imported",
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            payload={"imported_count": len(imported_records), "merge": merge},
        )

        self._log_audit_event(
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            action="long_term_memory.imported",
            payload={"imported_count": len(imported_records), "merge": merge},
        )

        return self._safe_result(
            message="Workspace long-term memory imported successfully.",
            data={
                "imported_count": len(imported_records),
                "merge": merge,
            },
            metadata={
                "user_id": user_id_str,
                "workspace_id": workspace_id_str,
            },
        )

    def backup_workspace_memory(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
    ) -> Dict[str, Any]:
        """
        Create a local JSON backup of a workspace memory file.
        """
        context_result = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not context_result["success"]:
            return context_result

        user_id_str = str(user_id)
        workspace_id_str = str(workspace_id)

        with self._lock:
            source_path = self._workspace_file_path(user_id_str, workspace_id_str)

            if not source_path.exists():
                self._save_workspace_records(user_id_str, workspace_id_str, [])

            timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            backup_name = f"{_safe_slug(user_id_str)}__{_safe_slug(workspace_id_str)}__{timestamp}.json"
            backup_path = self.backup_dir / backup_name
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_path, backup_path)

        self._log_audit_event(
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            action="long_term_memory.backup_created",
            payload={"backup_path": str(backup_path)},
        )

        return self._safe_result(
            message="Workspace long-term memory backup created successfully.",
            data={
                "backup_path": str(backup_path),
                "created_at": _utc_now_iso(),
            },
            metadata={
                "user_id": user_id_str,
                "workspace_id": workspace_id_str,
            },
        )

    def get_stats(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
    ) -> Dict[str, Any]:
        """
        Return memory stats for dashboard analytics.
        """
        context_result = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not context_result["success"]:
            return context_result

        user_id_str = str(user_id)
        workspace_id_str = str(workspace_id)

        with self._lock:
            records = self._load_workspace_records(user_id_str, workspace_id_str)

        by_status: Dict[str, int] = {}
        by_category: Dict[str, int] = {}
        by_scope: Dict[str, int] = {}
        sensitive_count = 0
        pinned_count = 0

        for record in records:
            by_status[record.status] = by_status.get(record.status, 0) + 1
            by_category[record.category] = by_category.get(record.category, 0) + 1
            by_scope[record.scope] = by_scope.get(record.scope, 0) + 1
            if record.sensitive:
                sensitive_count += 1
            if record.pinned:
                pinned_count += 1

        active_records = [item for item in records if item.status == "active"]

        stats = {
            "total": len(records),
            "active": len(active_records),
            "archived": by_status.get("archived", 0),
            "deleted": by_status.get("deleted", 0),
            "sensitive": sensitive_count,
            "pinned": pinned_count,
            "by_status": by_status,
            "by_category": by_category,
            "by_scope": by_scope,
            "max_records_per_workspace": self.max_records_per_workspace,
            "remaining_capacity": max(0, self.max_records_per_workspace - len(active_records)),
        }

        return self._safe_result(
            message="Long-term memory stats fetched successfully.",
            data={"stats": stats},
            metadata={
                "user_id": user_id_str,
                "workspace_id": workspace_id_str,
            },
        )

    # ---------------------------------------------------------------------
    # Required compatibility hooks
    # ---------------------------------------------------------------------

    def _validate_task_context(
        self,
        *,
        user_id: Union[str, int, None],
        workspace_id: Union[str, int, None],
        **_: Any,
    ) -> Dict[str, Any]:
        """
        Validate mandatory SaaS isolation context.

        Every user/workspace-specific action must include both identifiers.
        """
        if user_id is None or str(user_id).strip() == "":
            return self._error_result(
                message="user_id is required for long-term memory operations.",
                code="MISSING_USER_ID",
            )

        if workspace_id is None or str(workspace_id).strip() == "":
            return self._error_result(
                message="workspace_id is required for long-term memory operations.",
                code="MISSING_WORKSPACE_ID",
                metadata={"user_id": str(user_id)},
            )

        return self._safe_result(
            message="Task context validated.",
            data={
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
            },
        )

    def _requires_security_check(
        self,
        *,
        action: str,
        category: str = "",
        scope: str = "",
        visibility: str = "",
        sensitive: bool = False,
        require_security: Optional[bool] = None,
        **_: Any,
    ) -> bool:
        """
        Decide whether the Security Agent must approve this action.

        Security comes before memory behavior. This is intentionally cautious for:
            - system/internal memory
            - sensitive memory
            - safety rules
            - agent instructions
            - imports/deletes
        """
        if require_security is not None:
            return bool(require_security)

        if not self.enable_security_approval:
            return False

        high_risk_actions = {
            "delete_memory",
            "import_workspace_memory",
            "bulk_update",
            "hard_delete",
        }

        if action in high_risk_actions:
            return True

        if sensitive:
            return True

        if category in {"safety_rule", "agent_instruction"}:
            return True

        if scope in {"system", "agent"}:
            return True

        if visibility in {"agent_internal", "system_internal"}:
            return True

        return False

    def _request_security_approval(
        self,
        *,
        user_id: str,
        workspace_id: str,
        action: str,
        payload: Dict[str, Any],
        **_: Any,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        If a real security_agent exists, this method tries common approval
        method names. If no Security Agent exists yet, it returns an approved
        fallback with clear metadata for import-safe development.
        """
        approval_payload = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "agent": self.AGENT_NAME,
            "action": action,
            "payload": payload,
            "requested_at": _utc_now_iso(),
        }

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
                        result = method(approval_payload)
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
                    except Exception as exc:
                        logger.exception("Security approval failed: %s", exc)
                        return {
                            "approved": False,
                            "source": f"security_agent.{method_name}",
                            "error": str(exc),
                        }

        return {
            "approved": True,
            "source": "fallback_no_security_agent",
            "warning": "No Security Agent configured. Approved by safe fallback.",
            "payload": approval_payload,
        }

    def _prepare_verification_payload(
        self,
        *,
        action: str,
        user_id: str,
        workspace_id: str,
        memory_id: Optional[str] = None,
        success: bool = True,
        data: Optional[Dict[str, Any]] = None,
        **extra: Any,
    ) -> Dict[str, Any]:
        """
        Prepare payload for Verification Agent.

        The Verification Agent can later confirm:
            - correct user/workspace isolation
            - memory was written/updated/deleted
            - expected result schema is valid
        """
        return {
            "schema": "william.verification_payload.v1",
            "agent": self.AGENT_NAME,
            "module": self.AGENT_MODULE,
            "file_path": self.FILE_PATH,
            "action": action,
            "success": success,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "memory_id": memory_id,
            "data": data or {},
            "extra": extra,
            "created_at": _utc_now_iso(),
        }

    def _prepare_memory_payload(
        self,
        *,
        action: str,
        user_id: str,
        workspace_id: str,
        memory_id: Optional[str] = None,
        record: Optional[Dict[str, Any]] = None,
        **extra: Any,
    ) -> Dict[str, Any]:
        """
        Prepare a standardized payload for Memory Agent / Master Agent routing.

        Other agents can pass this payload to Memory Agent without knowing
        internal storage details.
        """
        return {
            "schema": "william.memory_payload.v1",
            "memory_type": "long_term",
            "agent": self.AGENT_NAME,
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "memory_id": memory_id,
            "record": record or {},
            "extra": extra,
            "created_at": _utc_now_iso(),
        }

    def _emit_agent_event(
        self,
        *,
        event_name: str,
        user_id: str,
        workspace_id: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Emit an event for Agent Registry, Dashboard, Router, or event bus.

        This method never raises because memory operations should not fail
        because an event bus is missing.
        """
        if not self.enable_agent_events:
            return

        event = {
            "event_id": str(uuid.uuid4()),
            "event_name": event_name,
            "agent": self.AGENT_NAME,
            "module": self.AGENT_MODULE,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "payload": payload or {},
            "created_at": _utc_now_iso(),
        }

        try:
            if self.event_bus is not None:
                for method_name in ("emit", "publish", "send", "dispatch"):
                    method = getattr(self.event_bus, method_name, None)
                    if callable(method):
                        method(event)
                        return

            emit_event = getattr(super(), "emit_event", None)
            if callable(emit_event):
                emit_event(event_name, event)

        except Exception as exc:
            logger.warning("Failed to emit agent event %s: %s", event_name, exc)

    def _log_audit_event(
        self,
        *,
        user_id: str,
        workspace_id: str,
        action: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log audit event for sensitive traceability.

        Future audit logger can persist this to database or dashboard.
        """
        if not self.enable_audit_logging:
            return

        event = {
            "audit_id": str(uuid.uuid4()),
            "agent": self.AGENT_NAME,
            "module": self.AGENT_MODULE,
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "payload": payload or {},
            "created_at": _utc_now_iso(),
        }

        try:
            if self.audit_logger is not None:
                for method_name in ("log", "write", "record", "emit"):
                    method = getattr(self.audit_logger, method_name, None)
                    if callable(method):
                        method(event)
                        return

            logger.info("AUDIT | %s", json.dumps(event, default=_json_default))

        except Exception as exc:
            logger.warning("Failed to log audit event %s: %s", action, exc)

    def _safe_result(
        self,
        *,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard success result shape used across William/Jarvis.
        """
        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": {
                "agent": self.AGENT_NAME,
                "module": self.AGENT_MODULE,
                "timestamp": _utc_now_iso(),
                **(metadata or {}),
            },
        }

    def _error_result(
        self,
        *,
        message: str,
        code: str = "LONG_TERM_MEMORY_ERROR",
        error: Optional[Union[str, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard error result shape used across William/Jarvis.
        """
        error_payload: Dict[str, Any]

        if isinstance(error, dict):
            error_payload = error
        else:
            error_payload = {
                "code": code,
                "details": error or message,
            }

        return {
            "success": False,
            "message": message,
            "data": {},
            "error": error_payload,
            "metadata": {
                "agent": self.AGENT_NAME,
                "module": self.AGENT_MODULE,
                "timestamp": _utc_now_iso(),
                **(metadata or {}),
            },
        }

    # ---------------------------------------------------------------------
    # Internal storage methods
    # ---------------------------------------------------------------------

    def _workspace_file_path(self, user_id: str, workspace_id: str) -> Path:
        """
        Build local JSON file path for a user/workspace.

        This physical separation reinforces SaaS isolation.
        """
        user_slug = _safe_slug(user_id)
        workspace_slug = _safe_slug(workspace_id)

        directory = self.storage_dir / f"user_{user_slug}"
        directory.mkdir(parents=True, exist_ok=True)

        return directory / f"workspace_{workspace_slug}.json"

    def _load_workspace_records(
        self,
        user_id: str,
        workspace_id: str,
    ) -> List[LongTermMemoryRecord]:
        """
        Load all records for a user/workspace from JSON.

        Corrupt files are backed up before returning an empty list.
        """
        path = self._workspace_file_path(user_id, workspace_id)

        if not path.exists():
            return []

        try:
            with path.open("r", encoding="utf-8") as file:
                raw = json.load(file)

            if isinstance(raw, dict):
                raw_records = raw.get("records", [])
            elif isinstance(raw, list):
                raw_records = raw
            else:
                raw_records = []

            records: List[LongTermMemoryRecord] = []
            for item in raw_records:
                if not isinstance(item, dict):
                    continue

                item["user_id"] = user_id
                item["workspace_id"] = workspace_id

                try:
                    records.append(LongTermMemoryRecord.from_dict(item))
                except Exception as exc:
                    logger.warning("Skipping invalid memory record in %s: %s", path, exc)

            return records

        except Exception as exc:
            logger.exception("Failed to load memory file %s: %s", path, exc)
            self._backup_corrupt_file(path)
            return []

    def _save_workspace_records(
        self,
        user_id: str,
        workspace_id: str,
        records: List[LongTermMemoryRecord],
    ) -> None:
        """
        Save all records for a user/workspace atomically.
        """
        path = self._workspace_file_path(user_id, workspace_id)
        temp_path = path.with_suffix(".tmp")

        payload = {
            "schema": "william.memory_agent.long_term.v1",
            "user_id": user_id,
            "workspace_id": workspace_id,
            "updated_at": _utc_now_iso(),
            "count": len(records),
            "records": [record.to_dict() for record in records],
        }

        with temp_path.open("w", encoding="utf-8") as file:
            json.dump(
                payload,
                file,
                ensure_ascii=False,
                indent=2,
                default=_json_default,
            )

        os.replace(temp_path, path)

    def _backup_corrupt_file(self, path: Path) -> None:
        """
        Backup a corrupt JSON file instead of deleting it.
        """
        try:
            if not path.exists():
                return

            timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            backup_path = self.backup_dir / f"corrupt__{path.stem}__{timestamp}.json"
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, backup_path)
            logger.warning("Backed up corrupt memory file to %s", backup_path)
        except Exception as exc:
            logger.warning("Failed to backup corrupt memory file %s: %s", path, exc)

    # ---------------------------------------------------------------------
    # Internal filtering/scoring
    # ---------------------------------------------------------------------

    def _filter_and_score_records(
        self,
        records: List[LongTermMemoryRecord],
        query: MemoryQuery,
    ) -> List[Tuple[float, LongTermMemoryRecord]]:
        """
        Filter records and assign a simple relevance score.

        Score is intentionally transparent:
            - pinned memories rank higher
            - importance/confidence matter
            - query terms in title/summary/content/tags/entities boost score
            - exact category/scope/project/client/team/agent filters are strict
        """
        scored: List[Tuple[float, LongTermMemoryRecord]] = []

        query_text = _normalize_text(query.query)
        query_terms = [term for term in query_text.split(" ") if len(term) >= 2]
        tag_filter = {_normalize_text(tag) for tag in query.tags}
        entity_filter = {_normalize_text(entity) for entity in query.entities}

        for record in records:
            if record.status == "deleted":
                continue

            if record.status == "archived" and not query.include_archived:
                continue

            if record.sensitive and not query.include_sensitive:
                continue

            if query.category and record.category != query.category:
                continue

            if query.scope and record.scope != query.scope:
                continue

            if query.project_id and record.project_id != query.project_id:
                continue

            if query.client_id and record.client_id != query.client_id:
                continue

            if query.team_id and record.team_id != query.team_id:
                continue

            if query.agent_name and _normalize_text(record.agent_name) != _normalize_text(query.agent_name):
                continue

            if query.min_importance is not None and record.importance < float(query.min_importance):
                continue

            if query.min_confidence is not None and record.confidence < float(query.min_confidence):
                continue

            record_tags = {_normalize_text(tag) for tag in record.tags}
            record_entities = {_normalize_text(entity) for entity in record.entities}

            if tag_filter and not tag_filter.intersection(record_tags):
                continue

            if entity_filter and not entity_filter.intersection(record_entities):
                continue

            score = self._score_record(record, query_terms)

            if query_text and score <= 0:
                continue

            scored.append((score, record))

        scored.sort(
            key=lambda item: (
                item[0],
                item[1].pinned,
                item[1].importance,
                item[1].confidence,
                item[1].updated_at,
            ),
            reverse=True,
        )

        return scored

    def _score_record(
        self,
        record: LongTermMemoryRecord,
        query_terms: List[str],
    ) -> float:
        """
        Score one memory record.

        Without query terms, returns base rank so list/filtered recall still
        produces useful highest-value memories.
        """
        score = 0.0

        if record.pinned:
            score += 2.0

        score += record.importance * 1.5
        score += record.confidence * 1.0

        if record.scope in {"project", "client", "business"}:
            score += 0.2

        if not query_terms:
            return round(score, 4)

        searchable = " ".join(
            [
                record.title or "",
                record.summary or "",
                record.content or "",
                " ".join(record.tags),
                " ".join(record.entities),
                record.category,
                record.scope,
                record.source or "",
                record.source_agent or "",
                record.agent_name or "",
            ]
        )

        searchable_norm = _normalize_text(searchable)

        for term in query_terms:
            if term in searchable_norm:
                score += 1.0

            if record.title and term in _normalize_text(record.title):
                score += 1.0

            if term in {_normalize_text(tag) for tag in record.tags}:
                score += 0.8

            if term in {_normalize_text(entity) for entity in record.entities}:
                score += 0.8

        return round(score, 4)

    # ---------------------------------------------------------------------
    # Internal record helpers
    # ---------------------------------------------------------------------

    def _find_record(
        self,
        records: List[LongTermMemoryRecord],
        memory_id: str,
    ) -> Optional[LongTermMemoryRecord]:
        """Find a memory record by ID."""
        memory_id = str(memory_id or "").strip()
        for record in records:
            if record.memory_id == memory_id:
                return record
        return None

    def _set_memory_status(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        memory_id: str,
        status: MemoryStatus,
        action_label: str,
    ) -> Dict[str, Any]:
        """
        Shared status update helper.
        """
        context_result = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not context_result["success"]:
            return context_result

        user_id_str = str(user_id)
        workspace_id_str = str(workspace_id)

        with self._lock:
            records = self._load_workspace_records(user_id_str, workspace_id_str)
            record = self._find_record(records, memory_id)

            if not record or record.status == "deleted":
                return self._error_result(
                    message="Memory not found.",
                    code="MEMORY_NOT_FOUND",
                    metadata={
                        "user_id": user_id_str,
                        "workspace_id": workspace_id_str,
                        "memory_id": memory_id,
                    },
                )

            record.status = status
            record.updated_at = _utc_now_iso()
            self._save_workspace_records(user_id_str, workspace_id_str, records)

        self._emit_agent_event(
            event_name=f"memory.long_term.{action_label}",
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            payload={"memory_id": memory_id, "status": status},
        )

        self._log_audit_event(
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            action=f"long_term_memory.{action_label}",
            payload={"memory_id": memory_id, "status": status},
        )

        return self._safe_result(
            message=f"Memory {action_label} successfully.",
            data={"memory": record.to_dict()},
            metadata={
                "user_id": user_id_str,
                "workspace_id": workspace_id_str,
                "memory_id": memory_id,
            },
        )

    def _auto_summary(self, content: str, max_chars: int = 180) -> str:
        """
        Generate a simple deterministic summary.

        Future memory_summarizer.py can replace this with LLM summarization.
        """
        clean = re.sub(r"\s+", " ", content or "").strip()
        if len(clean) <= max_chars:
            return clean
        return clean[: max_chars - 3].rstrip() + "..."

    def _normalize_category(self, value: Any) -> MemoryCategory:
        """Normalize category with safe fallback."""
        text = str(value or "fact").strip()
        if text not in self.VALID_CATEGORIES:
            logger.warning("Invalid memory category '%s', falling back to 'fact'.", text)
            return "fact"
        return text  # type: ignore[return-value]

    def _normalize_scope(self, value: Any) -> MemoryScope:
        """Normalize scope with safe fallback."""
        text = str(value or "workspace").strip()
        if text not in self.VALID_SCOPES:
            logger.warning("Invalid memory scope '%s', falling back to 'workspace'.", text)
            return "workspace"
        return text  # type: ignore[return-value]

    def _normalize_visibility(self, value: Any) -> MemoryVisibility:
        """Normalize visibility with safe fallback."""
        text = str(value or "workspace").strip()
        if text not in self.VALID_VISIBILITIES:
            logger.warning("Invalid memory visibility '%s', falling back to 'workspace'.", text)
            return "workspace"
        return text  # type: ignore[return-value]

    def _redact_sensitive_update_preview(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        """
        Redact long/sensitive values before sending to Security Agent.
        """
        redacted: Dict[str, Any] = {}

        for key, value in updates.items():
            if key in {"content", "summary"}:
                text = str(value or "")
                redacted[key] = text[:250] + ("..." if len(text) > 250 else "")
            elif key == "metadata":
                redacted[key] = {
                    "metadata_keys": sorted(list(value.keys())) if isinstance(value, dict) else []
                }
            else:
                redacted[key] = value

        return redacted


# ---------------------------------------------------------------------------
# Standalone smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    memory = LongTermMemory(storage_dir="data/dev_memory_agent/long_term")

    save_result = memory.remember(
        user_id="demo_user",
        workspace_id="demo_workspace",
        content="Digital Promotix prefers conversion-first SEO and mature business leads.",
        category="business_context",
        scope="business",
        tags=["Digital Promotix", "SEO", "Lead Generation"],
        importance=0.9,
        confidence=0.95,
        source_agent="manual_test",
    )

    print(json.dumps(save_result, indent=2, default=_json_default))

    recall_result = memory.recall(
        user_id="demo_user",
        workspace_id="demo_workspace",
        query="conversion SEO leads",
        limit=5,
    )

    print(json.dumps(recall_result, indent=2, default=_json_default))