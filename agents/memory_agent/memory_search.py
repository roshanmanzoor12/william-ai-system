"""
agents/memory_agent/memory_search.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix

Purpose:
    Unified keyword + semantic search by project/client/agent/date.

This module provides a production-ready, import-safe MemorySearch helper/agent that
can be used by the Memory Agent, Master Agent, Dashboard/API, Agent Router, and
future services to search memory safely across keyword, semantic, and hybrid modes.

Core guarantees:
    - SaaS isolation by user_id and workspace_id.
    - Structured JSON/dict responses.
    - Safe optional imports with fallback stubs.
    - No hard dependency on future William modules.
    - Permission/security hooks for sensitive memory search.
    - Verification payload generation after completed search actions.
    - Audit/event hooks for dashboard and observability.
    - Testable in standalone mode with in-memory records.

Expected integration points:
    - Memory Agent:
        Uses MemorySearch for unified search across short-term, long-term,
        project, client, team, and vector-backed memory layers.
    - Master Agent:
        Routes user recall/search requests here when memory lookup is required.
    - Security Agent:
        Approves sensitive or cross-scope search operations.
    - Verification Agent:
        Receives payloads to verify search quality, filtering, and isolation.
    - Dashboard/API:
        Uses public methods for filtered memory search endpoints.
    - Agent Registry/Loader/Router:
        Can discover this class through get_agent_manifest().
"""

from __future__ import annotations

import asyncio
import dataclasses
import datetime as _dt
import hashlib
import inspect
import json
import logging
import math
import re
import uuid
from enum import Enum
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Union,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Optional BaseAgent compatibility
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for standalone import safety
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps the file import-safe if the real William BaseAgent has not
        been generated yet. The real BaseAgent should override lifecycle,
        event, permission, and task methods when available.
        """

        agent_name: str = "base_agent_fallback"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_id = kwargs.get("agent_id", self.agent_name)
            self.config = kwargs.get("config", {})

        async def run(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent run() called.",
                "data": {},
                "error": "BASE_AGENT_NOT_AVAILABLE",
                "metadata": {},
            }


# =============================================================================
# Constants and enums
# =============================================================================

DEFAULT_AGENT_NAME = "memory_search"
DEFAULT_MODULE_NAME = "Memory Agent"
DEFAULT_VERSION = "1.0.0"

MAX_QUERY_LENGTH = 2_000
DEFAULT_LIMIT = 20
MAX_LIMIT = 100
DEFAULT_SNIPPET_LENGTH = 280

SUPPORTED_SEARCH_MODES = {"keyword", "semantic", "hybrid"}
SUPPORTED_SORT_MODES = {
    "relevance",
    "created_at_desc",
    "created_at_asc",
    "updated_at_desc",
    "updated_at_asc",
    "importance_desc",
    "importance_asc",
}


class PrivacyLevel(str, Enum):
    """Supported memory privacy levels."""

    PUBLIC = "public"
    TEAM = "team"
    WORKSPACE = "workspace"
    PRIVATE = "private"
    SENSITIVE = "sensitive"
    RESTRICTED = "restricted"


class MemoryCategory(str, Enum):
    """Common memory categories used by the Memory Agent."""

    SHORT_TERM = "short_term"
    LONG_TERM = "long_term"
    PROJECT = "project"
    CLIENT = "client"
    TEAM = "team"
    PREFERENCE = "preference"
    KNOWLEDGE_GRAPH = "knowledge_graph"
    SYSTEM = "system"
    UNKNOWN = "unknown"


class SearchMode(str, Enum):
    """Search modes supported by MemorySearch."""

    KEYWORD = "keyword"
    SEMANTIC = "semantic"
    HYBRID = "hybrid"


# =============================================================================
# Dataclasses
# =============================================================================

@dataclasses.dataclass
class SearchFilters:
    """
    Filters for memory search.

    All user-facing or API-facing filters are normalized into this structure.
    The search layer still enforces user_id/workspace_id isolation separately.
    """

    project_id: Optional[str] = None
    project_name: Optional[str] = None
    client_id: Optional[str] = None
    client_name: Optional[str] = None
    agent_name: Optional[str] = None
    agent_id: Optional[str] = None
    category: Optional[str] = None
    memory_type: Optional[str] = None
    privacy_level: Optional[str] = None
    tags: Optional[List[str]] = None
    date_from: Optional[_dt.datetime] = None
    date_to: Optional[_dt.datetime] = None
    created_by: Optional[str] = None
    source: Optional[str] = None
    include_archived: bool = False
    include_deleted: bool = False
    min_importance: Optional[float] = None
    max_importance: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        """Return JSON-safe dict version of filters."""
        return {
            "project_id": self.project_id,
            "project_name": self.project_name,
            "client_id": self.client_id,
            "client_name": self.client_name,
            "agent_name": self.agent_name,
            "agent_id": self.agent_id,
            "category": self.category,
            "memory_type": self.memory_type,
            "privacy_level": self.privacy_level,
            "tags": self.tags or [],
            "date_from": self.date_from.isoformat() if self.date_from else None,
            "date_to": self.date_to.isoformat() if self.date_to else None,
            "created_by": self.created_by,
            "source": self.source,
            "include_archived": self.include_archived,
            "include_deleted": self.include_deleted,
            "min_importance": self.min_importance,
            "max_importance": self.max_importance,
        }


@dataclasses.dataclass
class MemorySearchConfig:
    """
    Runtime configuration for MemorySearch.

    The class is intentionally lightweight and safe by default, so it can run
    standalone in tests or plug into future DB/vector services.
    """

    default_limit: int = DEFAULT_LIMIT
    max_limit: int = MAX_LIMIT
    snippet_length: int = DEFAULT_SNIPPET_LENGTH
    hybrid_keyword_weight: float = 0.48
    hybrid_semantic_weight: float = 0.42
    hybrid_recency_weight: float = 0.06
    hybrid_importance_weight: float = 0.04
    allow_sensitive_search_without_security: bool = False
    allow_cross_workspace_search: bool = False
    emit_events: bool = True
    audit_enabled: bool = True
    include_debug_scores: bool = False
    semantic_min_score: float = 0.0
    keyword_min_score: float = 0.0


@dataclasses.dataclass
class MemorySearchResult:
    """Normalized memory search result."""

    memory_id: str
    title: str
    content: str
    snippet: str
    category: str
    memory_type: str
    privacy_level: str
    score: float
    keyword_score: float = 0.0
    semantic_score: float = 0.0
    recency_score: float = 0.0
    importance_score: float = 0.0
    user_id: Optional[str] = None
    workspace_id: Optional[str] = None
    project_id: Optional[str] = None
    project_name: Optional[str] = None
    client_id: Optional[str] = None
    client_name: Optional[str] = None
    agent_name: Optional[str] = None
    agent_id: Optional[str] = None
    tags: Optional[List[str]] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    source: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self, include_debug_scores: bool = False) -> Dict[str, Any]:
        """Return structured JSON-safe dict."""
        payload = {
            "memory_id": self.memory_id,
            "title": self.title,
            "content": self.content,
            "snippet": self.snippet,
            "category": self.category,
            "memory_type": self.memory_type,
            "privacy_level": self.privacy_level,
            "score": round(float(self.score), 6),
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "project_id": self.project_id,
            "project_name": self.project_name,
            "client_id": self.client_id,
            "client_name": self.client_name,
            "agent_name": self.agent_name,
            "agent_id": self.agent_id,
            "tags": self.tags or [],
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "source": self.source,
            "metadata": self.metadata or {},
        }

        if include_debug_scores:
            payload["debug_scores"] = {
                "keyword_score": round(float(self.keyword_score), 6),
                "semantic_score": round(float(self.semantic_score), 6),
                "recency_score": round(float(self.recency_score), 6),
                "importance_score": round(float(self.importance_score), 6),
            }

        return payload


# =============================================================================
# Utility functions
# =============================================================================

def _utc_now() -> _dt.datetime:
    """Return timezone-aware UTC datetime."""
    return _dt.datetime.now(tz=_dt.timezone.utc)


def _json_safe(value: Any) -> Any:
    """Convert common Python objects to JSON-safe values."""
    if dataclasses.is_dataclass(value):
        return dataclasses.asdict(value)
    if isinstance(value, (_dt.datetime, _dt.date)):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(v) for v in value]
    return value


def _parse_datetime(value: Any) -> Optional[_dt.datetime]:
    """Parse datetime/date/string safely."""
    if value is None or value == "":
        return None

    if isinstance(value, _dt.datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=_dt.timezone.utc)
        return value

    if isinstance(value, _dt.date):
        return _dt.datetime.combine(value, _dt.time.min, tzinfo=_dt.timezone.utc)

    if isinstance(value, (int, float)):
        try:
            return _dt.datetime.fromtimestamp(float(value), tz=_dt.timezone.utc)
        except Exception:
            return None

    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return None

        normalized = raw.replace("Z", "+00:00")
        try:
            dt = _dt.datetime.fromisoformat(normalized)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=_dt.timezone.utc)
            return dt
        except Exception:
            pass

        for fmt in ("%Y-%m-%d", "%d-%m-%Y", "%m/%d/%Y", "%Y/%m/%d"):
            try:
                dt = _dt.datetime.strptime(raw, fmt)
                return dt.replace(tzinfo=_dt.timezone.utc)
            except Exception:
                continue

    return None


def _normalize_text(value: Any) -> str:
    """Normalize text for search."""
    if value is None:
        return ""
    text = str(value)
    text = text.replace("\u00a0", " ")
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _tokenize(text: str) -> List[str]:
    """
    Tokenize text into lowercase searchable terms.

    This intentionally avoids external dependencies for import safety.
    """
    text = _normalize_text(text).lower()
    if not text:
        return []
    return re.findall(r"[a-z0-9_@.\-]+", text)


def _stable_id(prefix: str, payload: Mapping[str, Any]) -> str:
    """Create a stable ID from payload content."""
    raw = json.dumps(_json_safe(payload), sort_keys=True, ensure_ascii=False)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]
    return f"{prefix}_{digest}"


def _coerce_float(value: Any, default: float = 0.0) -> float:
    """Safely coerce value to float."""
    try:
        if value is None:
            return default
        return float(value)
    except Exception:
        return default


def _coerce_bool(value: Any, default: bool = False) -> bool:
    """Safely coerce value to bool."""
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    return bool(value)


def _dedupe_keep_order(values: Iterable[str]) -> List[str]:
    """Deduplicate strings while preserving order."""
    seen = set()
    result = []
    for value in values:
        normalized = str(value).strip()
        if not normalized:
            continue
        key = normalized.lower()
        if key in seen:
            continue
        seen.add(key)
        result.append(normalized)
    return result


async def _maybe_await(value: Union[Any, Awaitable[Any]]) -> Any:
    """Await value if it is awaitable."""
    if inspect.isawaitable(value):
        return await value
    return value


# =============================================================================
# In-memory fallback store
# =============================================================================

class InMemorySearchStore:
    """
    Simple in-memory fallback search store.

    This is not a replacement for production database/vector storage. It exists
    so this file can be imported and tested before the rest of the William
    memory infrastructure is generated.
    """

    def __init__(self, records: Optional[Sequence[Mapping[str, Any]]] = None) -> None:
        self._records: List[Dict[str, Any]] = [dict(record) for record in records or []]

    def add(self, record: Mapping[str, Any]) -> Dict[str, Any]:
        """Add one memory record."""
        payload = dict(record)
        payload.setdefault("memory_id", _stable_id("mem", payload))
        payload.setdefault("created_at", _utc_now().isoformat())
        payload.setdefault("updated_at", payload["created_at"])
        self._records.append(payload)
        return payload

    def list_records(
        self,
        user_id: str,
        workspace_id: str,
        include_deleted: bool = False,
    ) -> List[Dict[str, Any]]:
        """Return records scoped by user_id and workspace_id."""
        scoped: List[Dict[str, Any]] = []
        for record in self._records:
            if str(record.get("user_id", "")) != str(user_id):
                continue
            if str(record.get("workspace_id", "")) != str(workspace_id):
                continue
            if not include_deleted and _coerce_bool(record.get("deleted"), False):
                continue
            scoped.append(dict(record))
        return scoped


# =============================================================================
# MemorySearch
# =============================================================================

class MemorySearch(BaseAgent):
    """
    Unified keyword + semantic memory search.

    Public methods:
        - search()
        - keyword_search()
        - semantic_search()
        - hybrid_search()
        - search_by_project()
        - search_by_client()
        - search_by_agent()
        - search_by_date()
        - index_memory()
        - get_agent_manifest()

    This class is intentionally storage-agnostic. Production can pass:
        - memory_store with list_records()/search()
        - vector_store with semantic_search()/search()
        - embedding_provider with embed_text()/embed()
        - security_client for approval
        - event_emitter/audit_logger callbacks
    """

    agent_name = DEFAULT_AGENT_NAME
    module_name = DEFAULT_MODULE_NAME
    version = DEFAULT_VERSION

    def __init__(
        self,
        config: Optional[Union[MemorySearchConfig, Mapping[str, Any]]] = None,
        memory_store: Optional[Any] = None,
        vector_store: Optional[Any] = None,
        embedding_provider: Optional[Any] = None,
        security_client: Optional[Any] = None,
        verification_client: Optional[Any] = None,
        event_emitter: Optional[Callable[..., Any]] = None,
        audit_logger: Optional[Callable[..., Any]] = None,
        logger_instance: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)

        if isinstance(config, MemorySearchConfig):
            self.search_config = config
        else:
            self.search_config = MemorySearchConfig(**dict(config or {}))

        self.memory_store = memory_store or InMemorySearchStore()
        self.vector_store = vector_store
        self.embedding_provider = embedding_provider
        self.security_client = security_client
        self.verification_client = verification_client
        self.event_emitter = event_emitter
        self.audit_logger = audit_logger
        self.log = logger_instance or logger

    # -------------------------------------------------------------------------
    # Required compatibility hooks
    # -------------------------------------------------------------------------

    def _safe_result(
        self,
        message: str = "Operation completed successfully.",
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **extra: Any,
    ) -> Dict[str, Any]:
        """Return standard success result."""
        result = {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": metadata or {},
        }
        result.update(extra)
        return _json_safe(result)

    def _error_result(
        self,
        message: str = "Operation failed.",
        error: Optional[Union[str, Exception, Dict[str, Any]]] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **extra: Any,
    ) -> Dict[str, Any]:
        """Return standard error result."""
        if isinstance(error, Exception):
            error_payload: Any = {
                "type": error.__class__.__name__,
                "detail": str(error),
            }
        else:
            error_payload = error or message

        result = {
            "success": False,
            "message": message,
            "data": data or {},
            "error": error_payload,
            "metadata": metadata or {},
        }
        result.update(extra)
        return _json_safe(result)

    def _validate_task_context(
        self,
        user_id: Optional[str],
        workspace_id: Optional[str],
        **context: Any,
    ) -> Dict[str, Any]:
        """
        Validate SaaS task context.

        Every memory search must be scoped to a user and workspace to avoid
        cross-tenant memory leakage.
        """
        errors: List[str] = []

        if not user_id or not str(user_id).strip():
            errors.append("user_id is required for memory search.")

        if not workspace_id or not str(workspace_id).strip():
            errors.append("workspace_id is required for memory search.")

        cross_workspace = _coerce_bool(context.get("cross_workspace"), False)
        if cross_workspace and not self.search_config.allow_cross_workspace_search:
            errors.append("cross_workspace search is disabled by configuration.")

        if errors:
            return self._error_result(
                message="Invalid memory search context.",
                error={
                    "code": "INVALID_TASK_CONTEXT",
                    "details": errors,
                },
                metadata={
                    "agent": self.agent_name,
                    "module": self.module_name,
                },
            )

        return self._safe_result(
            message="Task context validated.",
            data={
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
                "context": _json_safe(context),
            },
            metadata={
                "agent": self.agent_name,
                "module": self.module_name,
            },
        )

    def _requires_security_check(
        self,
        query: str,
        filters: Optional[SearchFilters] = None,
        include_sensitive: bool = False,
        **context: Any,
    ) -> bool:
        """
        Decide if Security Agent approval is required.

        Sensitive/restricted searches and cross-workspace-like requests should
        be approved before returning memory data.
        """
        if include_sensitive:
            return True

        if filters and filters.privacy_level in {
            PrivacyLevel.SENSITIVE.value,
            PrivacyLevel.RESTRICTED.value,
        }:
            return True

        if _coerce_bool(context.get("cross_workspace"), False):
            return True

        sensitive_terms = {
            "password",
            "secret",
            "api key",
            "token",
            "credential",
            "private key",
            "billing",
            "payment",
            "card",
            "medical",
            "health",
            "legal",
            "contract",
            "confidential",
        }
        query_lower = query.lower()
        if any(term in query_lower for term in sensitive_terms):
            return True

        return False

    async def _request_security_approval(
        self,
        user_id: str,
        workspace_id: str,
        action: str,
        reason: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        If no security client is connected, sensitive searches are denied unless
        explicitly allowed by config.
        """
        approval_payload = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "agent": self.agent_name,
            "module": self.module_name,
            "action": action,
            "reason": reason,
            "payload": payload or {},
            "requested_at": _utc_now().isoformat(),
        }

        if self.security_client is None:
            if self.search_config.allow_sensitive_search_without_security:
                return self._safe_result(
                    message="Security approval bypassed by configuration.",
                    data={
                        "approved": True,
                        "approval_id": "config_bypass",
                    },
                    metadata={"security_client": "not_configured"},
                )

            return self._error_result(
                message="Security approval required but Security Agent is not configured.",
                error={
                    "code": "SECURITY_APPROVAL_REQUIRED",
                    "reason": reason,
                },
                metadata={"security_client": "not_configured"},
            )

        try:
            if hasattr(self.security_client, "request_approval"):
                response = await _maybe_await(
                    self.security_client.request_approval(**approval_payload)
                )
            elif callable(self.security_client):
                response = await _maybe_await(self.security_client(approval_payload))
            else:
                return self._error_result(
                    message="Invalid security client configured.",
                    error="INVALID_SECURITY_CLIENT",
                )

            if isinstance(response, dict):
                approved = bool(
                    response.get("approved")
                    or response.get("success")
                    or response.get("data", {}).get("approved")
                )
                if approved:
                    return self._safe_result(
                        message="Security approval granted.",
                        data=response,
                        metadata={"security_client": "configured"},
                    )

                return self._error_result(
                    message="Security approval denied.",
                    error={
                        "code": "SECURITY_APPROVAL_DENIED",
                        "response": response,
                    },
                    metadata={"security_client": "configured"},
                )

            if bool(response):
                return self._safe_result(
                    message="Security approval granted.",
                    data={"approved": True},
                    metadata={"security_client": "configured"},
                )

            return self._error_result(
                message="Security approval denied.",
                error="SECURITY_APPROVAL_DENIED",
            )
        except Exception as exc:
            self.log.exception("Security approval failed.")
            return self._error_result(
                message="Security approval failed.",
                error=exc,
                metadata={"security_client": "configured"},
            )

    def _prepare_verification_payload(
        self,
        user_id: str,
        workspace_id: str,
        query: str,
        mode: str,
        filters: SearchFilters,
        results: Sequence[MemorySearchResult],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare payload for Verification Agent.

        Verification Agent can use this to confirm:
            - correct user/workspace isolation
            - filter accuracy
            - ranking reasonableness
            - no sensitive leakage
        """
        return _json_safe(
            {
                "verification_type": "memory_search_result",
                "agent": self.agent_name,
                "module": self.module_name,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "query_hash": hashlib.sha256(query.encode("utf-8")).hexdigest(),
                "query_preview": query[:160],
                "mode": mode,
                "filters": filters.to_dict(),
                "result_count": len(results),
                "result_ids": [item.memory_id for item in results],
                "privacy_levels": sorted(
                    {item.privacy_level for item in results if item.privacy_level}
                ),
                "categories": sorted({item.category for item in results if item.category}),
                "metadata": metadata or {},
                "created_at": _utc_now().isoformat(),
            }
        )

    def _prepare_memory_payload(
        self,
        user_id: str,
        workspace_id: str,
        query: str,
        mode: str,
        filters: SearchFilters,
        results: Sequence[MemorySearchResult],
    ) -> Dict[str, Any]:
        """
        Prepare a memory payload about this search event.

        The Memory Agent may store this as an audit/context item if useful.
        It stores only safe summaries and IDs, not full sensitive content.
        """
        return _json_safe(
            {
                "memory_event_type": "memory_search",
                "user_id": user_id,
                "workspace_id": workspace_id,
                "agent": self.agent_name,
                "mode": mode,
                "query_preview": query[:160],
                "filters": filters.to_dict(),
                "result_count": len(results),
                "top_result_ids": [item.memory_id for item in results[:5]],
                "created_at": _utc_now().isoformat(),
            }
        )

    async def _emit_agent_event(
        self,
        event_name: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Emit event to dashboard/event bus.

        Safe no-op if no emitter is configured.
        """
        event_payload = {
            "event_id": str(uuid.uuid4()),
            "event_name": event_name,
            "agent": self.agent_name,
            "module": self.module_name,
            "payload": payload or {},
            "created_at": _utc_now().isoformat(),
        }

        if not self.search_config.emit_events:
            return self._safe_result(
                message="Event emission disabled.",
                data=event_payload,
            )

        if self.event_emitter is None:
            return self._safe_result(
                message="No event emitter configured; event skipped.",
                data=event_payload,
                metadata={"emitted": False},
            )

        try:
            response = await _maybe_await(self.event_emitter(event_payload))
            return self._safe_result(
                message="Agent event emitted.",
                data={
                    "event": event_payload,
                    "response": response,
                },
                metadata={"emitted": True},
            )
        except Exception as exc:
            self.log.exception("Failed to emit agent event.")
            return self._error_result(
                message="Failed to emit agent event.",
                error=exc,
                data={"event": event_payload},
            )

    async def _log_audit_event(
        self,
        action: str,
        user_id: str,
        workspace_id: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Log audit event.

        Safe no-op if no audit logger is configured.
        """
        audit_payload = {
            "audit_id": str(uuid.uuid4()),
            "action": action,
            "agent": self.agent_name,
            "module": self.module_name,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "payload": payload or {},
            "created_at": _utc_now().isoformat(),
        }

        if not self.search_config.audit_enabled:
            return self._safe_result(
                message="Audit disabled.",
                data=audit_payload,
            )

        if self.audit_logger is None:
            return self._safe_result(
                message="No audit logger configured; audit skipped.",
                data=audit_payload,
                metadata={"logged": False},
            )

        try:
            response = await _maybe_await(self.audit_logger(audit_payload))
            return self._safe_result(
                message="Audit event logged.",
                data={
                    "audit": audit_payload,
                    "response": response,
                },
                metadata={"logged": True},
            )
        except Exception as exc:
            self.log.exception("Failed to log audit event.")
            return self._error_result(
                message="Failed to log audit event.",
                error=exc,
                data={"audit": audit_payload},
            )

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    async def run(self, task: Optional[Mapping[str, Any]] = None, **kwargs: Any) -> Dict[str, Any]:
        """
        BaseAgent-compatible run entrypoint.

        Expected task format:
            {
                "query": "search text",
                "user_id": "...",
                "workspace_id": "...",
                "mode": "hybrid",
                "filters": {...},
                "limit": 20
            }
        """
        payload = dict(task or {})
        payload.update(kwargs)

        return await self.search(
            query=payload.get("query", ""),
            user_id=payload.get("user_id"),
            workspace_id=payload.get("workspace_id"),
            mode=payload.get("mode", SearchMode.HYBRID.value),
            filters=payload.get("filters"),
            limit=payload.get("limit"),
            offset=payload.get("offset", 0),
            sort_by=payload.get("sort_by", "relevance"),
            include_sensitive=_coerce_bool(payload.get("include_sensitive"), False),
            include_content=_coerce_bool(payload.get("include_content"), True),
            context=payload.get("context") or {},
        )

    async def search(
        self,
        query: str,
        user_id: Optional[str],
        workspace_id: Optional[str],
        mode: str = SearchMode.HYBRID.value,
        filters: Optional[Union[SearchFilters, Mapping[str, Any]]] = None,
        limit: Optional[int] = None,
        offset: int = 0,
        sort_by: str = "relevance",
        include_sensitive: bool = False,
        include_content: bool = True,
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Unified search entrypoint.

        Supports:
            - keyword
            - semantic
            - hybrid

        Always enforces user_id and workspace_id isolation.
        """
        started_at = _utc_now()
        request_context = dict(context or {})

        try:
            query = self._validate_query(query)
            mode = self._normalize_mode(mode)
            normalized_limit = self._normalize_limit(limit)
            offset = max(0, int(offset or 0))
            sort_by = self._normalize_sort_by(sort_by)
            normalized_filters = self._normalize_filters(filters)

            context_result = self._validate_task_context(
                user_id=user_id,
                workspace_id=workspace_id,
                **request_context,
            )
            if not context_result["success"]:
                return context_result

            safe_user_id = str(user_id)
            safe_workspace_id = str(workspace_id)

            requires_security = self._requires_security_check(
                query=query,
                filters=normalized_filters,
                include_sensitive=include_sensitive,
                **request_context,
            )
            if requires_security:
                approval = await self._request_security_approval(
                    user_id=safe_user_id,
                    workspace_id=safe_workspace_id,
                    action="memory_search",
                    reason="Sensitive or elevated memory search requested.",
                    payload={
                        "query_preview": query[:160],
                        "mode": mode,
                        "filters": normalized_filters.to_dict(),
                        "include_sensitive": include_sensitive,
                    },
                )
                if not approval["success"]:
                    await self._log_audit_event(
                        action="memory_search_denied",
                        user_id=safe_user_id,
                        workspace_id=safe_workspace_id,
                        payload={
                            "query_preview": query[:160],
                            "mode": mode,
                            "filters": normalized_filters.to_dict(),
                            "reason": "security_denied",
                        },
                    )
                    return approval

            await self._emit_agent_event(
                "memory_search.started",
                {
                    "user_id": safe_user_id,
                    "workspace_id": safe_workspace_id,
                    "mode": mode,
                    "query_preview": query[:160],
                    "filters": normalized_filters.to_dict(),
                },
            )

            if mode == SearchMode.KEYWORD.value:
                raw_results = await self._keyword_search_internal(
                    query=query,
                    user_id=safe_user_id,
                    workspace_id=safe_workspace_id,
                    filters=normalized_filters,
                    include_sensitive=include_sensitive,
                )
            elif mode == SearchMode.SEMANTIC.value:
                raw_results = await self._semantic_search_internal(
                    query=query,
                    user_id=safe_user_id,
                    workspace_id=safe_workspace_id,
                    filters=normalized_filters,
                    include_sensitive=include_sensitive,
                )
            else:
                raw_results = await self._hybrid_search_internal(
                    query=query,
                    user_id=safe_user_id,
                    workspace_id=safe_workspace_id,
                    filters=normalized_filters,
                    include_sensitive=include_sensitive,
                )

            sorted_results = self._sort_results(raw_results, sort_by)
            total = len(sorted_results)
            paged_results = sorted_results[offset: offset + normalized_limit]

            result_dicts = [
                item.to_dict(include_debug_scores=self.search_config.include_debug_scores)
                for item in paged_results
            ]

            if not include_content:
                for item in result_dicts:
                    item["content"] = ""

            duration_ms = int((_utc_now() - started_at).total_seconds() * 1000)

            verification_payload = self._prepare_verification_payload(
                user_id=safe_user_id,
                workspace_id=safe_workspace_id,
                query=query,
                mode=mode,
                filters=normalized_filters,
                results=paged_results,
                metadata={
                    "total_matches": total,
                    "returned": len(paged_results),
                    "duration_ms": duration_ms,
                    "sort_by": sort_by,
                },
            )

            memory_payload = self._prepare_memory_payload(
                user_id=safe_user_id,
                workspace_id=safe_workspace_id,
                query=query,
                mode=mode,
                filters=normalized_filters,
                results=paged_results,
            )

            await self._log_audit_event(
                action="memory_search_completed",
                user_id=safe_user_id,
                workspace_id=safe_workspace_id,
                payload={
                    "query_preview": query[:160],
                    "mode": mode,
                    "filters": normalized_filters.to_dict(),
                    "total_matches": total,
                    "returned": len(paged_results),
                    "duration_ms": duration_ms,
                },
            )

            await self._emit_agent_event(
                "memory_search.completed",
                {
                    "user_id": safe_user_id,
                    "workspace_id": safe_workspace_id,
                    "mode": mode,
                    "total_matches": total,
                    "returned": len(paged_results),
                    "duration_ms": duration_ms,
                },
            )

            return self._safe_result(
                message="Memory search completed.",
                data={
                    "query": query,
                    "mode": mode,
                    "results": result_dicts,
                    "pagination": {
                        "limit": normalized_limit,
                        "offset": offset,
                        "returned": len(result_dicts),
                        "total": total,
                        "has_more": offset + normalized_limit < total,
                    },
                    "filters": normalized_filters.to_dict(),
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                metadata={
                    "agent": self.agent_name,
                    "module": self.module_name,
                    "version": self.version,
                    "duration_ms": duration_ms,
                    "sort_by": sort_by,
                    "security_checked": requires_security,
                },
            )

        except Exception as exc:
            self.log.exception("Memory search failed.")
            return self._error_result(
                message="Memory search failed.",
                error=exc,
                metadata={
                    "agent": self.agent_name,
                    "module": self.module_name,
                    "version": self.version,
                },
            )

    async def keyword_search(
        self,
        query: str,
        user_id: str,
        workspace_id: str,
        filters: Optional[Union[SearchFilters, Mapping[str, Any]]] = None,
        limit: Optional[int] = None,
        offset: int = 0,
        sort_by: str = "relevance",
        include_sensitive: bool = False,
        include_content: bool = True,
    ) -> Dict[str, Any]:
        """Public keyword search wrapper."""
        return await self.search(
            query=query,
            user_id=user_id,
            workspace_id=workspace_id,
            mode=SearchMode.KEYWORD.value,
            filters=filters,
            limit=limit,
            offset=offset,
            sort_by=sort_by,
            include_sensitive=include_sensitive,
            include_content=include_content,
        )

    async def semantic_search(
        self,
        query: str,
        user_id: str,
        workspace_id: str,
        filters: Optional[Union[SearchFilters, Mapping[str, Any]]] = None,
        limit: Optional[int] = None,
        offset: int = 0,
        sort_by: str = "relevance",
        include_sensitive: bool = False,
        include_content: bool = True,
    ) -> Dict[str, Any]:
        """Public semantic search wrapper."""
        return await self.search(
            query=query,
            user_id=user_id,
            workspace_id=workspace_id,
            mode=SearchMode.SEMANTIC.value,
            filters=filters,
            limit=limit,
            offset=offset,
            sort_by=sort_by,
            include_sensitive=include_sensitive,
            include_content=include_content,
        )

    async def hybrid_search(
        self,
        query: str,
        user_id: str,
        workspace_id: str,
        filters: Optional[Union[SearchFilters, Mapping[str, Any]]] = None,
        limit: Optional[int] = None,
        offset: int = 0,
        sort_by: str = "relevance",
        include_sensitive: bool = False,
        include_content: bool = True,
    ) -> Dict[str, Any]:
        """Public hybrid search wrapper."""
        return await self.search(
            query=query,
            user_id=user_id,
            workspace_id=workspace_id,
            mode=SearchMode.HYBRID.value,
            filters=filters,
            limit=limit,
            offset=offset,
            sort_by=sort_by,
            include_sensitive=include_sensitive,
            include_content=include_content,
        )

    async def search_by_project(
        self,
        query: str,
        user_id: str,
        workspace_id: str,
        project_id: Optional[str] = None,
        project_name: Optional[str] = None,
        mode: str = SearchMode.HYBRID.value,
        limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Search memory scoped to a project."""
        filters = SearchFilters(project_id=project_id, project_name=project_name)
        return await self.search(
            query=query,
            user_id=user_id,
            workspace_id=workspace_id,
            mode=mode,
            filters=filters,
            limit=limit,
        )

    async def search_by_client(
        self,
        query: str,
        user_id: str,
        workspace_id: str,
        client_id: Optional[str] = None,
        client_name: Optional[str] = None,
        mode: str = SearchMode.HYBRID.value,
        limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Search memory scoped to a client."""
        filters = SearchFilters(client_id=client_id, client_name=client_name)
        return await self.search(
            query=query,
            user_id=user_id,
            workspace_id=workspace_id,
            mode=mode,
            filters=filters,
            limit=limit,
        )

    async def search_by_agent(
        self,
        query: str,
        user_id: str,
        workspace_id: str,
        agent_name: Optional[str] = None,
        agent_id: Optional[str] = None,
        mode: str = SearchMode.HYBRID.value,
        limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Search memory scoped to an agent."""
        filters = SearchFilters(agent_name=agent_name, agent_id=agent_id)
        return await self.search(
            query=query,
            user_id=user_id,
            workspace_id=workspace_id,
            mode=mode,
            filters=filters,
            limit=limit,
        )

    async def search_by_date(
        self,
        query: str,
        user_id: str,
        workspace_id: str,
        date_from: Optional[Any] = None,
        date_to: Optional[Any] = None,
        mode: str = SearchMode.HYBRID.value,
        limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Search memory scoped to a date range."""
        filters = SearchFilters(
            date_from=_parse_datetime(date_from),
            date_to=_parse_datetime(date_to),
        )
        return await self.search(
            query=query,
            user_id=user_id,
            workspace_id=workspace_id,
            mode=mode,
            filters=filters,
            limit=limit,
        )

    async def index_memory(
        self,
        memory_record: Mapping[str, Any],
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Index/add a memory record to the configured fallback memory store.

        In production, memory creation may be handled by long_term.py,
        project_memory.py, client_memory.py, or embeddings.py. This helper exists
        for tests, local development, and dashboard/API integration.
        """
        try:
            payload = dict(memory_record)

            if user_id is not None:
                payload["user_id"] = user_id
            if workspace_id is not None:
                payload["workspace_id"] = workspace_id

            context_result = self._validate_task_context(
                user_id=payload.get("user_id"),
                workspace_id=payload.get("workspace_id"),
            )
            if not context_result["success"]:
                return context_result

            payload.setdefault("memory_id", _stable_id("mem", payload))
            payload.setdefault("title", "")
            payload.setdefault("content", "")
            payload.setdefault("category", MemoryCategory.UNKNOWN.value)
            payload.setdefault("memory_type", payload.get("category", MemoryCategory.UNKNOWN.value))
            payload.setdefault("privacy_level", PrivacyLevel.WORKSPACE.value)
            payload.setdefault("tags", [])
            payload.setdefault("created_at", _utc_now().isoformat())
            payload.setdefault("updated_at", payload["created_at"])
            payload.setdefault("importance", 0.5)
            payload.setdefault("archived", False)
            payload.setdefault("deleted", False)

            if hasattr(self.memory_store, "add"):
                stored = await _maybe_await(self.memory_store.add(payload))
            elif hasattr(self.memory_store, "index_memory"):
                stored = await _maybe_await(self.memory_store.index_memory(payload))
            else:
                return self._error_result(
                    message="Configured memory_store cannot index memory.",
                    error="MEMORY_STORE_INDEX_UNSUPPORTED",
                )

            await self._log_audit_event(
                action="memory_indexed_for_search",
                user_id=str(payload["user_id"]),
                workspace_id=str(payload["workspace_id"]),
                payload={
                    "memory_id": payload.get("memory_id"),
                    "category": payload.get("category"),
                    "privacy_level": payload.get("privacy_level"),
                },
            )

            return self._safe_result(
                message="Memory record indexed.",
                data={
                    "memory": _json_safe(stored),
                },
                metadata={
                    "agent": self.agent_name,
                    "module": self.module_name,
                },
            )
        except Exception as exc:
            self.log.exception("Failed to index memory.")
            return self._error_result(
                message="Failed to index memory.",
                error=exc,
            )

    def get_agent_manifest(self) -> Dict[str, Any]:
        """
        Registry/Loader manifest.

        Agent Registry can use this to discover capabilities and public methods.
        """
        return {
            "agent_name": self.agent_name,
            "module_name": self.module_name,
            "version": self.version,
            "class_name": self.__class__.__name__,
            "file_path": "agents/memory_agent/memory_search.py",
            "description": "Unified keyword + semantic search by project/client/agent/date.",
            "capabilities": [
                "memory.keyword_search",
                "memory.semantic_search",
                "memory.hybrid_search",
                "memory.search_by_project",
                "memory.search_by_client",
                "memory.search_by_agent",
                "memory.search_by_date",
            ],
            "public_methods": [
                "run",
                "search",
                "keyword_search",
                "semantic_search",
                "hybrid_search",
                "search_by_project",
                "search_by_client",
                "search_by_agent",
                "search_by_date",
                "index_memory",
                "get_agent_manifest",
            ],
            "requires_context": ["user_id", "workspace_id"],
            "security_sensitive": True,
            "safe_to_import": True,
            "integrations": {
                "master_agent": True,
                "memory_agent": True,
                "security_agent": True,
                "verification_agent": True,
                "dashboard_api": True,
                "agent_registry": True,
                "agent_router": True,
            },
        }

    # -------------------------------------------------------------------------
    # Internal search implementations
    # -------------------------------------------------------------------------

    async def _keyword_search_internal(
        self,
        query: str,
        user_id: str,
        workspace_id: str,
        filters: SearchFilters,
        include_sensitive: bool = False,
    ) -> List[MemorySearchResult]:
        """Keyword search implementation."""
        records = await self._load_records(user_id, workspace_id, filters)
        query_tokens = _tokenize(query)

        results: List[MemorySearchResult] = []
        for record in records:
            if not self._record_allowed(record, filters, include_sensitive):
                continue

            keyword_score = self._keyword_score(record, query_tokens)
            if keyword_score < self.search_config.keyword_min_score:
                continue

            result = self._record_to_result(
                record=record,
                query=query,
                keyword_score=keyword_score,
                semantic_score=0.0,
            )
            result.score = keyword_score
            results.append(result)

        return results

    async def _semantic_search_internal(
        self,
        query: str,
        user_id: str,
        workspace_id: str,
        filters: SearchFilters,
        include_sensitive: bool = False,
    ) -> List[MemorySearchResult]:
        """Semantic search implementation with vector-store fallback."""
        vector_results = await self._vector_store_search(
            query=query,
            user_id=user_id,
            workspace_id=workspace_id,
            filters=filters,
        )

        if vector_results is not None:
            results: List[MemorySearchResult] = []
            for record, semantic_score in vector_results:
                if not self._record_allowed(record, filters, include_sensitive):
                    continue
                if semantic_score < self.search_config.semantic_min_score:
                    continue

                result = self._record_to_result(
                    record=record,
                    query=query,
                    keyword_score=0.0,
                    semantic_score=semantic_score,
                )
                result.score = semantic_score
                results.append(result)
            return results

        records = await self._load_records(user_id, workspace_id, filters)
        query_tokens = _tokenize(query)

        results = []
        for record in records:
            if not self._record_allowed(record, filters, include_sensitive):
                continue

            semantic_score = self._fallback_semantic_score(record, query_tokens)
            if semantic_score < self.search_config.semantic_min_score:
                continue

            result = self._record_to_result(
                record=record,
                query=query,
                keyword_score=0.0,
                semantic_score=semantic_score,
            )
            result.score = semantic_score
            results.append(result)

        return results

    async def _hybrid_search_internal(
        self,
        query: str,
        user_id: str,
        workspace_id: str,
        filters: SearchFilters,
        include_sensitive: bool = False,
    ) -> List[MemorySearchResult]:
        """Hybrid search combining keyword, semantic, recency, and importance."""
        records = await self._load_records(user_id, workspace_id, filters)
        query_tokens = _tokenize(query)
        semantic_scores_by_id = await self._semantic_scores_for_records(
            query=query,
            records=records,
            user_id=user_id,
            workspace_id=workspace_id,
            filters=filters,
        )

        results: List[MemorySearchResult] = []
        for record in records:
            if not self._record_allowed(record, filters, include_sensitive):
                continue

            memory_id = str(record.get("memory_id") or _stable_id("mem", record))

            keyword_score = self._keyword_score(record, query_tokens)
            semantic_score = semantic_scores_by_id.get(
                memory_id,
                self._fallback_semantic_score(record, query_tokens),
            )
            recency_score = self._recency_score(record)
            importance_score = self._importance_score(record)

            score = (
                (keyword_score * self.search_config.hybrid_keyword_weight)
                + (semantic_score * self.search_config.hybrid_semantic_weight)
                + (recency_score * self.search_config.hybrid_recency_weight)
                + (importance_score * self.search_config.hybrid_importance_weight)
            )

            if score <= 0:
                continue

            result = self._record_to_result(
                record=record,
                query=query,
                keyword_score=keyword_score,
                semantic_score=semantic_score,
                recency_score=recency_score,
                importance_score=importance_score,
            )
            result.score = score
            results.append(result)

        return results

    async def _load_records(
        self,
        user_id: str,
        workspace_id: str,
        filters: SearchFilters,
    ) -> List[Dict[str, Any]]:
        """
        Load candidate records from configured store.

        Supported store interfaces:
            - list_records(user_id, workspace_id, include_deleted=False)
            - search(user_id=..., workspace_id=..., filters=...)
            - all()/list()
        """
        include_deleted = filters.include_deleted

        try:
            if hasattr(self.memory_store, "list_records"):
                records = await _maybe_await(
                    self.memory_store.list_records(
                        user_id=user_id,
                        workspace_id=workspace_id,
                        include_deleted=include_deleted,
                    )
                )
            elif hasattr(self.memory_store, "search"):
                records = await _maybe_await(
                    self.memory_store.search(
                        user_id=user_id,
                        workspace_id=workspace_id,
                        filters=filters.to_dict(),
                    )
                )
            elif hasattr(self.memory_store, "all"):
                records = await _maybe_await(self.memory_store.all())
            elif hasattr(self.memory_store, "list"):
                records = await _maybe_await(self.memory_store.list())
            else:
                records = []

            normalized = [dict(record) for record in records or []]
            return [
                record
                for record in normalized
                if self._basic_scope_match(record, user_id, workspace_id)
            ]
        except Exception:
            self.log.exception("Failed to load records from memory store.")
            return []

    async def _vector_store_search(
        self,
        query: str,
        user_id: str,
        workspace_id: str,
        filters: SearchFilters,
    ) -> Optional[List[Tuple[Dict[str, Any], float]]]:
        """
        Search vector store if configured.

        Supported vector store interfaces:
            - semantic_search(query=..., user_id=..., workspace_id=..., filters=...)
            - search(query=..., user_id=..., workspace_id=..., mode="semantic")
        """
        if self.vector_store is None:
            return None

        try:
            if hasattr(self.vector_store, "semantic_search"):
                response = await _maybe_await(
                    self.vector_store.semantic_search(
                        query=query,
                        user_id=user_id,
                        workspace_id=workspace_id,
                        filters=filters.to_dict(),
                    )
                )
            elif hasattr(self.vector_store, "search"):
                response = await _maybe_await(
                    self.vector_store.search(
                        query=query,
                        user_id=user_id,
                        workspace_id=workspace_id,
                        filters=filters.to_dict(),
                        mode="semantic",
                    )
                )
            else:
                return None

            return self._normalize_vector_response(response)
        except Exception:
            self.log.exception("Vector store semantic search failed.")
            return None

    async def _semantic_scores_for_records(
        self,
        query: str,
        records: Sequence[Mapping[str, Any]],
        user_id: str,
        workspace_id: str,
        filters: SearchFilters,
    ) -> Dict[str, float]:
        """Return semantic scores keyed by memory_id."""
        vector_results = await self._vector_store_search(
            query=query,
            user_id=user_id,
            workspace_id=workspace_id,
            filters=filters,
        )

        scores: Dict[str, float] = {}
        if vector_results is None:
            return scores

        for record, score in vector_results:
            memory_id = str(record.get("memory_id") or _stable_id("mem", record))
            scores[memory_id] = max(scores.get(memory_id, 0.0), _coerce_float(score))

        return scores

    # -------------------------------------------------------------------------
    # Scoring and filtering
    # -------------------------------------------------------------------------

    def _keyword_score(self, record: Mapping[str, Any], query_tokens: Sequence[str]) -> float:
        """Compute keyword relevance score."""
        if not query_tokens:
            return 0.0

        title = _normalize_text(record.get("title"))
        content = _normalize_text(record.get("content") or record.get("text") or "")
        tags = " ".join(str(tag) for tag in record.get("tags") or [])
        project_name = _normalize_text(record.get("project_name"))
        client_name = _normalize_text(record.get("client_name"))
        agent_name = _normalize_text(record.get("agent_name"))

        searchable = {
            "title": title,
            "content": content,
            "tags": tags,
            "project_name": project_name,
            "client_name": client_name,
            "agent_name": agent_name,
        }

        weighted_text = (
            f"{title} {title} {title} "
            f"{tags} {tags} "
            f"{project_name} {client_name} {agent_name} "
            f"{content}"
        ).lower()

        searchable_tokens = _tokenize(weighted_text)
        if not searchable_tokens:
            return 0.0

        token_counts: Dict[str, int] = {}
        for token in searchable_tokens:
            token_counts[token] = token_counts.get(token, 0) + 1

        exact_matches = 0
        partial_matches = 0
        field_bonus = 0.0

        for token in query_tokens:
            if token in token_counts:
                exact_matches += min(token_counts[token], 3)
            else:
                for candidate in token_counts:
                    if len(token) >= 4 and (token in candidate or candidate in token):
                        partial_matches += 1
                        break

            if token in title.lower():
                field_bonus += 0.18
            if token in tags.lower():
                field_bonus += 0.12
            if token in project_name.lower() or token in client_name.lower():
                field_bonus += 0.08

        phrase_bonus = 0.0
        query_phrase = " ".join(query_tokens)
        if query_phrase and query_phrase in weighted_text:
            phrase_bonus = 0.25

        base = exact_matches / max(len(query_tokens) * 3, 1)
        partial = partial_matches / max(len(query_tokens), 1) * 0.25
        score = min(1.0, base + partial + field_bonus + phrase_bonus)
        return max(0.0, score)

    def _fallback_semantic_score(
        self,
        record: Mapping[str, Any],
        query_tokens: Sequence[str],
    ) -> float:
        """
        Dependency-free semantic-ish score.

        This uses token overlap, soft term matching, and metadata similarity as
        fallback until embeddings/vector storage are connected.
        """
        if not query_tokens:
            return 0.0

        content = self._record_search_text(record)
        record_tokens = set(_tokenize(content))

        if not record_tokens:
            return 0.0

        query_set = set(query_tokens)
        intersection = query_set.intersection(record_tokens)
        union = query_set.union(record_tokens)

        jaccard = len(intersection) / max(len(union), 1)

        soft_matches = 0
        for q in query_set:
            if q in record_tokens:
                continue
            if len(q) < 4:
                continue
            for r in record_tokens:
                if q in r or r in q:
                    soft_matches += 1
                    break

        soft = soft_matches / max(len(query_set), 1) * 0.25
        keyword_like = self._keyword_score(record, list(query_set)) * 0.55

        return min(1.0, (jaccard * 1.3) + soft + keyword_like)

    def _recency_score(self, record: Mapping[str, Any]) -> float:
        """
        Calculate recency score from updated_at/created_at.

        Recent memories get a slight boost in hybrid ranking, but old high-quality
        matches can still win through keyword/semantic relevance.
        """
        dt = _parse_datetime(record.get("updated_at") or record.get("created_at"))
        if not dt:
            return 0.0

        age_days = max((_utc_now() - dt).total_seconds() / 86400.0, 0.0)
        return 1.0 / (1.0 + (age_days / 30.0))

    def _importance_score(self, record: Mapping[str, Any]) -> float:
        """Normalize importance score into 0..1."""
        importance = _coerce_float(record.get("importance"), 0.5)
        if importance > 1:
            importance = importance / 100.0
        return min(1.0, max(0.0, importance))

    def _record_allowed(
        self,
        record: Mapping[str, Any],
        filters: SearchFilters,
        include_sensitive: bool = False,
    ) -> bool:
        """Apply privacy and user filters to one record."""
        privacy_level = str(record.get("privacy_level") or PrivacyLevel.WORKSPACE.value).lower()
        if privacy_level in {PrivacyLevel.SENSITIVE.value, PrivacyLevel.RESTRICTED.value}:
            if not include_sensitive:
                return False

        if _coerce_bool(record.get("archived"), False) and not filters.include_archived:
            return False

        if _coerce_bool(record.get("deleted"), False) and not filters.include_deleted:
            return False

        if filters.project_id and str(record.get("project_id")) != str(filters.project_id):
            return False

        if filters.project_name:
            if filters.project_name.lower() not in str(record.get("project_name", "")).lower():
                return False

        if filters.client_id and str(record.get("client_id")) != str(filters.client_id):
            return False

        if filters.client_name:
            if filters.client_name.lower() not in str(record.get("client_name", "")).lower():
                return False

        if filters.agent_name:
            if str(record.get("agent_name", "")).lower() != filters.agent_name.lower():
                return False

        if filters.agent_id and str(record.get("agent_id")) != str(filters.agent_id):
            return False

        if filters.category:
            if str(record.get("category", "")).lower() != filters.category.lower():
                return False

        if filters.memory_type:
            if str(record.get("memory_type", "")).lower() != filters.memory_type.lower():
                return False

        if filters.privacy_level:
            if privacy_level != filters.privacy_level.lower():
                return False

        if filters.created_by and str(record.get("created_by")) != str(filters.created_by):
            return False

        if filters.source:
            if str(record.get("source", "")).lower() != filters.source.lower():
                return False

        if filters.tags:
            record_tags = {str(tag).lower() for tag in record.get("tags") or []}
            required_tags = {str(tag).lower() for tag in filters.tags}
            if not required_tags.issubset(record_tags):
                return False

        record_dt = _parse_datetime(
            record.get("created_at") or record.get("updated_at") or record.get("timestamp")
        )

        if filters.date_from:
            if record_dt is None or record_dt < filters.date_from:
                return False

        if filters.date_to:
            if record_dt is None or record_dt > filters.date_to:
                return False

        importance = self._importance_score(record)
        if filters.min_importance is not None and importance < float(filters.min_importance):
            return False

        if filters.max_importance is not None and importance > float(filters.max_importance):
            return False

        return True

    def _basic_scope_match(
        self,
        record: Mapping[str, Any],
        user_id: str,
        workspace_id: str,
    ) -> bool:
        """Hard SaaS isolation check."""
        return (
            str(record.get("user_id", "")) == str(user_id)
            and str(record.get("workspace_id", "")) == str(workspace_id)
        )

    # -------------------------------------------------------------------------
    # Normalization and conversion
    # -------------------------------------------------------------------------

    def _validate_query(self, query: Any) -> str:
        """Validate and normalize query string."""
        normalized = _normalize_text(query)
        if not normalized:
            raise ValueError("query is required for memory search.")
        if len(normalized) > MAX_QUERY_LENGTH:
            raise ValueError(f"query is too long. Max length is {MAX_QUERY_LENGTH}.")
        return normalized

    def _normalize_mode(self, mode: Any) -> str:
        """Normalize search mode."""
        normalized = str(mode or SearchMode.HYBRID.value).strip().lower()
        if normalized not in SUPPORTED_SEARCH_MODES:
            raise ValueError(
                f"Unsupported search mode '{mode}'. "
                f"Supported modes: {sorted(SUPPORTED_SEARCH_MODES)}"
            )
        return normalized

    def _normalize_sort_by(self, sort_by: Any) -> str:
        """Normalize sort mode."""
        normalized = str(sort_by or "relevance").strip().lower()
        if normalized not in SUPPORTED_SORT_MODES:
            raise ValueError(
                f"Unsupported sort_by '{sort_by}'. "
                f"Supported values: {sorted(SUPPORTED_SORT_MODES)}"
            )
        return normalized

    def _normalize_limit(self, limit: Optional[int]) -> int:
        """Normalize pagination limit."""
        if limit is None:
            return self.search_config.default_limit
        try:
            normalized = int(limit)
        except Exception:
            normalized = self.search_config.default_limit

        normalized = max(1, normalized)
        normalized = min(normalized, self.search_config.max_limit, MAX_LIMIT)
        return normalized

    def _normalize_filters(
        self,
        filters: Optional[Union[SearchFilters, Mapping[str, Any]]],
    ) -> SearchFilters:
        """Normalize dict filters into SearchFilters."""
        if filters is None:
            return SearchFilters()

        if isinstance(filters, SearchFilters):
            return filters

        raw = dict(filters)

        tags_raw = raw.get("tags")
        if tags_raw is None:
            tags = None
        elif isinstance(tags_raw, str):
            tags = _dedupe_keep_order(
                [tag.strip() for tag in re.split(r"[,|]", tags_raw) if tag.strip()]
            )
        else:
            tags = _dedupe_keep_order([str(tag) for tag in tags_raw])

        return SearchFilters(
            project_id=self._optional_string(raw.get("project_id")),
            project_name=self._optional_string(raw.get("project_name")),
            client_id=self._optional_string(raw.get("client_id")),
            client_name=self._optional_string(raw.get("client_name")),
            agent_name=self._optional_string(raw.get("agent_name")),
            agent_id=self._optional_string(raw.get("agent_id")),
            category=self._optional_string(raw.get("category")),
            memory_type=self._optional_string(raw.get("memory_type")),
            privacy_level=self._optional_string(raw.get("privacy_level")),
            tags=tags,
            date_from=_parse_datetime(raw.get("date_from") or raw.get("from")),
            date_to=_parse_datetime(raw.get("date_to") or raw.get("to")),
            created_by=self._optional_string(raw.get("created_by")),
            source=self._optional_string(raw.get("source")),
            include_archived=_coerce_bool(raw.get("include_archived"), False),
            include_deleted=_coerce_bool(raw.get("include_deleted"), False),
            min_importance=self._optional_float(raw.get("min_importance")),
            max_importance=self._optional_float(raw.get("max_importance")),
        )

    @staticmethod
    def _optional_string(value: Any) -> Optional[str]:
        """Return stripped string or None."""
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    @staticmethod
    def _optional_float(value: Any) -> Optional[float]:
        """Return float or None."""
        if value is None or value == "":
            return None
        return _coerce_float(value, 0.0)

    def _normalize_vector_response(
        self,
        response: Any,
    ) -> List[Tuple[Dict[str, Any], float]]:
        """
        Normalize vector store response into [(record, score), ...].

        Supported shapes:
            - [{"record": {...}, "score": 0.8}]
            - [{"memory": {...}, "similarity": 0.8}]
            - [{"memory_id": "...", "content": "...", "score": 0.8}]
            - {"results": [...]}
            - {"data": {"results": [...]}}
        """
        if response is None:
            return []

        if isinstance(response, dict):
            if "data" in response and isinstance(response["data"], dict):
                response = response["data"].get("results", response["data"])
            elif "results" in response:
                response = response["results"]
            elif "items" in response:
                response = response["items"]
            else:
                response = [response]

        normalized: List[Tuple[Dict[str, Any], float]] = []
        for item in response or []:
            if not isinstance(item, Mapping):
                continue

            record = (
                item.get("record")
                or item.get("memory")
                or item.get("document")
                or item.get("metadata")
                or item
            )

            if not isinstance(record, Mapping):
                continue

            score = (
                item.get("score")
                if item.get("score") is not None
                else item.get("similarity")
                if item.get("similarity") is not None
                else item.get("distance_score")
            )

            score_float = _coerce_float(score, 0.0)
            if "distance" in item and score is None:
                distance = _coerce_float(item.get("distance"), 1.0)
                score_float = 1.0 / (1.0 + max(distance, 0.0))

            normalized.append((dict(record), max(0.0, min(1.0, score_float))))

        return normalized

    def _record_to_result(
        self,
        record: Mapping[str, Any],
        query: str,
        keyword_score: float = 0.0,
        semantic_score: float = 0.0,
        recency_score: float = 0.0,
        importance_score: float = 0.0,
    ) -> MemorySearchResult:
        """Convert raw memory record into normalized MemorySearchResult."""
        memory_id = str(record.get("memory_id") or record.get("id") or _stable_id("mem", record))
        title = _normalize_text(record.get("title") or record.get("name") or "")
        content = _normalize_text(record.get("content") or record.get("text") or record.get("body") or "")
        category = str(record.get("category") or MemoryCategory.UNKNOWN.value)
        memory_type = str(record.get("memory_type") or category)
        privacy_level = str(record.get("privacy_level") or PrivacyLevel.WORKSPACE.value)

        snippet = self._make_snippet(content=content, query=query)

        return MemorySearchResult(
            memory_id=memory_id,
            title=title,
            content=content,
            snippet=snippet,
            category=category,
            memory_type=memory_type,
            privacy_level=privacy_level,
            score=0.0,
            keyword_score=keyword_score,
            semantic_score=semantic_score,
            recency_score=recency_score,
            importance_score=importance_score,
            user_id=self._optional_string(record.get("user_id")),
            workspace_id=self._optional_string(record.get("workspace_id")),
            project_id=self._optional_string(record.get("project_id")),
            project_name=self._optional_string(record.get("project_name")),
            client_id=self._optional_string(record.get("client_id")),
            client_name=self._optional_string(record.get("client_name")),
            agent_name=self._optional_string(record.get("agent_name")),
            agent_id=self._optional_string(record.get("agent_id")),
            tags=[str(tag) for tag in record.get("tags") or []],
            created_at=self._datetime_to_string(record.get("created_at")),
            updated_at=self._datetime_to_string(record.get("updated_at")),
            source=self._optional_string(record.get("source")),
            metadata=dict(record.get("metadata") or {}),
        )

    def _make_snippet(self, content: str, query: str) -> str:
        """Create a short relevant snippet from content."""
        content = _normalize_text(content)
        if not content:
            return ""

        max_len = max(80, self.search_config.snippet_length)
        if len(content) <= max_len:
            return content

        query_tokens = _tokenize(query)
        lower = content.lower()

        first_match_index: Optional[int] = None
        for token in query_tokens:
            idx = lower.find(token.lower())
            if idx >= 0:
                first_match_index = idx if first_match_index is None else min(first_match_index, idx)

        if first_match_index is None:
            return content[:max_len].rstrip() + "..."

        start = max(0, first_match_index - max_len // 3)
        end = min(len(content), start + max_len)

        snippet = content[start:end].strip()
        if start > 0:
            snippet = "..." + snippet
        if end < len(content):
            snippet = snippet + "..."
        return snippet

    def _record_search_text(self, record: Mapping[str, Any]) -> str:
        """Build searchable text from record fields."""
        parts = [
            record.get("title"),
            record.get("name"),
            record.get("content"),
            record.get("text"),
            record.get("body"),
            record.get("category"),
            record.get("memory_type"),
            record.get("project_name"),
            record.get("client_name"),
            record.get("agent_name"),
            " ".join(str(tag) for tag in record.get("tags") or []),
        ]
        return _normalize_text(" ".join(str(part) for part in parts if part is not None))

    @staticmethod
    def _datetime_to_string(value: Any) -> Optional[str]:
        """Convert datetime-like value to ISO string."""
        dt = _parse_datetime(value)
        return dt.isoformat() if dt else None

    def _sort_results(
        self,
        results: Sequence[MemorySearchResult],
        sort_by: str,
    ) -> List[MemorySearchResult]:
        """Sort normalized results."""
        if sort_by == "created_at_desc":
            return sorted(results, key=lambda item: item.created_at or "", reverse=True)

        if sort_by == "created_at_asc":
            return sorted(results, key=lambda item: item.created_at or "")

        if sort_by == "updated_at_desc":
            return sorted(results, key=lambda item: item.updated_at or "", reverse=True)

        if sort_by == "updated_at_asc":
            return sorted(results, key=lambda item: item.updated_at or "")

        if sort_by == "importance_desc":
            return sorted(results, key=lambda item: item.importance_score, reverse=True)

        if sort_by == "importance_asc":
            return sorted(results, key=lambda item: item.importance_score)

        return sorted(results, key=lambda item: item.score, reverse=True)


# =============================================================================
# Standalone helper
# =============================================================================

def create_memory_search(
    records: Optional[Sequence[Mapping[str, Any]]] = None,
    config: Optional[Union[MemorySearchConfig, Mapping[str, Any]]] = None,
    **kwargs: Any,
) -> MemorySearch:
    """
    Create MemorySearch with an in-memory store.

    Useful for tests and local development.
    """
    return MemorySearch(
        config=config,
        memory_store=InMemorySearchStore(records=records),
        **kwargs,
    )


__all__ = [
    "MemorySearch",
    "MemorySearchConfig",
    "MemorySearchResult",
    "SearchFilters",
    "SearchMode",
    "PrivacyLevel",
    "MemoryCategory",
    "InMemorySearchStore",
    "create_memory_search",
]