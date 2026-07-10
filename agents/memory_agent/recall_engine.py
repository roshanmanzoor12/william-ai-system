"""
agents/memory_agent/recall_engine.py

Purpose:
    Keyword, semantic, project, client, time-based memory recall and ranking engine
    for the William / Jarvis Multi-Agent AI SaaS System by Digital Promotix.

Responsibilities:
    - Recall memories by keyword search.
    - Recall memories by semantic/vector-style search when an embedding backend is available.
    - Recall memories by project_id, client_id, memory_type, tags, agent_name, and time ranges.
    - Rank recalled memory candidates using hybrid scoring.
    - Enforce SaaS isolation through user_id and workspace_id.
    - Return structured dict/JSON-style results.
    - Stay import-safe even when future William modules are not created yet.
    - Provide compatibility hooks for Master Agent, Memory Agent, Security Agent,
      Verification Agent, Agent Registry, Agent Loader, Agent Router, Dashboard/API.

Important:
    This file does not perform destructive actions.
    This file does not execute system/browser/call/message/financial operations.
    This file is safe to import independently.

Author:
    Digital Promotix / William-Jarvis Architecture
"""

from __future__ import annotations

import hashlib
import logging
import math
import re
import time
import traceback
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple, Union


# =============================================================================
# Optional / Safe Imports
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps recall_engine.py import-safe even if the real BaseAgent
        has not been created yet.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)

        def emit_event(self, *args: Any, **kwargs: Any) -> None:
            return None


try:
    from agents.memory_agent.embeddings import EmbeddingManager  # type: ignore
except Exception:  # pragma: no cover
    EmbeddingManager = None  # type: ignore


try:
    from agents.memory_agent.long_term import LongTermMemoryStore  # type: ignore
except Exception:  # pragma: no cover
    LongTermMemoryStore = None  # type: ignore


try:
    from agents.memory_agent.short_term import ShortTermMemoryStore  # type: ignore
except Exception:  # pragma: no cover
    ShortTermMemoryStore = None  # type: ignore


# =============================================================================
# Logging
# =============================================================================

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# =============================================================================
# Enums / Constants
# =============================================================================

class RecallMode(str, Enum):
    """Supported recall modes."""

    KEYWORD = "keyword"
    SEMANTIC = "semantic"
    HYBRID = "hybrid"
    PROJECT = "project"
    CLIENT = "client"
    TIME = "time"
    TAG = "tag"
    AGENT = "agent"


class RecallScope(str, Enum):
    """Memory scope filters."""

    ALL = "all"
    SHORT_TERM = "short_term"
    LONG_TERM = "long_term"
    PROJECT = "project"
    CLIENT = "client"
    TEAM = "team"
    KNOWLEDGE = "knowledge"
    PREFERENCE = "preference"


class RankingStrategy(str, Enum):
    """Ranking strategy options."""

    HYBRID = "hybrid"
    RECENCY_FIRST = "recency_first"
    RELEVANCE_FIRST = "relevance_first"
    IMPORTANCE_FIRST = "importance_first"
    FREQUENCY_FIRST = "frequency_first"


DEFAULT_MAX_RESULTS = 10
DEFAULT_CANDIDATE_LIMIT = 100
DEFAULT_MIN_SCORE = 0.0
DEFAULT_CONTEXT_WINDOW = 3
DEFAULT_RECENCY_HALF_LIFE_DAYS = 30.0
MAX_QUERY_LENGTH = 5000
MAX_TAGS = 50
MAX_RESULTS_HARD_LIMIT = 100


# =============================================================================
# Data Structures
# =============================================================================

@dataclass
class RecallQuery:
    """
    Structured recall query.

    This object can be built directly by API/Dashboard/Master Agent or through
    the public recall() method using dict/string input.
    """

    query: str = ""
    user_id: Optional[Union[str, int]] = None
    workspace_id: Optional[Union[str, int]] = None

    mode: RecallMode = RecallMode.HYBRID
    scope: RecallScope = RecallScope.ALL
    ranking_strategy: RankingStrategy = RankingStrategy.HYBRID

    project_id: Optional[Union[str, int]] = None
    client_id: Optional[Union[str, int]] = None
    team_id: Optional[Union[str, int]] = None

    memory_type: Optional[str] = None
    agent_name: Optional[str] = None
    task_id: Optional[Union[str, int]] = None
    session_id: Optional[Union[str, int]] = None

    tags: List[str] = field(default_factory=list)
    include_tags: List[str] = field(default_factory=list)
    exclude_tags: List[str] = field(default_factory=list)

    start_time: Optional[Union[str, datetime]] = None
    end_time: Optional[Union[str, datetime]] = None

    max_results: int = DEFAULT_MAX_RESULTS
    candidate_limit: int = DEFAULT_CANDIDATE_LIMIT
    min_score: float = DEFAULT_MIN_SCORE

    include_metadata: bool = True
    include_raw_memory: bool = False
    include_explanation: bool = True
    include_context_window: bool = False

    strict_isolation: bool = True
    allow_cross_workspace: bool = False

    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RecallCandidate:
    """
    Normalized memory candidate used internally before final ranking.
    """

    memory_id: str
    content: str

    user_id: Optional[Union[str, int]] = None
    workspace_id: Optional[Union[str, int]] = None

    source: str = "unknown"
    scope: str = "unknown"
    memory_type: Optional[str] = None

    project_id: Optional[Union[str, int]] = None
    client_id: Optional[Union[str, int]] = None
    team_id: Optional[Union[str, int]] = None

    agent_name: Optional[str] = None
    task_id: Optional[Union[str, int]] = None
    session_id: Optional[Union[str, int]] = None

    tags: List[str] = field(default_factory=list)

    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    last_accessed_at: Optional[datetime] = None

    importance: float = 0.5
    confidence: float = 0.5
    frequency: float = 0.0

    raw: Dict[str, Any] = field(default_factory=dict)

    keyword_score: float = 0.0
    semantic_score: float = 0.0
    recency_score: float = 0.0
    importance_score: float = 0.0
    context_score: float = 0.0
    tag_score: float = 0.0
    final_score: float = 0.0

    ranking_reasons: List[str] = field(default_factory=list)


# =============================================================================
# Utility Functions
# =============================================================================

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _safe_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _normalize_text(text: Any) -> str:
    raw = _safe_str(text).lower()
    raw = re.sub(r"\s+", " ", raw)
    return raw.strip()


def _tokenize(text: Any) -> List[str]:
    normalized = _normalize_text(text)
    if not normalized:
        return []
    return re.findall(r"[a-zA-Z0-9_@.#:/+-]+", normalized)


def _unique_preserve_order(items: Iterable[Any]) -> List[Any]:
    seen = set()
    output = []
    for item in items:
        marker = _safe_str(item).lower()
        if marker and marker not in seen:
            seen.add(marker)
            output.append(item)
    return output


def _parse_datetime(value: Optional[Union[str, datetime]]) -> Optional[datetime]:
    if value is None:
        return None

    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None

        try:
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            parsed = datetime.fromisoformat(text)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except Exception:
            pass

        for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%d-%m-%Y", "%d/%m/%Y"):
            try:
                parsed = datetime.strptime(text, fmt)
                return parsed.replace(tzinfo=timezone.utc)
            except Exception:
                continue

    return None


def _stable_memory_id(content: str, metadata: Optional[Dict[str, Any]] = None) -> str:
    metadata = metadata or {}
    raw = f"{content}|{metadata.get('created_at', '')}|{metadata.get('source', '')}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    try:
        return max(low, min(high, float(value)))
    except Exception:
        return low


def _cosine_similarity(vec_a: Sequence[float], vec_b: Sequence[float]) -> float:
    if not vec_a or not vec_b:
        return 0.0

    length = min(len(vec_a), len(vec_b))
    if length <= 0:
        return 0.0

    a = [float(x) for x in vec_a[:length]]
    b = [float(x) for x in vec_b[:length]]

    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))

    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0

    return _clamp((dot / (norm_a * norm_b) + 1.0) / 2.0)


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None:
            return default
        return float(value)
    except Exception:
        return default


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        if value is None:
            return default
        return int(value)
    except Exception:
        return default


# =============================================================================
# Recall Engine
# =============================================================================

class RecallEngine(BaseAgent):
    """
    Keyword, semantic, project, client, and time recall engine.

    This class is designed as a helper/agent component inside Memory Agent.
    It can be called by:
        - Master Agent for context recall before routing.
        - Memory Agent for user/project/client memory lookup.
        - Agent Router for selecting context.
        - Dashboard/API for user-facing search.
        - Verification Agent for attaching evidence/context payloads.

    SaaS Isolation:
        Every recall operation validates user_id and workspace_id before returning
        memory candidates. By default, cross-workspace access is denied.

    Import Safety:
        If real memory stores or embedding modules are unavailable, this engine
        can still operate with in-memory data or dependency-injected providers.
    """

    agent_name = "RecallEngine"
    agent_type = "memory_helper"
    version = "1.0.0"

    def __init__(
        self,
        memory_provider: Optional[Any] = None,
        embedding_provider: Optional[Any] = None,
        security_provider: Optional[Any] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], None]] = None,
        event_emitter: Optional[Callable[[Dict[str, Any]], None]] = None,
        config: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        try:
            super().__init__(agent_name=self.agent_name, **kwargs)
        except TypeError:
            super().__init__()

        self.config = self._build_config(config or {})

        self.memory_provider = memory_provider
        self.embedding_provider = embedding_provider
        self.security_provider = security_provider
        self.audit_logger = audit_logger
        self.event_emitter = event_emitter

        self._local_memory_index: List[Dict[str, Any]] = []

        self._initialize_optional_providers()

    # -------------------------------------------------------------------------
    # Configuration
    # -------------------------------------------------------------------------

    def _build_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        defaults = {
            "max_results": DEFAULT_MAX_RESULTS,
            "candidate_limit": DEFAULT_CANDIDATE_LIMIT,
            "min_score": DEFAULT_MIN_SCORE,
            "hard_max_results": MAX_RESULTS_HARD_LIMIT,
            "recency_half_life_days": DEFAULT_RECENCY_HALF_LIFE_DAYS,
            "keyword_weight": 0.35,
            "semantic_weight": 0.35,
            "recency_weight": 0.10,
            "importance_weight": 0.10,
            "tag_weight": 0.05,
            "context_weight": 0.05,
            "strict_isolation": True,
            "allow_cross_workspace": False,
            "enable_semantic": True,
            "enable_audit_log": True,
            "enable_agent_events": True,
            "safe_debug_errors": False,
        }
        merged = dict(defaults)
        merged.update(config or {})
        return merged

    def _initialize_optional_providers(self) -> None:
        """
        Initialize optional providers only when available.

        No failure here should break imports or object construction.
        """

        if self.embedding_provider is None and EmbeddingManager is not None:
            try:
                self.embedding_provider = EmbeddingManager()
            except Exception:
                self.embedding_provider = None

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    def recall(
        self,
        query: Union[str, Dict[str, Any], RecallQuery],
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Main recall entry point.

        Args:
            query:
                Text query, dict query, or RecallQuery object.
            user_id:
                SaaS user ID. Required unless already inside query.
            workspace_id:
                SaaS workspace ID. Required unless already inside query.
            **kwargs:
                Optional filters and recall parameters.

        Returns:
            Structured result dict:
                {
                    "success": bool,
                    "message": str,
                    "data": {
                        "query": {...},
                        "results": [...],
                        "count": int,
                        "ranking_strategy": str
                    },
                    "error": None | {...},
                    "metadata": {...}
                }
        """

        started_at = time.time()
        request_id = str(uuid.uuid4())

        try:
            recall_query = self._coerce_recall_query(
                query=query,
                user_id=user_id,
                workspace_id=workspace_id,
                kwargs=kwargs,
            )

            validation = self._validate_task_context(recall_query)
            if not validation["success"]:
                return validation

            if self._requires_security_check(recall_query):
                approval = self._request_security_approval(recall_query)
                if not approval.get("success"):
                    return self._error_result(
                        message="Security approval failed for recall request.",
                        error_code="SECURITY_APPROVAL_FAILED",
                        details=approval,
                        metadata={"request_id": request_id},
                    )

            self._emit_agent_event(
                event_type="memory.recall.started",
                payload={
                    "request_id": request_id,
                    "user_id": recall_query.user_id,
                    "workspace_id": recall_query.workspace_id,
                    "mode": recall_query.mode.value,
                    "scope": recall_query.scope.value,
                },
            )

            candidates = self._collect_candidates(recall_query)
            filtered_candidates = self._filter_candidates(candidates, recall_query)
            ranked_candidates = self._rank_candidates(filtered_candidates, recall_query)

            max_results = min(
                max(1, recall_query.max_results),
                int(self.config.get("hard_max_results", MAX_RESULTS_HARD_LIMIT)),
            )
            final_candidates = [
                candidate
                for candidate in ranked_candidates
                if candidate.final_score >= recall_query.min_score
            ][:max_results]

            results = [
                self._candidate_to_result(candidate, recall_query)
                for candidate in final_candidates
            ]

            verification_payload = self._prepare_verification_payload(
                recall_query=recall_query,
                results=results,
                request_id=request_id,
            )

            memory_payload = self._prepare_memory_payload(
                recall_query=recall_query,
                results=results,
                request_id=request_id,
            )

            duration_ms = round((time.time() - started_at) * 1000, 2)

            response = self._safe_result(
                message="Memory recall completed successfully.",
                data={
                    "query": self._query_to_public_dict(recall_query),
                    "results": results,
                    "count": len(results),
                    "total_candidates": len(candidates),
                    "filtered_candidates": len(filtered_candidates),
                    "ranking_strategy": recall_query.ranking_strategy.value,
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                metadata={
                    "request_id": request_id,
                    "duration_ms": duration_ms,
                    "agent": self.agent_name,
                    "version": self.version,
                },
            )

            self._log_audit_event(
                action="memory_recall",
                status="success",
                recall_query=recall_query,
                metadata={
                    "request_id": request_id,
                    "result_count": len(results),
                    "duration_ms": duration_ms,
                },
            )

            self._emit_agent_event(
                event_type="memory.recall.completed",
                payload={
                    "request_id": request_id,
                    "user_id": recall_query.user_id,
                    "workspace_id": recall_query.workspace_id,
                    "result_count": len(results),
                    "duration_ms": duration_ms,
                },
            )

            return response

        except Exception as exc:
            duration_ms = round((time.time() - started_at) * 1000, 2)

            self._emit_agent_event(
                event_type="memory.recall.failed",
                payload={
                    "request_id": request_id,
                    "error": str(exc),
                    "duration_ms": duration_ms,
                },
            )

            return self._error_result(
                message="Memory recall failed.",
                error_code="RECALL_FAILED",
                exception=exc,
                metadata={
                    "request_id": request_id,
                    "duration_ms": duration_ms,
                    "agent": self.agent_name,
                },
            )

    def keyword_recall(
        self,
        query: str,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        **filters: Any,
    ) -> Dict[str, Any]:
        """Recall memories using keyword matching."""

        return self.recall(
            {
                "query": query,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "mode": RecallMode.KEYWORD.value,
                **filters,
            }
        )

    def semantic_recall(
        self,
        query: str,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        **filters: Any,
    ) -> Dict[str, Any]:
        """Recall memories using semantic/vector similarity when available."""

        return self.recall(
            {
                "query": query,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "mode": RecallMode.SEMANTIC.value,
                **filters,
            }
        )

    def hybrid_recall(
        self,
        query: str,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        **filters: Any,
    ) -> Dict[str, Any]:
        """Recall memories using hybrid keyword + semantic + metadata ranking."""

        return self.recall(
            {
                "query": query,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "mode": RecallMode.HYBRID.value,
                **filters,
            }
        )

    def project_recall(
        self,
        project_id: Union[str, int],
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        query: str = "",
        **filters: Any,
    ) -> Dict[str, Any]:
        """Recall project-specific memories."""

        return self.recall(
            {
                "query": query,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "project_id": project_id,
                "mode": RecallMode.PROJECT.value,
                "scope": RecallScope.PROJECT.value,
                **filters,
            }
        )

    def client_recall(
        self,
        client_id: Union[str, int],
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        query: str = "",
        **filters: Any,
    ) -> Dict[str, Any]:
        """Recall client-specific memories."""

        return self.recall(
            {
                "query": query,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "client_id": client_id,
                "mode": RecallMode.CLIENT.value,
                "scope": RecallScope.CLIENT.value,
                **filters,
            }
        )

    def time_recall(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        start_time: Optional[Union[str, datetime]] = None,
        end_time: Optional[Union[str, datetime]] = None,
        query: str = "",
        **filters: Any,
    ) -> Dict[str, Any]:
        """Recall memories by time range."""

        return self.recall(
            {
                "query": query,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "start_time": start_time,
                "end_time": end_time,
                "mode": RecallMode.TIME.value,
                **filters,
            }
        )

    def add_local_memory(self, memory: Dict[str, Any]) -> Dict[str, Any]:
        """
        Add memory to the local in-memory index.

        This is useful for tests, local development, and fallback operation.
        Production systems should usually inject a memory_provider.
        """

        try:
            normalized = self._normalize_memory_dict(memory)
            self._local_memory_index.append(normalized)
            return self._safe_result(
                message="Local memory added.",
                data={"memory_id": normalized.get("memory_id")},
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to add local memory.",
                error_code="LOCAL_MEMORY_ADD_FAILED",
                exception=exc,
            )

    def clear_local_memory(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
    ) -> Dict[str, Any]:
        """
        Clear local in-memory index.

        When user_id/workspace_id are provided, only matching local memories
        are removed.
        """

        before = len(self._local_memory_index)

        if user_id is None and workspace_id is None:
            self._local_memory_index.clear()
        else:
            self._local_memory_index = [
                memory
                for memory in self._local_memory_index
                if not (
                    (user_id is None or _safe_str(memory.get("user_id")) == _safe_str(user_id))
                    and (
                        workspace_id is None
                        or _safe_str(memory.get("workspace_id")) == _safe_str(workspace_id)
                    )
                )
            ]

        after = len(self._local_memory_index)

        return self._safe_result(
            message="Local memory cleared.",
            data={"removed": before - after, "remaining": after},
        )

    # -------------------------------------------------------------------------
    # Query Coercion / Validation
    # -------------------------------------------------------------------------

    def _coerce_recall_query(
        self,
        query: Union[str, Dict[str, Any], RecallQuery],
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        kwargs: Dict[str, Any],
    ) -> RecallQuery:
        if isinstance(query, RecallQuery):
            recall_query = query
            if user_id is not None:
                recall_query.user_id = user_id
            if workspace_id is not None:
                recall_query.workspace_id = workspace_id
            for key, value in kwargs.items():
                if hasattr(recall_query, key):
                    setattr(recall_query, key, value)
            return self._normalize_recall_query(recall_query)

        if isinstance(query, str):
            data: Dict[str, Any] = {"query": query}
        elif isinstance(query, dict):
            data = dict(query)
        else:
            data = {"query": _safe_str(query)}

        if user_id is not None:
            data["user_id"] = user_id
        if workspace_id is not None:
            data["workspace_id"] = workspace_id

        data.update(kwargs)

        mode = self._safe_enum(RecallMode, data.get("mode"), RecallMode.HYBRID)
        scope = self._safe_enum(RecallScope, data.get("scope"), RecallScope.ALL)
        ranking_strategy = self._safe_enum(
            RankingStrategy,
            data.get("ranking_strategy"),
            RankingStrategy.HYBRID,
        )

        recall_query = RecallQuery(
            query=_safe_str(data.get("query", ""))[:MAX_QUERY_LENGTH],
            user_id=data.get("user_id"),
            workspace_id=data.get("workspace_id"),
            mode=mode,
            scope=scope,
            ranking_strategy=ranking_strategy,
            project_id=data.get("project_id"),
            client_id=data.get("client_id"),
            team_id=data.get("team_id"),
            memory_type=data.get("memory_type"),
            agent_name=data.get("agent_name"),
            task_id=data.get("task_id"),
            session_id=data.get("session_id"),
            tags=self._coerce_tags(data.get("tags", [])),
            include_tags=self._coerce_tags(data.get("include_tags", [])),
            exclude_tags=self._coerce_tags(data.get("exclude_tags", [])),
            start_time=data.get("start_time"),
            end_time=data.get("end_time"),
            max_results=_safe_int(data.get("max_results"), int(self.config["max_results"])),
            candidate_limit=_safe_int(
                data.get("candidate_limit"),
                int(self.config["candidate_limit"]),
            ),
            min_score=_safe_float(data.get("min_score"), float(self.config["min_score"])),
            include_metadata=bool(data.get("include_metadata", True)),
            include_raw_memory=bool(data.get("include_raw_memory", False)),
            include_explanation=bool(data.get("include_explanation", True)),
            include_context_window=bool(data.get("include_context_window", False)),
            strict_isolation=bool(data.get("strict_isolation", self.config["strict_isolation"])),
            allow_cross_workspace=bool(
                data.get("allow_cross_workspace", self.config["allow_cross_workspace"])
            ),
            metadata=dict(data.get("metadata", {}) or {}),
        )

        return self._normalize_recall_query(recall_query)

    def _normalize_recall_query(self, recall_query: RecallQuery) -> RecallQuery:
        recall_query.query = _safe_str(recall_query.query)[:MAX_QUERY_LENGTH]
        recall_query.tags = self._coerce_tags(recall_query.tags)
        recall_query.include_tags = self._coerce_tags(recall_query.include_tags)
        recall_query.exclude_tags = self._coerce_tags(recall_query.exclude_tags)

        recall_query.max_results = min(
            max(1, _safe_int(recall_query.max_results, DEFAULT_MAX_RESULTS)),
            MAX_RESULTS_HARD_LIMIT,
        )

        recall_query.candidate_limit = min(
            max(recall_query.max_results, _safe_int(recall_query.candidate_limit, DEFAULT_CANDIDATE_LIMIT)),
            max(MAX_RESULTS_HARD_LIMIT, DEFAULT_CANDIDATE_LIMIT),
        )

        recall_query.min_score = _clamp(_safe_float(recall_query.min_score, DEFAULT_MIN_SCORE), 0.0, 1.0)

        if isinstance(recall_query.mode, str):
            recall_query.mode = self._safe_enum(RecallMode, recall_query.mode, RecallMode.HYBRID)

        if isinstance(recall_query.scope, str):
            recall_query.scope = self._safe_enum(RecallScope, recall_query.scope, RecallScope.ALL)

        if isinstance(recall_query.ranking_strategy, str):
            recall_query.ranking_strategy = self._safe_enum(
                RankingStrategy,
                recall_query.ranking_strategy,
                RankingStrategy.HYBRID,
            )

        return recall_query

    def _safe_enum(self, enum_cls: Any, value: Any, default: Any) -> Any:
        if isinstance(value, enum_cls):
            return value

        if value is None:
            return default

        try:
            return enum_cls(str(value))
        except Exception:
            return default

    def _coerce_tags(self, tags: Any) -> List[str]:
        if tags is None:
            return []

        if isinstance(tags, str):
            raw_tags = re.split(r"[,|;]", tags)
        elif isinstance(tags, (list, tuple, set)):
            raw_tags = list(tags)
        else:
            raw_tags = [tags]

        cleaned = [
            _normalize_text(tag)
            for tag in raw_tags
            if _normalize_text(tag)
        ]

        return _unique_preserve_order(cleaned)[:MAX_TAGS]

    def _validate_task_context(self, recall_query: RecallQuery) -> Dict[str, Any]:
        """
        Required compatibility hook.

        Validates SaaS user/workspace isolation context.
        """

        if recall_query.user_id is None or _safe_str(recall_query.user_id) == "":
            return self._error_result(
                message="user_id is required for memory recall.",
                error_code="MISSING_USER_ID",
            )

        if recall_query.workspace_id is None or _safe_str(recall_query.workspace_id) == "":
            return self._error_result(
                message="workspace_id is required for memory recall.",
                error_code="MISSING_WORKSPACE_ID",
            )

        if recall_query.strict_isolation and recall_query.allow_cross_workspace:
            return self._error_result(
                message="Cross-workspace recall is not allowed while strict isolation is enabled.",
                error_code="CROSS_WORKSPACE_BLOCKED",
            )

        if len(recall_query.query) > MAX_QUERY_LENGTH:
            return self._error_result(
                message="Recall query is too long.",
                error_code="QUERY_TOO_LONG",
            )

        return self._safe_result(
            message="Recall context validated.",
            data={
                "user_id": recall_query.user_id,
                "workspace_id": recall_query.workspace_id,
            },
        )

    # -------------------------------------------------------------------------
    # Candidate Collection
    # -------------------------------------------------------------------------

    def _collect_candidates(self, recall_query: RecallQuery) -> List[RecallCandidate]:
        """
        Collect recall candidates from injected memory provider and local fallback.
        """

        candidates: List[RecallCandidate] = []

        provider_candidates = self._collect_from_memory_provider(recall_query)
        candidates.extend(provider_candidates)

        local_candidates = self._collect_from_local_memory(recall_query)
        candidates.extend(local_candidates)

        candidates = self._deduplicate_candidates(candidates)

        return candidates[: recall_query.candidate_limit]

    def _collect_from_memory_provider(self, recall_query: RecallQuery) -> List[RecallCandidate]:
        """
        Collect candidates from external memory provider.

        Supported provider shapes:
            - provider.search(query_dict)
            - provider.recall(query_dict)
            - provider.list_memories(user_id=..., workspace_id=...)
            - callable provider(query_dict)
        """

        if self.memory_provider is None:
            return []

        query_dict = self._query_to_provider_dict(recall_query)

        try:
            if hasattr(self.memory_provider, "search"):
                raw_result = self.memory_provider.search(query_dict)
            elif hasattr(self.memory_provider, "recall"):
                raw_result = self.memory_provider.recall(query_dict)
            elif hasattr(self.memory_provider, "list_memories"):
                raw_result = self.memory_provider.list_memories(
                    user_id=recall_query.user_id,
                    workspace_id=recall_query.workspace_id,
                    filters=query_dict,
                )
            elif callable(self.memory_provider):
                raw_result = self.memory_provider(query_dict)
            else:
                return []

            raw_memories = self._extract_memory_list(raw_result)
            return [
                self._memory_dict_to_candidate(memory, source="memory_provider")
                for memory in raw_memories
                if isinstance(memory, dict)
            ]

        except Exception as exc:
            logger.warning("Memory provider candidate collection failed: %s", exc)
            return []

    def _collect_from_local_memory(self, recall_query: RecallQuery) -> List[RecallCandidate]:
        candidates: List[RecallCandidate] = []

        for memory in self._local_memory_index:
            try:
                candidate = self._memory_dict_to_candidate(memory, source="local_memory")
                candidates.append(candidate)
            except Exception:
                continue

        return candidates

    def _extract_memory_list(self, raw_result: Any) -> List[Dict[str, Any]]:
        if raw_result is None:
            return []

        if isinstance(raw_result, list):
            return [item for item in raw_result if isinstance(item, dict)]

        if isinstance(raw_result, dict):
            if isinstance(raw_result.get("data"), dict):
                data = raw_result["data"]
                for key in ("results", "memories", "items", "records"):
                    if isinstance(data.get(key), list):
                        return [item for item in data[key] if isinstance(item, dict)]

            for key in ("results", "memories", "items", "records"):
                if isinstance(raw_result.get(key), list):
                    return [item for item in raw_result[key] if isinstance(item, dict)]

        return []

    def _normalize_memory_dict(self, memory: Dict[str, Any]) -> Dict[str, Any]:
        content = (
            memory.get("content")
            or memory.get("text")
            or memory.get("summary")
            or memory.get("value")
            or ""
        )

        metadata = dict(memory.get("metadata", {}) or {})

        memory_id = (
            memory.get("memory_id")
            or memory.get("id")
            or metadata.get("memory_id")
            or _stable_memory_id(_safe_str(content), metadata)
        )

        normalized = dict(memory)
        normalized["memory_id"] = _safe_str(memory_id)
        normalized["content"] = _safe_str(content)
        normalized["metadata"] = metadata

        normalized.setdefault("created_at", metadata.get("created_at"))
        normalized.setdefault("updated_at", metadata.get("updated_at"))
        normalized.setdefault("last_accessed_at", metadata.get("last_accessed_at"))

        normalized.setdefault("tags", metadata.get("tags", []))
        normalized.setdefault("scope", metadata.get("scope", memory.get("scope", "unknown")))

        return normalized

    def _memory_dict_to_candidate(
        self,
        memory: Dict[str, Any],
        source: str = "unknown",
    ) -> RecallCandidate:
        normalized = self._normalize_memory_dict(memory)
        metadata = dict(normalized.get("metadata", {}) or {})

        tags = normalized.get("tags", metadata.get("tags", []))
        tags = self._coerce_tags(tags)

        content = _safe_str(normalized.get("content"))

        candidate = RecallCandidate(
            memory_id=_safe_str(normalized.get("memory_id")),
            content=content,
            user_id=normalized.get("user_id", metadata.get("user_id")),
            workspace_id=normalized.get("workspace_id", metadata.get("workspace_id")),
            source=source,
            scope=_safe_str(normalized.get("scope", metadata.get("scope", "unknown"))) or "unknown",
            memory_type=normalized.get("memory_type", metadata.get("memory_type")),
            project_id=normalized.get("project_id", metadata.get("project_id")),
            client_id=normalized.get("client_id", metadata.get("client_id")),
            team_id=normalized.get("team_id", metadata.get("team_id")),
            agent_name=normalized.get("agent_name", metadata.get("agent_name")),
            task_id=normalized.get("task_id", metadata.get("task_id")),
            session_id=normalized.get("session_id", metadata.get("session_id")),
            tags=tags,
            created_at=_parse_datetime(normalized.get("created_at", metadata.get("created_at"))),
            updated_at=_parse_datetime(normalized.get("updated_at", metadata.get("updated_at"))),
            last_accessed_at=_parse_datetime(
                normalized.get("last_accessed_at", metadata.get("last_accessed_at"))
            ),
            importance=_clamp(_safe_float(normalized.get("importance", metadata.get("importance", 0.5)), 0.5)),
            confidence=_clamp(_safe_float(normalized.get("confidence", metadata.get("confidence", 0.5)), 0.5)),
            frequency=max(0.0, _safe_float(normalized.get("frequency", metadata.get("frequency", 0.0)), 0.0)),
            raw=normalized,
        )

        return candidate

    def _deduplicate_candidates(self, candidates: List[RecallCandidate]) -> List[RecallCandidate]:
        by_id: Dict[str, RecallCandidate] = {}

        for candidate in candidates:
            key = candidate.memory_id or _stable_memory_id(candidate.content, candidate.raw)

            if key not in by_id:
                by_id[key] = candidate
                continue

            existing = by_id[key]
            if self._candidate_quality(candidate) > self._candidate_quality(existing):
                by_id[key] = candidate

        return list(by_id.values())

    def _candidate_quality(self, candidate: RecallCandidate) -> float:
        return (
            len(candidate.content) / 10000.0
            + candidate.importance
            + candidate.confidence
            + min(candidate.frequency / 100.0, 1.0)
        )

    # -------------------------------------------------------------------------
    # Filtering
    # -------------------------------------------------------------------------

    def _filter_candidates(
        self,
        candidates: List[RecallCandidate],
        recall_query: RecallQuery,
    ) -> List[RecallCandidate]:
        output: List[RecallCandidate] = []

        for candidate in candidates:
            if not self._passes_isolation(candidate, recall_query):
                continue

            if not self._passes_scope(candidate, recall_query):
                continue

            if not self._passes_entity_filters(candidate, recall_query):
                continue

            if not self._passes_tag_filters(candidate, recall_query):
                continue

            if not self._passes_time_filters(candidate, recall_query):
                continue

            if not self._passes_text_presence(candidate, recall_query):
                continue

            output.append(candidate)

        return output

    def _passes_isolation(self, candidate: RecallCandidate, recall_query: RecallQuery) -> bool:
        if not recall_query.strict_isolation:
            return True

        if _safe_str(candidate.user_id) != _safe_str(recall_query.user_id):
            return False

        if recall_query.allow_cross_workspace:
            return True

        if _safe_str(candidate.workspace_id) != _safe_str(recall_query.workspace_id):
            return False

        return True

    def _passes_scope(self, candidate: RecallCandidate, recall_query: RecallQuery) -> bool:
        if recall_query.scope == RecallScope.ALL:
            return True

        candidate_scope = _normalize_text(candidate.scope)

        if recall_query.scope.value == candidate_scope:
            return True

        if recall_query.scope == RecallScope.PROJECT and candidate.project_id is not None:
            return True

        if recall_query.scope == RecallScope.CLIENT and candidate.client_id is not None:
            return True

        return False

    def _passes_entity_filters(self, candidate: RecallCandidate, recall_query: RecallQuery) -> bool:
        comparisons = [
            ("project_id", candidate.project_id, recall_query.project_id),
            ("client_id", candidate.client_id, recall_query.client_id),
            ("team_id", candidate.team_id, recall_query.team_id),
            ("memory_type", candidate.memory_type, recall_query.memory_type),
            ("agent_name", candidate.agent_name, recall_query.agent_name),
            ("task_id", candidate.task_id, recall_query.task_id),
            ("session_id", candidate.session_id, recall_query.session_id),
        ]

        for _, candidate_value, query_value in comparisons:
            if query_value is not None and _safe_str(candidate_value) != _safe_str(query_value):
                return False

        return True

    def _passes_tag_filters(self, candidate: RecallCandidate, recall_query: RecallQuery) -> bool:
        candidate_tags = set(self._coerce_tags(candidate.tags))

        all_required_tags = set(recall_query.tags + recall_query.include_tags)
        excluded_tags = set(recall_query.exclude_tags)

        if all_required_tags and not all_required_tags.intersection(candidate_tags):
            return False

        if excluded_tags and excluded_tags.intersection(candidate_tags):
            return False

        return True

    def _passes_time_filters(self, candidate: RecallCandidate, recall_query: RecallQuery) -> bool:
        start = _parse_datetime(recall_query.start_time)
        end = _parse_datetime(recall_query.end_time)

        if start is None and end is None:
            return True

        candidate_time = candidate.updated_at or candidate.created_at or candidate.last_accessed_at

        if candidate_time is None:
            return False

        if start is not None and candidate_time < start:
            return False

        if end is not None and candidate_time > end:
            return False

        return True

    def _passes_text_presence(self, candidate: RecallCandidate, recall_query: RecallQuery) -> bool:
        """
        For entity-only recalls, empty query is allowed.
        For pure keyword/semantic recall, empty content is not useful.
        """

        if not candidate.content:
            return False

        if recall_query.query:
            return True

        if recall_query.mode in {
            RecallMode.PROJECT,
            RecallMode.CLIENT,
            RecallMode.TIME,
            RecallMode.TAG,
            RecallMode.AGENT,
        }:
            return True

        if recall_query.project_id or recall_query.client_id or recall_query.tags:
            return True

        return True

    # -------------------------------------------------------------------------
    # Ranking
    # -------------------------------------------------------------------------

    def _rank_candidates(
        self,
        candidates: List[RecallCandidate],
        recall_query: RecallQuery,
    ) -> List[RecallCandidate]:
        query_embedding = self._get_query_embedding(recall_query)

        for candidate in candidates:
            candidate.keyword_score = self._calculate_keyword_score(candidate, recall_query)
            candidate.semantic_score = self._calculate_semantic_score(
                candidate=candidate,
                recall_query=recall_query,
                query_embedding=query_embedding,
            )
            candidate.recency_score = self._calculate_recency_score(candidate)
            candidate.importance_score = self._calculate_importance_score(candidate)
            candidate.tag_score = self._calculate_tag_score(candidate, recall_query)
            candidate.context_score = self._calculate_context_score(candidate, recall_query)
            candidate.final_score = self._calculate_final_score(candidate, recall_query)
            candidate.ranking_reasons = self._build_ranking_reasons(candidate, recall_query)

        strategy = recall_query.ranking_strategy

        if strategy == RankingStrategy.RECENCY_FIRST:
            key_fn = lambda c: (c.recency_score, c.final_score, c.importance_score)
        elif strategy == RankingStrategy.RELEVANCE_FIRST:
            key_fn = lambda c: (max(c.keyword_score, c.semantic_score), c.final_score, c.recency_score)
        elif strategy == RankingStrategy.IMPORTANCE_FIRST:
            key_fn = lambda c: (c.importance_score, c.final_score, c.recency_score)
        elif strategy == RankingStrategy.FREQUENCY_FIRST:
            key_fn = lambda c: (min(c.frequency / 100.0, 1.0), c.final_score, c.recency_score)
        else:
            key_fn = lambda c: (c.final_score, c.importance_score, c.recency_score)

        return sorted(candidates, key=key_fn, reverse=True)

    def _calculate_keyword_score(
        self,
        candidate: RecallCandidate,
        recall_query: RecallQuery,
    ) -> float:
        query = recall_query.query
        if not query:
            return 0.0

        query_tokens = _tokenize(query)
        content_tokens = _tokenize(candidate.content)

        if not query_tokens or not content_tokens:
            return 0.0

        query_set = set(query_tokens)
        content_set = set(content_tokens)

        overlap = query_set.intersection(content_set)
        overlap_ratio = len(overlap) / max(len(query_set), 1)

        phrase_bonus = 0.0
        normalized_query = _normalize_text(query)
        normalized_content = _normalize_text(candidate.content)

        if normalized_query and normalized_query in normalized_content:
            phrase_bonus = 0.35

        density_bonus = 0.0
        for token in query_set:
            count = content_tokens.count(token)
            if count > 1:
                density_bonus += min(count / 20.0, 0.05)

        score = overlap_ratio * 0.65 + phrase_bonus + min(density_bonus, 0.15)
        return _clamp(score)

    def _calculate_semantic_score(
        self,
        candidate: RecallCandidate,
        recall_query: RecallQuery,
        query_embedding: Optional[List[float]],
    ) -> float:
        if recall_query.mode == RecallMode.KEYWORD:
            return 0.0

        if not recall_query.query:
            return 0.0

        if not self.config.get("enable_semantic", True):
            return 0.0

        raw_embedding = (
            candidate.raw.get("embedding")
            or candidate.raw.get("vector")
            or candidate.raw.get("metadata", {}).get("embedding")
            or candidate.raw.get("metadata", {}).get("vector")
        )

        if raw_embedding and query_embedding:
            try:
                return _cosine_similarity(query_embedding, raw_embedding)
            except Exception:
                return 0.0

        provider_score = self._semantic_score_from_provider(candidate, recall_query)
        if provider_score is not None:
            return provider_score

        return self._fallback_semantic_score(candidate, recall_query)

    def _semantic_score_from_provider(
        self,
        candidate: RecallCandidate,
        recall_query: RecallQuery,
    ) -> Optional[float]:
        if self.embedding_provider is None:
            return None

        try:
            if hasattr(self.embedding_provider, "similarity"):
                score = self.embedding_provider.similarity(recall_query.query, candidate.content)
                return _clamp(_safe_float(score, 0.0))

            if hasattr(self.embedding_provider, "compare_text"):
                score = self.embedding_provider.compare_text(recall_query.query, candidate.content)
                return _clamp(_safe_float(score, 0.0))

        except Exception:
            return None

        return None

    def _fallback_semantic_score(
        self,
        candidate: RecallCandidate,
        recall_query: RecallQuery,
    ) -> float:
        """
        Lightweight semantic fallback.

        This is not a replacement for embeddings. It approximates semantic recall
        through token shingles and fuzzy overlap so the file remains functional
        without external dependencies.
        """

        query_tokens = _tokenize(recall_query.query)
        content_tokens = _tokenize(candidate.content)

        if not query_tokens or not content_tokens:
            return 0.0

        query_bigrams = set(zip(query_tokens, query_tokens[1:]))
        content_bigrams = set(zip(content_tokens, content_tokens[1:]))

        unigram_overlap = len(set(query_tokens).intersection(content_tokens)) / max(len(set(query_tokens)), 1)

        if query_bigrams:
            bigram_overlap = len(query_bigrams.intersection(content_bigrams)) / max(len(query_bigrams), 1)
        else:
            bigram_overlap = 0.0

        stem_overlap = self._simple_stem_overlap(query_tokens, content_tokens)

        return _clamp((unigram_overlap * 0.50) + (bigram_overlap * 0.30) + (stem_overlap * 0.20))

    def _simple_stem_overlap(self, query_tokens: List[str], content_tokens: List[str]) -> float:
        def stem(token: str) -> str:
            for suffix in ("ing", "ed", "er", "ers", "tion", "s"):
                if len(token) > len(suffix) + 3 and token.endswith(suffix):
                    return token[: -len(suffix)]
            return token

        query_stems = {stem(token) for token in query_tokens}
        content_stems = {stem(token) for token in content_tokens}

        if not query_stems:
            return 0.0

        return len(query_stems.intersection(content_stems)) / len(query_stems)

    def _calculate_recency_score(self, candidate: RecallCandidate) -> float:
        timestamp = candidate.updated_at or candidate.last_accessed_at or candidate.created_at

        if timestamp is None:
            return 0.25

        now = _utc_now()
        age_days = max((now - timestamp).total_seconds() / 86400.0, 0.0)
        half_life = max(float(self.config.get("recency_half_life_days", DEFAULT_RECENCY_HALF_LIFE_DAYS)), 1.0)

        score = 0.5 ** (age_days / half_life)
        return _clamp(score)

    def _calculate_importance_score(self, candidate: RecallCandidate) -> float:
        frequency_score = _clamp(candidate.frequency / 50.0)
        score = (
            candidate.importance * 0.60
            + candidate.confidence * 0.25
            + frequency_score * 0.15
        )
        return _clamp(score)

    def _calculate_tag_score(
        self,
        candidate: RecallCandidate,
        recall_query: RecallQuery,
    ) -> float:
        query_tags = set(recall_query.tags + recall_query.include_tags)
        if not query_tags:
            return 0.0

        candidate_tags = set(candidate.tags)
        if not candidate_tags:
            return 0.0

        overlap = query_tags.intersection(candidate_tags)
        return _clamp(len(overlap) / max(len(query_tags), 1))

    def _calculate_context_score(
        self,
        candidate: RecallCandidate,
        recall_query: RecallQuery,
    ) -> float:
        score = 0.0

        if recall_query.project_id is not None and _safe_str(candidate.project_id) == _safe_str(recall_query.project_id):
            score += 0.30

        if recall_query.client_id is not None and _safe_str(candidate.client_id) == _safe_str(recall_query.client_id):
            score += 0.30

        if recall_query.team_id is not None and _safe_str(candidate.team_id) == _safe_str(recall_query.team_id):
            score += 0.15

        if recall_query.agent_name is not None and _safe_str(candidate.agent_name) == _safe_str(recall_query.agent_name):
            score += 0.10

        if recall_query.memory_type is not None and _safe_str(candidate.memory_type) == _safe_str(recall_query.memory_type):
            score += 0.10

        if recall_query.task_id is not None and _safe_str(candidate.task_id) == _safe_str(recall_query.task_id):
            score += 0.05

        return _clamp(score)

    def _calculate_final_score(
        self,
        candidate: RecallCandidate,
        recall_query: RecallQuery,
    ) -> float:
        if recall_query.mode == RecallMode.KEYWORD:
            weights = {
                "keyword": 0.65,
                "semantic": 0.00,
                "recency": 0.10,
                "importance": 0.10,
                "tag": 0.05,
                "context": 0.10,
            }
        elif recall_query.mode == RecallMode.SEMANTIC:
            weights = {
                "keyword": 0.05,
                "semantic": 0.65,
                "recency": 0.10,
                "importance": 0.10,
                "tag": 0.05,
                "context": 0.05,
            }
        elif recall_query.mode in {RecallMode.PROJECT, RecallMode.CLIENT, RecallMode.TIME, RecallMode.TAG, RecallMode.AGENT}:
            weights = {
                "keyword": 0.20,
                "semantic": 0.20,
                "recency": 0.15,
                "importance": 0.15,
                "tag": 0.10,
                "context": 0.20,
            }
        else:
            weights = {
                "keyword": float(self.config.get("keyword_weight", 0.35)),
                "semantic": float(self.config.get("semantic_weight", 0.35)),
                "recency": float(self.config.get("recency_weight", 0.10)),
                "importance": float(self.config.get("importance_weight", 0.10)),
                "tag": float(self.config.get("tag_weight", 0.05)),
                "context": float(self.config.get("context_weight", 0.05)),
            }

        total_weight = sum(weights.values()) or 1.0

        score = (
            candidate.keyword_score * weights["keyword"]
            + candidate.semantic_score * weights["semantic"]
            + candidate.recency_score * weights["recency"]
            + candidate.importance_score * weights["importance"]
            + candidate.tag_score * weights["tag"]
            + candidate.context_score * weights["context"]
        ) / total_weight

        if not recall_query.query and candidate.context_score > 0:
            score = max(score, candidate.context_score)

        return _clamp(score)

    def _build_ranking_reasons(
        self,
        candidate: RecallCandidate,
        recall_query: RecallQuery,
    ) -> List[str]:
        reasons: List[str] = []

        if candidate.keyword_score >= 0.5:
            reasons.append("Strong keyword match")
        elif candidate.keyword_score > 0:
            reasons.append("Partial keyword match")

        if candidate.semantic_score >= 0.5:
            reasons.append("Semantic similarity match")
        elif candidate.semantic_score > 0:
            reasons.append("Partial semantic match")

        if candidate.recency_score >= 0.7:
            reasons.append("Recent memory")

        if candidate.importance_score >= 0.7:
            reasons.append("High importance memory")

        if candidate.tag_score > 0:
            reasons.append("Tag match")

        if candidate.context_score > 0:
            reasons.append("Context/entity match")

        if recall_query.project_id and _safe_str(candidate.project_id) == _safe_str(recall_query.project_id):
            reasons.append("Same project")

        if recall_query.client_id and _safe_str(candidate.client_id) == _safe_str(recall_query.client_id):
            reasons.append("Same client")

        return reasons

    def _get_query_embedding(self, recall_query: RecallQuery) -> Optional[List[float]]:
        if not recall_query.query:
            return None

        if recall_query.mode == RecallMode.KEYWORD:
            return None

        if not self.embedding_provider:
            return None

        try:
            if hasattr(self.embedding_provider, "embed_query"):
                vector = self.embedding_provider.embed_query(recall_query.query)
            elif hasattr(self.embedding_provider, "embed_text"):
                vector = self.embedding_provider.embed_text(recall_query.query)
            elif hasattr(self.embedding_provider, "create_embedding"):
                vector = self.embedding_provider.create_embedding(recall_query.query)
            else:
                return None

            if isinstance(vector, dict):
                vector = vector.get("embedding") or vector.get("vector") or vector.get("data")

            if isinstance(vector, list):
                return [float(x) for x in vector]

        except Exception:
            return None

        return None

    # -------------------------------------------------------------------------
    # Result Serialization
    # -------------------------------------------------------------------------

    def _candidate_to_result(
        self,
        candidate: RecallCandidate,
        recall_query: RecallQuery,
    ) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "memory_id": candidate.memory_id,
            "content": candidate.content,
            "score": round(candidate.final_score, 6),
            "scores": {
                "keyword": round(candidate.keyword_score, 6),
                "semantic": round(candidate.semantic_score, 6),
                "recency": round(candidate.recency_score, 6),
                "importance": round(candidate.importance_score, 6),
                "tag": round(candidate.tag_score, 6),
                "context": round(candidate.context_score, 6),
            },
            "source": candidate.source,
            "scope": candidate.scope,
            "memory_type": candidate.memory_type,
            "project_id": candidate.project_id,
            "client_id": candidate.client_id,
            "team_id": candidate.team_id,
            "agent_name": candidate.agent_name,
            "task_id": candidate.task_id,
            "session_id": candidate.session_id,
            "tags": candidate.tags,
            "created_at": self._datetime_to_iso(candidate.created_at),
            "updated_at": self._datetime_to_iso(candidate.updated_at),
            "last_accessed_at": self._datetime_to_iso(candidate.last_accessed_at),
        }

        if recall_query.include_explanation:
            result["ranking_reasons"] = candidate.ranking_reasons

        if recall_query.include_metadata:
            result["metadata"] = {
                "importance": candidate.importance,
                "confidence": candidate.confidence,
                "frequency": candidate.frequency,
            }

        if recall_query.include_raw_memory:
            result["raw"] = candidate.raw

        if recall_query.include_context_window:
            result["context_window"] = self._build_context_window(candidate, recall_query)

        return result

    def _build_context_window(
        self,
        candidate: RecallCandidate,
        recall_query: RecallQuery,
    ) -> Dict[str, Any]:
        """
        Build lightweight context window metadata.

        Future memory_router.py / memory_search.py can expand this with adjacent
        records from a database or vector store.
        """

        return {
            "memory_id": candidate.memory_id,
            "window_size": DEFAULT_CONTEXT_WINDOW,
            "before": [],
            "after": [],
            "note": "Context window placeholder-compatible structure. No adjacent provider available in recall_engine.py.",
        }

    def _datetime_to_iso(self, value: Optional[datetime]) -> Optional[str]:
        if value is None:
            return None

        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)

        return value.astimezone(timezone.utc).isoformat()

    def _query_to_public_dict(self, recall_query: RecallQuery) -> Dict[str, Any]:
        data = asdict(recall_query)
        data["mode"] = recall_query.mode.value
        data["scope"] = recall_query.scope.value
        data["ranking_strategy"] = recall_query.ranking_strategy.value

        if isinstance(data.get("start_time"), datetime):
            data["start_time"] = self._datetime_to_iso(data["start_time"])

        if isinstance(data.get("end_time"), datetime):
            data["end_time"] = self._datetime_to_iso(data["end_time"])

        return data

    def _query_to_provider_dict(self, recall_query: RecallQuery) -> Dict[str, Any]:
        return self._query_to_public_dict(recall_query)

    # -------------------------------------------------------------------------
    # Security / Verification / Memory / Events / Audit Hooks
    # -------------------------------------------------------------------------

    def _requires_security_check(self, recall_query: RecallQuery) -> bool:
        """
        Required compatibility hook.

        Recall is normally read-only and safe. Security approval is required only
        for cross-workspace or non-strict recall behavior.
        """

        if recall_query.allow_cross_workspace:
            return True

        if not recall_query.strict_isolation:
            return True

        return False

    def _request_security_approval(self, recall_query: RecallQuery) -> Dict[str, Any]:
        """
        Required compatibility hook.

        Delegates to Security Agent/provider when available.
        """

        if self.security_provider is None:
            if recall_query.allow_cross_workspace or not recall_query.strict_isolation:
                return self._error_result(
                    message="Security provider required for cross-workspace or non-strict recall.",
                    error_code="SECURITY_PROVIDER_REQUIRED",
                )

            return self._safe_result(
                message="Security approval not required.",
                data={"approved": True},
            )

        payload = {
            "action": "memory_recall",
            "risk_level": "medium",
            "user_id": recall_query.user_id,
            "workspace_id": recall_query.workspace_id,
            "allow_cross_workspace": recall_query.allow_cross_workspace,
            "strict_isolation": recall_query.strict_isolation,
            "query": recall_query.query,
            "metadata": recall_query.metadata,
        }

        try:
            if hasattr(self.security_provider, "approve"):
                result = self.security_provider.approve(payload)
            elif hasattr(self.security_provider, "check_permission"):
                result = self.security_provider.check_permission(payload)
            elif callable(self.security_provider):
                result = self.security_provider(payload)
            else:
                return self._error_result(
                    message="Invalid security provider.",
                    error_code="INVALID_SECURITY_PROVIDER",
                )

            if isinstance(result, dict):
                if result.get("success") is False:
                    return result

                approved = bool(
                    result.get("approved")
                    or result.get("data", {}).get("approved")
                    or result.get("success")
                )

                if approved:
                    return self._safe_result(
                        message="Security approval granted.",
                        data={"approved": True, "provider_result": result},
                    )

            return self._error_result(
                message="Security approval denied.",
                error_code="SECURITY_DENIED",
                details={"provider_result": result},
            )

        except Exception as exc:
            return self._error_result(
                message="Security approval request failed.",
                error_code="SECURITY_APPROVAL_ERROR",
                exception=exc,
            )

    def _prepare_verification_payload(
        self,
        recall_query: RecallQuery,
        results: List[Dict[str, Any]],
        request_id: str,
    ) -> Dict[str, Any]:
        """
        Required compatibility hook.

        This payload can be sent to Verification Agent after recall completes.
        """

        return {
            "type": "memory_recall_verification",
            "request_id": request_id,
            "agent": self.agent_name,
            "user_id": recall_query.user_id,
            "workspace_id": recall_query.workspace_id,
            "query": recall_query.query,
            "mode": recall_query.mode.value,
            "scope": recall_query.scope.value,
            "result_count": len(results),
            "top_memory_ids": [item.get("memory_id") for item in results[:5]],
            "checks": {
                "saas_isolation_enforced": recall_query.strict_isolation,
                "cross_workspace_allowed": recall_query.allow_cross_workspace,
                "structured_result": True,
                "read_only_operation": True,
            },
            "created_at": _utc_now().isoformat(),
        }

    def _prepare_memory_payload(
        self,
        recall_query: RecallQuery,
        results: List[Dict[str, Any]],
        request_id: str,
    ) -> Dict[str, Any]:
        """
        Required compatibility hook.

        This payload can be stored by Memory Agent as task history / recall trace.
        """

        return {
            "type": "memory_recall_trace",
            "request_id": request_id,
            "user_id": recall_query.user_id,
            "workspace_id": recall_query.workspace_id,
            "content": f"Recall executed for query: {recall_query.query}",
            "metadata": {
                "mode": recall_query.mode.value,
                "scope": recall_query.scope.value,
                "ranking_strategy": recall_query.ranking_strategy.value,
                "result_count": len(results),
                "top_scores": [item.get("score") for item in results[:5]],
                "top_memory_ids": [item.get("memory_id") for item in results[:5]],
                "agent": self.agent_name,
                "created_at": _utc_now().isoformat(),
            },
        }

    def _emit_agent_event(
        self,
        event_type: str,
        payload: Dict[str, Any],
    ) -> None:
        """
        Required compatibility hook.

        Emits events to Agent Registry / Dashboard / Master Agent if an emitter
        is injected. Never raises.
        """

        if not self.config.get("enable_agent_events", True):
            return

        event = {
            "event_type": event_type,
            "agent": self.agent_name,
            "timestamp": _utc_now().isoformat(),
            "payload": payload,
        }

        try:
            if self.event_emitter:
                self.event_emitter(event)
                return

            if hasattr(self, "emit_event"):
                try:
                    self.emit_event(event_type, event)
                except TypeError:
                    self.emit_event(event)

        except Exception:
            logger.debug("Failed to emit agent event.", exc_info=True)

    def _log_audit_event(
        self,
        action: str,
        status: str,
        recall_query: Optional[RecallQuery] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Required compatibility hook.

        Audit logs are important for SaaS privacy and workspace isolation.
        """

        if not self.config.get("enable_audit_log", True):
            return

        event = {
            "action": action,
            "status": status,
            "agent": self.agent_name,
            "timestamp": _utc_now().isoformat(),
            "metadata": metadata or {},
        }

        if recall_query is not None:
            event.update(
                {
                    "user_id": recall_query.user_id,
                    "workspace_id": recall_query.workspace_id,
                    "mode": recall_query.mode.value,
                    "scope": recall_query.scope.value,
                    "project_id": recall_query.project_id,
                    "client_id": recall_query.client_id,
                }
            )

        try:
            if self.audit_logger:
                self.audit_logger(event)
            else:
                logger.info("Audit event: %s", event)
        except Exception:
            logger.debug("Failed to write audit event.", exc_info=True)

    # -------------------------------------------------------------------------
    # Structured Result Helpers
    # -------------------------------------------------------------------------

    def _safe_result(
        self,
        message: str = "Success.",
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Required compatibility hook.

        Returns William/Jarvis standard success response.
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
        message: str,
        error_code: str = "ERROR",
        exception: Optional[BaseException] = None,
        details: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Required compatibility hook.

        Returns William/Jarvis standard error response.
        """

        error: Dict[str, Any] = {
            "code": error_code,
            "message": message,
            "details": details or {},
        }

        if exception is not None:
            error["exception_type"] = exception.__class__.__name__
            error["exception_message"] = str(exception)

            if self.config.get("safe_debug_errors", False):
                error["traceback"] = traceback.format_exc()

        return {
            "success": False,
            "message": message,
            "data": {},
            "error": error,
            "metadata": metadata or {},
        }

    # -------------------------------------------------------------------------
    # Health / Diagnostics
    # -------------------------------------------------------------------------

    def health_check(self) -> Dict[str, Any]:
        """
        Lightweight health check for Dashboard/API/Agent Registry.
        """

        return self._safe_result(
            message="RecallEngine is healthy.",
            data={
                "agent": self.agent_name,
                "agent_type": self.agent_type,
                "version": self.version,
                "local_memory_count": len(self._local_memory_index),
                "memory_provider_available": self.memory_provider is not None,
                "embedding_provider_available": self.embedding_provider is not None,
                "security_provider_available": self.security_provider is not None,
                "supports": [
                    RecallMode.KEYWORD.value,
                    RecallMode.SEMANTIC.value,
                    RecallMode.HYBRID.value,
                    RecallMode.PROJECT.value,
                    RecallMode.CLIENT.value,
                    RecallMode.TIME.value,
                    RecallMode.TAG.value,
                    RecallMode.AGENT.value,
                ],
            },
            metadata={
                "timestamp": _utc_now().isoformat(),
            },
        )

    def get_capabilities(self) -> Dict[str, Any]:
        """
        Capability manifest for Agent Loader / Agent Registry.
        """

        return self._safe_result(
            message="RecallEngine capabilities loaded.",
            data={
                "name": self.agent_name,
                "type": self.agent_type,
                "version": self.version,
                "public_methods": [
                    "recall",
                    "keyword_recall",
                    "semantic_recall",
                    "hybrid_recall",
                    "project_recall",
                    "client_recall",
                    "time_recall",
                    "add_local_memory",
                    "clear_local_memory",
                    "health_check",
                    "get_capabilities",
                ],
                "requires_user_id": True,
                "requires_workspace_id": True,
                "read_only": True,
                "destructive_actions": False,
                "security_check_required_for": [
                    "cross_workspace_recall",
                    "non_strict_isolation_recall",
                ],
                "result_format": {
                    "success": "bool",
                    "message": "str",
                    "data": "dict",
                    "error": "dict|null",
                    "metadata": "dict",
                },
            },
        )


# =============================================================================
# Module-Level Convenience Factory
# =============================================================================

def create_recall_engine(
    memory_provider: Optional[Any] = None,
    embedding_provider: Optional[Any] = None,
    security_provider: Optional[Any] = None,
    audit_logger: Optional[Callable[[Dict[str, Any]], None]] = None,
    event_emitter: Optional[Callable[[Dict[str, Any]], None]] = None,
    config: Optional[Dict[str, Any]] = None,
) -> RecallEngine:
    """
    Factory used by Agent Loader / Registry / FastAPI dependency injection.
    """

    return RecallEngine(
        memory_provider=memory_provider,
        embedding_provider=embedding_provider,
        security_provider=security_provider,
        audit_logger=audit_logger,
        event_emitter=event_emitter,
        config=config,
    )


__all__ = [
    "RecallEngine",
    "RecallQuery",
    "RecallCandidate",
    "RecallMode",
    "RecallScope",
    "RankingStrategy",
    "create_recall_engine",
]