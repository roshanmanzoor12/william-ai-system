"""
William / Jarvis Multi-Agent AI SaaS System
Visual Agent - Visual Memory

File:
    agents/visual_agent/visual_memory.py

Purpose:
    Stores repeated screen patterns, app layouts, error screens, and UI positions
    in a safe, user/workspace-isolated, import-safe memory helper.

Architecture:
    - Belongs to Visual Agent module.
    - Compatible with Master Agent routing.
    - Compatible with BaseAgent, Agent Registry, Agent Loader, and Agent Router.
    - Compatible with Memory Agent payloads.
    - Can prepare Verification Agent payloads after memory writes/matches.
    - Does not perform browser, system, financial, messaging, call, or destructive
      actions.
    - Uses local in-memory storage by default so the file is safe to import and test.
    - Can optionally be connected later to database/cache/vector storage by passing
      storage_adapter or memory_client.

Core Responsibilities:
    - Store repeated screen patterns.
    - Store app layout fingerprints.
    - Store known error screens.
    - Store UI element positions.
    - Match current visual snapshots against known visual memory.
    - Return structured dict/JSON style results.
    - Preserve strict SaaS isolation using user_id and workspace_id.
"""

from __future__ import annotations

import copy
import datetime as _dt
import hashlib
import json
import logging
import math
import re
import threading
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# =============================================================================
# Safe optional imports / fallback stubs
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps the file import-safe even if the full William/Jarvis framework
        is not present yet.
        """

        agent_name: str = "base_agent"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.logger = logging.getLogger(self.__class__.__name__)

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback emit_event: %s %s", event_name, payload)

        def log_audit(self, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback log_audit: %s", payload)


try:
    from agents.visual_agent.config import VISUAL_AGENT_CONFIG  # type: ignore
except Exception:  # pragma: no cover
    VISUAL_AGENT_CONFIG: Dict[str, Any] = {
        "visual_memory": {
            "default_similarity_threshold": 0.72,
            "strict_similarity_threshold": 0.88,
            "max_records_per_workspace": 10000,
            "max_elements_per_snapshot": 3000,
            "max_match_results": 20,
            "audit_enabled": True,
            "memory_payload_enabled": True,
            "case_sensitive_default": False,
            "store_raw_snapshot": False,
        }
    }


# =============================================================================
# Logging
# =============================================================================

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# =============================================================================
# Enums
# =============================================================================

class VisualMemoryType(str, Enum):
    """Supported visual memory record types."""

    SCREEN_PATTERN = "screen_pattern"
    APP_LAYOUT = "app_layout"
    ERROR_SCREEN = "error_screen"
    UI_POSITION = "ui_position"


class VisualMemoryStatus(str, Enum):
    """Record lifecycle status."""

    ACTIVE = "active"
    ARCHIVED = "archived"
    DISABLED = "disabled"


class VisualMatchStrength(str, Enum):
    """Human-friendly match strength labels."""

    EXACT = "exact"
    STRONG = "strong"
    PARTIAL = "partial"
    WEAK = "weak"
    NONE = "none"


# =============================================================================
# Dataclasses
# =============================================================================

@dataclass
class VisualTaskContext:
    """
    Required SaaS execution context.

    Every user-specific visual memory operation must include user_id and
    workspace_id so records never mix between users or workspaces.
    """

    user_id: str
    workspace_id: str
    task_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_name: str = "visual_agent"
    source_agent: Optional[str] = None
    session_id: Optional[str] = None
    permissions: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VisualElementPosition:
    """Normalized UI element position inside a visual snapshot."""

    element_id: Optional[str] = None
    element_type: Optional[str] = None
    role: Optional[str] = None
    text: Optional[str] = None
    selector: Optional[str] = None
    x: Optional[float] = None
    y: Optional[float] = None
    width: Optional[float] = None
    height: Optional[float] = None
    center_x: Optional[float] = None
    center_y: Optional[float] = None
    confidence: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VisualMemoryRecord:
    """
    Stored visual memory record.

    One record may represent:
        - repeated screen pattern
        - app layout
        - error screen
        - UI position map
    """

    memory_id: str
    user_id: str
    workspace_id: str
    memory_type: str
    title: str
    app_name: Optional[str] = None
    screen_name: Optional[str] = None
    url: Optional[str] = None
    route: Optional[str] = None
    fingerprint: str = ""
    text_fingerprint: str = ""
    layout_fingerprint: str = ""
    element_fingerprint: str = ""
    normalized_text: str = ""
    elements: List[Dict[str, Any]] = field(default_factory=list)
    positions: List[Dict[str, Any]] = field(default_factory=list)
    error_signature: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    occurrence_count: int = 1
    confidence: float = 1.0
    status: str = VisualMemoryStatus.ACTIVE.value
    raw_snapshot: Optional[Dict[str, Any]] = None
    created_at: str = field(default_factory=lambda: _utc_now_iso())
    updated_at: str = field(default_factory=lambda: _utc_now_iso())
    last_seen_at: str = field(default_factory=lambda: _utc_now_iso())
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VisualMemoryMatch:
    """Match result between an input snapshot and a stored visual memory."""

    memory_id: str
    memory_type: str
    title: str
    app_name: Optional[str]
    screen_name: Optional[str]
    similarity: float
    match_strength: str
    matched_by: List[str] = field(default_factory=list)
    occurrence_count: int = 0
    last_seen_at: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VisualSnapshotFeatures:
    """Normalized features extracted from visual/screen snapshot."""

    app_name: Optional[str] = None
    screen_name: Optional[str] = None
    url: Optional[str] = None
    route: Optional[str] = None
    normalized_text: str = ""
    text_tokens: List[str] = field(default_factory=list)
    elements: List[Dict[str, Any]] = field(default_factory=list)
    positions: List[Dict[str, Any]] = field(default_factory=list)
    fingerprint: str = ""
    text_fingerprint: str = ""
    layout_fingerprint: str = ""
    element_fingerprint: str = ""
    error_signature: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# Utility functions
# =============================================================================

def _utc_now_iso() -> str:
    """Return current UTC time as ISO string."""

    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def _safe_json_dumps(value: Any) -> str:
    """Dump JSON safely with stable key order."""

    try:
        return json.dumps(value, sort_keys=True, default=str, ensure_ascii=False)
    except Exception:
        return json.dumps(str(value), sort_keys=True)


def _sha256_text(value: str) -> str:
    """Return sha256 hash of text."""

    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()


def _normalize_space(value: Any) -> str:
    """Normalize whitespace."""

    if value is None:
        return ""
    return re.sub(r"\s+", " ", str(value)).strip()


def _normalize_text(value: Any, *, case_sensitive: bool = False) -> str:
    """Normalize text for comparison."""

    text = _normalize_space(value)
    if not case_sensitive:
        text = text.lower()
    return text


def _tokenize(value: Any, *, case_sensitive: bool = False) -> List[str]:
    """Tokenize text into stable lowercase tokens."""

    text = _normalize_text(value, case_sensitive=case_sensitive)
    return re.findall(r"[a-zA-Z0-9_@.#:/-]+", text)


def _safe_float(value: Any) -> Optional[float]:
    """Convert value to float safely."""

    if value is None:
        return None
    if isinstance(value, bool):
        return float(value)
    try:
        if isinstance(value, str):
            cleaned = value.strip().replace("%", "")
            if not cleaned:
                return None
            return float(cleaned)
        return float(value)
    except Exception:
        return None


def _safe_int(value: Any, default: int = 0) -> int:
    """Convert value to int safely."""

    try:
        return int(value)
    except Exception:
        return default


def _listify(value: Any) -> List[Any]:
    """Normalize any value into a list."""

    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _compact_dict(data: Mapping[str, Any]) -> Dict[str, Any]:
    """Remove None values from top-level dict."""

    return {k: v for k, v in dict(data).items() if v is not None}


def _jaccard_similarity(a: Iterable[str], b: Iterable[str]) -> float:
    """Calculate Jaccard similarity between two iterables."""

    set_a = set(a)
    set_b = set(b)

    if not set_a and not set_b:
        return 1.0

    if not set_a or not set_b:
        return 0.0

    return len(set_a.intersection(set_b)) / max(len(set_a.union(set_b)), 1)


def _cosine_similarity_counts(a: Iterable[str], b: Iterable[str]) -> float:
    """Simple cosine similarity using token counts."""

    counts_a: Dict[str, int] = {}
    counts_b: Dict[str, int] = {}

    for token in a:
        counts_a[token] = counts_a.get(token, 0) + 1

    for token in b:
        counts_b[token] = counts_b.get(token, 0) + 1

    if not counts_a and not counts_b:
        return 1.0

    if not counts_a or not counts_b:
        return 0.0

    all_tokens = set(counts_a).union(counts_b)
    dot = sum(counts_a.get(token, 0) * counts_b.get(token, 0) for token in all_tokens)
    norm_a = math.sqrt(sum(value * value for value in counts_a.values()))
    norm_b = math.sqrt(sum(value * value for value in counts_b.values()))

    if norm_a <= 0 or norm_b <= 0:
        return 0.0

    return dot / (norm_a * norm_b)


def _clamp(value: float, minimum: float = 0.0, maximum: float = 1.0) -> float:
    """Clamp float value."""

    return max(minimum, min(maximum, value))


def _stable_bucket(value: Optional[float], size: float = 25.0) -> Optional[int]:
    """Convert coordinate into stable layout bucket."""

    if value is None:
        return None
    try:
        return int(round(float(value) / size))
    except Exception:
        return None


def _extract_first(mapping: Mapping[str, Any], keys: Sequence[str], default: Any = None) -> Any:
    """Extract first existing key from mapping."""

    for key in keys:
        if key in mapping:
            return mapping.get(key)
    return default


# =============================================================================
# In-memory storage adapter
# =============================================================================

class InMemoryVisualMemoryStore:
    """
    Thread-safe in-memory storage adapter.

    This default store is useful for local tests, development, and import safety.
    Production can replace it with DB/cache/vector adapters later.
    """

    def __init__(self) -> None:
        self._records: Dict[Tuple[str, str, str], VisualMemoryRecord] = {}
        self._lock = threading.RLock()

    def upsert(self, record: VisualMemoryRecord) -> VisualMemoryRecord:
        """Insert or update a visual memory record."""

        key = (record.user_id, record.workspace_id, record.memory_id)
        with self._lock:
            self._records[key] = copy.deepcopy(record)
            return copy.deepcopy(record)

    def get(self, user_id: str, workspace_id: str, memory_id: str) -> Optional[VisualMemoryRecord]:
        """Get a record by isolated key."""

        key = (user_id, workspace_id, memory_id)
        with self._lock:
            record = self._records.get(key)
            return copy.deepcopy(record) if record else None

    def delete(self, user_id: str, workspace_id: str, memory_id: str) -> bool:
        """Delete a record by isolated key."""

        key = (user_id, workspace_id, memory_id)
        with self._lock:
            if key in self._records:
                del self._records[key]
                return True
            return False

    def list_records(
        self,
        *,
        user_id: str,
        workspace_id: str,
        memory_type: Optional[str] = None,
        status: Optional[str] = VisualMemoryStatus.ACTIVE.value,
        app_name: Optional[str] = None,
        screen_name: Optional[str] = None,
        tags: Optional[Sequence[str]] = None,
        limit: int = 100,
    ) -> List[VisualMemoryRecord]:
        """List records inside one user/workspace scope."""

        tag_set = set(tags or [])

        with self._lock:
            scoped = [
                copy.deepcopy(record)
                for (record_user_id, record_workspace_id, _), record in self._records.items()
                if record_user_id == user_id and record_workspace_id == workspace_id
            ]

        filtered: List[VisualMemoryRecord] = []

        for record in scoped:
            if memory_type and record.memory_type != memory_type:
                continue
            if status and record.status != status:
                continue
            if app_name and (record.app_name or "").lower() != app_name.lower():
                continue
            if screen_name and (record.screen_name or "").lower() != screen_name.lower():
                continue
            if tag_set and not tag_set.issubset(set(record.tags)):
                continue

            filtered.append(record)

        filtered.sort(key=lambda item: item.updated_at, reverse=True)
        return filtered[: max(1, limit)]

    def count_workspace_records(self, user_id: str, workspace_id: str) -> int:
        """Count records inside one workspace."""

        with self._lock:
            return sum(
                1
                for record_user_id, record_workspace_id, _ in self._records.keys()
                if record_user_id == user_id and record_workspace_id == workspace_id
            )


# =============================================================================
# Main class
# =============================================================================

class VisualMemory(BaseAgent):
    """
    Stores and matches visual memory for screens, layouts, errors, and UI positions.

    Master Agent:
        Can route tasks here for "remember this screen", "match current layout",
        "store error screen", or "find known button position".

    Security Agent:
        This class is read/write to local memory only. It does not perform external
        actions. Permission hooks exist for future policy and sensitive memory rules.

    Memory Agent:
        This class prepares memory-compatible payloads and can optionally use an
        injected memory_client for future long-term storage.

    Verification Agent:
        Every store/match operation can prepare a verification payload proving what
        was stored or matched.

    Dashboard/API:
        Public methods return consistent JSON-style dicts with success, message,
        data, error, and metadata.

    Registry/Loader:
        Import-safe and exposes stable class name VisualMemory.
    """

    agent_name = "visual_memory"
    agent_module = "visual_agent"
    version = "1.0.0"

    def __init__(
        self,
        config: Optional[Mapping[str, Any]] = None,
        storage_adapter: Optional[Any] = None,
        event_emitter: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], None]] = None,
        security_client: Optional[Any] = None,
        memory_client: Optional[Any] = None,
    ) -> None:
        super().__init__()

        config_root = copy.deepcopy(VISUAL_AGENT_CONFIG or {})
        visual_memory_config = dict(config_root.get("visual_memory", {}))

        if config:
            visual_memory_config.update(dict(config))

        self.config: Dict[str, Any] = visual_memory_config
        self.storage = storage_adapter or InMemoryVisualMemoryStore()
        self.event_emitter = event_emitter
        self.audit_logger = audit_logger
        self.security_client = security_client
        self.memory_client = memory_client

        self.default_similarity_threshold = float(
            self.config.get("default_similarity_threshold", 0.72)
        )
        self.strict_similarity_threshold = float(
            self.config.get("strict_similarity_threshold", 0.88)
        )
        self.max_records_per_workspace = int(
            self.config.get("max_records_per_workspace", 10000)
        )
        self.max_elements_per_snapshot = int(
            self.config.get("max_elements_per_snapshot", 3000)
        )
        self.max_match_results = int(self.config.get("max_match_results", 20))
        self.audit_enabled = bool(self.config.get("audit_enabled", True))
        self.memory_payload_enabled = bool(
            self.config.get("memory_payload_enabled", True)
        )
        self.case_sensitive_default = bool(
            self.config.get("case_sensitive_default", False)
        )
        self.store_raw_snapshot = bool(self.config.get("store_raw_snapshot", False))

        self.logger = logging.getLogger(f"{self.agent_module}.{self.agent_name}")

    # =========================================================================
    # Public store methods
    # =========================================================================

    def store_screen_pattern(
        self,
        *,
        user_id: str,
        workspace_id: str,
        snapshot: Mapping[str, Any],
        title: Optional[str] = None,
        app_name: Optional[str] = None,
        screen_name: Optional[str] = None,
        tags: Optional[Sequence[str]] = None,
        task_id: Optional[str] = None,
        request_id: Optional[str] = None,
        source_agent: Optional[str] = None,
        session_id: Optional[str] = None,
        permissions: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Store a repeated visual screen pattern."""

        return self._store_visual_memory(
            user_id=user_id,
            workspace_id=workspace_id,
            snapshot=snapshot,
            memory_type=VisualMemoryType.SCREEN_PATTERN.value,
            title=title,
            app_name=app_name,
            screen_name=screen_name,
            tags=tags,
            task_id=task_id,
            request_id=request_id,
            source_agent=source_agent,
            session_id=session_id,
            permissions=permissions,
            metadata=metadata,
        )

    def store_app_layout(
        self,
        *,
        user_id: str,
        workspace_id: str,
        snapshot: Mapping[str, Any],
        title: Optional[str] = None,
        app_name: Optional[str] = None,
        screen_name: Optional[str] = None,
        tags: Optional[Sequence[str]] = None,
        task_id: Optional[str] = None,
        request_id: Optional[str] = None,
        source_agent: Optional[str] = None,
        session_id: Optional[str] = None,
        permissions: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Store an app layout memory."""

        return self._store_visual_memory(
            user_id=user_id,
            workspace_id=workspace_id,
            snapshot=snapshot,
            memory_type=VisualMemoryType.APP_LAYOUT.value,
            title=title,
            app_name=app_name,
            screen_name=screen_name,
            tags=tags,
            task_id=task_id,
            request_id=request_id,
            source_agent=source_agent,
            session_id=session_id,
            permissions=permissions,
            metadata=metadata,
        )

    def store_error_screen(
        self,
        *,
        user_id: str,
        workspace_id: str,
        snapshot: Mapping[str, Any],
        title: Optional[str] = None,
        app_name: Optional[str] = None,
        screen_name: Optional[str] = None,
        error_signature: Optional[str] = None,
        tags: Optional[Sequence[str]] = None,
        task_id: Optional[str] = None,
        request_id: Optional[str] = None,
        source_agent: Optional[str] = None,
        session_id: Optional[str] = None,
        permissions: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Store a known error screen memory."""

        merged_metadata = dict(metadata or {})
        if error_signature:
            merged_metadata["provided_error_signature"] = error_signature

        result = self._store_visual_memory(
            user_id=user_id,
            workspace_id=workspace_id,
            snapshot=snapshot,
            memory_type=VisualMemoryType.ERROR_SCREEN.value,
            title=title,
            app_name=app_name,
            screen_name=screen_name,
            tags=list(tags or []) + ["error_screen"],
            task_id=task_id,
            request_id=request_id,
            source_agent=source_agent,
            session_id=session_id,
            permissions=permissions,
            metadata=merged_metadata,
        )

        if result.get("success") and error_signature:
            record_data = result.get("data", {}).get("record", {})
            memory_id = record_data.get("memory_id")
            if memory_id:
                record = self.storage.get(user_id, workspace_id, memory_id)
                if record:
                    record.error_signature = error_signature
                    record.updated_at = _utc_now_iso()
                    self.storage.upsert(record)
                    result["data"]["record"]["error_signature"] = error_signature

        return result

    def store_ui_positions(
        self,
        *,
        user_id: str,
        workspace_id: str,
        snapshot: Mapping[str, Any],
        title: Optional[str] = None,
        app_name: Optional[str] = None,
        screen_name: Optional[str] = None,
        tags: Optional[Sequence[str]] = None,
        task_id: Optional[str] = None,
        request_id: Optional[str] = None,
        source_agent: Optional[str] = None,
        session_id: Optional[str] = None,
        permissions: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Store stable UI element positions from a visual snapshot."""

        return self._store_visual_memory(
            user_id=user_id,
            workspace_id=workspace_id,
            snapshot=snapshot,
            memory_type=VisualMemoryType.UI_POSITION.value,
            title=title,
            app_name=app_name,
            screen_name=screen_name,
            tags=list(tags or []) + ["ui_positions"],
            task_id=task_id,
            request_id=request_id,
            source_agent=source_agent,
            session_id=session_id,
            permissions=permissions,
            metadata=metadata,
        )

    # =========================================================================
    # Public match / retrieve methods
    # =========================================================================

    def match_visual_memory(
        self,
        *,
        user_id: str,
        workspace_id: str,
        snapshot: Mapping[str, Any],
        memory_type: Optional[str] = None,
        app_name: Optional[str] = None,
        screen_name: Optional[str] = None,
        tags: Optional[Sequence[str]] = None,
        threshold: Optional[float] = None,
        strict: bool = False,
        limit: Optional[int] = None,
        task_id: Optional[str] = None,
        request_id: Optional[str] = None,
        source_agent: Optional[str] = None,
        session_id: Optional[str] = None,
        permissions: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Match current visual snapshot against stored visual memory records.

        Returns top matches with similarity scores and evidence.
        """

        context = VisualTaskContext(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id or str(uuid.uuid4()),
            request_id=request_id or str(uuid.uuid4()),
            source_agent=source_agent,
            session_id=session_id,
            permissions=dict(permissions or {}),
            metadata=dict(metadata or {}),
        )

        valid_context = self._validate_task_context(context)
        if not valid_context["success"]:
            return valid_context

        security_result = self._request_security_approval(
            context=context,
            action="visual_memory_match",
            payload={
                "memory_type": memory_type,
                "app_name": app_name,
                "screen_name": screen_name,
            },
        )
        if not security_result["success"]:
            return security_result

        try:
            started_at = _utc_now_iso()
            features = self._extract_snapshot_features(
                snapshot=snapshot,
                app_name=app_name,
                screen_name=screen_name,
                metadata=metadata,
            )

            match_threshold = float(
                threshold
                if threshold is not None
                else (
                    self.strict_similarity_threshold
                    if strict
                    else self.default_similarity_threshold
                )
            )

            records = self.storage.list_records(
                user_id=user_id,
                workspace_id=workspace_id,
                memory_type=memory_type,
                status=VisualMemoryStatus.ACTIVE.value,
                app_name=app_name,
                screen_name=screen_name,
                tags=tags,
                limit=self.max_records_per_workspace,
            )

            matches: List[VisualMemoryMatch] = []

            for record in records:
                match = self._score_record_match(record, features)
                if match.similarity >= match_threshold:
                    matches.append(match)

            matches.sort(key=lambda item: item.similarity, reverse=True)
            selected_matches = matches[: max(1, limit or self.max_match_results)]

            passed = len(selected_matches) > 0
            message = (
                f"Matched {len(selected_matches)} visual memory record(s)."
                if passed
                else "No visual memory records matched the supplied snapshot."
            )

            verification_payload = self._prepare_verification_payload(
                context=context,
                operation="match_visual_memory",
                success=passed,
                message=message,
                data={
                    "threshold": match_threshold,
                    "match_count": len(selected_matches),
                    "memory_type": memory_type,
                    "features": self._features_summary(features),
                    "matches": [asdict(match) for match in selected_matches],
                },
                started_at=started_at,
            )

            result = self._safe_result(
                success=passed,
                message=message,
                data={
                    "matched": passed,
                    "threshold": match_threshold,
                    "match_count": len(selected_matches),
                    "scanned_record_count": len(records),
                    "features": self._features_summary(features),
                    "matches": [asdict(match) for match in selected_matches],
                    "verification_payload": verification_payload,
                    "memory_payload": self._prepare_memory_payload(
                        context=context,
                        memory_action="match",
                        payload=verification_payload,
                    ),
                },
                metadata={
                    "agent": self.agent_name,
                    "module": self.agent_module,
                    "version": self.version,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "task_id": context.task_id,
                    "request_id": context.request_id,
                    "completed_at": _utc_now_iso(),
                },
            )

            self._emit_agent_event(
                "visual_memory.matched",
                {
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "task_id": context.task_id,
                    "memory_type": memory_type,
                    "match_count": len(selected_matches),
                    "threshold": match_threshold,
                },
            )

            self._log_audit_event(
                {
                    "event": "visual_memory_match",
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "task_id": context.task_id,
                    "request_id": context.request_id,
                    "memory_type": memory_type,
                    "match_count": len(selected_matches),
                    "threshold": match_threshold,
                    "timestamp": _utc_now_iso(),
                }
            )

            return result

        except Exception as exc:
            self.logger.exception("Visual memory match failed")
            return self._error_result(
                message="Visual memory match failed.",
                error=exc,
                metadata={
                    "agent": self.agent_name,
                    "module": self.agent_module,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "task_id": context.task_id,
                    "request_id": context.request_id,
                },
            )

    def find_ui_position(
        self,
        *,
        user_id: str,
        workspace_id: str,
        element_text: Optional[str] = None,
        element_type: Optional[str] = None,
        selector: Optional[str] = None,
        app_name: Optional[str] = None,
        screen_name: Optional[str] = None,
        limit: int = 10,
        task_id: Optional[str] = None,
        request_id: Optional[str] = None,
        source_agent: Optional[str] = None,
        session_id: Optional[str] = None,
        permissions: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Find remembered UI element positions."""

        context = VisualTaskContext(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id or str(uuid.uuid4()),
            request_id=request_id or str(uuid.uuid4()),
            source_agent=source_agent,
            session_id=session_id,
            permissions=dict(permissions or {}),
            metadata=dict(metadata or {}),
        )

        valid_context = self._validate_task_context(context)
        if not valid_context["success"]:
            return valid_context

        try:
            records = self.storage.list_records(
                user_id=user_id,
                workspace_id=workspace_id,
                memory_type=VisualMemoryType.UI_POSITION.value,
                status=VisualMemoryStatus.ACTIVE.value,
                app_name=app_name,
                screen_name=screen_name,
                limit=self.max_records_per_workspace,
            )

            query_tokens = set(_tokenize(" ".join([element_text or "", element_type or "", selector or ""])))
            results: List[Dict[str, Any]] = []

            for record in records:
                for position in record.positions:
                    score = self._score_position_match(
                        position=position,
                        element_text=element_text,
                        element_type=element_type,
                        selector=selector,
                        query_tokens=query_tokens,
                    )

                    if score <= 0:
                        continue

                    results.append(
                        {
                            "memory_id": record.memory_id,
                            "title": record.title,
                            "app_name": record.app_name,
                            "screen_name": record.screen_name,
                            "position": position,
                            "score": round(score, 4),
                            "last_seen_at": record.last_seen_at,
                            "occurrence_count": record.occurrence_count,
                        }
                    )

            results.sort(key=lambda item: item["score"], reverse=True)
            selected = results[: max(1, limit)]

            return self._safe_result(
                success=bool(selected),
                message=(
                    f"Found {len(selected)} remembered UI position(s)."
                    if selected
                    else "No remembered UI positions matched the query."
                ),
                data={
                    "positions": selected,
                    "query": {
                        "element_text": element_text,
                        "element_type": element_type,
                        "selector": selector,
                        "app_name": app_name,
                        "screen_name": screen_name,
                    },
                },
                metadata={
                    "agent": self.agent_name,
                    "module": self.agent_module,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "task_id": context.task_id,
                    "request_id": context.request_id,
                    "completed_at": _utc_now_iso(),
                },
            )

        except Exception as exc:
            self.logger.exception("Find UI position failed")
            return self._error_result(
                message="Find UI position failed.",
                error=exc,
                metadata={
                    "agent": self.agent_name,
                    "module": self.agent_module,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "task_id": context.task_id,
                    "request_id": context.request_id,
                },
            )

    def get_memory(
        self,
        *,
        user_id: str,
        workspace_id: str,
        memory_id: str,
        task_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Get one visual memory record by id."""

        context = VisualTaskContext(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id or str(uuid.uuid4()),
            request_id=request_id or str(uuid.uuid4()),
        )

        valid_context = self._validate_task_context(context)
        if not valid_context["success"]:
            return valid_context

        record = self.storage.get(user_id, workspace_id, memory_id)

        if not record:
            return self._error_result(
                message="Visual memory record not found.",
                error="visual_memory_not_found",
                metadata={
                    "agent": self.agent_name,
                    "module": self.agent_module,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "memory_id": memory_id,
                },
            )

        return self._safe_result(
            success=True,
            message="Visual memory record found.",
            data={"record": asdict(record)},
            metadata={
                "agent": self.agent_name,
                "module": self.agent_module,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "memory_id": memory_id,
            },
        )

    def list_memories(
        self,
        *,
        user_id: str,
        workspace_id: str,
        memory_type: Optional[str] = None,
        app_name: Optional[str] = None,
        screen_name: Optional[str] = None,
        tags: Optional[Sequence[str]] = None,
        status: Optional[str] = VisualMemoryStatus.ACTIVE.value,
        limit: int = 100,
        task_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """List visual memory records in one user/workspace scope."""

        context = VisualTaskContext(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id or str(uuid.uuid4()),
            request_id=request_id or str(uuid.uuid4()),
        )

        valid_context = self._validate_task_context(context)
        if not valid_context["success"]:
            return valid_context

        records = self.storage.list_records(
            user_id=user_id,
            workspace_id=workspace_id,
            memory_type=memory_type,
            status=status,
            app_name=app_name,
            screen_name=screen_name,
            tags=tags,
            limit=limit,
        )

        return self._safe_result(
            success=True,
            message=f"Returned {len(records)} visual memory record(s).",
            data={
                "records": [asdict(record) for record in records],
                "count": len(records),
            },
            metadata={
                "agent": self.agent_name,
                "module": self.agent_module,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "task_id": context.task_id,
                "request_id": context.request_id,
            },
        )

    def archive_memory(
        self,
        *,
        user_id: str,
        workspace_id: str,
        memory_id: str,
        task_id: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Archive a visual memory record without deleting it."""

        context = VisualTaskContext(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id or str(uuid.uuid4()),
            request_id=request_id or str(uuid.uuid4()),
            metadata=dict(metadata or {}),
        )

        valid_context = self._validate_task_context(context)
        if not valid_context["success"]:
            return valid_context

        security_result = self._request_security_approval(
            context=context,
            action="visual_memory_archive",
            payload={"memory_id": memory_id},
        )
        if not security_result["success"]:
            return security_result

        record = self.storage.get(user_id, workspace_id, memory_id)

        if not record:
            return self._error_result(
                message="Visual memory record not found.",
                error="visual_memory_not_found",
                metadata={
                    "agent": self.agent_name,
                    "module": self.agent_module,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "memory_id": memory_id,
                },
            )

        record.status = VisualMemoryStatus.ARCHIVED.value
        record.updated_at = _utc_now_iso()
        self.storage.upsert(record)

        self._log_audit_event(
            {
                "event": "visual_memory_archived",
                "user_id": user_id,
                "workspace_id": workspace_id,
                "memory_id": memory_id,
                "task_id": context.task_id,
                "request_id": context.request_id,
                "timestamp": _utc_now_iso(),
            }
        )

        return self._safe_result(
            success=True,
            message="Visual memory record archived.",
            data={"record": asdict(record)},
            metadata={
                "agent": self.agent_name,
                "module": self.agent_module,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "memory_id": memory_id,
            },
        )

    # =========================================================================
    # Internal store implementation
    # =========================================================================

    def _store_visual_memory(
        self,
        *,
        user_id: str,
        workspace_id: str,
        snapshot: Mapping[str, Any],
        memory_type: str,
        title: Optional[str],
        app_name: Optional[str],
        screen_name: Optional[str],
        tags: Optional[Sequence[str]],
        task_id: Optional[str],
        request_id: Optional[str],
        source_agent: Optional[str],
        session_id: Optional[str],
        permissions: Optional[Mapping[str, Any]],
        metadata: Optional[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """Core visual memory store method used by public wrappers."""

        context = VisualTaskContext(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id or str(uuid.uuid4()),
            request_id=request_id or str(uuid.uuid4()),
            source_agent=source_agent,
            session_id=session_id,
            permissions=dict(permissions or {}),
            metadata=dict(metadata or {}),
        )

        valid_context = self._validate_task_context(context)
        if not valid_context["success"]:
            return valid_context

        security_result = self._request_security_approval(
            context=context,
            action="visual_memory_store",
            payload={"memory_type": memory_type, "title": title},
        )
        if not security_result["success"]:
            return security_result

        try:
            started_at = _utc_now_iso()

            workspace_count = self.storage.count_workspace_records(user_id, workspace_id)
            if workspace_count >= self.max_records_per_workspace:
                return self._error_result(
                    message="Visual memory workspace record limit reached.",
                    error="visual_memory_limit_reached",
                    metadata={
                        "agent": self.agent_name,
                        "module": self.agent_module,
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                        "limit": self.max_records_per_workspace,
                    },
                )

            features = self._extract_snapshot_features(
                snapshot=snapshot,
                app_name=app_name,
                screen_name=screen_name,
                metadata=metadata,
            )

            resolved_app_name = app_name or features.app_name
            resolved_screen_name = screen_name or features.screen_name
            resolved_title = title or self._build_title(
                memory_type=memory_type,
                app_name=resolved_app_name,
                screen_name=resolved_screen_name,
                features=features,
            )

            existing = self._find_existing_record(
                user_id=user_id,
                workspace_id=workspace_id,
                memory_type=memory_type,
                features=features,
                app_name=resolved_app_name,
                screen_name=resolved_screen_name,
            )

            if existing:
                record = self._merge_existing_record(
                    existing=existing,
                    features=features,
                    title=resolved_title,
                    tags=tags,
                    metadata=metadata,
                    snapshot=snapshot,
                )
                created_new = False
            else:
                record = VisualMemoryRecord(
                    memory_id=str(uuid.uuid4()),
                    user_id=user_id,
                    workspace_id=workspace_id,
                    memory_type=memory_type,
                    title=resolved_title,
                    app_name=resolved_app_name,
                    screen_name=resolved_screen_name,
                    url=features.url,
                    route=features.route,
                    fingerprint=features.fingerprint,
                    text_fingerprint=features.text_fingerprint,
                    layout_fingerprint=features.layout_fingerprint,
                    element_fingerprint=features.element_fingerprint,
                    normalized_text=features.normalized_text,
                    elements=features.elements,
                    positions=features.positions,
                    error_signature=features.error_signature,
                    tags=self._normalize_tags(tags),
                    occurrence_count=1,
                    confidence=1.0,
                    status=VisualMemoryStatus.ACTIVE.value,
                    raw_snapshot=copy.deepcopy(dict(snapshot)) if self.store_raw_snapshot else None,
                    created_at=_utc_now_iso(),
                    updated_at=_utc_now_iso(),
                    last_seen_at=_utc_now_iso(),
                    metadata={
                        **dict(metadata or {}),
                        "features": self._features_summary(features),
                    },
                )
                created_new = True

            stored = self.storage.upsert(record)

            verification_payload = self._prepare_verification_payload(
                context=context,
                operation="store_visual_memory",
                success=True,
                message=(
                    "Created new visual memory record."
                    if created_new
                    else "Updated existing visual memory record occurrence."
                ),
                data={
                    "created_new": created_new,
                    "memory_type": memory_type,
                    "memory_id": stored.memory_id,
                    "features": self._features_summary(features),
                },
                started_at=started_at,
            )

            memory_payload = self._prepare_memory_payload(
                context=context,
                memory_action="store",
                payload={
                    "record": asdict(stored),
                    "verification_payload": verification_payload,
                },
            )

            result = self._safe_result(
                success=True,
                message=(
                    "Created new visual memory record."
                    if created_new
                    else "Updated existing visual memory record occurrence."
                ),
                data={
                    "created_new": created_new,
                    "record": asdict(stored),
                    "features": self._features_summary(features),
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                metadata={
                    "agent": self.agent_name,
                    "module": self.agent_module,
                    "version": self.version,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "task_id": context.task_id,
                    "request_id": context.request_id,
                    "completed_at": _utc_now_iso(),
                },
            )

            self._emit_agent_event(
                "visual_memory.stored",
                {
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "task_id": context.task_id,
                    "memory_id": stored.memory_id,
                    "memory_type": memory_type,
                    "created_new": created_new,
                },
            )

            self._log_audit_event(
                {
                    "event": "visual_memory_store",
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "task_id": context.task_id,
                    "request_id": context.request_id,
                    "memory_id": stored.memory_id,
                    "memory_type": memory_type,
                    "created_new": created_new,
                    "timestamp": _utc_now_iso(),
                }
            )

            return result

        except Exception as exc:
            self.logger.exception("Visual memory store failed")
            return self._error_result(
                message="Visual memory store failed.",
                error=exc,
                metadata={
                    "agent": self.agent_name,
                    "module": self.agent_module,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "task_id": context.task_id,
                    "request_id": context.request_id,
                },
            )

    # =========================================================================
    # Feature extraction
    # =========================================================================

    def _extract_snapshot_features(
        self,
        *,
        snapshot: Mapping[str, Any],
        app_name: Optional[str] = None,
        screen_name: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> VisualSnapshotFeatures:
        """Extract normalized visual features from flexible snapshot data."""

        if not isinstance(snapshot, Mapping):
            snapshot = {}

        resolved_app_name = (
            app_name
            or snapshot.get("app_name")
            or snapshot.get("application")
            or snapshot.get("app")
            or snapshot.get("package_name")
        )

        resolved_screen_name = (
            screen_name
            or snapshot.get("screen_name")
            or snapshot.get("page_name")
            or snapshot.get("title")
            or snapshot.get("route_name")
        )

        url = snapshot.get("url") or snapshot.get("current_url") or snapshot.get("page_url")
        route = snapshot.get("route") or snapshot.get("path") or snapshot.get("current_route")

        text = self._extract_snapshot_text(snapshot)
        tokens = _tokenize(text, case_sensitive=self.case_sensitive_default)
        elements = self._extract_elements(snapshot)
        positions = self._extract_positions(elements)

        text_fingerprint = self._build_text_fingerprint(tokens)
        layout_fingerprint = self._build_layout_fingerprint(elements)
        element_fingerprint = self._build_element_fingerprint(elements)

        fingerprint_payload = {
            "app_name": _normalize_text(resolved_app_name),
            "screen_name": _normalize_text(resolved_screen_name),
            "url": _normalize_text(url),
            "route": _normalize_text(route),
            "text_fingerprint": text_fingerprint,
            "layout_fingerprint": layout_fingerprint,
            "element_fingerprint": element_fingerprint,
        }

        fingerprint = _sha256_text(_safe_json_dumps(fingerprint_payload))
        error_signature = self._infer_error_signature(text=text, elements=elements, snapshot=snapshot)

        return VisualSnapshotFeatures(
            app_name=str(resolved_app_name) if resolved_app_name else None,
            screen_name=str(resolved_screen_name) if resolved_screen_name else None,
            url=str(url) if url else None,
            route=str(route) if route else None,
            normalized_text=_normalize_text(text, case_sensitive=self.case_sensitive_default),
            text_tokens=tokens,
            elements=elements,
            positions=positions,
            fingerprint=fingerprint,
            text_fingerprint=text_fingerprint,
            layout_fingerprint=layout_fingerprint,
            element_fingerprint=element_fingerprint,
            error_signature=error_signature,
            metadata=dict(metadata or {}),
        )

    def _extract_snapshot_text(self, snapshot: Mapping[str, Any]) -> str:
        """Extract visible/OCR/accessibility text from snapshot."""

        parts: List[str] = []

        direct_text_keys = (
            "text",
            "ocr_text",
            "visible_text",
            "screen_text",
            "page_text",
            "title",
            "heading",
            "message",
            "error_message",
            "description",
        )

        for key in direct_text_keys:
            value = snapshot.get(key)
            if value and not isinstance(value, (dict, list, tuple)):
                parts.append(_normalize_space(value))

        for nested_key in (
            "ocr",
            "screenshot_analysis",
            "screen_context",
            "browser_state",
            "app_state",
            "visual_analysis",
            "data",
            "result",
        ):
            nested = snapshot.get(nested_key)
            if isinstance(nested, Mapping):
                for key in direct_text_keys:
                    value = nested.get(key)
                    if value and not isinstance(value, (dict, list, tuple)):
                        parts.append(_normalize_space(value))

        elements = self._extract_raw_element_collections(snapshot)
        for element in elements:
            if isinstance(element, Mapping):
                for key in (
                    "text",
                    "label",
                    "name",
                    "title",
                    "aria_label",
                    "aria-label",
                    "placeholder",
                    "value",
                    "message",
                    "content",
                    "inner_text",
                    "innerText",
                    "accessible_name",
                ):
                    value = element.get(key)
                    if value and not isinstance(value, (dict, list, tuple)):
                        parts.append(_normalize_space(value))

                attrs = element.get("attributes")
                if isinstance(attrs, Mapping):
                    for key in ("aria-label", "title", "placeholder", "value", "name"):
                        value = attrs.get(key)
                        if value and not isinstance(value, (dict, list, tuple)):
                            parts.append(_normalize_space(value))

        unique: List[str] = []
        seen: set = set()

        for part in parts:
            normalized = _normalize_text(part)
            if normalized and normalized not in seen:
                seen.add(normalized)
                unique.append(part)

        return " ".join(unique)

    def _extract_raw_element_collections(self, snapshot: Mapping[str, Any]) -> List[Any]:
        """Extract raw element collections from common snapshot shapes."""

        raw: List[Any] = []

        for key in (
            "elements",
            "ui_elements",
            "nodes",
            "detected_elements",
            "visible_elements",
            "components",
            "matches",
        ):
            if key in snapshot:
                raw.extend(_listify(snapshot.get(key)))

        for nested_key in (
            "accessibility_tree",
            "dom",
            "browser_state",
            "screenshot_analysis",
            "screen_context",
            "ui_map",
            "element_detector",
            "data",
            "result",
        ):
            nested = snapshot.get(nested_key)
            if isinstance(nested, Mapping):
                for key in (
                    "elements",
                    "ui_elements",
                    "nodes",
                    "detected_elements",
                    "visible_elements",
                    "components",
                    "matches",
                ):
                    if key in nested:
                        raw.extend(_listify(nested.get(key)))

        return raw

    def _extract_elements(self, snapshot: Mapping[str, Any]) -> List[Dict[str, Any]]:
        """Extract and normalize UI elements."""

        raw_collections = self._extract_raw_element_collections(snapshot)
        normalized: List[Dict[str, Any]] = []
        seen: set = set()

        def walk(item: Any, depth: int = 0) -> None:
            if len(normalized) >= self.max_elements_per_snapshot:
                return
            if depth > 5:
                return

            if isinstance(item, Mapping):
                element = self._normalize_element(item, raw_index=len(normalized))
                signature = self._element_signature(element)

                if signature not in seen:
                    seen.add(signature)
                    normalized.append(element)

                for child_key in ("children", "child_nodes", "nodes", "items", "options"):
                    children = item.get(child_key)
                    if isinstance(children, (list, tuple)):
                        for child in children:
                            walk(child, depth + 1)

            elif isinstance(item, (list, tuple)):
                for child in item:
                    walk(child, depth + 1)

        for item in raw_collections:
            walk(item)

        return normalized[: self.max_elements_per_snapshot]

    def _normalize_element(self, element: Mapping[str, Any], raw_index: int) -> Dict[str, Any]:
        """Normalize one UI element."""

        attrs = dict(element.get("attributes") or {})
        merged = {**attrs, **dict(element)}

        role = _extract_first(merged, ("role", "aria_role", "type"))
        tag = _extract_first(merged, ("tag", "tag_name", "nodeName"))
        text = self._extract_element_text(merged)
        selector = self._extract_selector(merged)
        bounds = self._extract_bounds(merged)

        x, y, width, height, center_x, center_y = self._bounds_to_position(bounds)

        element_id = _extract_first(
            merged,
            (
                "element_id",
                "id",
                "uid",
                "uuid",
                "node_id",
                "backend_node_id",
                "automation_id",
            ),
        )

        visible = self._infer_visible(merged, bounds)

        return {
            "element_id": str(element_id) if element_id is not None else None,
            "element_type": str(merged.get("element_type") or merged.get("type") or role or tag or "").lower() or None,
            "role": str(role).lower() if role is not None else None,
            "tag": str(tag).lower() if tag is not None else None,
            "text": text,
            "selector": selector,
            "visible": visible,
            "bounds": bounds,
            "x": x,
            "y": y,
            "width": width,
            "height": height,
            "center_x": center_x,
            "center_y": center_y,
            "confidence": float(_safe_float(merged.get("confidence")) or 0.0),
            "raw_index": raw_index,
            "metadata": {
                "name": merged.get("name"),
                "placeholder": merged.get("placeholder"),
                "class": merged.get("class") or merged.get("className"),
                "value_present": merged.get("value") is not None,
            },
        }

    def _extract_element_text(self, element: Mapping[str, Any]) -> str:
        """Extract text from one element."""

        parts: List[str] = []

        for key in (
            "text",
            "label",
            "name",
            "title",
            "aria_label",
            "aria-label",
            "placeholder",
            "value",
            "message",
            "content",
            "inner_text",
            "innerText",
            "accessible_name",
        ):
            value = element.get(key)
            if value is not None and not isinstance(value, (dict, list, tuple)):
                text = _normalize_space(value)
                if text:
                    parts.append(text)

        attrs = element.get("attributes")
        if isinstance(attrs, Mapping):
            for key in ("aria-label", "title", "placeholder", "value", "name"):
                value = attrs.get(key)
                if value is not None and not isinstance(value, (dict, list, tuple)):
                    text = _normalize_space(value)
                    if text:
                        parts.append(text)

        unique: List[str] = []
        seen: set = set()

        for part in parts:
            normalized = _normalize_text(part)
            if normalized not in seen:
                seen.add(normalized)
                unique.append(part)

        return " | ".join(unique)

    def _extract_selector(self, element: Mapping[str, Any]) -> Optional[str]:
        """Extract selector-like identifier."""

        for key in (
            "selector",
            "css",
            "css_selector",
            "xpath",
            "id",
            "data-testid",
            "data_testid",
            "test_id",
            "automation_id",
        ):
            value = element.get(key)
            if value:
                if key == "id" and not str(value).startswith("#"):
                    return f"#{value}"
                return str(value)

        attrs = element.get("attributes")
        if isinstance(attrs, Mapping):
            for key in (
                "id",
                "data-testid",
                "data_testid",
                "test_id",
                "name",
                "aria-label",
            ):
                value = attrs.get(key)
                if value:
                    if key == "id" and not str(value).startswith("#"):
                        return f"#{value}"
                    return str(value)

        return None

    def _extract_bounds(self, element: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract bounds from common shapes."""

        for key in ("bounds", "bounding_box", "bbox", "rect", "location"):
            value = element.get(key)
            if isinstance(value, Mapping):
                return dict(value)

        keys = ("x", "y", "left", "top", "right", "bottom", "width", "height")
        if any(key in element for key in keys):
            return {key: element.get(key) for key in keys if key in element}

        return None

    def _bounds_to_position(
        self,
        bounds: Optional[Mapping[str, Any]],
    ) -> Tuple[Optional[float], Optional[float], Optional[float], Optional[float], Optional[float], Optional[float]]:
        """Convert bounds into x/y/width/height/center."""

        if not bounds:
            return None, None, None, None, None, None

        x = _safe_float(bounds.get("x"))
        y = _safe_float(bounds.get("y"))

        left = _safe_float(bounds.get("left"))
        top = _safe_float(bounds.get("top"))
        right = _safe_float(bounds.get("right"))
        bottom = _safe_float(bounds.get("bottom"))

        if x is None:
            x = left
        if y is None:
            y = top

        width = _safe_float(bounds.get("width"))
        height = _safe_float(bounds.get("height"))

        if width is None and left is not None and right is not None:
            width = max(0.0, right - left)

        if height is None and top is not None and bottom is not None:
            height = max(0.0, bottom - top)

        center_x = None
        center_y = None

        if x is not None and width is not None:
            center_x = x + width / 2.0

        if y is not None and height is not None:
            center_y = y + height / 2.0

        return x, y, width, height, center_x, center_y

    def _infer_visible(
        self,
        element: Mapping[str, Any],
        bounds: Optional[Mapping[str, Any]],
    ) -> Optional[bool]:
        """Infer visibility from flags, style, and bounds."""

        for key in (
            "visible",
            "is_visible",
            "displayed",
            "is_displayed",
            "shown",
            "in_viewport",
            "rendered",
        ):
            if key in element:
                value = element.get(key)
                if isinstance(value, bool):
                    return value
                if isinstance(value, str):
                    normalized = value.strip().lower()
                    if normalized in {"true", "yes", "1", "visible", "shown"}:
                        return True
                    if normalized in {"false", "no", "0", "hidden", "none"}:
                        return False

        style = str(element.get("style") or "").lower()
        if "display: none" in style or "visibility: hidden" in style or "opacity: 0" in style:
            return False

        attrs = element.get("attributes")
        if isinstance(attrs, Mapping):
            if str(attrs.get("aria-hidden", "")).lower() == "true":
                return False

        if bounds:
            width = _safe_float(bounds.get("width"))
            height = _safe_float(bounds.get("height"))
            if width is not None and height is not None:
                return width > 0 and height > 0

        return None

    def _extract_positions(self, elements: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
        """Extract stable UI positions from normalized elements."""

        positions: List[Dict[str, Any]] = []

        for element in elements:
            if element.get("center_x") is None and element.get("center_y") is None:
                continue

            position = VisualElementPosition(
                element_id=element.get("element_id"),
                element_type=element.get("element_type"),
                role=element.get("role"),
                text=element.get("text"),
                selector=element.get("selector"),
                x=element.get("x"),
                y=element.get("y"),
                width=element.get("width"),
                height=element.get("height"),
                center_x=element.get("center_x"),
                center_y=element.get("center_y"),
                confidence=float(element.get("confidence") or 0.0),
                metadata=dict(element.get("metadata") or {}),
            )

            positions.append(asdict(position))

        return positions

    def _element_signature(self, element: Mapping[str, Any]) -> Tuple[Any, ...]:
        """Build dedupe signature for normalized element."""

        return (
            element.get("element_id"),
            element.get("role"),
            element.get("tag"),
            _normalize_text(element.get("text")),
            element.get("selector"),
            _stable_bucket(element.get("center_x")),
            _stable_bucket(element.get("center_y")),
        )

    def _build_text_fingerprint(self, tokens: Sequence[str]) -> str:
        """Build stable text fingerprint from top tokens."""

        useful = [
            token
            for token in tokens
            if len(token) > 1 and token not in {"the", "and", "for", "with", "you"}
        ]
        token_counts: Dict[str, int] = {}

        for token in useful:
            token_counts[token] = token_counts.get(token, 0) + 1

        top = sorted(token_counts.items(), key=lambda item: (-item[1], item[0]))[:80]
        return _sha256_text(_safe_json_dumps(top))

    def _build_layout_fingerprint(self, elements: Sequence[Mapping[str, Any]]) -> str:
        """Build stable layout fingerprint from element roles and coordinate buckets."""

        layout_items: List[Tuple[Any, ...]] = []

        for element in elements:
            if element.get("visible") is False:
                continue

            item = (
                element.get("role") or element.get("tag") or element.get("element_type"),
                _stable_bucket(element.get("center_x"), 32.0),
                _stable_bucket(element.get("center_y"), 32.0),
                _stable_bucket(element.get("width"), 32.0),
                _stable_bucket(element.get("height"), 32.0),
            )
            layout_items.append(item)

        layout_items = sorted(layout_items)[:300]
        return _sha256_text(_safe_json_dumps(layout_items))

    def _build_element_fingerprint(self, elements: Sequence[Mapping[str, Any]]) -> str:
        """Build stable element fingerprint from role/text/selector hints."""

        items: List[Tuple[Any, ...]] = []

        for element in elements:
            text_tokens = _tokenize(element.get("text"))[:8]
            items.append(
                (
                    element.get("role"),
                    element.get("tag"),
                    element.get("selector"),
                    tuple(text_tokens),
                )
            )

        items = sorted(items, key=lambda item: _safe_json_dumps(item))[:300]
        return _sha256_text(_safe_json_dumps(items))

    def _infer_error_signature(
        self,
        *,
        text: str,
        elements: Sequence[Mapping[str, Any]],
        snapshot: Mapping[str, Any],
    ) -> Optional[str]:
        """Infer common error screen signature from text/elements."""

        direct_error = (
            snapshot.get("error_signature")
            or snapshot.get("error_type")
            or snapshot.get("exception")
            or snapshot.get("error_code")
        )

        if direct_error:
            return _normalize_text(direct_error)

        normalized = _normalize_text(text)
        error_keywords = [
            "error",
            "failed",
            "failure",
            "exception",
            "timeout",
            "not found",
            "404",
            "403",
            "500",
            "crashed",
            "unavailable",
            "permission denied",
            "access denied",
            "network error",
            "something went wrong",
            "try again",
        ]

        found = [keyword for keyword in error_keywords if keyword in normalized]

        if not found:
            return None

        tokens = _tokenize(normalized)
        important = [token for token in tokens if token in set(_tokenize(" ".join(error_keywords)))]

        payload = {
            "keywords": sorted(set(found)),
            "important_tokens": sorted(set(important))[:30],
        }

        return _sha256_text(_safe_json_dumps(payload))[:24]

    # =========================================================================
    # Matching
    # =========================================================================

    def _find_existing_record(
        self,
        *,
        user_id: str,
        workspace_id: str,
        memory_type: str,
        features: VisualSnapshotFeatures,
        app_name: Optional[str],
        screen_name: Optional[str],
    ) -> Optional[VisualMemoryRecord]:
        """Find existing similar record for occurrence update."""

        records = self.storage.list_records(
            user_id=user_id,
            workspace_id=workspace_id,
            memory_type=memory_type,
            status=VisualMemoryStatus.ACTIVE.value,
            app_name=app_name,
            screen_name=screen_name,
            limit=self.max_records_per_workspace,
        )

        best_record: Optional[VisualMemoryRecord] = None
        best_score = 0.0

        for record in records:
            match = self._score_record_match(record, features)
            if match.similarity > best_score:
                best_score = match.similarity
                best_record = record

        if best_record and best_score >= self.strict_similarity_threshold:
            return best_record

        return None

    def _score_record_match(
        self,
        record: VisualMemoryRecord,
        features: VisualSnapshotFeatures,
    ) -> VisualMemoryMatch:
        """Score one stored record against extracted snapshot features."""

        matched_by: List[str] = []
        evidence: Dict[str, Any] = {}

        exact_fingerprint = 1.0 if record.fingerprint == features.fingerprint else 0.0
        if exact_fingerprint:
            matched_by.append("fingerprint_exact")

        text_score = self._text_similarity(record.normalized_text, features.normalized_text)
        if text_score >= 0.70:
            matched_by.append("text_similarity")

        layout_score = 1.0 if record.layout_fingerprint == features.layout_fingerprint else 0.0
        if layout_score:
            matched_by.append("layout_fingerprint")

        element_score = 1.0 if record.element_fingerprint == features.element_fingerprint else 0.0
        if element_score:
            matched_by.append("element_fingerprint")

        position_score = self._position_similarity(record.positions, features.positions)
        if position_score >= 0.65:
            matched_by.append("position_similarity")

        app_score = 0.0
        if record.app_name and features.app_name:
            app_score = 1.0 if record.app_name.lower() == features.app_name.lower() else 0.0
            if app_score:
                matched_by.append("app_name")

        screen_score = 0.0
        if record.screen_name and features.screen_name:
            screen_score = 1.0 if record.screen_name.lower() == features.screen_name.lower() else 0.0
            if screen_score:
                matched_by.append("screen_name")

        error_score = 0.0
        if record.memory_type == VisualMemoryType.ERROR_SCREEN.value:
            if record.error_signature and features.error_signature:
                error_score = 1.0 if record.error_signature == features.error_signature else 0.0
                if error_score:
                    matched_by.append("error_signature")

        if exact_fingerprint:
            similarity = 1.0
        else:
            weights = {
                "text": 0.30,
                "layout": 0.24,
                "element": 0.18,
                "position": 0.16,
                "app": 0.05,
                "screen": 0.05,
                "error": 0.20 if record.memory_type == VisualMemoryType.ERROR_SCREEN.value else 0.02,
            }

            total_weight = sum(weights.values())
            similarity = (
                text_score * weights["text"]
                + layout_score * weights["layout"]
                + element_score * weights["element"]
                + position_score * weights["position"]
                + app_score * weights["app"]
                + screen_score * weights["screen"]
                + error_score * weights["error"]
            ) / total_weight

        similarity = _clamp(similarity)

        evidence.update(
            {
                "text_score": round(text_score, 4),
                "layout_score": round(layout_score, 4),
                "element_score": round(element_score, 4),
                "position_score": round(position_score, 4),
                "app_score": round(app_score, 4),
                "screen_score": round(screen_score, 4),
                "error_score": round(error_score, 4),
            }
        )

        return VisualMemoryMatch(
            memory_id=record.memory_id,
            memory_type=record.memory_type,
            title=record.title,
            app_name=record.app_name,
            screen_name=record.screen_name,
            similarity=round(similarity, 4),
            match_strength=self._match_strength(similarity),
            matched_by=matched_by,
            occurrence_count=record.occurrence_count,
            last_seen_at=record.last_seen_at,
            evidence=evidence,
        )

    def _text_similarity(self, a: str, b: str) -> float:
        """Calculate text similarity from normalized strings."""

        tokens_a = _tokenize(a, case_sensitive=self.case_sensitive_default)
        tokens_b = _tokenize(b, case_sensitive=self.case_sensitive_default)

        if not tokens_a and not tokens_b:
            return 1.0

        if not tokens_a or not tokens_b:
            return 0.0

        jaccard = _jaccard_similarity(tokens_a, tokens_b)
        cosine = _cosine_similarity_counts(tokens_a, tokens_b)

        return _clamp((jaccard * 0.45) + (cosine * 0.55))

    def _position_similarity(
        self,
        stored_positions: Sequence[Mapping[str, Any]],
        current_positions: Sequence[Mapping[str, Any]],
    ) -> float:
        """Compare UI positions using role/text/coordinate buckets."""

        if not stored_positions and not current_positions:
            return 1.0

        if not stored_positions or not current_positions:
            return 0.0

        stored_signatures = set(self._position_signature(item) for item in stored_positions)
        current_signatures = set(self._position_signature(item) for item in current_positions)

        return _jaccard_similarity(stored_signatures, current_signatures)

    def _position_signature(self, position: Mapping[str, Any]) -> Tuple[Any, ...]:
        """Build stable signature for a UI position."""

        text_tokens = tuple(_tokenize(position.get("text"))[:4])

        return (
            position.get("role") or position.get("element_type"),
            text_tokens,
            position.get("selector"),
            _stable_bucket(_safe_float(position.get("center_x")), 40.0),
            _stable_bucket(_safe_float(position.get("center_y")), 40.0),
        )

    def _score_position_match(
        self,
        *,
        position: Mapping[str, Any],
        element_text: Optional[str],
        element_type: Optional[str],
        selector: Optional[str],
        query_tokens: set,
    ) -> float:
        """Score one stored UI position against query."""

        score = 0.0
        possible = 0.0

        if element_text:
            possible += 0.45
            text_score = _cosine_similarity_counts(
                _tokenize(position.get("text")),
                _tokenize(element_text),
            )
            score += 0.45 * text_score

        if element_type:
            possible += 0.25
            stored_type = _normalize_text(
                position.get("element_type") or position.get("role")
            )
            expected_type = _normalize_text(element_type)
            if expected_type and expected_type in stored_type:
                score += 0.25

        if selector:
            possible += 0.30
            stored_selector = _normalize_text(position.get("selector"))
            expected_selector = _normalize_text(selector)
            if stored_selector == expected_selector:
                score += 0.30
            elif expected_selector and expected_selector in stored_selector:
                score += 0.20

        if possible <= 0 and query_tokens:
            text_blob = " ".join(
                [
                    str(position.get("text") or ""),
                    str(position.get("selector") or ""),
                    str(position.get("role") or ""),
                    str(position.get("element_type") or ""),
                ]
            )
            return _jaccard_similarity(query_tokens, set(_tokenize(text_blob)))

        if possible <= 0:
            return 0.0

        return _clamp(score / possible)

    def _match_strength(self, similarity: float) -> str:
        """Convert similarity score to label."""

        if similarity >= 0.97:
            return VisualMatchStrength.EXACT.value
        if similarity >= 0.85:
            return VisualMatchStrength.STRONG.value
        if similarity >= 0.65:
            return VisualMatchStrength.PARTIAL.value
        if similarity > 0:
            return VisualMatchStrength.WEAK.value
        return VisualMatchStrength.NONE.value

    # =========================================================================
    # Record merge / title / summaries
    # =========================================================================

    def _merge_existing_record(
        self,
        *,
        existing: VisualMemoryRecord,
        features: VisualSnapshotFeatures,
        title: str,
        tags: Optional[Sequence[str]],
        metadata: Optional[Mapping[str, Any]],
        snapshot: Mapping[str, Any],
    ) -> VisualMemoryRecord:
        """Update an existing record occurrence safely."""

        record = copy.deepcopy(existing)
        record.title = title or record.title
        record.occurrence_count += 1
        record.last_seen_at = _utc_now_iso()
        record.updated_at = _utc_now_iso()
        record.confidence = min(1.0, max(record.confidence, 0.95))
        record.normalized_text = features.normalized_text or record.normalized_text
        record.elements = features.elements or record.elements
        record.positions = features.positions or record.positions
        record.error_signature = features.error_signature or record.error_signature
        record.tags = sorted(set(record.tags).union(self._normalize_tags(tags)))
        record.metadata.update(dict(metadata or {}))
        record.metadata["features"] = self._features_summary(features)

        if self.store_raw_snapshot:
            record.raw_snapshot = copy.deepcopy(dict(snapshot))

        return record

    def _build_title(
        self,
        *,
        memory_type: str,
        app_name: Optional[str],
        screen_name: Optional[str],
        features: VisualSnapshotFeatures,
    ) -> str:
        """Build a readable title for memory record."""

        readable_type = memory_type.replace("_", " ").title()
        parts = [part for part in (app_name, screen_name) if part]

        if parts:
            return f"{readable_type}: {' / '.join(parts)}"

        if features.url:
            return f"{readable_type}: {features.url}"

        if features.normalized_text:
            preview = features.normalized_text[:60].strip()
            return f"{readable_type}: {preview}"

        return f"{readable_type}: {features.fingerprint[:12]}"

    def _normalize_tags(self, tags: Optional[Sequence[str]]) -> List[str]:
        """Normalize tags."""

        cleaned: List[str] = []
        seen: set = set()

        for tag in tags or []:
            normalized = _normalize_text(tag)
            normalized = re.sub(r"[^a-zA-Z0-9_.:-]+", "_", normalized).strip("_")
            if normalized and normalized not in seen:
                seen.add(normalized)
                cleaned.append(normalized)

        return cleaned

    def _features_summary(self, features: VisualSnapshotFeatures) -> Dict[str, Any]:
        """Return safe summary of features."""

        return {
            "app_name": features.app_name,
            "screen_name": features.screen_name,
            "url": features.url,
            "route": features.route,
            "fingerprint": features.fingerprint,
            "text_fingerprint": features.text_fingerprint,
            "layout_fingerprint": features.layout_fingerprint,
            "element_fingerprint": features.element_fingerprint,
            "error_signature": features.error_signature,
            "text_token_count": len(features.text_tokens),
            "element_count": len(features.elements),
            "position_count": len(features.positions),
        }

    # =========================================================================
    # Required compatibility hooks
    # =========================================================================

    def _validate_task_context(self, context: VisualTaskContext) -> Dict[str, Any]:
        """
        Validate SaaS isolation context.

        All memory operations require both user_id and workspace_id.
        """

        if not context.user_id or not str(context.user_id).strip():
            return self._error_result(
                message="Missing required user_id for visual memory operation.",
                error="missing_user_id",
                metadata={
                    "agent": self.agent_name,
                    "module": self.agent_module,
                    "task_id": context.task_id,
                    "request_id": context.request_id,
                },
            )

        if not context.workspace_id or not str(context.workspace_id).strip():
            return self._error_result(
                message="Missing required workspace_id for visual memory operation.",
                error="missing_workspace_id",
                metadata={
                    "agent": self.agent_name,
                    "module": self.agent_module,
                    "user_id": context.user_id,
                    "task_id": context.task_id,
                    "request_id": context.request_id,
                },
            )

        return self._safe_result(
            success=True,
            message="Task context is valid.",
            data={
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
                "task_id": context.task_id,
                "request_id": context.request_id,
            },
            metadata={
                "agent": self.agent_name,
                "module": self.agent_module,
            },
        )

    def _requires_security_check(
        self,
        action: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Return whether an operation requires Security Agent approval.

        Visual memory is not destructive, but store/archive operations can affect
        user/workspace memory. This hook allows future stricter policies.
        """

        _ = payload

        read_only_actions = {
            "visual_memory_match",
            "visual_memory_get",
            "visual_memory_list",
            "prepare_verification_payload",
            "prepare_memory_payload",
        }

        write_actions = {
            "visual_memory_store",
            "visual_memory_archive",
            "visual_memory_delete",
        }

        if action in read_only_actions:
            return False

        if action in write_actions:
            return bool(self.config.get("require_security_for_writes", False))

        return True

    def _request_security_approval(
        self,
        *,
        context: VisualTaskContext,
        action: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval when policy requires it.

        Safe default:
            - read-only operations pass automatically
            - write operations pass unless config requires strict approval
        """

        if not self._requires_security_check(action, payload):
            return self._safe_result(
                success=True,
                message="Security approval not required for this visual memory operation.",
                data={"approved": True, "action": action},
                metadata={
                    "agent": self.agent_name,
                    "module": self.agent_module,
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "task_id": context.task_id,
                },
            )

        if self.security_client and hasattr(self.security_client, "approve"):
            try:
                approval = self.security_client.approve(
                    user_id=context.user_id,
                    workspace_id=context.workspace_id,
                    action=action,
                    payload=dict(payload or {}),
                )

                approved = bool(
                    approval.get("approved")
                    if isinstance(approval, Mapping)
                    else approval
                )

                if approved:
                    return self._safe_result(
                        success=True,
                        message="Security Agent approved visual memory operation.",
                        data={"approved": True, "action": action},
                        metadata={
                            "agent": self.agent_name,
                            "module": self.agent_module,
                        },
                    )

            except Exception as exc:
                return self._error_result(
                    message="Security approval failed.",
                    error=exc,
                    metadata={
                        "agent": self.agent_name,
                        "module": self.agent_module,
                        "user_id": context.user_id,
                        "workspace_id": context.workspace_id,
                        "task_id": context.task_id,
                    },
                )

        return self._error_result(
            message="Security approval is required but was not granted.",
            error="security_approval_required",
            metadata={
                "agent": self.agent_name,
                "module": self.agent_module,
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
                "task_id": context.task_id,
                "action": action,
            },
        )

    def _prepare_verification_payload(
        self,
        *,
        context: VisualTaskContext,
        operation: str,
        success: bool,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        started_at: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent-compatible payload.

        Used after visual memory store/match/archive operations to prove what
        happened and keep task history/dashboard records structured.
        """

        return {
            "verification_type": "visual_memory",
            "agent": self.agent_name,
            "module": self.agent_module,
            "version": self.version,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "task_id": context.task_id,
            "request_id": context.request_id,
            "source_agent": context.source_agent,
            "session_id": context.session_id,
            "operation": operation,
            "success": bool(success),
            "message": message,
            "data": dict(data or {}),
            "started_at": started_at,
            "completed_at": _utc_now_iso(),
            "proof": {
                "method": "visual_memory_record_operation",
                "read_only": operation.startswith("match") or operation.startswith("get"),
                "destructive_action_performed": False,
            },
            "metadata": {
                **context.metadata,
                "permissions": context.permissions,
            },
        }

    def _prepare_memory_payload(
        self,
        *,
        context: VisualTaskContext,
        memory_action: str,
        payload: Mapping[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """
        Prepare Memory Agent-compatible payload.

        This does not force persistence into the Memory Agent. If memory_client is
        injected and supports prepare_payload, it can adapt this payload.
        """

        if not self.memory_payload_enabled:
            return None

        memory_payload = {
            "memory_type": "visual_memory",
            "memory_action": memory_action,
            "scope": "workspace",
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "task_id": context.task_id,
            "request_id": context.request_id,
            "source": self.agent_name,
            "content": dict(payload),
            "created_at": _utc_now_iso(),
        }

        if self.memory_client and hasattr(self.memory_client, "prepare_payload"):
            try:
                prepared = self.memory_client.prepare_payload(memory_payload)
                if isinstance(prepared, Mapping):
                    return dict(prepared)
            except Exception:
                self.logger.debug("Memory client prepare_payload failed", exc_info=True)

        return memory_payload

    def _emit_agent_event(self, event_name: str, payload: Dict[str, Any]) -> None:
        """
        Emit event for Dashboard/API/Agent analytics.

        Safe no-op if no event infrastructure exists yet.
        """

        safe_payload = copy.deepcopy(payload)
        safe_payload.setdefault("agent", self.agent_name)
        safe_payload.setdefault("module", self.agent_module)
        safe_payload.setdefault("timestamp", _utc_now_iso())

        try:
            if self.event_emitter:
                self.event_emitter(event_name, safe_payload)
                return

            if hasattr(self, "emit_event"):
                try:
                    self.emit_event(event_name, safe_payload)  # type: ignore[attr-defined]
                    return
                except TypeError:
                    pass

            self.logger.debug("Agent event emitted: %s %s", event_name, safe_payload)
        except Exception:
            self.logger.debug("Agent event emission failed", exc_info=True)

    def _log_audit_event(self, payload: Dict[str, Any]) -> None:
        """
        Log audit event.

        All audit payloads include user_id/workspace_id where relevant to preserve
        SaaS isolation.
        """

        if not self.audit_enabled:
            return

        safe_payload = copy.deepcopy(payload)
        safe_payload.setdefault("agent", self.agent_name)
        safe_payload.setdefault("module", self.agent_module)
        safe_payload.setdefault("timestamp", _utc_now_iso())

        try:
            if self.audit_logger:
                self.audit_logger(safe_payload)
                return

            if hasattr(self, "log_audit"):
                try:
                    self.log_audit(safe_payload)  # type: ignore[attr-defined]
                    return
                except TypeError:
                    pass

            self.logger.info("Audit event: %s", safe_payload)
        except Exception:
            self.logger.debug("Audit logging failed", exc_info=True)

    def _safe_result(
        self,
        *,
        success: bool,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        error: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard structured result."""

        return {
            "success": bool(success),
            "message": str(message),
            "data": dict(data or {}),
            "error": self._serialize_error(error) if error else None,
            "metadata": {
                "timestamp": _utc_now_iso(),
                **dict(metadata or {}),
            },
        }

    def _error_result(
        self,
        *,
        message: str,
        error: Any,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard structured error result."""

        return self._safe_result(
            success=False,
            message=message,
            data=data or {},
            error=error,
            metadata=metadata or {},
        )

    def _serialize_error(self, error: Any) -> Dict[str, Any]:
        """Serialize errors safely."""

        if isinstance(error, Mapping):
            return dict(error)

        if isinstance(error, str):
            return {
                "type": "Error",
                "message": error,
            }

        return {
            "type": error.__class__.__name__,
            "message": str(error),
        }

    # =========================================================================
    # Registry / health helpers
    # =========================================================================

    def get_capabilities(self) -> Dict[str, Any]:
        """
        Return capabilities for Agent Registry / Agent Loader / Dashboard.
        """

        return {
            "agent": self.agent_name,
            "module": self.agent_module,
            "version": self.version,
            "class": self.__class__.__name__,
            "read_only": False,
            "supports": [
                "store_screen_pattern",
                "store_app_layout",
                "store_error_screen",
                "store_ui_positions",
                "match_visual_memory",
                "find_ui_position",
                "get_memory",
                "list_memories",
                "archive_memory",
                "saas_user_workspace_isolation",
                "verification_payload",
                "memory_payload",
                "audit_event",
                "agent_event",
            ],
            "public_methods": [
                "store_screen_pattern",
                "store_app_layout",
                "store_error_screen",
                "store_ui_positions",
                "match_visual_memory",
                "find_ui_position",
                "get_memory",
                "list_memories",
                "archive_memory",
                "get_capabilities",
                "health_check",
            ],
            "memory_types": [item.value for item in VisualMemoryType],
        }

    def health_check(self) -> Dict[str, Any]:
        """Return health status for FastAPI/dashboard checks."""

        return self._safe_result(
            success=True,
            message="VisualMemory is healthy.",
            data={
                "agent": self.agent_name,
                "module": self.agent_module,
                "version": self.version,
                "default_similarity_threshold": self.default_similarity_threshold,
                "strict_similarity_threshold": self.strict_similarity_threshold,
                "max_records_per_workspace": self.max_records_per_workspace,
                "max_elements_per_snapshot": self.max_elements_per_snapshot,
                "store_raw_snapshot": self.store_raw_snapshot,
                "storage_adapter": self.storage.__class__.__name__,
            },
            metadata={
                "agent": self.agent_name,
                "module": self.agent_module,
            },
        )


# =============================================================================
# Factory function for Agent Loader / Registry
# =============================================================================

def create_visual_memory(
    config: Optional[Mapping[str, Any]] = None,
    **kwargs: Any,
) -> VisualMemory:
    """
    Factory function for Agent Loader / Agent Registry.

    Args:
        config: Optional visual memory config.
        **kwargs: Optional storage/client/callback injections.

    Returns:
        VisualMemory instance.
    """

    return VisualMemory(config=config, **kwargs)


__all__ = [
    "VisualMemory",
    "VisualMemoryType",
    "VisualMemoryStatus",
    "VisualMatchStrength",
    "VisualTaskContext",
    "VisualElementPosition",
    "VisualMemoryRecord",
    "VisualMemoryMatch",
    "VisualSnapshotFeatures",
    "InMemoryVisualMemoryStore",
    "create_visual_memory",
]