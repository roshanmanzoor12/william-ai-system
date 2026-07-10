"""
agents/memory_agent/short_term.py

Short-term memory layer for the William / Jarvis Multi-Agent AI SaaS System.

Purpose:
    - Store current session context.
    - Track active task per user/workspace/session.
    - Track active agent per user/workspace/session.
    - Track recent commands per user/workspace/session.
    - Provide safe, structured, import-safe public methods for Master Agent,
      Agent Router, Agent Registry, Dashboard/API, Security Agent, Verification
      Agent, and Memory Agent integration.

Architecture Notes:
    William is a Jarvis-style multi-agent SaaS system with a Master Agent and
    specialized agents such as Voice, System, Browser, Code, Memory, Security,
    Verification, Visual, Workflow, Hologram, Call, Business, Finance, Creator.

    This file is intentionally import-safe:
        - It does not require the rest of the William system to exist.
        - If BaseAgent or shared modules are not available yet, local fallback
          stubs are used.
        - It avoids hardcoded secrets.
        - It avoids real external side effects.
        - It keeps all memory isolated by user_id + workspace_id + session_id.

Safety Priority:
    1. Safety and permission rules.
    2. SaaS user/workspace isolation.
    3. BaseAgent compatibility.
    4. MasterAgent / Registry compatibility.
    5. File-specific functionality.
    6. Future upgrades.

Public Class:
    ShortTermMemory

Typical Usage:
    memory = ShortTermMemory()
    memory.set_session_context(user_id="u1", workspace_id="w1", session_id="s1", context={...})
    memory.set_active_task(user_id="u1", workspace_id="w1", session_id="s1", task={...})
    memory.set_active_agent(user_id="u1", workspace_id="w1", session_id="s1", agent_name="Code")
    memory.add_recent_command(user_id="u1", workspace_id="w1", session_id="s1", command="open file")
    memory.get_session_snapshot(user_id="u1", workspace_id="w1", session_id="s1")

No external dependencies required.
"""

from __future__ import annotations

import copy
import json
import logging
import re
import threading
import time
import uuid
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Deque, Dict, Iterable, List, Mapping, Optional, Tuple, Union


# =============================================================================
# Optional BaseAgent compatibility
# =============================================================================

try:
    # Future William/Jarvis structure example.
    # This import is optional so this file remains safe to import before the
    # full project is generated.
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback exists for import safety
    class BaseAgent:  # type: ignore
        """
        Local fallback BaseAgent.

        This fallback keeps ShortTermMemory import-safe when the real BaseAgent
        does not exist yet. The real William system can replace this automatically
        once agents/base_agent.py is available.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_version = kwargs.get("agent_version", "1.0.0")
            self.logger = logging.getLogger(self.agent_name)

        def health_check(self) -> Dict[str, Any]:
            return {
                "success": True,
                "message": "Fallback BaseAgent is active.",
                "data": {
                    "agent_name": self.agent_name,
                    "agent_version": self.agent_version,
                },
                "error": None,
                "metadata": {
                    "fallback_base_agent": True,
                    "timestamp": _utc_now_iso(),
                },
            }


# =============================================================================
# Constants
# =============================================================================

DEFAULT_MAX_SESSIONS_PER_SCOPE = 250
DEFAULT_MAX_COMMANDS_PER_SESSION = 100
DEFAULT_SESSION_TTL_SECONDS = 60 * 60 * 6  # 6 hours
DEFAULT_AUDIT_LOG_LIMIT = 1000
DEFAULT_EVENT_LOG_LIMIT = 1000
DEFAULT_PAYLOAD_MAX_DEPTH = 8
DEFAULT_STRING_MAX_LENGTH = 5000

SENSITIVE_KEY_PATTERNS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "authorization",
    "auth",
    "bearer",
    "cookie",
    "session_cookie",
    "access_key",
    "refresh_token",
    "client_secret",
)

SENSITIVE_COMMAND_PATTERNS = (
    r"\brm\s+-rf\b",
    r"\bdelete\b",
    r"\bdrop\s+table\b",
    r"\btruncate\b",
    r"\bshutdown\b",
    r"\breboot\b",
    r"\bformat\b",
    r"\btransfer\b",
    r"\bpayment\b",
    r"\bwithdraw\b",
    r"\bsend\s+email\b",
    r"\bsend\s+message\b",
    r"\bcall\s+",
    r"\bbrowser\s+execute\b",
    r"\bdeploy\b",
    r"\bprod\b",
    r"\bproduction\b",
)

SAFE_TASK_STATUSES = {
    "new",
    "queued",
    "running",
    "paused",
    "blocked",
    "waiting_security_approval",
    "completed",
    "failed",
    "cancelled",
}

SAFE_AGENT_STATUSES = {
    "idle",
    "active",
    "busy",
    "paused",
    "blocked",
    "error",
    "offline",
}

ALLOWED_CONTEXT_VALUE_TYPES = (
    str,
    int,
    float,
    bool,
    type(None),
    dict,
    list,
    tuple,
)


# =============================================================================
# Utility functions
# =============================================================================

def _utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def _unix_now() -> float:
    """Return current Unix timestamp as float."""
    return time.time()


def _safe_uuid(prefix: str = "stm") -> str:
    """Return a safe unique id with a readable prefix."""
    clean_prefix = re.sub(r"[^a-zA-Z0-9_-]", "", prefix or "stm")[:24] or "stm"
    return f"{clean_prefix}_{uuid.uuid4().hex}"


def _normalize_identifier(value: Any, field_name: str) -> str:
    """
    Normalize and validate user_id, workspace_id, session_id, task_id, etc.

    Raises:
        ValueError: if the identifier is missing or unsafe.
    """
    if value is None:
        raise ValueError(f"{field_name} is required.")

    normalized = str(value).strip()

    if not normalized:
        raise ValueError(f"{field_name} cannot be empty.")

    if len(normalized) > 256:
        raise ValueError(f"{field_name} is too long. Maximum length is 256 characters.")

    if not re.match(r"^[a-zA-Z0-9_.:@\-]+$", normalized):
        raise ValueError(
            f"{field_name} contains unsafe characters. "
            "Allowed characters: letters, numbers, underscore, dash, dot, colon, at-sign."
        )

    return normalized


def _deepcopy_safe(value: Any) -> Any:
    """Best-effort deepcopy that never raises outward."""
    try:
        return copy.deepcopy(value)
    except Exception:
        try:
            return json.loads(json.dumps(value, default=str))
        except Exception:
            return str(value)


def _is_mapping(value: Any) -> bool:
    return isinstance(value, Mapping)


def _safe_json_dumps(value: Any) -> str:
    """Serialize a value to JSON safely for logs/debugging."""
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    except Exception:
        return str(value)


def _truncate_string(value: str, max_length: int = DEFAULT_STRING_MAX_LENGTH) -> str:
    """Truncate long strings to protect memory and UI rendering."""
    if len(value) <= max_length:
        return value
    return value[:max_length] + "...[truncated]"


def _coerce_dict(value: Optional[Mapping[str, Any]], field_name: str) -> Dict[str, Any]:
    """
    Coerce optional mapping to regular dict.

    Raises:
        ValueError: if value is not a mapping.
    """
    if value is None:
        return {}
    if not _is_mapping(value):
        raise ValueError(f"{field_name} must be a dictionary/mapping.")
    return dict(value)


# =============================================================================
# Data models
# =============================================================================

@dataclass
class ShortTermMemoryConfig:
    """
    Configuration for ShortTermMemory.

    Attributes:
        max_sessions_per_scope:
            Maximum session records per user/workspace scope.

        max_commands_per_session:
            Maximum recent commands stored per session.

        session_ttl_seconds:
            Sessions older than this are considered stale and can be pruned.

        audit_log_limit:
            Maximum in-memory audit log entries.

        event_log_limit:
            Maximum in-memory agent event entries.

        enable_auto_cleanup:
            If True, mutating operations opportunistically prune stale sessions.

        redact_sensitive_values:
            If True, sensitive keys/values are redacted before storage.

        allow_command_storage:
            If False, commands are not stored. Useful for privacy-sensitive deployments.

        strict_context_validation:
            If True, rejects unsupported context payload types.

        payload_max_depth:
            Maximum nested structure depth retained during sanitization.

        string_max_length:
            Maximum retained string length for any stored string.
    """

    max_sessions_per_scope: int = DEFAULT_MAX_SESSIONS_PER_SCOPE
    max_commands_per_session: int = DEFAULT_MAX_COMMANDS_PER_SESSION
    session_ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS
    audit_log_limit: int = DEFAULT_AUDIT_LOG_LIMIT
    event_log_limit: int = DEFAULT_EVENT_LOG_LIMIT
    enable_auto_cleanup: bool = True
    redact_sensitive_values: bool = True
    allow_command_storage: bool = True
    strict_context_validation: bool = True
    payload_max_depth: int = DEFAULT_PAYLOAD_MAX_DEPTH
    string_max_length: int = DEFAULT_STRING_MAX_LENGTH


@dataclass
class CommandRecord:
    """Recent command record stored inside a session."""

    command_id: str
    command: str
    command_type: str = "user"
    status: str = "recorded"
    agent_name: Optional[str] = None
    task_id: Optional[str] = None
    source: str = "unknown"
    requires_security_check: bool = False
    security_approved: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=_utc_now_iso)
    updated_at: str = field(default_factory=_utc_now_iso)


@dataclass
class ActiveTaskRecord:
    """Active task record stored inside a session."""

    task_id: str
    title: str
    status: str = "running"
    agent_name: Optional[str] = None
    priority: str = "normal"
    input_summary: Optional[str] = None
    progress: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    started_at: str = field(default_factory=_utc_now_iso)
    updated_at: str = field(default_factory=_utc_now_iso)


@dataclass
class ActiveAgentRecord:
    """Active agent record stored inside a session."""

    agent_name: str
    status: str = "active"
    agent_id: Optional[str] = None
    capabilities: List[str] = field(default_factory=list)
    route_reason: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    activated_at: str = field(default_factory=_utc_now_iso)
    updated_at: str = field(default_factory=_utc_now_iso)


@dataclass
class SessionMemoryRecord:
    """
    Complete short-term session memory.

    This is isolated by:
        user_id + workspace_id + session_id
    """

    user_id: str
    workspace_id: str
    session_id: str
    context: Dict[str, Any] = field(default_factory=dict)
    active_task: Optional[ActiveTaskRecord] = None
    active_agent: Optional[ActiveAgentRecord] = None
    recent_commands: Deque[CommandRecord] = field(default_factory=deque)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=_utc_now_iso)
    updated_at: str = field(default_factory=_utc_now_iso)
    last_accessed_at: str = field(default_factory=_utc_now_iso)
    expires_at_unix: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert dataclass record to JSON/dict-safe payload."""
        return {
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "session_id": self.session_id,
            "context": _deepcopy_safe(self.context),
            "active_task": asdict(self.active_task) if self.active_task else None,
            "active_agent": asdict(self.active_agent) if self.active_agent else None,
            "recent_commands": [asdict(command) for command in list(self.recent_commands)],
            "metadata": _deepcopy_safe(self.metadata),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "last_accessed_at": self.last_accessed_at,
            "expires_at_unix": self.expires_at_unix,
        }


# =============================================================================
# ShortTermMemory
# =============================================================================

class ShortTermMemory(BaseAgent):
    """
    Production-ready short-term memory helper for the Memory Agent.

    Responsibilities:
        - Maintain current session context.
        - Maintain active task.
        - Maintain active agent.
        - Maintain recent commands.
        - Keep all records isolated per user/workspace/session.
        - Provide structured dict results.
        - Provide security, audit, verification, event, and Memory Agent hooks.

    This class does not persist to a database by default. It is designed as the
    fast current-session memory layer. A future memory_sync.py or memory_backup.py
    can periodically persist snapshots using get_session_snapshot() or export_scope().

    Compatibility:
        - Master Agent can use get_session_snapshot() to route context-aware tasks.
        - Agent Router can use get_active_agent() and set_active_agent().
        - Security Agent can use _requires_security_check() and
          _request_security_approval().
        - Verification Agent can consume _prepare_verification_payload().
        - Memory Agent can consume _prepare_memory_payload().
        - Dashboard/API can consume list_sessions(), get_recent_commands(),
          get_audit_events(), and get_agent_events().
    """

    def __init__(
        self,
        config: Optional[Union[ShortTermMemoryConfig, Mapping[str, Any]]] = None,
        logger: Optional[logging.Logger] = None,
        agent_name: str = "ShortTermMemory",
        agent_version: str = "1.0.0",
    ) -> None:
        """
        Initialize ShortTermMemory.

        Args:
            config:
                Optional ShortTermMemoryConfig or dict.

            logger:
                Optional logger. If not provided, a module logger is used.

            agent_name:
                Name used by BaseAgent/Registry.

            agent_version:
                Version used by BaseAgent/Registry.
        """
        try:
            super().__init__(agent_name=agent_name, agent_version=agent_version)
        except TypeError:
            super().__init__()

        self.agent_name = agent_name
        self.agent_version = agent_version
        self.logger = logger or logging.getLogger(f"william.memory_agent.{self.__class__.__name__}")

        if isinstance(config, ShortTermMemoryConfig):
            self.config = config
        elif isinstance(config, Mapping):
            self.config = ShortTermMemoryConfig(**dict(config))
        else:
            self.config = ShortTermMemoryConfig()

        self._validate_config()

        self._lock = threading.RLock()

        # Storage shape:
        # {
        #   (user_id, workspace_id): {
        #       session_id: SessionMemoryRecord
        #   }
        # }
        self._sessions: Dict[Tuple[str, str], Dict[str, SessionMemoryRecord]] = {}

        self._audit_events: Deque[Dict[str, Any]] = deque(maxlen=self.config.audit_log_limit)
        self._agent_events: Deque[Dict[str, Any]] = deque(maxlen=self.config.event_log_limit)

        self._emit_agent_event(
            event_type="short_term_memory_initialized",
            user_id=None,
            workspace_id=None,
            session_id=None,
            data={
                "agent_name": self.agent_name,
                "agent_version": self.agent_version,
                "config": asdict(self.config),
            },
        )

    # -------------------------------------------------------------------------
    # Configuration and validation
    # -------------------------------------------------------------------------

    def _validate_config(self) -> None:
        """Validate configuration values at initialization."""
        if self.config.max_sessions_per_scope < 1:
            raise ValueError("max_sessions_per_scope must be >= 1.")
        if self.config.max_commands_per_session < 1:
            raise ValueError("max_commands_per_session must be >= 1.")
        if self.config.session_ttl_seconds < 60:
            raise ValueError("session_ttl_seconds must be >= 60.")
        if self.config.audit_log_limit < 10:
            raise ValueError("audit_log_limit must be >= 10.")
        if self.config.event_log_limit < 10:
            raise ValueError("event_log_limit must be >= 10.")
        if self.config.payload_max_depth < 1:
            raise ValueError("payload_max_depth must be >= 1.")
        if self.config.string_max_length < 100:
            raise ValueError("string_max_length must be >= 100.")

    def _validate_task_context(
        self,
        user_id: Any,
        workspace_id: Any,
        session_id: Any,
        require_session_id: bool = True,
    ) -> Dict[str, str]:
        """
        Validate and normalize SaaS task context.

        This is a core compatibility hook required by the project.

        Args:
            user_id:
                SaaS user id.

            workspace_id:
                SaaS workspace id.

            session_id:
                Current session id.

            require_session_id:
                Whether session_id must be present.

        Returns:
            Dict with normalized user_id, workspace_id, session_id.

        Raises:
            ValueError: if any required identifier is invalid.
        """
        normalized_user_id = _normalize_identifier(user_id, "user_id")
        normalized_workspace_id = _normalize_identifier(workspace_id, "workspace_id")

        if require_session_id:
            normalized_session_id = _normalize_identifier(session_id, "session_id")
        else:
            normalized_session_id = str(session_id).strip() if session_id is not None else ""

        return {
            "user_id": normalized_user_id,
            "workspace_id": normalized_workspace_id,
            "session_id": normalized_session_id,
        }

    def _scope_key(self, user_id: str, workspace_id: str) -> Tuple[str, str]:
        """Build isolated SaaS scope key."""
        return user_id, workspace_id

    def _session_key(self, user_id: Any, workspace_id: Any, session_id: Any) -> Tuple[str, str, str]:
        """Validate and return normalized user/workspace/session tuple."""
        ctx = self._validate_task_context(user_id, workspace_id, session_id)
        return ctx["user_id"], ctx["workspace_id"], ctx["session_id"]

    # -------------------------------------------------------------------------
    # Sanitization and privacy
    # -------------------------------------------------------------------------

    def _sanitize_payload(
        self,
        payload: Any,
        depth: int = 0,
        parent_key: str = "",
    ) -> Any:
        """
        Sanitize payload before storage.

        Features:
            - Redacts sensitive values.
            - Truncates long strings.
            - Limits nested depth.
            - Converts unsupported values to strings.
            - Prevents accidental storage of secrets.

        Args:
            payload:
                Any incoming payload.

            depth:
                Current recursion depth.

            parent_key:
                Key name for sensitivity detection.

        Returns:
            Sanitized payload.
        """
        if depth > self.config.payload_max_depth:
            return "[max_depth_reached]"

        if self.config.redact_sensitive_values and self._is_sensitive_key(parent_key):
            return "[redacted]"

        if isinstance(payload, str):
            if self.config.redact_sensitive_values and self._looks_like_secret(payload):
                return "[redacted]"
            return _truncate_string(payload, self.config.string_max_length)

        if isinstance(payload, (int, float, bool)) or payload is None:
            return payload

        if isinstance(payload, Mapping):
            sanitized: Dict[str, Any] = {}
            for raw_key, raw_value in payload.items():
                key = _truncate_string(str(raw_key), 256)
                if self.config.redact_sensitive_values and self._is_sensitive_key(key):
                    sanitized[key] = "[redacted]"
                else:
                    sanitized[key] = self._sanitize_payload(raw_value, depth + 1, key)
            return sanitized

        if isinstance(payload, (list, tuple, set)):
            return [
                self._sanitize_payload(item, depth + 1, parent_key)
                for item in list(payload)[:500]
            ]

        if self.config.strict_context_validation:
            if not isinstance(payload, ALLOWED_CONTEXT_VALUE_TYPES):
                return _truncate_string(str(payload), self.config.string_max_length)

        return _deepcopy_safe(payload)

    def _is_sensitive_key(self, key: str) -> bool:
        """Return True if a key name appears sensitive."""
        lowered = str(key or "").lower()
        return any(pattern in lowered for pattern in SENSITIVE_KEY_PATTERNS)

    def _looks_like_secret(self, value: str) -> bool:
        """
        Return True if a string looks like a secret/token.

        This is intentionally conservative. It avoids storing obvious secrets
        while keeping normal task context usable.
        """
        if not value:
            return False

        stripped = value.strip()

        secret_patterns = [
            r"sk-[A-Za-z0-9_\-]{20,}",
            r"AKIA[0-9A-Z]{16}",
            r"AIza[0-9A-Za-z_\-]{20,}",
            r"(?i)bearer\s+[a-z0-9._\-]{20,}",
            r"(?i)token\s*[:=]\s*[a-z0-9._\-]{16,}",
            r"(?i)password\s*[:=]\s*.+",
        ]

        return any(re.search(pattern, stripped) for pattern in secret_patterns)

    # -------------------------------------------------------------------------
    # Internal session helpers
    # -------------------------------------------------------------------------

    def _get_or_create_session(
        self,
        user_id: str,
        workspace_id: str,
        session_id: str,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> SessionMemoryRecord:
        """
        Get or create a session record. Caller must hold lock.

        Args:
            user_id:
                Normalized user id.

            workspace_id:
                Normalized workspace id.

            session_id:
                Normalized session id.

            metadata:
                Optional metadata for newly created session.

        Returns:
            SessionMemoryRecord
        """
        scope = self._scope_key(user_id, workspace_id)
        if scope not in self._sessions:
            self._sessions[scope] = {}

        sessions = self._sessions[scope]

        if session_id not in sessions:
            if len(sessions) >= self.config.max_sessions_per_scope:
                self._prune_oldest_session_in_scope(scope)

            now = _unix_now()
            sessions[session_id] = SessionMemoryRecord(
                user_id=user_id,
                workspace_id=workspace_id,
                session_id=session_id,
                metadata=self._sanitize_payload(metadata or {}),
                expires_at_unix=now + self.config.session_ttl_seconds,
            )

            self._log_audit_event(
                action="session_created",
                user_id=user_id,
                workspace_id=workspace_id,
                session_id=session_id,
                details={"metadata": metadata or {}},
            )

        record = sessions[session_id]
        self._touch_session(record)
        return record

    def _get_existing_session(
        self,
        user_id: str,
        workspace_id: str,
        session_id: str,
    ) -> Optional[SessionMemoryRecord]:
        """Get existing session record without creating it. Caller must hold lock."""
        scope = self._scope_key(user_id, workspace_id)
        return self._sessions.get(scope, {}).get(session_id)

    def _touch_session(self, record: SessionMemoryRecord) -> None:
        """Update last access time and extend TTL."""
        now_iso = _utc_now_iso()
        record.last_accessed_at = now_iso
        record.expires_at_unix = _unix_now() + self.config.session_ttl_seconds

    def _mark_updated(self, record: SessionMemoryRecord) -> None:
        """Mark session as updated and touched."""
        now_iso = _utc_now_iso()
        record.updated_at = now_iso
        record.last_accessed_at = now_iso
        record.expires_at_unix = _unix_now() + self.config.session_ttl_seconds

    def _prune_oldest_session_in_scope(self, scope: Tuple[str, str]) -> None:
        """
        Remove the oldest session inside a user/workspace scope.
        Caller must hold lock.
        """
        sessions = self._sessions.get(scope, {})
        if not sessions:
            return

        oldest_session_id = min(
            sessions.keys(),
            key=lambda sid: sessions[sid].last_accessed_at,
        )

        removed = sessions.pop(oldest_session_id, None)
        if removed:
            self._log_audit_event(
                action="session_pruned_oldest",
                user_id=removed.user_id,
                workspace_id=removed.workspace_id,
                session_id=removed.session_id,
                details={"reason": "max_sessions_per_scope_reached"},
            )

    def _cleanup_stale_sessions_locked(self) -> int:
        """
        Remove expired sessions. Caller must hold lock.

        Returns:
            Number of removed sessions.
        """
        now = _unix_now()
        removed_count = 0
        empty_scopes: List[Tuple[str, str]] = []

        for scope, sessions in self._sessions.items():
            expired_ids = [
                session_id
                for session_id, record in sessions.items()
                if record.expires_at_unix is not None and record.expires_at_unix < now
            ]

            for session_id in expired_ids:
                record = sessions.pop(session_id, None)
                if record:
                    removed_count += 1
                    self._log_audit_event(
                        action="session_expired",
                        user_id=record.user_id,
                        workspace_id=record.workspace_id,
                        session_id=record.session_id,
                        details={"reason": "ttl_expired"},
                    )

            if not sessions:
                empty_scopes.append(scope)

        for scope in empty_scopes:
            self._sessions.pop(scope, None)

        return removed_count

    def _maybe_cleanup(self) -> None:
        """Opportunistically cleanup stale sessions when enabled."""
        if not self.config.enable_auto_cleanup:
            return
        with self._lock:
            self._cleanup_stale_sessions_locked()

    # -------------------------------------------------------------------------
    # Structured result helpers
    # -------------------------------------------------------------------------

    def _safe_result(
        self,
        message: str,
        data: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Return standard success result.

        Required compatibility hook.
        """
        return {
            "success": True,
            "message": message,
            "data": data if data is not None else {},
            "error": None,
            "metadata": {
                "agent": self.agent_name,
                "agent_version": self.agent_version,
                "timestamp": _utc_now_iso(),
                **dict(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Union[str, Exception]] = None,
        data: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Return standard error result.

        Required compatibility hook.
        """
        error_value = str(error) if error is not None else message
        return {
            "success": False,
            "message": message,
            "data": data if data is not None else {},
            "error": error_value,
            "metadata": {
                "agent": self.agent_name,
                "agent_version": self.agent_version,
                "timestamp": _utc_now_iso(),
                **dict(metadata or {}),
            },
        }

    # -------------------------------------------------------------------------
    # Security hooks
    # -------------------------------------------------------------------------

    def _requires_security_check(
        self,
        action: str,
        command: Optional[str] = None,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Determine whether an action requires Security Agent approval.

        Required compatibility hook.

        This method does not call external services. It returns a boolean that
        the Master Agent / Security Agent can use to decide routing.

        Args:
            action:
                Action name such as add_recent_command, set_active_task.

            command:
                Optional command text.

            payload:
                Optional payload.

        Returns:
            True if action appears sensitive.
        """
        action_lower = str(action or "").lower()
        command_lower = str(command or "").lower()

        sensitive_actions = {
            "delete_session",
            "clear_scope",
            "clear_all",
            "execute_command",
            "send_message",
            "send_email",
            "make_call",
            "browser_action",
            "financial_action",
            "system_action",
            "destructive_action",
        }

        if action_lower in sensitive_actions:
            return True

        if command_lower:
            for pattern in SENSITIVE_COMMAND_PATTERNS:
                if re.search(pattern, command_lower, flags=re.IGNORECASE):
                    return True

        if payload:
            serialized = _safe_json_dumps(payload).lower()
            for pattern in SENSITIVE_COMMAND_PATTERNS:
                if re.search(pattern, serialized, flags=re.IGNORECASE):
                    return True

        return False

    def _request_security_approval(
        self,
        user_id: str,
        workspace_id: str,
        session_id: str,
        action: str,
        reason: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare a Security Agent approval request payload.

        Required compatibility hook.

        This method does not approve anything by itself. It prepares a structured
        payload that Master Agent or Agent Router can send to Security Agent.
        """
        approval_request = {
            "approval_id": _safe_uuid("sec_approval"),
            "requested_by_agent": self.agent_name,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "session_id": session_id,
            "action": action,
            "reason": reason,
            "payload": self._sanitize_payload(payload or {}),
            "status": "pending",
            "created_at": _utc_now_iso(),
        }

        self._log_audit_event(
            action="security_approval_requested",
            user_id=user_id,
            workspace_id=workspace_id,
            session_id=session_id,
            details=approval_request,
        )

        self._emit_agent_event(
            event_type="security_approval_requested",
            user_id=user_id,
            workspace_id=workspace_id,
            session_id=session_id,
            data=approval_request,
        )

        return approval_request

    # -------------------------------------------------------------------------
    # Verification, Memory, Event, Audit hooks
    # -------------------------------------------------------------------------

    def _prepare_verification_payload(
        self,
        user_id: str,
        workspace_id: str,
        session_id: str,
        action: str,
        result: Mapping[str, Any],
        before: Optional[Mapping[str, Any]] = None,
        after: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        Required compatibility hook.
        """
        return {
            "verification_id": _safe_uuid("verify"),
            "source_agent": self.agent_name,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "session_id": session_id,
            "action": action,
            "success": bool(result.get("success")),
            "message": result.get("message"),
            "before": self._sanitize_payload(before or {}),
            "after": self._sanitize_payload(after or {}),
            "result_metadata": self._sanitize_payload(result.get("metadata", {})),
            "created_at": _utc_now_iso(),
        }

    def _prepare_memory_payload(
        self,
        user_id: str,
        workspace_id: str,
        session_id: str,
        memory_type: str,
        content: Mapping[str, Any],
        importance: str = "session",
    ) -> Dict[str, Any]:
        """
        Prepare payload compatible with Memory Agent.

        Required compatibility hook.

        This is useful when short-term context should later be summarized,
        synced, backed up, or moved to long-term memory.
        """
        return {
            "memory_id": _safe_uuid("memory_payload"),
            "source_agent": self.agent_name,
            "memory_type": memory_type,
            "importance": importance,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "session_id": session_id,
            "content": self._sanitize_payload(content),
            "created_at": _utc_now_iso(),
            "ttl_seconds": self.config.session_ttl_seconds,
        }

    def _emit_agent_event(
        self,
        event_type: str,
        user_id: Optional[str],
        workspace_id: Optional[str],
        session_id: Optional[str],
        data: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Emit an internal agent event.

        Required compatibility hook.

        This in-memory event queue can be consumed later by dashboard/API or an
        event bus integration.
        """
        event = {
            "event_id": _safe_uuid("evt"),
            "event_type": str(event_type),
            "source_agent": self.agent_name,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "session_id": session_id,
            "data": self._sanitize_payload(data or {}),
            "created_at": _utc_now_iso(),
        }

        with self._lock:
            self._agent_events.append(event)

        return event

    def _log_audit_event(
        self,
        action: str,
        user_id: Optional[str],
        workspace_id: Optional[str],
        session_id: Optional[str],
        details: Optional[Mapping[str, Any]] = None,
        level: str = "info",
    ) -> Dict[str, Any]:
        """
        Log internal audit event.

        Required compatibility hook.

        This is in-memory only. Future memory_backup.py or audit service can
        persist it.
        """
        event = {
            "audit_id": _safe_uuid("audit"),
            "action": str(action),
            "level": str(level),
            "source_agent": self.agent_name,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "session_id": session_id,
            "details": self._sanitize_payload(details or {}),
            "created_at": _utc_now_iso(),
        }

        with self._lock:
            self._audit_events.append(event)

        if level.lower() in {"warning", "error", "critical"}:
            self.logger.warning("ShortTermMemory audit event: %s", _safe_json_dumps(event))
        else:
            self.logger.debug("ShortTermMemory audit event: %s", _safe_json_dumps(event))

        return event

    # -------------------------------------------------------------------------
    # Session context public methods
    # -------------------------------------------------------------------------

    def set_session_context(
        self,
        user_id: Any,
        workspace_id: Any,
        session_id: Any,
        context: Mapping[str, Any],
        merge: bool = True,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Set or merge current session context.

        Args:
            user_id:
                SaaS user id.

            workspace_id:
                SaaS workspace id.

            session_id:
                Current session id.

            context:
                Context dictionary. Example:
                    {
                        "current_page": "dashboard",
                        "last_user_message": "...",
                        "active_file": "agents/code_agent/editor.py"
                    }

            merge:
                If True, merge into existing context.
                If False, replace context.

            metadata:
                Optional metadata.

        Returns:
            Structured result.
        """
        try:
            self._maybe_cleanup()

            normalized_user_id, normalized_workspace_id, normalized_session_id = self._session_key(
                user_id, workspace_id, session_id
            )
            context_dict = _coerce_dict(context, "context")
            metadata_dict = _coerce_dict(metadata, "metadata")

            sanitized_context = self._sanitize_payload(context_dict)

            with self._lock:
                record = self._get_or_create_session(
                    normalized_user_id,
                    normalized_workspace_id,
                    normalized_session_id,
                    metadata=metadata_dict,
                )
                before = record.to_dict()

                if merge:
                    record.context.update(sanitized_context)
                else:
                    record.context = sanitized_context

                if metadata_dict:
                    record.metadata.update(self._sanitize_payload(metadata_dict))

                self._mark_updated(record)
                after = record.to_dict()

            result = self._safe_result(
                message="Session context updated.",
                data={
                    "session": after,
                    "verification_payload": self._prepare_verification_payload(
                        normalized_user_id,
                        normalized_workspace_id,
                        normalized_session_id,
                        "set_session_context",
                        {"success": True, "message": "Session context updated."},
                        before=before,
                        after=after,
                    ),
                    "memory_payload": self._prepare_memory_payload(
                        normalized_user_id,
                        normalized_workspace_id,
                        normalized_session_id,
                        "short_term_session_context",
                        after,
                    ),
                },
            )

            self._log_audit_event(
                action="session_context_updated",
                user_id=normalized_user_id,
                workspace_id=normalized_workspace_id,
                session_id=normalized_session_id,
                details={"merge": merge, "context_keys": list(sanitized_context.keys())},
            )

            self._emit_agent_event(
                event_type="session_context_updated",
                user_id=normalized_user_id,
                workspace_id=normalized_workspace_id,
                session_id=normalized_session_id,
                data={"merge": merge, "context_keys": list(sanitized_context.keys())},
            )

            return result

        except Exception as exc:
            return self._error_result("Failed to set session context.", exc)

    def get_session_context(
        self,
        user_id: Any,
        workspace_id: Any,
        session_id: Any,
    ) -> Dict[str, Any]:
        """
        Get current session context.

        Returns:
            Structured result with context.
        """
        try:
            normalized_user_id, normalized_workspace_id, normalized_session_id = self._session_key(
                user_id, workspace_id, session_id
            )

            with self._lock:
                record = self._get_existing_session(
                    normalized_user_id,
                    normalized_workspace_id,
                    normalized_session_id,
                )

                if not record:
                    return self._safe_result(
                        message="Session context not found.",
                        data={
                            "context": {},
                            "exists": False,
                            "user_id": normalized_user_id,
                            "workspace_id": normalized_workspace_id,
                            "session_id": normalized_session_id,
                        },
                    )

                self._touch_session(record)
                context = _deepcopy_safe(record.context)

            return self._safe_result(
                message="Session context retrieved.",
                data={
                    "context": context,
                    "exists": True,
                    "user_id": normalized_user_id,
                    "workspace_id": normalized_workspace_id,
                    "session_id": normalized_session_id,
                },
            )

        except Exception as exc:
            return self._error_result("Failed to get session context.", exc)

    def update_context_key(
        self,
        user_id: Any,
        workspace_id: Any,
        session_id: Any,
        key: str,
        value: Any,
    ) -> Dict[str, Any]:
        """
        Update a single context key in a session.

        Useful for dashboard/API incremental updates.
        """
        try:
            if not str(key).strip():
                raise ValueError("key is required.")

            return self.set_session_context(
                user_id=user_id,
                workspace_id=workspace_id,
                session_id=session_id,
                context={str(key): value},
                merge=True,
            )

        except Exception as exc:
            return self._error_result("Failed to update context key.", exc)

    def remove_context_key(
        self,
        user_id: Any,
        workspace_id: Any,
        session_id: Any,
        key: str,
    ) -> Dict[str, Any]:
        """
        Remove a single key from session context.
        """
        try:
            normalized_user_id, normalized_workspace_id, normalized_session_id = self._session_key(
                user_id, workspace_id, session_id
            )
            clean_key = str(key).strip()
            if not clean_key:
                raise ValueError("key is required.")

            with self._lock:
                record = self._get_existing_session(
                    normalized_user_id,
                    normalized_workspace_id,
                    normalized_session_id,
                )
                if not record:
                    return self._safe_result(
                        message="Session not found. No context key removed.",
                        data={"removed": False, "key": clean_key},
                    )

                before = record.to_dict()
                existed = clean_key in record.context
                removed_value = record.context.pop(clean_key, None)
                self._mark_updated(record)
                after = record.to_dict()

            result = self._safe_result(
                message="Context key removed." if existed else "Context key did not exist.",
                data={
                    "removed": existed,
                    "key": clean_key,
                    "removed_value": self._sanitize_payload(removed_value),
                    "verification_payload": self._prepare_verification_payload(
                        normalized_user_id,
                        normalized_workspace_id,
                        normalized_session_id,
                        "remove_context_key",
                        {"success": True, "message": "Context key removal attempted."},
                        before=before,
                        after=after,
                    ),
                },
            )

            self._log_audit_event(
                action="context_key_removed",
                user_id=normalized_user_id,
                workspace_id=normalized_workspace_id,
                session_id=normalized_session_id,
                details={"key": clean_key, "removed": existed},
            )

            return result

        except Exception as exc:
            return self._error_result("Failed to remove context key.", exc)

    # -------------------------------------------------------------------------
    # Active task public methods
    # -------------------------------------------------------------------------

    def set_active_task(
        self,
        user_id: Any,
        workspace_id: Any,
        session_id: Any,
        task: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Set active task for a session.

        Expected task fields:
            - task_id optional, auto-created if missing.
            - title optional.
            - status optional, default running.
            - agent_name optional.
            - priority optional.
            - input_summary optional.
            - progress optional.
            - metadata optional.
        """
        try:
            self._maybe_cleanup()

            normalized_user_id, normalized_workspace_id, normalized_session_id = self._session_key(
                user_id, workspace_id, session_id
            )
            task_dict = self._sanitize_payload(_coerce_dict(task, "task"))

            task_id = str(task_dict.get("task_id") or _safe_uuid("task"))
            title = str(task_dict.get("title") or task_dict.get("name") or "Untitled Task")
            status = str(task_dict.get("status") or "running").lower()

            if status not in SAFE_TASK_STATUSES:
                raise ValueError(
                    f"Invalid task status '{status}'. Allowed: {sorted(SAFE_TASK_STATUSES)}"
                )

            progress_raw = task_dict.get("progress", 0.0)
            try:
                progress = float(progress_raw)
            except Exception:
                progress = 0.0
            progress = max(0.0, min(100.0, progress))

            task_record = ActiveTaskRecord(
                task_id=_normalize_identifier(task_id, "task_id"),
                title=_truncate_string(title, 512),
                status=status,
                agent_name=str(task_dict.get("agent_name")).strip()
                if task_dict.get("agent_name") is not None
                else None,
                priority=str(task_dict.get("priority") or "normal"),
                input_summary=str(task_dict.get("input_summary")).strip()
                if task_dict.get("input_summary") is not None
                else None,
                progress=progress,
                metadata=self._sanitize_payload(task_dict.get("metadata", {})),
            )

            requires_security = self._requires_security_check(
                action="set_active_task",
                payload=task_dict,
            )
            security_request = None
            if requires_security:
                security_request = self._request_security_approval(
                    normalized_user_id,
                    normalized_workspace_id,
                    normalized_session_id,
                    action="set_active_task",
                    reason="Active task payload appears sensitive.",
                    payload=task_dict,
                )
                task_record.status = "waiting_security_approval"

            with self._lock:
                record = self._get_or_create_session(
                    normalized_user_id,
                    normalized_workspace_id,
                    normalized_session_id,
                )
                before = record.to_dict()
                record.active_task = task_record
                self._mark_updated(record)
                after = record.to_dict()

            result = self._safe_result(
                message="Active task updated.",
                data={
                    "active_task": asdict(task_record),
                    "requires_security_check": requires_security,
                    "security_request": security_request,
                    "verification_payload": self._prepare_verification_payload(
                        normalized_user_id,
                        normalized_workspace_id,
                        normalized_session_id,
                        "set_active_task",
                        {"success": True, "message": "Active task updated."},
                        before=before,
                        after=after,
                    ),
                    "memory_payload": self._prepare_memory_payload(
                        normalized_user_id,
                        normalized_workspace_id,
                        normalized_session_id,
                        "short_term_active_task",
                        {"active_task": asdict(task_record)},
                    ),
                },
            )

            self._log_audit_event(
                action="active_task_updated",
                user_id=normalized_user_id,
                workspace_id=normalized_workspace_id,
                session_id=normalized_session_id,
                details={
                    "task_id": task_record.task_id,
                    "status": task_record.status,
                    "agent_name": task_record.agent_name,
                    "requires_security_check": requires_security,
                },
            )

            self._emit_agent_event(
                event_type="active_task_updated",
                user_id=normalized_user_id,
                workspace_id=normalized_workspace_id,
                session_id=normalized_session_id,
                data=asdict(task_record),
            )

            return result

        except Exception as exc:
            return self._error_result("Failed to set active task.", exc)

    def get_active_task(
        self,
        user_id: Any,
        workspace_id: Any,
        session_id: Any,
    ) -> Dict[str, Any]:
        """
        Get active task for a session.
        """
        try:
            normalized_user_id, normalized_workspace_id, normalized_session_id = self._session_key(
                user_id, workspace_id, session_id
            )

            with self._lock:
                record = self._get_existing_session(
                    normalized_user_id,
                    normalized_workspace_id,
                    normalized_session_id,
                )

                if not record or not record.active_task:
                    return self._safe_result(
                        message="No active task found.",
                        data={
                            "active_task": None,
                            "exists": False,
                            "user_id": normalized_user_id,
                            "workspace_id": normalized_workspace_id,
                            "session_id": normalized_session_id,
                        },
                    )

                self._touch_session(record)
                task_payload = asdict(record.active_task)

            return self._safe_result(
                message="Active task retrieved.",
                data={
                    "active_task": task_payload,
                    "exists": True,
                    "user_id": normalized_user_id,
                    "workspace_id": normalized_workspace_id,
                    "session_id": normalized_session_id,
                },
            )

        except Exception as exc:
            return self._error_result("Failed to get active task.", exc)

    def update_active_task_status(
        self,
        user_id: Any,
        workspace_id: Any,
        session_id: Any,
        status: str,
        progress: Optional[float] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Update active task status and optional progress.
        """
        try:
            normalized_user_id, normalized_workspace_id, normalized_session_id = self._session_key(
                user_id, workspace_id, session_id
            )
            normalized_status = str(status).lower().strip()

            if normalized_status not in SAFE_TASK_STATUSES:
                raise ValueError(
                    f"Invalid task status '{normalized_status}'. "
                    f"Allowed: {sorted(SAFE_TASK_STATUSES)}"
                )

            metadata_dict = self._sanitize_payload(_coerce_dict(metadata, "metadata"))

            with self._lock:
                record = self._get_existing_session(
                    normalized_user_id,
                    normalized_workspace_id,
                    normalized_session_id,
                )

                if not record or not record.active_task:
                    return self._safe_result(
                        message="No active task found to update.",
                        data={"updated": False, "active_task": None},
                    )

                before = record.to_dict()

                record.active_task.status = normalized_status
                record.active_task.updated_at = _utc_now_iso()

                if progress is not None:
                    record.active_task.progress = max(0.0, min(100.0, float(progress)))

                if metadata_dict:
                    record.active_task.metadata.update(metadata_dict)

                self._mark_updated(record)
                after = record.to_dict()

            result = self._safe_result(
                message="Active task status updated.",
                data={
                    "updated": True,
                    "active_task": after.get("active_task"),
                    "verification_payload": self._prepare_verification_payload(
                        normalized_user_id,
                        normalized_workspace_id,
                        normalized_session_id,
                        "update_active_task_status",
                        {"success": True, "message": "Active task status updated."},
                        before=before,
                        after=after,
                    ),
                },
            )

            self._log_audit_event(
                action="active_task_status_updated",
                user_id=normalized_user_id,
                workspace_id=normalized_workspace_id,
                session_id=normalized_session_id,
                details={
                    "status": normalized_status,
                    "progress": progress,
                    "metadata_keys": list(metadata_dict.keys()),
                },
            )

            return result

        except Exception as exc:
            return self._error_result("Failed to update active task status.", exc)

    def clear_active_task(
        self,
        user_id: Any,
        workspace_id: Any,
        session_id: Any,
    ) -> Dict[str, Any]:
        """
        Clear active task from a session.
        """
        try:
            normalized_user_id, normalized_workspace_id, normalized_session_id = self._session_key(
                user_id, workspace_id, session_id
            )

            with self._lock:
                record = self._get_existing_session(
                    normalized_user_id,
                    normalized_workspace_id,
                    normalized_session_id,
                )

                if not record:
                    return self._safe_result(
                        message="Session not found. No active task cleared.",
                        data={"cleared": False},
                    )

                before = record.to_dict()
                existed = record.active_task is not None
                record.active_task = None
                self._mark_updated(record)
                after = record.to_dict()

            result = self._safe_result(
                message="Active task cleared." if existed else "No active task existed.",
                data={
                    "cleared": existed,
                    "verification_payload": self._prepare_verification_payload(
                        normalized_user_id,
                        normalized_workspace_id,
                        normalized_session_id,
                        "clear_active_task",
                        {"success": True, "message": "Active task clear attempted."},
                        before=before,
                        after=after,
                    ),
                },
            )

            self._log_audit_event(
                action="active_task_cleared",
                user_id=normalized_user_id,
                workspace_id=normalized_workspace_id,
                session_id=normalized_session_id,
                details={"cleared": existed},
            )

            return result

        except Exception as exc:
            return self._error_result("Failed to clear active task.", exc)

    # -------------------------------------------------------------------------
    # Active agent public methods
    # -------------------------------------------------------------------------

    def set_active_agent(
        self,
        user_id: Any,
        workspace_id: Any,
        session_id: Any,
        agent_name: str,
        agent_id: Optional[str] = None,
        status: str = "active",
        capabilities: Optional[Iterable[str]] = None,
        route_reason: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Set active routed agent for a session.

        Useful for Master Agent and Agent Router.
        """
        try:
            self._maybe_cleanup()

            normalized_user_id, normalized_workspace_id, normalized_session_id = self._session_key(
                user_id, workspace_id, session_id
            )

            clean_agent_name = str(agent_name or "").strip()
            if not clean_agent_name:
                raise ValueError("agent_name is required.")

            normalized_status = str(status or "active").strip().lower()
            if normalized_status not in SAFE_AGENT_STATUSES:
                raise ValueError(
                    f"Invalid agent status '{normalized_status}'. "
                    f"Allowed: {sorted(SAFE_AGENT_STATUSES)}"
                )

            clean_capabilities = [
                _truncate_string(str(item).strip(), 128)
                for item in list(capabilities or [])
                if str(item).strip()
            ]

            agent_record = ActiveAgentRecord(
                agent_name=_truncate_string(clean_agent_name, 128),
                status=normalized_status,
                agent_id=_truncate_string(str(agent_id), 128) if agent_id else None,
                capabilities=clean_capabilities,
                route_reason=_truncate_string(str(route_reason), 1024) if route_reason else None,
                metadata=self._sanitize_payload(_coerce_dict(metadata, "metadata")),
            )

            with self._lock:
                record = self._get_or_create_session(
                    normalized_user_id,
                    normalized_workspace_id,
                    normalized_session_id,
                )
                before = record.to_dict()
                record.active_agent = agent_record
                self._mark_updated(record)
                after = record.to_dict()

            result = self._safe_result(
                message="Active agent updated.",
                data={
                    "active_agent": asdict(agent_record),
                    "verification_payload": self._prepare_verification_payload(
                        normalized_user_id,
                        normalized_workspace_id,
                        normalized_session_id,
                        "set_active_agent",
                        {"success": True, "message": "Active agent updated."},
                        before=before,
                        after=after,
                    ),
                    "memory_payload": self._prepare_memory_payload(
                        normalized_user_id,
                        normalized_workspace_id,
                        normalized_session_id,
                        "short_term_active_agent",
                        {"active_agent": asdict(agent_record)},
                    ),
                },
            )

            self._log_audit_event(
                action="active_agent_updated",
                user_id=normalized_user_id,
                workspace_id=normalized_workspace_id,
                session_id=normalized_session_id,
                details={
                    "agent_name": agent_record.agent_name,
                    "agent_id": agent_record.agent_id,
                    "status": agent_record.status,
                },
            )

            self._emit_agent_event(
                event_type="active_agent_updated",
                user_id=normalized_user_id,
                workspace_id=normalized_workspace_id,
                session_id=normalized_session_id,
                data=asdict(agent_record),
            )

            return result

        except Exception as exc:
            return self._error_result("Failed to set active agent.", exc)

    def get_active_agent(
        self,
        user_id: Any,
        workspace_id: Any,
        session_id: Any,
    ) -> Dict[str, Any]:
        """
        Get active agent for a session.
        """
        try:
            normalized_user_id, normalized_workspace_id, normalized_session_id = self._session_key(
                user_id, workspace_id, session_id
            )

            with self._lock:
                record = self._get_existing_session(
                    normalized_user_id,
                    normalized_workspace_id,
                    normalized_session_id,
                )

                if not record or not record.active_agent:
                    return self._safe_result(
                        message="No active agent found.",
                        data={
                            "active_agent": None,
                            "exists": False,
                            "user_id": normalized_user_id,
                            "workspace_id": normalized_workspace_id,
                            "session_id": normalized_session_id,
                        },
                    )

                self._touch_session(record)
                agent_payload = asdict(record.active_agent)

            return self._safe_result(
                message="Active agent retrieved.",
                data={
                    "active_agent": agent_payload,
                    "exists": True,
                    "user_id": normalized_user_id,
                    "workspace_id": normalized_workspace_id,
                    "session_id": normalized_session_id,
                },
            )

        except Exception as exc:
            return self._error_result("Failed to get active agent.", exc)

    def clear_active_agent(
        self,
        user_id: Any,
        workspace_id: Any,
        session_id: Any,
    ) -> Dict[str, Any]:
        """
        Clear active agent from a session.
        """
        try:
            normalized_user_id, normalized_workspace_id, normalized_session_id = self._session_key(
                user_id, workspace_id, session_id
            )

            with self._lock:
                record = self._get_existing_session(
                    normalized_user_id,
                    normalized_workspace_id,
                    normalized_session_id,
                )

                if not record:
                    return self._safe_result(
                        message="Session not found. No active agent cleared.",
                        data={"cleared": False},
                    )

                before = record.to_dict()
                existed = record.active_agent is not None
                record.active_agent = None
                self._mark_updated(record)
                after = record.to_dict()

            result = self._safe_result(
                message="Active agent cleared." if existed else "No active agent existed.",
                data={
                    "cleared": existed,
                    "verification_payload": self._prepare_verification_payload(
                        normalized_user_id,
                        normalized_workspace_id,
                        normalized_session_id,
                        "clear_active_agent",
                        {"success": True, "message": "Active agent clear attempted."},
                        before=before,
                        after=after,
                    ),
                },
            )

            self._log_audit_event(
                action="active_agent_cleared",
                user_id=normalized_user_id,
                workspace_id=normalized_workspace_id,
                session_id=normalized_session_id,
                details={"cleared": existed},
            )

            return result

        except Exception as exc:
            return self._error_result("Failed to clear active agent.", exc)

    # -------------------------------------------------------------------------
    # Recent commands public methods
    # -------------------------------------------------------------------------

    def add_recent_command(
        self,
        user_id: Any,
        workspace_id: Any,
        session_id: Any,
        command: str,
        command_type: str = "user",
        status: str = "recorded",
        agent_name: Optional[str] = None,
        task_id: Optional[str] = None,
        source: str = "unknown",
        metadata: Optional[Mapping[str, Any]] = None,
        security_approved: bool = False,
    ) -> Dict[str, Any]:
        """
        Add a recent command to session memory.

        Commands are not executed here. This method only records the command.

        Args:
            user_id:
                SaaS user id.

            workspace_id:
                SaaS workspace id.

            session_id:
                Current session id.

            command:
                Command text or user instruction.

            command_type:
                user/system/agent/api/dashboard.

            status:
                recorded/queued/running/completed/failed/blocked.

            agent_name:
                Optional agent associated with the command.

            task_id:
                Optional active task id.

            source:
                Where the command came from: chat, api, dashboard, scheduler, etc.

            metadata:
                Optional metadata.

            security_approved:
                Whether external Security Agent has already approved it.

        Returns:
            Structured result.
        """
        try:
            if not self.config.allow_command_storage:
                return self._safe_result(
                    message="Command storage is disabled by configuration.",
                    data={"stored": False},
                )

            self._maybe_cleanup()

            normalized_user_id, normalized_workspace_id, normalized_session_id = self._session_key(
                user_id, workspace_id, session_id
            )

            clean_command = str(command or "").strip()
            if not clean_command:
                raise ValueError("command is required.")

            clean_command = self._sanitize_payload(clean_command)
            clean_metadata = self._sanitize_payload(_coerce_dict(metadata, "metadata"))

            requires_security = self._requires_security_check(
                action="add_recent_command",
                command=clean_command,
                payload=clean_metadata if isinstance(clean_metadata, Mapping) else {},
            )

            security_request = None
            final_status = str(status or "recorded").strip().lower()

            if requires_security and not security_approved:
                final_status = "waiting_security_approval"
                security_request = self._request_security_approval(
                    normalized_user_id,
                    normalized_workspace_id,
                    normalized_session_id,
                    action="add_recent_command",
                    reason="Command appears sensitive and requires Security Agent review.",
                    payload={
                        "command": clean_command,
                        "command_type": command_type,
                        "agent_name": agent_name,
                        "task_id": task_id,
                        "source": source,
                        "metadata": clean_metadata,
                    },
                )

            command_record = CommandRecord(
                command_id=_safe_uuid("cmd"),
                command=str(clean_command),
                command_type=_truncate_string(str(command_type or "user"), 64),
                status=_truncate_string(final_status, 64),
                agent_name=_truncate_string(str(agent_name), 128) if agent_name else None,
                task_id=_truncate_string(str(task_id), 128) if task_id else None,
                source=_truncate_string(str(source or "unknown"), 128),
                requires_security_check=requires_security,
                security_approved=bool(security_approved),
                metadata=clean_metadata if isinstance(clean_metadata, dict) else {"value": clean_metadata},
            )

            with self._lock:
                record = self._get_or_create_session(
                    normalized_user_id,
                    normalized_workspace_id,
                    normalized_session_id,
                )
                before = record.to_dict()

                while len(record.recent_commands) >= self.config.max_commands_per_session:
                    record.recent_commands.popleft()

                record.recent_commands.append(command_record)
                self._mark_updated(record)
                after = record.to_dict()

            result = self._safe_result(
                message="Recent command recorded.",
                data={
                    "stored": True,
                    "command": asdict(command_record),
                    "requires_security_check": requires_security,
                    "security_request": security_request,
                    "verification_payload": self._prepare_verification_payload(
                        normalized_user_id,
                        normalized_workspace_id,
                        normalized_session_id,
                        "add_recent_command",
                        {"success": True, "message": "Recent command recorded."},
                        before=before,
                        after=after,
                    ),
                    "memory_payload": self._prepare_memory_payload(
                        normalized_user_id,
                        normalized_workspace_id,
                        normalized_session_id,
                        "short_term_recent_command",
                        {"command": asdict(command_record)},
                    ),
                },
            )

            self._log_audit_event(
                action="recent_command_added",
                user_id=normalized_user_id,
                workspace_id=normalized_workspace_id,
                session_id=normalized_session_id,
                details={
                    "command_id": command_record.command_id,
                    "command_type": command_record.command_type,
                    "status": command_record.status,
                    "agent_name": command_record.agent_name,
                    "requires_security_check": requires_security,
                },
            )

            self._emit_agent_event(
                event_type="recent_command_added",
                user_id=normalized_user_id,
                workspace_id=normalized_workspace_id,
                session_id=normalized_session_id,
                data=asdict(command_record),
            )

            return result

        except Exception as exc:
            return self._error_result("Failed to add recent command.", exc)

    def get_recent_commands(
        self,
        user_id: Any,
        workspace_id: Any,
        session_id: Any,
        limit: int = 20,
        newest_first: bool = True,
        agent_name: Optional[str] = None,
        command_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Get recent commands from a session.

        Args:
            limit:
                Maximum commands to return.

            newest_first:
                If True, return newest commands first.

            agent_name:
                Optional filter.

            command_type:
                Optional filter.
        """
        try:
            normalized_user_id, normalized_workspace_id, normalized_session_id = self._session_key(
                user_id, workspace_id, session_id
            )

            safe_limit = max(1, min(int(limit), self.config.max_commands_per_session))

            with self._lock:
                record = self._get_existing_session(
                    normalized_user_id,
                    normalized_workspace_id,
                    normalized_session_id,
                )

                if not record:
                    return self._safe_result(
                        message="Session not found. No recent commands returned.",
                        data={"commands": [], "count": 0, "exists": False},
                    )

                self._touch_session(record)
                commands = list(record.recent_commands)

            if agent_name:
                commands = [
                    item for item in commands
                    if item.agent_name and item.agent_name.lower() == str(agent_name).lower()
                ]

            if command_type:
                commands = [
                    item for item in commands
                    if item.command_type.lower() == str(command_type).lower()
                ]

            if newest_first:
                commands = list(reversed(commands))

            commands = commands[:safe_limit]
            payload = [asdict(item) for item in commands]

            return self._safe_result(
                message="Recent commands retrieved.",
                data={
                    "commands": payload,
                    "count": len(payload),
                    "exists": True,
                    "limit": safe_limit,
                    "newest_first": newest_first,
                },
            )

        except Exception as exc:
            return self._error_result("Failed to get recent commands.", exc)

    def clear_recent_commands(
        self,
        user_id: Any,
        workspace_id: Any,
        session_id: Any,
    ) -> Dict[str, Any]:
        """
        Clear recent commands for a session.
        """
        try:
            normalized_user_id, normalized_workspace_id, normalized_session_id = self._session_key(
                user_id, workspace_id, session_id
            )

            with self._lock:
                record = self._get_existing_session(
                    normalized_user_id,
                    normalized_workspace_id,
                    normalized_session_id,
                )

                if not record:
                    return self._safe_result(
                        message="Session not found. No recent commands cleared.",
                        data={"cleared": False, "count": 0},
                    )

                before = record.to_dict()
                count = len(record.recent_commands)
                record.recent_commands.clear()
                self._mark_updated(record)
                after = record.to_dict()

            result = self._safe_result(
                message="Recent commands cleared.",
                data={
                    "cleared": True,
                    "count": count,
                    "verification_payload": self._prepare_verification_payload(
                        normalized_user_id,
                        normalized_workspace_id,
                        normalized_session_id,
                        "clear_recent_commands",
                        {"success": True, "message": "Recent commands cleared."},
                        before=before,
                        after=after,
                    ),
                },
            )

            self._log_audit_event(
                action="recent_commands_cleared",
                user_id=normalized_user_id,
                workspace_id=normalized_workspace_id,
                session_id=normalized_session_id,
                details={"count": count},
            )

            return result

        except Exception as exc:
            return self._error_result("Failed to clear recent commands.", exc)

    # -------------------------------------------------------------------------
    # Snapshot / export public methods
    # -------------------------------------------------------------------------

    def get_session_snapshot(
        self,
        user_id: Any,
        workspace_id: Any,
        session_id: Any,
        include_verification_payload: bool = True,
        include_memory_payload: bool = True,
    ) -> Dict[str, Any]:
        """
        Get complete short-term snapshot for current session.

        This is the main method for Master Agent, Dashboard/API, and Agent Router.
        """
        try:
            normalized_user_id, normalized_workspace_id, normalized_session_id = self._session_key(
                user_id, workspace_id, session_id
            )

            with self._lock:
                record = self._get_existing_session(
                    normalized_user_id,
                    normalized_workspace_id,
                    normalized_session_id,
                )

                if not record:
                    return self._safe_result(
                        message="Session snapshot not found.",
                        data={
                            "snapshot": None,
                            "exists": False,
                            "user_id": normalized_user_id,
                            "workspace_id": normalized_workspace_id,
                            "session_id": normalized_session_id,
                        },
                    )

                self._touch_session(record)
                snapshot = record.to_dict()

            data: Dict[str, Any] = {
                "snapshot": snapshot,
                "exists": True,
                "user_id": normalized_user_id,
                "workspace_id": normalized_workspace_id,
                "session_id": normalized_session_id,
            }

            if include_verification_payload:
                data["verification_payload"] = self._prepare_verification_payload(
                    normalized_user_id,
                    normalized_workspace_id,
                    normalized_session_id,
                    "get_session_snapshot",
                    {"success": True, "message": "Session snapshot retrieved."},
                    before=snapshot,
                    after=snapshot,
                )

            if include_memory_payload:
                data["memory_payload"] = self._prepare_memory_payload(
                    normalized_user_id,
                    normalized_workspace_id,
                    normalized_session_id,
                    "short_term_session_snapshot",
                    snapshot,
                    importance="session_snapshot",
                )

            return self._safe_result(
                message="Session snapshot retrieved.",
                data=data,
            )

        except Exception as exc:
            return self._error_result("Failed to get session snapshot.", exc)

    def list_sessions(
        self,
        user_id: Any,
        workspace_id: Any,
        include_context: bool = False,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """
        List sessions for a specific user/workspace scope.

        Never returns sessions from another user/workspace.
        """
        try:
            ctx = self._validate_task_context(
                user_id=user_id,
                workspace_id=workspace_id,
                session_id="scope",
                require_session_id=True,
            )
            normalized_user_id = ctx["user_id"]
            normalized_workspace_id = ctx["workspace_id"]
            safe_limit = max(1, min(int(limit), self.config.max_sessions_per_scope))

            with self._lock:
                scope = self._scope_key(normalized_user_id, normalized_workspace_id)
                sessions = list(self._sessions.get(scope, {}).values())

                sessions.sort(key=lambda item: item.last_accessed_at, reverse=True)
                sessions = sessions[:safe_limit]

                payload = []
                for record in sessions:
                    item = {
                        "user_id": record.user_id,
                        "workspace_id": record.workspace_id,
                        "session_id": record.session_id,
                        "has_active_task": record.active_task is not None,
                        "has_active_agent": record.active_agent is not None,
                        "recent_command_count": len(record.recent_commands),
                        "created_at": record.created_at,
                        "updated_at": record.updated_at,
                        "last_accessed_at": record.last_accessed_at,
                        "expires_at_unix": record.expires_at_unix,
                        "metadata": _deepcopy_safe(record.metadata),
                    }
                    if include_context:
                        item["context"] = _deepcopy_safe(record.context)
                    payload.append(item)

            return self._safe_result(
                message="Sessions listed.",
                data={
                    "sessions": payload,
                    "count": len(payload),
                    "user_id": normalized_user_id,
                    "workspace_id": normalized_workspace_id,
                },
            )

        except Exception as exc:
            return self._error_result("Failed to list sessions.", exc)

    def export_scope(
        self,
        user_id: Any,
        workspace_id: Any,
        include_audit_events: bool = False,
        include_agent_events: bool = False,
    ) -> Dict[str, Any]:
        """
        Export all short-term memory for a user/workspace scope.

        Useful for memory_sync.py, memory_backup.py, or dashboard export.
        """
        try:
            ctx = self._validate_task_context(
                user_id=user_id,
                workspace_id=workspace_id,
                session_id="scope",
                require_session_id=True,
            )
            normalized_user_id = ctx["user_id"]
            normalized_workspace_id = ctx["workspace_id"]

            with self._lock:
                scope = self._scope_key(normalized_user_id, normalized_workspace_id)
                sessions = [
                    record.to_dict()
                    for record in self._sessions.get(scope, {}).values()
                ]

                audit_events = []
                agent_events = []

                if include_audit_events:
                    audit_events = [
                        event for event in list(self._audit_events)
                        if event.get("user_id") == normalized_user_id
                        and event.get("workspace_id") == normalized_workspace_id
                    ]

                if include_agent_events:
                    agent_events = [
                        event for event in list(self._agent_events)
                        if event.get("user_id") == normalized_user_id
                        and event.get("workspace_id") == normalized_workspace_id
                    ]

            export_payload = {
                "export_id": _safe_uuid("stm_export"),
                "user_id": normalized_user_id,
                "workspace_id": normalized_workspace_id,
                "sessions": sessions,
                "session_count": len(sessions),
                "audit_events": audit_events,
                "agent_events": agent_events,
                "created_at": _utc_now_iso(),
            }

            return self._safe_result(
                message="Scope exported.",
                data=export_payload,
            )

        except Exception as exc:
            return self._error_result("Failed to export scope.", exc)

    # -------------------------------------------------------------------------
    # Clear/delete public methods
    # -------------------------------------------------------------------------

    def delete_session(
        self,
        user_id: Any,
        workspace_id: Any,
        session_id: Any,
        security_approved: bool = False,
    ) -> Dict[str, Any]:
        """
        Delete one session from short-term memory.

        Because deletion is destructive, it can require Security Agent approval.
        """
        try:
            normalized_user_id, normalized_workspace_id, normalized_session_id = self._session_key(
                user_id, workspace_id, session_id
            )

            requires_security = self._requires_security_check("delete_session")
            if requires_security and not security_approved:
                security_request = self._request_security_approval(
                    normalized_user_id,
                    normalized_workspace_id,
                    normalized_session_id,
                    action="delete_session",
                    reason="Deleting short-term session memory is a destructive action.",
                    payload={"session_id": normalized_session_id},
                )
                return self._safe_result(
                    message="Security approval required before deleting session.",
                    data={
                        "deleted": False,
                        "requires_security_check": True,
                        "security_request": security_request,
                    },
                )

            with self._lock:
                scope = self._scope_key(normalized_user_id, normalized_workspace_id)
                sessions = self._sessions.get(scope, {})
                existed = normalized_session_id in sessions
                removed = sessions.pop(normalized_session_id, None)

                if not sessions and scope in self._sessions:
                    self._sessions.pop(scope, None)

            self._log_audit_event(
                action="session_deleted",
                user_id=normalized_user_id,
                workspace_id=normalized_workspace_id,
                session_id=normalized_session_id,
                details={"deleted": existed},
                level="warning",
            )

            return self._safe_result(
                message="Session deleted." if existed else "Session did not exist.",
                data={
                    "deleted": existed,
                    "session": removed.to_dict() if removed else None,
                    "requires_security_check": requires_security,
                },
            )

        except Exception as exc:
            return self._error_result("Failed to delete session.", exc)

    def clear_scope(
        self,
        user_id: Any,
        workspace_id: Any,
        security_approved: bool = False,
    ) -> Dict[str, Any]:
        """
        Clear all sessions for a single user/workspace scope.

        Never clears another user's workspace.
        """
        try:
            ctx = self._validate_task_context(
                user_id=user_id,
                workspace_id=workspace_id,
                session_id="scope",
                require_session_id=True,
            )
            normalized_user_id = ctx["user_id"]
            normalized_workspace_id = ctx["workspace_id"]

            requires_security = self._requires_security_check("clear_scope")
            if requires_security and not security_approved:
                security_request = self._request_security_approval(
                    normalized_user_id,
                    normalized_workspace_id,
                    session_id="scope",
                    action="clear_scope",
                    reason="Clearing all short-term sessions in a workspace is destructive.",
                    payload={
                        "user_id": normalized_user_id,
                        "workspace_id": normalized_workspace_id,
                    },
                )
                return self._safe_result(
                    message="Security approval required before clearing scope.",
                    data={
                        "cleared": False,
                        "requires_security_check": True,
                        "security_request": security_request,
                    },
                )

            with self._lock:
                scope = self._scope_key(normalized_user_id, normalized_workspace_id)
                count = len(self._sessions.get(scope, {}))
                self._sessions.pop(scope, None)

            self._log_audit_event(
                action="scope_cleared",
                user_id=normalized_user_id,
                workspace_id=normalized_workspace_id,
                session_id=None,
                details={"cleared_session_count": count},
                level="warning",
            )

            return self._safe_result(
                message="Workspace short-term memory scope cleared.",
                data={
                    "cleared": True,
                    "cleared_session_count": count,
                    "requires_security_check": requires_security,
                },
            )

        except Exception as exc:
            return self._error_result("Failed to clear scope.", exc)

    def cleanup_stale_sessions(self) -> Dict[str, Any]:
        """
        Public cleanup method for scheduler/dashboard.

        Removes expired sessions.
        """
        try:
            with self._lock:
                removed_count = self._cleanup_stale_sessions_locked()

            return self._safe_result(
                message="Stale sessions cleaned up.",
                data={"removed_count": removed_count},
            )

        except Exception as exc:
            return self._error_result("Failed to cleanup stale sessions.", exc)

    # -------------------------------------------------------------------------
    # Audit / events / diagnostics
    # -------------------------------------------------------------------------

    def get_audit_events(
        self,
        user_id: Optional[Any] = None,
        workspace_id: Optional[Any] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """
        Return recent audit events.

        If user_id/workspace_id are provided, filters to that SaaS scope.
        """
        try:
            safe_limit = max(1, min(int(limit), self.config.audit_log_limit))

            normalized_user_id = None
            normalized_workspace_id = None

            if user_id is not None:
                normalized_user_id = _normalize_identifier(user_id, "user_id")
            if workspace_id is not None:
                normalized_workspace_id = _normalize_identifier(workspace_id, "workspace_id")

            with self._lock:
                events = list(self._audit_events)

            if normalized_user_id is not None:
                events = [event for event in events if event.get("user_id") == normalized_user_id]
            if normalized_workspace_id is not None:
                events = [
                    event for event in events
                    if event.get("workspace_id") == normalized_workspace_id
                ]

            events = list(reversed(events))[:safe_limit]

            return self._safe_result(
                message="Audit events retrieved.",
                data={"events": events, "count": len(events)},
            )

        except Exception as exc:
            return self._error_result("Failed to get audit events.", exc)

    def get_agent_events(
        self,
        user_id: Optional[Any] = None,
        workspace_id: Optional[Any] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """
        Return recent internal agent events.

        Dashboard/API can use this for live activity panels.
        """
        try:
            safe_limit = max(1, min(int(limit), self.config.event_log_limit))

            normalized_user_id = None
            normalized_workspace_id = None

            if user_id is not None:
                normalized_user_id = _normalize_identifier(user_id, "user_id")
            if workspace_id is not None:
                normalized_workspace_id = _normalize_identifier(workspace_id, "workspace_id")

            with self._lock:
                events = list(self._agent_events)

            if normalized_user_id is not None:
                events = [event for event in events if event.get("user_id") == normalized_user_id]
            if normalized_workspace_id is not None:
                events = [
                    event for event in events
                    if event.get("workspace_id") == normalized_workspace_id
                ]

            events = list(reversed(events))[:safe_limit]

            return self._safe_result(
                message="Agent events retrieved.",
                data={"events": events, "count": len(events)},
            )

        except Exception as exc:
            return self._error_result("Failed to get agent events.", exc)

    def get_memory_stats(self) -> Dict[str, Any]:
        """
        Return short-term memory statistics.

        Useful for health checks, dashboard cards, and monitoring.
        """
        try:
            with self._lock:
                scope_count = len(self._sessions)
                session_count = sum(len(sessions) for sessions in self._sessions.values())
                command_count = sum(
                    len(record.recent_commands)
                    for sessions in self._sessions.values()
                    for record in sessions.values()
                )
                active_task_count = sum(
                    1
                    for sessions in self._sessions.values()
                    for record in sessions.values()
                    if record.active_task is not None
                )
                active_agent_count = sum(
                    1
                    for sessions in self._sessions.values()
                    for record in sessions.values()
                    if record.active_agent is not None
                )

            return self._safe_result(
                message="Short-term memory stats retrieved.",
                data={
                    "scope_count": scope_count,
                    "session_count": session_count,
                    "recent_command_count": command_count,
                    "active_task_count": active_task_count,
                    "active_agent_count": active_agent_count,
                    "audit_event_count": len(self._audit_events),
                    "agent_event_count": len(self._agent_events),
                    "config": asdict(self.config),
                },
            )

        except Exception as exc:
            return self._error_result("Failed to get memory stats.", exc)

    def health_check(self) -> Dict[str, Any]:
        """
        Health check for Agent Registry / Agent Loader.

        Overrides/fits BaseAgent compatibility.
        """
        stats = self.get_memory_stats()
        return self._safe_result(
            message="ShortTermMemory is healthy.",
            data={
                "agent_name": self.agent_name,
                "agent_version": self.agent_version,
                "healthy": True,
                "stats": stats.get("data", {}),
                "capabilities": self.get_capabilities(),
            },
            metadata={"component": "memory_agent.short_term"},
        )

    def get_capabilities(self) -> List[str]:
        """
        Return capabilities for Agent Registry.

        Master Agent / Router can inspect this list.
        """
        return [
            "short_term_session_context",
            "active_task_tracking",
            "active_agent_tracking",
            "recent_command_tracking",
            "saas_user_workspace_isolation",
            "audit_event_logging",
            "agent_event_emission",
            "verification_payload_preparation",
            "memory_payload_preparation",
            "security_check_detection",
            "session_snapshot_export",
            "ttl_cleanup",
        ]


# =============================================================================
# Module-level factory
# =============================================================================

def create_short_term_memory(
    config: Optional[Union[ShortTermMemoryConfig, Mapping[str, Any]]] = None,
    logger: Optional[logging.Logger] = None,
) -> ShortTermMemory:
    """
    Factory for Agent Loader / Registry.

    Args:
        config:
            Optional ShortTermMemoryConfig or dict.

        logger:
            Optional logger.

    Returns:
        ShortTermMemory instance.
    """
    return ShortTermMemory(config=config, logger=logger)


# =============================================================================
# Manual smoke test
# =============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    memory = ShortTermMemory()

    print(
        json.dumps(
            memory.set_session_context(
                user_id="user_1",
                workspace_id="workspace_1",
                session_id="session_1",
                context={
                    "current_page": "dashboard",
                    "active_file": "agents/memory_agent/short_term.py",
                    "password": "should_not_be_saved",
                },
            ),
            indent=2,
            default=str,
        )
    )

    print(
        json.dumps(
            memory.set_active_agent(
                user_id="user_1",
                workspace_id="workspace_1",
                session_id="session_1",
                agent_name="Memory",
                capabilities=["recall", "session_context"],
                route_reason="User requested current session memory file.",
            ),
            indent=2,
            default=str,
        )
    )

    print(
        json.dumps(
            memory.set_active_task(
                user_id="user_1",
                workspace_id="workspace_1",
                session_id="session_1",
                task={
                    "title": "Generate short_term.py",
                    "status": "running",
                    "agent_name": "Memory",
                    "progress": 35,
                },
            ),
            indent=2,
            default=str,
        )
    )

    print(
        json.dumps(
            memory.add_recent_command(
                user_id="user_1",
                workspace_id="workspace_1",
                session_id="session_1",
                command="Generate full final short_term.py file",
                command_type="user",
                agent_name="Memory",
                source="chat",
            ),
            indent=2,
            default=str,
        )
    )

    print(
        json.dumps(
            memory.get_session_snapshot(
                user_id="user_1",
                workspace_id="workspace_1",
                session_id="session_1",
            ),
            indent=2,
            default=str,
        )
    )

    print(json.dumps(memory.health_check(), indent=2, default=str))