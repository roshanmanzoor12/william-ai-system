"""
core/memory_bridge.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Bridge recall/save/update/forget requests from Master Agent, Router,
    Workflow Agent, Dashboard/API, or other agents to the Memory Agent.

This file is designed to be:
    - Import-safe even when future modules are not created yet
    - SaaS-ready with strict user_id and workspace_id isolation
    - Compatible with BaseAgent, Agent Registry, Agent Loader, Agent Router,
      Master Agent, Security Agent, Verification Agent, Dashboard/API, and audit logs
    - Production-level, testable, and safe by default

Core responsibilities:
    - Validate user/workspace memory context
    - Route memory actions: recall, save, update, forget
    - Prevent cross-user/workspace memory leakage
    - Request Security Agent approval for sensitive memory operations
    - Prepare Verification Agent-compatible payloads after memory mutations
    - Emit dashboard/registry events
    - Log audit events
    - Return structured JSON/dict results
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Protocol, Tuple, Union


# =============================================================================
# Safe optional imports
# =============================================================================

try:
    from core.context import TaskContext  # type: ignore
except Exception:
    TaskContext = None  # type: ignore


try:
    from core.config import settings  # type: ignore
except Exception:
    settings = None  # type: ignore


try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:

    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps memory_bridge.py import-safe while the full William/Jarvis
        agent stack is still being generated.
        """

        name: str = "fallback_base_agent"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.name = kwargs.get("name", self.name)

        def run(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent has no runtime implementation.",
                "data": {},
                "error": "BASE_AGENT_NOT_AVAILABLE",
                "metadata": {},
            }


# =============================================================================
# Logging
# =============================================================================

logger = logging.getLogger("william.core.memory_bridge")
if not logger.handlers:
    logger.addHandler(logging.NullHandler())


# =============================================================================
# Constants
# =============================================================================

DEFAULT_MEMORY_LIMIT = 20
DEFAULT_MEMORY_TIMEOUT_SECONDS = 30
DEFAULT_MAX_MEMORY_CONTENT_CHARS = 20000

SENSITIVE_MEMORY_ACTIONS = {
    "forget",
    "delete",
    "purge",
    "erase",
    "export",
    "bulk_forget",
    "bulk_delete",
    "admin_recall",
    "cross_workspace_recall",
}

MEMORY_MUTATION_ACTIONS = {
    "save",
    "update",
    "forget",
    "delete",
    "purge",
    "erase",
    "bulk_forget",
    "bulk_delete",
}

SUPPORTED_MEMORY_ACTIONS = {
    "recall",
    "search",
    "save",
    "update",
    "forget",
    "delete",
    "list",
    "summarize",
}


# =============================================================================
# Protocols
# =============================================================================

class MemoryAgentProtocol(Protocol):
    """
    Protocol expected from Memory Agent.

    Future MemoryAgent may implement one or more of these methods.
    """

    def recall(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        ...

    def save(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        ...

    def update(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        ...

    def forget(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        ...

    def run(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        ...


class SecurityAgentProtocol(Protocol):
    """
    Protocol expected from Security Agent.
    """

    def approve_action(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        ...

    def check_permission(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        ...

    def run(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        ...


class VerificationBridgeProtocol(Protocol):
    """
    Protocol expected from VerificationBridge or Verification Agent.
    """

    def submit_for_verification(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        ...

    def verify_completed_task(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        ...

    def run(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        ...


class EventEmitterProtocol(Protocol):
    """
    Protocol for event bus / dashboard / registry integrations.
    """

    def emit(self, event_name: str, payload: Dict[str, Any]) -> None:
        ...


class AuditLoggerProtocol(Protocol):
    """
    Protocol for external audit logging integrations.
    """

    def log(self, event_name: str, payload: Dict[str, Any]) -> None:
        ...


# =============================================================================
# Enums
# =============================================================================

class MemoryAction(str, Enum):
    RECALL = "recall"
    SEARCH = "search"
    SAVE = "save"
    UPDATE = "update"
    FORGET = "forget"
    DELETE = "delete"
    LIST = "list"
    SUMMARIZE = "summarize"


class MemoryScope(str, Enum):
    USER = "user"
    WORKSPACE = "workspace"
    USER_WORKSPACE = "user_workspace"
    SESSION = "session"
    TASK = "task"


class MemoryStatus(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    BLOCKED = "blocked"
    SKIPPED = "skipped"
    REQUIRES_REVIEW = "requires_review"
    ERROR = "error"


class MemoryType(str, Enum):
    FACT = "fact"
    PREFERENCE = "preference"
    PROJECT = "project"
    TASK = "task"
    CONVERSATION = "conversation"
    AGENT_CONTEXT = "agent_context"
    WORKFLOW_CONTEXT = "workflow_context"
    USER_PROFILE = "user_profile"
    SYSTEM_NOTE = "system_note"


# =============================================================================
# Data structures
# =============================================================================

@dataclass
class MemoryBridgeConfig:
    """
    Memory bridge configuration.

    This can later be hydrated from core/config.py, user settings,
    workspace policy, subscription tier, or admin dashboard settings.
    """

    enabled: bool = True
    require_security_for_sensitive_actions: bool = True
    timeout_seconds: int = DEFAULT_MEMORY_TIMEOUT_SECONDS
    default_limit: int = DEFAULT_MEMORY_LIMIT
    max_memory_content_chars: int = DEFAULT_MAX_MEMORY_CONTENT_CHARS
    allow_fallback_local_memory: bool = True
    emit_events: bool = True
    audit_enabled: bool = True
    verification_after_mutation: bool = True
    redact_sensitive_fields: bool = True


@dataclass
class MemoryRequest:
    """
    Normalized memory request.

    Used internally and also safe for future FastAPI/dashboard integrations.
    """

    request_id: str
    action: MemoryAction
    user_id: Union[str, int]
    workspace_id: Union[str, int]
    query: Optional[str] = None
    content: Optional[Any] = None
    memory_id: Optional[str] = None
    memory_type: MemoryType = MemoryType.AGENT_CONTEXT
    scope: MemoryScope = MemoryScope.USER_WORKSPACE
    limit: int = DEFAULT_MEMORY_LIMIT
    task_id: Optional[Union[str, int]] = None
    agent_name: Optional[str] = None
    created_at: str = field(default_factory=lambda: utc_now_iso())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["action"] = self.action.value
        payload["memory_type"] = self.memory_type.value
        payload["scope"] = self.scope.value
        return payload


@dataclass
class MemoryRecord:
    """
    Local fallback memory record.

    This is not a replacement for the full Memory Agent database.
    It exists so this bridge remains testable before Memory Agent is created.
    """

    memory_id: str
    user_id: Union[str, int]
    workspace_id: Union[str, int]
    content: Any
    memory_type: MemoryType
    scope: MemoryScope
    source: str = "core.memory_bridge"
    created_at: str = field(default_factory=lambda: utc_now_iso())
    updated_at: str = field(default_factory=lambda: utc_now_iso())
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["memory_type"] = self.memory_type.value
        payload["scope"] = self.scope.value
        return payload


# =============================================================================
# Utility helpers
# =============================================================================

def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO format."""
    return datetime.now(timezone.utc).isoformat()


def safe_json_dumps(value: Any) -> str:
    """Safely JSON serialize any value."""
    try:
        return json.dumps(value, sort_keys=True, default=str, ensure_ascii=False)
    except Exception:
        return json.dumps(str(value), sort_keys=True, ensure_ascii=False)


def stable_hash(value: Any) -> str:
    """Generate a stable SHA256 hash for a payload."""
    raw = safe_json_dumps(value).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def normalize_id(value: Any) -> Optional[Union[str, int]]:
    """Normalize user/workspace/task identifiers."""
    if value is None:
        return None

    if isinstance(value, str):
        clean = value.strip()
        if not clean:
            return None
        return clean

    if isinstance(value, int):
        return value

    return str(value).strip() or None


def safe_int(value: Any, default: int, minimum: int = 1, maximum: int = 500) -> int:
    """Safely parse an integer and clamp it."""
    try:
        parsed = int(value)
    except Exception:
        parsed = default

    if parsed < minimum:
        return minimum

    if parsed > maximum:
        return maximum

    return parsed


# =============================================================================
# MemoryBridge
# =============================================================================

class MemoryBridge(BaseAgent):
    """
    Bridge between William/Jarvis agents and Memory Agent.

    How this connects inside William/Jarvis:

    Master Agent:
        Uses MemoryBridge to recall context before planning and save useful
        verified outcomes after task completion.

    Agent Router:
        Can route memory-specific actions through this bridge.

    Memory Agent:
        Receives normalized recall/save/update/forget payloads from this bridge.

    Security Agent:
        Sensitive memory actions such as forget, delete, export, or admin recall
        must go through security approval before execution.

    Verification Agent:
        Memory mutations can prepare verification payloads so the system can
        prove what memory changed and under which user/workspace scope.

    Dashboard/API:
        The structured outputs can be stored/displayed in memory activity logs,
        task history, audit pages, admin tools, and analytics widgets.

    Registry/Loader:
        The bridge is import-safe and exposes predictable public methods for
        registration and plugin-style future agents.
    """

    name = "memory_bridge"
    version = "1.0.0"
    module = "core"
    description = "Bridge recall/save/update/forget requests to Memory Agent."

    def __init__(
        self,
        memory_agent: Optional[MemoryAgentProtocol] = None,
        security_agent: Optional[SecurityAgentProtocol] = None,
        verification_bridge: Optional[VerificationBridgeProtocol] = None,
        event_emitter: Optional[EventEmitterProtocol] = None,
        audit_logger: Optional[AuditLoggerProtocol] = None,
        config: Optional[MemoryBridgeConfig] = None,
        registry: Optional[Any] = None,
    ) -> None:
        super().__init__(name=self.name)

        self.memory_agent = memory_agent
        self.security_agent = security_agent
        self.verification_bridge = verification_bridge
        self.event_emitter = event_emitter
        self.audit_logger = audit_logger
        self.registry = registry
        self.config = config or self._load_config()

        self._local_memory: Dict[str, MemoryRecord] = {}

    # -------------------------------------------------------------------------
    # Public methods
    # -------------------------------------------------------------------------

    def recall(
        self,
        query: str,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        limit: Optional[int] = None,
        task_id: Optional[Union[str, int]] = None,
        agent_name: Optional[str] = None,
        scope: Union[MemoryScope, str] = MemoryScope.USER_WORKSPACE,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Recall/search user/workspace memory.

        This method never searches another user's memory.
        """
        return self.handle_memory_request(
            action=MemoryAction.RECALL,
            user_id=user_id,
            workspace_id=workspace_id,
            query=query,
            limit=limit or self.config.default_limit,
            task_id=task_id,
            agent_name=agent_name,
            scope=scope,
            metadata=metadata,
        )

    def search_memory(
        self,
        query: str,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        limit: Optional[int] = None,
        task_id: Optional[Union[str, int]] = None,
        agent_name: Optional[str] = None,
        scope: Union[MemoryScope, str] = MemoryScope.USER_WORKSPACE,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Alias for recall(), using action search.
        """
        return self.handle_memory_request(
            action=MemoryAction.SEARCH,
            user_id=user_id,
            workspace_id=workspace_id,
            query=query,
            limit=limit or self.config.default_limit,
            task_id=task_id,
            agent_name=agent_name,
            scope=scope,
            metadata=metadata,
        )

    def save(
        self,
        content: Any,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        memory_type: Union[MemoryType, str] = MemoryType.AGENT_CONTEXT,
        scope: Union[MemoryScope, str] = MemoryScope.USER_WORKSPACE,
        task_id: Optional[Union[str, int]] = None,
        agent_name: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Save a new memory item under a specific user/workspace.
        """
        return self.handle_memory_request(
            action=MemoryAction.SAVE,
            user_id=user_id,
            workspace_id=workspace_id,
            content=content,
            memory_type=memory_type,
            scope=scope,
            task_id=task_id,
            agent_name=agent_name,
            metadata=metadata,
        )

    def update(
        self,
        memory_id: str,
        content: Any,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        memory_type: Union[MemoryType, str] = MemoryType.AGENT_CONTEXT,
        scope: Union[MemoryScope, str] = MemoryScope.USER_WORKSPACE,
        task_id: Optional[Union[str, int]] = None,
        agent_name: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Update an existing memory item.

        The target memory must belong to the same user_id/workspace_id.
        """
        return self.handle_memory_request(
            action=MemoryAction.UPDATE,
            user_id=user_id,
            workspace_id=workspace_id,
            memory_id=memory_id,
            content=content,
            memory_type=memory_type,
            scope=scope,
            task_id=task_id,
            agent_name=agent_name,
            metadata=metadata,
        )

    def forget(
        self,
        memory_id: Optional[str] = None,
        *,
        query: Optional[str] = None,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        scope: Union[MemoryScope, str] = MemoryScope.USER_WORKSPACE,
        task_id: Optional[Union[str, int]] = None,
        agent_name: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Forget/delete a memory item or memories matching a query.

        This is a sensitive action and should go through Security Agent when
        security checks are enabled.
        """
        return self.handle_memory_request(
            action=MemoryAction.FORGET,
            user_id=user_id,
            workspace_id=workspace_id,
            memory_id=memory_id,
            query=query,
            scope=scope,
            task_id=task_id,
            agent_name=agent_name,
            metadata=metadata,
        )

    def list_memory(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        limit: Optional[int] = None,
        scope: Union[MemoryScope, str] = MemoryScope.USER_WORKSPACE,
        task_id: Optional[Union[str, int]] = None,
        agent_name: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        List memory items for the same user/workspace.
        """
        return self.handle_memory_request(
            action=MemoryAction.LIST,
            user_id=user_id,
            workspace_id=workspace_id,
            limit=limit or self.config.default_limit,
            scope=scope,
            task_id=task_id,
            agent_name=agent_name,
            metadata=metadata,
        )

    def summarize_memory(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        query: Optional[str] = None,
        limit: Optional[int] = None,
        scope: Union[MemoryScope, str] = MemoryScope.USER_WORKSPACE,
        task_id: Optional[Union[str, int]] = None,
        agent_name: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request a memory summary from Memory Agent or fallback local records.
        """
        return self.handle_memory_request(
            action=MemoryAction.SUMMARIZE,
            user_id=user_id,
            workspace_id=workspace_id,
            query=query,
            limit=limit or self.config.default_limit,
            scope=scope,
            task_id=task_id,
            agent_name=agent_name,
            metadata=metadata,
        )

    def handle_memory_request(
        self,
        *,
        action: Union[MemoryAction, str],
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        query: Optional[str] = None,
        content: Optional[Any] = None,
        memory_id: Optional[str] = None,
        memory_type: Union[MemoryType, str] = MemoryType.AGENT_CONTEXT,
        scope: Union[MemoryScope, str] = MemoryScope.USER_WORKSPACE,
        limit: Optional[int] = None,
        task_id: Optional[Union[str, int]] = None,
        agent_name: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Main public memory bridge handler.

        All memory requests pass through this method.
        """
        started_at = time.time()
        metadata = metadata or {}

        try:
            normalized_action = self._normalize_memory_action(action)

            if not self.config.enabled:
                return self._safe_result(
                    message="Memory bridge is disabled by configuration.",
                    data={},
                    metadata={"status": MemoryStatus.SKIPPED.value},
                )

            request = MemoryRequest(
                request_id=str(uuid.uuid4()),
                action=normalized_action,
                user_id=user_id,
                workspace_id=workspace_id,
                query=query,
                content=self._truncate_content(content),
                memory_id=memory_id,
                memory_type=self._normalize_memory_type(memory_type),
                scope=self._normalize_memory_scope(scope),
                limit=safe_int(limit, self.config.default_limit, minimum=1, maximum=500),
                task_id=task_id,
                agent_name=agent_name,
                metadata=metadata,
            )

            validation = self._validate_task_context(request.to_dict())
            if not validation["success"]:
                return validation

            action_validation = self._validate_memory_request(request)
            if not action_validation["success"]:
                return action_validation

            if self._requires_security_check(request.to_dict()):
                security_result = self._request_security_approval(request.to_dict(), metadata=metadata)
                if not security_result.get("success"):
                    self._emit_agent_event(
                        "memory.security_blocked",
                        {
                            "request": self._safe_memory_request_summary(request),
                            "security_result": security_result,
                        },
                    )

                    self._log_audit_event(
                        "memory.security_blocked",
                        {
                            "request": self._safe_memory_request_summary(request),
                            "security_result": security_result,
                        },
                    )

                    return self._error_result(
                        message="Memory request blocked by Security Agent.",
                        error=security_result.get("error") or "SECURITY_BLOCKED",
                        data={"security_result": security_result},
                        metadata={"status": MemoryStatus.BLOCKED.value},
                    )

            self._emit_agent_event(
                "memory.request_started",
                {
                    "request": self._safe_memory_request_summary(request),
                },
            )

            memory_result = self._send_to_memory_agent(request)

            normalized_result = self._normalize_memory_result(
                request=request,
                memory_result=memory_result,
                started_at=started_at,
            )

            if request.action.value in MEMORY_MUTATION_ACTIONS:
                verification_payload = self._prepare_verification_payload(
                    task_payload=request.to_dict(),
                    completed_result=normalized_result,
                    metadata=metadata,
                )

                verification_result = self._maybe_verify_memory_mutation(verification_payload)

                normalized_result.setdefault("data", {})
                normalized_result["data"]["verification_payload"] = verification_payload
                normalized_result["data"]["verification_result"] = verification_result

            self._emit_agent_event(
                "memory.request_completed",
                {
                    "request": self._safe_memory_request_summary(request),
                    "result": self._safe_memory_result_summary(normalized_result),
                },
            )

            self._log_audit_event(
                "memory.request_completed",
                {
                    "request": self._safe_memory_request_summary(request),
                    "result": self._safe_memory_result_summary(normalized_result),
                },
            )

            return normalized_result

        except Exception as exc:
            logger.exception("MemoryBridge handle_memory_request failed.")

            return self._error_result(
                message="Memory bridge failed while handling request.",
                error="MEMORY_BRIDGE_EXCEPTION",
                data={"exception": str(exc)},
                metadata=metadata,
            )

    def run(self, payload: Dict[str, Any], **kwargs: Any) -> Dict[str, Any]:
        """
        BaseAgent-compatible run method.

        Expected payload:
            {
                "action": "recall|save|update|forget|list|summarize",
                "user_id": "...",
                "workspace_id": "...",
                "query": "...",
                "content": {...},
                "memory_id": "...",
                "memory_type": "agent_context",
                "scope": "user_workspace",
                "limit": 20,
                "task_id": "...",
                "agent_name": "...",
                "metadata": {...}
            }
        """
        if not isinstance(payload, dict):
            return self._error_result(
                message="MemoryBridge.run payload must be a dictionary.",
                error="INVALID_RUN_PAYLOAD",
            )

        return self.handle_memory_request(
            action=payload.get("action") or payload.get("type") or "recall",
            user_id=payload.get("user_id") or payload.get("context", {}).get("user_id"),
            workspace_id=payload.get("workspace_id") or payload.get("context", {}).get("workspace_id"),
            query=payload.get("query"),
            content=payload.get("content"),
            memory_id=payload.get("memory_id"),
            memory_type=payload.get("memory_type") or MemoryType.AGENT_CONTEXT,
            scope=payload.get("scope") or MemoryScope.USER_WORKSPACE,
            limit=payload.get("limit"),
            task_id=payload.get("task_id") or payload.get("metadata", {}).get("task_id"),
            agent_name=payload.get("agent_name") or payload.get("agent"),
            metadata=payload.get("metadata") or {},
        )

    # -------------------------------------------------------------------------
    # Required compatibility hooks
    # -------------------------------------------------------------------------

    def _validate_task_context(self, task_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate user/workspace context.

        Required by the William/Jarvis prompt bible.

        Memory requests must always be scoped to user_id and workspace_id.
        """
        user_id = normalize_id(
            task_payload.get("user_id")
            or task_payload.get("context", {}).get("user_id")
            or task_payload.get("metadata", {}).get("user_id")
        )

        workspace_id = normalize_id(
            task_payload.get("workspace_id")
            or task_payload.get("context", {}).get("workspace_id")
            or task_payload.get("metadata", {}).get("workspace_id")
        )

        if user_id is None:
            return self._error_result(
                message="user_id is required for memory requests.",
                error="MISSING_USER_ID",
                metadata={"scope": "memory_context"},
            )

        if workspace_id is None:
            return self._error_result(
                message="workspace_id is required for memory requests.",
                error="MISSING_WORKSPACE_ID",
                metadata={"scope": "memory_context"},
            )

        return self._safe_result(
            message="Memory context validated.",
            data={"user_id": user_id, "workspace_id": workspace_id},
        )

    def _requires_security_check(self, task_payload: Dict[str, Any]) -> bool:
        """
        Decide whether this memory request must go through Security Agent.

        Required by the William/Jarvis prompt bible.
        """
        if not self.config.require_security_for_sensitive_actions:
            return False

        action = str(task_payload.get("action") or "").lower()

        if action in SENSITIVE_MEMORY_ACTIONS:
            return True

        if action in {"forget", "delete"}:
            return True

        sensitivity = str(
            task_payload.get("sensitivity")
            or task_payload.get("risk_level")
            or task_payload.get("metadata", {}).get("sensitivity")
            or ""
        ).lower()

        if sensitivity in {"high", "critical", "sensitive", "restricted"}:
            return True

        metadata = task_payload.get("metadata") or {}
        if isinstance(metadata, dict):
            if metadata.get("requires_security") is True:
                return True
            if metadata.get("admin_action") is True:
                return True
            if metadata.get("bulk_action") is True:
                return True

        return False

    def _request_security_approval(
        self,
        task_payload: Dict[str, Any],
        *,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval before sensitive memory actions.

        Required by the William/Jarvis prompt bible.
        """
        metadata = metadata or {}

        security_payload = {
            "request_id": str(uuid.uuid4()),
            "type": "memory_security_approval",
            "action": task_payload.get("action"),
            "user_id": task_payload.get("user_id"),
            "workspace_id": task_payload.get("workspace_id"),
            "task_id": task_payload.get("task_id"),
            "memory_id": task_payload.get("memory_id"),
            "scope": task_payload.get("scope"),
            "summary": self._safe_dict(task_payload),
            "created_at": utc_now_iso(),
            "metadata": metadata,
        }

        if not self.security_agent:
            return self._error_result(
                message="Security approval required, but Security Agent is not configured.",
                error="SECURITY_AGENT_NOT_CONFIGURED",
                data={"security_payload": security_payload},
            )

        try:
            if hasattr(self.security_agent, "approve_action"):
                result = self.security_agent.approve_action(security_payload)  # type: ignore
            elif hasattr(self.security_agent, "check_permission"):
                result = self.security_agent.check_permission(security_payload)  # type: ignore
            elif hasattr(self.security_agent, "run"):
                result = self.security_agent.run(security_payload)  # type: ignore
            else:
                return self._error_result(
                    message="Security Agent does not expose an approval method.",
                    error="SECURITY_AGENT_METHOD_MISSING",
                    data={"security_payload": security_payload},
                )

            if not isinstance(result, dict):
                return self._error_result(
                    message="Security Agent returned invalid response.",
                    error="INVALID_SECURITY_RESPONSE",
                    data={"raw_response": str(result)},
                )

            approved = bool(
                result.get("success") is True
                or result.get("approved") is True
                or result.get("data", {}).get("approved") is True
            )

            if not approved:
                return self._error_result(
                    message=result.get("message") or "Security Agent did not approve memory request.",
                    error=result.get("error") or "SECURITY_APPROVAL_DENIED",
                    data={"security_result": result},
                )

            return self._safe_result(
                message="Security Agent approved memory request.",
                data={"security_result": result},
            )

        except Exception as exc:
            logger.exception("Security approval request failed.")

            return self._error_result(
                message="Security approval request failed.",
                error="SECURITY_APPROVAL_EXCEPTION",
                data={"exception": str(exc), "security_payload": security_payload},
            )

    def _prepare_verification_payload(
        self,
        task_payload: Dict[str, Any],
        completed_result: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent-compatible payload after memory mutation.

        Required by the William/Jarvis prompt bible.
        """
        metadata = metadata or {}

        verification_id = str(uuid.uuid4())

        payload = {
            "verification_id": verification_id,
            "type": "memory_mutation_verification_request",
            "source": "core.memory_bridge",
            "user_id": task_payload.get("user_id"),
            "workspace_id": task_payload.get("workspace_id"),
            "task_id": task_payload.get("task_id") or task_payload.get("request_id"),
            "action_type": f"memory_{task_payload.get('action')}",
            "memory_action": task_payload.get("action"),
            "memory_id": task_payload.get("memory_id"),
            "scope": task_payload.get("scope"),
            "completed_result": completed_result,
            "proof_items": [
                {
                    "proof_type": "json",
                    "label": "Memory request payload hash",
                    "value": stable_hash(task_payload),
                    "source": "core.memory_bridge",
                    "confidence": 0.95,
                    "created_at": utc_now_iso(),
                    "metadata": {},
                },
                {
                    "proof_type": "json",
                    "label": "Memory result payload hash",
                    "value": stable_hash(completed_result),
                    "source": "core.memory_bridge",
                    "confidence": 0.95,
                    "created_at": utc_now_iso(),
                    "metadata": {},
                },
            ],
            "payload_hash": stable_hash(
                {
                    "task_payload": task_payload,
                    "completed_result": completed_result,
                }
            ),
            "created_at": utc_now_iso(),
            "metadata": {
                **metadata,
                "bridge_name": self.name,
                "bridge_version": self.version,
            },
        }

        return payload

    def _prepare_memory_payload(
        self,
        task_payload: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent-compatible payload.

        Required by the William/Jarvis prompt bible.
        """
        metadata = metadata or {}

        return {
            "request_id": str(uuid.uuid4()),
            "type": "memory_agent_request",
            "source": "core.memory_bridge",
            "action": task_payload.get("action"),
            "user_id": task_payload.get("user_id"),
            "workspace_id": task_payload.get("workspace_id"),
            "query": task_payload.get("query"),
            "content": task_payload.get("content"),
            "memory_id": task_payload.get("memory_id"),
            "memory_type": task_payload.get("memory_type"),
            "scope": task_payload.get("scope"),
            "limit": task_payload.get("limit"),
            "task_id": task_payload.get("task_id"),
            "agent_name": task_payload.get("agent_name"),
            "created_at": utc_now_iso(),
            "metadata": {
                **metadata,
                "memory_safe": True,
                "scope_required": True,
            },
        }

    def _emit_agent_event(self, event_name: str, payload: Dict[str, Any]) -> None:
        """
        Emit event for Dashboard/API, Registry, Router, or event bus.

        Required by the William/Jarvis prompt bible.
        """
        if not self.config.emit_events:
            return

        event_payload = {
            "event": event_name,
            "source": "core.memory_bridge",
            "created_at": utc_now_iso(),
            "payload": payload,
        }

        try:
            if self.event_emitter and hasattr(self.event_emitter, "emit"):
                self.event_emitter.emit(event_name, event_payload)
                return

            if self.registry and hasattr(self.registry, "emit"):
                self.registry.emit(event_name, event_payload)
                return

            logger.info("MemoryBridge event emitted: %s | %s", event_name, safe_json_dumps(event_payload))

        except Exception as exc:
            logger.warning("Failed to emit memory event %s: %s", event_name, exc)

    def _log_audit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
        """
        Log audit event for compliance, dashboard, task history, and debugging.

        Required by the William/Jarvis prompt bible.
        """
        if not self.config.audit_enabled:
            return

        audit_payload = {
            "event": event_name,
            "source": "core.memory_bridge",
            "created_at": utc_now_iso(),
            "payload": payload,
        }

        try:
            if self.audit_logger and hasattr(self.audit_logger, "log"):
                self.audit_logger.log(event_name, audit_payload)
                return

            logger.info("MemoryBridge audit event: %s | %s", event_name, safe_json_dumps(audit_payload))

        except Exception as exc:
            logger.warning("Failed to log memory audit event %s: %s", event_name, exc)

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Return standard success result.

        Required by the William/Jarvis prompt bible.
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
        error: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Return standard error result.

        Required by the William/Jarvis prompt bible.
        """
        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": error,
            "metadata": metadata or {},
        }

    # -------------------------------------------------------------------------
    # Memory Agent routing
    # -------------------------------------------------------------------------

    def _send_to_memory_agent(self, request: MemoryRequest) -> Dict[str, Any]:
        """
        Send normalized memory request to Memory Agent.

        If Memory Agent is unavailable and fallback is enabled, local in-memory
        behavior is used for testing and early development.
        """
        payload = self._prepare_memory_payload(request.to_dict(), metadata=request.metadata)

        if self.memory_agent:
            try:
                if hasattr(self.memory_agent, "run_task"):
                    # The real agents.memory_agent.memory_agent.MemoryAgent
                    # only exposes run_task(task: dict), keyed by
                    # task["action"] using vocabulary store/recall/search/
                    # update/delete -- it has no recall()/save()/update()/
                    # forget()/run() methods, so _memory_method_for_action's
                    # mapping (and the "save" action name itself, which the
                    # real agent calls "store") never matched anything,
                    # always falling through to MEMORY_AGENT_METHOD_MISSING.
                    real_action = self._real_memory_agent_action(request.action)
                    real_task = dict(payload)
                    real_task["action"] = real_action
                    result = self.memory_agent.run_task(real_task)  # type: ignore
                elif hasattr(self.memory_agent, "run"):
                    result = self.memory_agent.run(payload)  # type: ignore
                else:
                    return self._error_result(
                        message="Memory Agent does not expose a compatible method.",
                        error="MEMORY_AGENT_METHOD_MISSING",
                        data={"payload": self._safe_dict(payload)},
                    )

                if not isinstance(result, dict):
                    return self._error_result(
                        message="Memory Agent returned invalid response.",
                        error="INVALID_MEMORY_AGENT_RESPONSE",
                        data={"raw_response": str(result)},
                    )

                return result

            except Exception as exc:
                logger.exception("Memory Agent call failed.")

                return self._error_result(
                    message="Memory Agent call failed.",
                    error="MEMORY_AGENT_EXCEPTION",
                    data={"exception": str(exc)},
                )

        if self.config.allow_fallback_local_memory:
            return self._fallback_local_memory(request)

        return self._error_result(
            message="Memory Agent is not configured.",
            error="MEMORY_AGENT_NOT_CONFIGURED",
        )

    def _real_memory_agent_action(self, action: MemoryAction) -> str:
        """
        Translate this bridge's MemoryAction vocabulary to the real
        agents.memory_agent.memory_agent.MemoryAgent.run_task() action
        vocabulary (store/recall/search/update/delete). Only SAVE differs
        by name (-> store); LIST/SUMMARIZE have no direct real-agent
        action, so they map to recall (closest real capability), matching
        _memory_method_for_action's existing behavior below.
        """
        if action == MemoryAction.SAVE:
            return "store"
        if action in {MemoryAction.LIST, MemoryAction.SUMMARIZE}:
            return "recall"
        return action.value

    def _memory_method_for_action(self, action: MemoryAction) -> Optional[str]:
        """
        Map MemoryAction to common MemoryAgent method names.
        """
        if action in {MemoryAction.RECALL, MemoryAction.SEARCH, MemoryAction.LIST, MemoryAction.SUMMARIZE}:
            return "recall"

        if action == MemoryAction.SAVE:
            return "save"

        if action == MemoryAction.UPDATE:
            return "update"

        if action in {MemoryAction.FORGET, MemoryAction.DELETE}:
            return "forget"

        return None

    def _fallback_local_memory(self, request: MemoryRequest) -> Dict[str, Any]:
        """
        Local fallback memory store for testing before Memory Agent exists.
        """
        if request.action == MemoryAction.SAVE:
            memory_id = request.memory_id or str(uuid.uuid4())

            record = MemoryRecord(
                memory_id=memory_id,
                user_id=request.user_id,
                workspace_id=request.workspace_id,
                content=request.content,
                memory_type=request.memory_type,
                scope=request.scope,
                tags=self._extract_tags(request),
                metadata={
                    **request.metadata,
                    "request_id": request.request_id,
                    "task_id": request.task_id,
                    "agent_name": request.agent_name,
                    "fallback": True,
                },
            )

            self._local_memory[memory_id] = record

            return self._safe_result(
                message="Memory saved using fallback local memory store.",
                data={"memory": record.to_dict(), "fallback": True},
                metadata={"status": MemoryStatus.SUCCESS.value},
            )

        if request.action == MemoryAction.UPDATE:
            if not request.memory_id:
                return self._error_result(
                    message="memory_id is required for memory update.",
                    error="MISSING_MEMORY_ID",
                )

            record = self._local_memory.get(request.memory_id)
            if not record:
                return self._error_result(
                    message="Memory record not found.",
                    error="MEMORY_NOT_FOUND",
                    metadata={"memory_id": request.memory_id},
                )

            if not self._record_matches_scope(record, request.user_id, request.workspace_id):
                return self._error_result(
                    message="Memory record does not belong to this user/workspace.",
                    error="MEMORY_SCOPE_MISMATCH",
                    metadata={"memory_id": request.memory_id},
                )

            record.content = request.content
            record.memory_type = request.memory_type
            record.scope = request.scope
            record.updated_at = utc_now_iso()
            record.metadata.update(
                {
                    **request.metadata,
                    "last_request_id": request.request_id,
                    "updated_by_bridge": True,
                }
            )

            return self._safe_result(
                message="Memory updated using fallback local memory store.",
                data={"memory": record.to_dict(), "fallback": True},
                metadata={"status": MemoryStatus.SUCCESS.value},
            )

        if request.action in {MemoryAction.FORGET, MemoryAction.DELETE}:
            forgotten: List[Dict[str, Any]] = []

            if request.memory_id:
                record = self._local_memory.get(request.memory_id)

                if not record:
                    return self._error_result(
                        message="Memory record not found.",
                        error="MEMORY_NOT_FOUND",
                        metadata={"memory_id": request.memory_id},
                    )

                if not self._record_matches_scope(record, request.user_id, request.workspace_id):
                    return self._error_result(
                        message="Memory record does not belong to this user/workspace.",
                        error="MEMORY_SCOPE_MISMATCH",
                        metadata={"memory_id": request.memory_id},
                    )

                forgotten.append(record.to_dict())
                del self._local_memory[request.memory_id]

            elif request.query:
                query = request.query.lower()
                ids_to_delete = []

                for memory_id, record in self._local_memory.items():
                    if not self._record_matches_scope(record, request.user_id, request.workspace_id):
                        continue

                    searchable = safe_json_dumps(record.to_dict()).lower()
                    if query in searchable:
                        ids_to_delete.append(memory_id)

                for memory_id in ids_to_delete:
                    forgotten.append(self._local_memory[memory_id].to_dict())
                    del self._local_memory[memory_id]

            else:
                return self._error_result(
                    message="memory_id or query is required for forget/delete.",
                    error="MISSING_MEMORY_TARGET",
                )

            return self._safe_result(
                message="Memory forgotten using fallback local memory store.",
                data={"forgotten": forgotten, "count": len(forgotten), "fallback": True},
                metadata={"status": MemoryStatus.SUCCESS.value},
            )

        if request.action in {MemoryAction.RECALL, MemoryAction.SEARCH, MemoryAction.LIST}:
            records = self._local_recall(request)

            return self._safe_result(
                message="Memory recalled using fallback local memory store.",
                data={"memories": records, "count": len(records), "fallback": True},
                metadata={"status": MemoryStatus.SUCCESS.value},
            )

        if request.action == MemoryAction.SUMMARIZE:
            records = self._local_recall(request)
            summary = self._summarize_records(records)

            return self._safe_result(
                message="Memory summarized using fallback local memory store.",
                data={
                    "summary": summary,
                    "memories": records,
                    "count": len(records),
                    "fallback": True,
                },
                metadata={"status": MemoryStatus.SUCCESS.value},
            )

        return self._error_result(
            message="Unsupported memory action.",
            error="UNSUPPORTED_MEMORY_ACTION",
            metadata={"action": request.action.value},
        )

    def _local_recall(self, request: MemoryRequest) -> List[Dict[str, Any]]:
        """
        Recall fallback local memory with strict user/workspace filtering.
        """
        records: List[MemoryRecord] = []

        query = (request.query or "").lower().strip()

        for record in self._local_memory.values():
            if not self._record_matches_scope(record, request.user_id, request.workspace_id):
                continue

            if query:
                searchable = safe_json_dumps(record.to_dict()).lower()
                if query not in searchable:
                    continue

            records.append(record)

        records = sorted(records, key=lambda item: item.updated_at, reverse=True)
        records = records[: request.limit]

        return [record.to_dict() for record in records]

    def _record_matches_scope(
        self,
        record: MemoryRecord,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
    ) -> bool:
        """
        Enforce strict SaaS isolation for fallback local memory.
        """
        return str(record.user_id) == str(user_id) and str(record.workspace_id) == str(workspace_id)

    # -------------------------------------------------------------------------
    # Verification integration
    # -------------------------------------------------------------------------

    def _maybe_verify_memory_mutation(self, verification_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send memory mutation proof to VerificationBridge when configured.
        """
        if not self.config.verification_after_mutation:
            return self._safe_result(
                message="Verification after memory mutation is disabled.",
                metadata={"status": "skipped"},
            )

        if not self.verification_bridge:
            return self._safe_result(
                message="VerificationBridge is not configured. Payload prepared only.",
                data={"verification_payload_prepared": True},
                metadata={"status": "prepared_only"},
            )

        try:
            task_payload = {
                "task_id": verification_payload.get("task_id"),
                "user_id": verification_payload.get("user_id"),
                "workspace_id": verification_payload.get("workspace_id"),
                "action_type": verification_payload.get("action_type"),
                "title": "Verify memory mutation",
                "status": "completed",
                "metadata": verification_payload.get("metadata", {}),
            }

            completed_result = verification_payload.get("completed_result") or {}
            proof_items = verification_payload.get("proof_items") or []

            if hasattr(self.verification_bridge, "submit_for_verification"):
                return self.verification_bridge.submit_for_verification(
                    task_payload=task_payload,
                    completed_result=completed_result,
                    proof_items=proof_items,
                    verification_level="standard",
                    metadata=verification_payload.get("metadata", {}),
                )

            if hasattr(self.verification_bridge, "verify_completed_task"):
                return self.verification_bridge.verify_completed_task(
                    task_payload=task_payload,
                    completed_result=completed_result,
                    proof_items=proof_items,
                    verification_level="standard",
                    metadata=verification_payload.get("metadata", {}),
                )

            if hasattr(self.verification_bridge, "run"):
                return self.verification_bridge.run(verification_payload)  # type: ignore

            return self._error_result(
                message="VerificationBridge does not expose a compatible method.",
                error="VERIFICATION_BRIDGE_METHOD_MISSING",
            )

        except Exception as exc:
            logger.exception("Memory mutation verification failed.")

            return self._error_result(
                message="Memory mutation verification failed.",
                error="MEMORY_MUTATION_VERIFICATION_EXCEPTION",
                data={"exception": str(exc)},
            )

    # -------------------------------------------------------------------------
    # Normalization and validation helpers
    # -------------------------------------------------------------------------

    def _normalize_memory_action(self, action: Union[MemoryAction, str]) -> MemoryAction:
        if isinstance(action, MemoryAction):
            return action

        clean = str(action or "").strip().lower()

        aliases = {
            "remember": MemoryAction.SAVE,
            "store": MemoryAction.SAVE,
            "create": MemoryAction.SAVE,
            "edit": MemoryAction.UPDATE,
            "remove": MemoryAction.FORGET,
            "erase": MemoryAction.FORGET,
            "purge": MemoryAction.FORGET,
            "get": MemoryAction.RECALL,
            "find": MemoryAction.RECALL,
            "retrieve": MemoryAction.RECALL,
        }

        if clean in aliases:
            return aliases[clean]

        for item in MemoryAction:
            if item.value == clean:
                return item

        return MemoryAction.RECALL

    def _normalize_memory_type(self, memory_type: Union[MemoryType, str]) -> MemoryType:
        if isinstance(memory_type, MemoryType):
            return memory_type

        clean = str(memory_type or "").strip().lower()

        for item in MemoryType:
            if item.value == clean:
                return item

        return MemoryType.AGENT_CONTEXT

    def _normalize_memory_scope(self, scope: Union[MemoryScope, str]) -> MemoryScope:
        if isinstance(scope, MemoryScope):
            return scope

        clean = str(scope or "").strip().lower()

        aliases = {
            "user_workspace": MemoryScope.USER_WORKSPACE,
            "workspace_user": MemoryScope.USER_WORKSPACE,
            "personal": MemoryScope.USER,
            "team": MemoryScope.WORKSPACE,
        }

        if clean in aliases:
            return aliases[clean]

        for item in MemoryScope:
            if item.value == clean:
                return item

        return MemoryScope.USER_WORKSPACE

    def _validate_memory_request(self, request: MemoryRequest) -> Dict[str, Any]:
        """
        Validate memory request by action.
        """
        if request.action.value not in SUPPORTED_MEMORY_ACTIONS:
            return self._error_result(
                message="Unsupported memory action.",
                error="UNSUPPORTED_MEMORY_ACTION",
                metadata={"action": request.action.value},
            )

        if request.action in {MemoryAction.RECALL, MemoryAction.SEARCH}:
            if not request.query or not str(request.query).strip():
                return self._error_result(
                    message="query is required for recall/search.",
                    error="MISSING_MEMORY_QUERY",
                )

        if request.action == MemoryAction.SAVE:
            if request.content is None or request.content == "":
                return self._error_result(
                    message="content is required for save.",
                    error="MISSING_MEMORY_CONTENT",
                )

        if request.action == MemoryAction.UPDATE:
            if not request.memory_id:
                return self._error_result(
                    message="memory_id is required for update.",
                    error="MISSING_MEMORY_ID",
                )
            if request.content is None or request.content == "":
                return self._error_result(
                    message="content is required for update.",
                    error="MISSING_MEMORY_CONTENT",
                )

        if request.action in {MemoryAction.FORGET, MemoryAction.DELETE}:
            if not request.memory_id and not request.query:
                return self._error_result(
                    message="memory_id or query is required for forget/delete.",
                    error="MISSING_MEMORY_TARGET",
                )

        return self._safe_result(
            message="Memory request validated.",
            data={"request": self._safe_memory_request_summary(request)},
        )

    def _normalize_memory_result(
        self,
        request: MemoryRequest,
        memory_result: Dict[str, Any],
        *,
        started_at: float,
    ) -> Dict[str, Any]:
        """
        Normalize Memory Agent response.
        """
        elapsed_ms = int((time.time() - started_at) * 1000)

        if not isinstance(memory_result, dict):
            return self._error_result(
                message="Invalid memory result.",
                error="INVALID_MEMORY_RESULT",
                data={"raw_response": str(memory_result)},
                metadata={"elapsed_ms": elapsed_ms},
            )

        success = bool(memory_result.get("success"))
        message = memory_result.get("message") or (
            "Memory request completed." if success else "Memory request failed."
        )

        data = memory_result.get("data") or {}
        error = memory_result.get("error")

        metadata = {
            **(memory_result.get("metadata") or {}),
            "elapsed_ms": elapsed_ms,
            "request_id": request.request_id,
            "action": request.action.value,
            "user_id": request.user_id,
            "workspace_id": request.workspace_id,
        }

        if success:
            return self._safe_result(
                message=message,
                data=data,
                metadata=metadata,
            )

        return self._error_result(
            message=message,
            error=error or "MEMORY_REQUEST_FAILED",
            data=data,
            metadata=metadata,
        )

    # -------------------------------------------------------------------------
    # Safety helpers
    # -------------------------------------------------------------------------

    def _safe_dict(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Redact sensitive fields from payloads before logs/events/audits.
        """
        if not self.config.redact_sensitive_fields:
            return payload

        sensitive_keys = {
            "password",
            "token",
            "secret",
            "api_key",
            "authorization",
            "access_token",
            "refresh_token",
            "credential",
            "private_key",
        }

        def redact(value: Any) -> Any:
            if isinstance(value, dict):
                clean_dict = {}
                for key, inner_value in value.items():
                    lower_key = str(key).lower()
                    if lower_key in sensitive_keys or any(secret in lower_key for secret in sensitive_keys):
                        clean_dict[key] = "[REDACTED]"
                    else:
                        clean_dict[key] = redact(inner_value)
                return clean_dict

            if isinstance(value, list):
                return [redact(item) for item in value]

            return value

        return redact(payload)

    def _truncate_content(self, content: Any) -> Any:
        """
        Prevent extremely large memory content from going through bridge.
        """
        if content is None:
            return None

        if isinstance(content, str):
            if len(content) > self.config.max_memory_content_chars:
                return content[: self.config.max_memory_content_chars] + "...[TRUNCATED]"
            return content

        serialized = safe_json_dumps(content)

        if len(serialized) > self.config.max_memory_content_chars:
            return serialized[: self.config.max_memory_content_chars] + "...[TRUNCATED]"

        return content

    def _safe_memory_request_summary(self, request: MemoryRequest) -> Dict[str, Any]:
        """
        Create a safe request summary for logs/events/audits.
        """
        return self._safe_dict(
            {
                "request_id": request.request_id,
                "action": request.action.value,
                "user_id": request.user_id,
                "workspace_id": request.workspace_id,
                "memory_id": request.memory_id,
                "memory_type": request.memory_type.value,
                "scope": request.scope.value,
                "limit": request.limit,
                "task_id": request.task_id,
                "agent_name": request.agent_name,
                "has_query": bool(request.query),
                "has_content": request.content is not None,
                "created_at": request.created_at,
                "metadata": request.metadata,
            }
        )

    def _safe_memory_result_summary(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a safe result summary for logs/events/audits.
        """
        data = result.get("data") or {}

        return self._safe_dict(
            {
                "success": result.get("success"),
                "message": result.get("message"),
                "error": result.get("error"),
                "metadata": result.get("metadata"),
                "data_keys": list(data.keys()) if isinstance(data, dict) else [],
                "count": data.get("count") if isinstance(data, dict) else None,
            }
        )

    def _extract_tags(self, request: MemoryRequest) -> List[str]:
        """
        Extract simple tags from metadata for fallback local memory.
        """
        tags: List[str] = []

        if request.agent_name:
            tags.append(f"agent:{request.agent_name}")

        if request.task_id:
            tags.append(f"task:{request.task_id}")

        tags.append(f"type:{request.memory_type.value}")
        tags.append(f"scope:{request.scope.value}")

        meta_tags = request.metadata.get("tags") if isinstance(request.metadata, dict) else None
        if isinstance(meta_tags, list):
            tags.extend(str(item) for item in meta_tags if str(item).strip())

        return sorted(set(tags))

    def _summarize_records(self, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Lightweight fallback summarizer for local memory records.
        """
        memory_types: Dict[str, int] = {}
        tags: Dict[str, int] = {}

        for record in records:
            memory_type = str(record.get("memory_type") or "unknown")
            memory_types[memory_type] = memory_types.get(memory_type, 0) + 1

            for tag in record.get("tags") or []:
                tag = str(tag)
                tags[tag] = tags.get(tag, 0) + 1

        return {
            "total_memories": len(records),
            "memory_types": memory_types,
            "top_tags": dict(sorted(tags.items(), key=lambda item: item[1], reverse=True)[:10]),
            "generated_at": utc_now_iso(),
        }

    # -------------------------------------------------------------------------
    # Configuration
    # -------------------------------------------------------------------------

    def _load_config(self) -> MemoryBridgeConfig:
        """
        Load bridge config from core.config.settings when available.

        Falls back to safe defaults.
        """
        config = MemoryBridgeConfig()

        if settings is None:
            return config

        try:
            enabled = getattr(settings, "MEMORY_BRIDGE_ENABLED", None)
            if enabled is not None:
                config.enabled = bool(enabled)

            timeout = getattr(settings, "MEMORY_TIMEOUT_SECONDS", None)
            if timeout is not None:
                config.timeout_seconds = int(timeout)

            default_limit = getattr(settings, "MEMORY_DEFAULT_LIMIT", None)
            if default_limit is not None:
                config.default_limit = safe_int(default_limit, DEFAULT_MEMORY_LIMIT, minimum=1, maximum=500)

            max_chars = getattr(settings, "MEMORY_MAX_CONTENT_CHARS", None)
            if max_chars is not None:
                config.max_memory_content_chars = safe_int(
                    max_chars,
                    DEFAULT_MAX_MEMORY_CONTENT_CHARS,
                    minimum=1000,
                    maximum=500000,
                )

            security_required = getattr(settings, "MEMORY_REQUIRE_SECURITY", None)
            if security_required is not None:
                config.require_security_for_sensitive_actions = bool(security_required)

            fallback = getattr(settings, "MEMORY_ALLOW_FALLBACK", None)
            if fallback is not None:
                config.allow_fallback_local_memory = bool(fallback)

            emit_events = getattr(settings, "MEMORY_EMIT_EVENTS", None)
            if emit_events is not None:
                config.emit_events = bool(emit_events)

            audit_enabled = getattr(settings, "MEMORY_AUDIT_ENABLED", None)
            if audit_enabled is not None:
                config.audit_enabled = bool(audit_enabled)

            verify_mutations = getattr(settings, "MEMORY_VERIFY_MUTATIONS", None)
            if verify_mutations is not None:
                config.verification_after_mutation = bool(verify_mutations)

        except Exception as exc:
            logger.warning("Failed to load MemoryBridge settings. Using defaults. Error: %s", exc)

        return config


# =============================================================================
# Factory helpers
# =============================================================================

def create_memory_bridge(
    memory_agent: Optional[MemoryAgentProtocol] = None,
    security_agent: Optional[SecurityAgentProtocol] = None,
    verification_bridge: Optional[VerificationBridgeProtocol] = None,
    event_emitter: Optional[EventEmitterProtocol] = None,
    audit_logger: Optional[AuditLoggerProtocol] = None,
    config: Optional[MemoryBridgeConfig] = None,
    registry: Optional[Any] = None,
) -> MemoryBridge:
    """
    Factory helper for Agent Loader / Registry / FastAPI dependency injection.
    """
    return MemoryBridge(
        memory_agent=memory_agent,
        security_agent=security_agent,
        verification_bridge=verification_bridge,
        event_emitter=event_emitter,
        audit_logger=audit_logger,
        config=config,
        registry=registry,
    )


def get_module_info() -> Dict[str, Any]:
    """
    Registry-compatible module metadata.
    """
    return {
        "module": "core",
        "file": "memory_bridge.py",
        "class": "MemoryBridge",
        "name": MemoryBridge.name,
        "version": MemoryBridge.version,
        "description": MemoryBridge.description,
        "safe_to_import": True,
        "requires": [],
        "optional_integrations": [
            "MemoryAgent",
            "SecurityAgent",
            "VerificationBridge",
            "AgentRegistry",
            "DashboardAPI",
            "AuditLogger",
            "EventEmitter",
        ],
        "public_methods": [
            "recall",
            "search_memory",
            "save",
            "update",
            "forget",
            "list_memory",
            "summarize_memory",
            "handle_memory_request",
            "run",
        ],
    }


# =============================================================================
# Self-test
# =============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    bridge = MemoryBridge()

    save_result = bridge.save(
        content={
            "note": "William should remember this project uses strict user/workspace memory isolation.",
            "project": "William / Jarvis Multi-Agent AI SaaS System",
        },
        user_id="user_1",
        workspace_id="workspace_1",
        memory_type="project",
        task_id="task_memory_demo_001",
        agent_name="master_agent",
        metadata={"source": "local_self_test", "tags": ["william", "memory", "core"]},
    )

    print("SAVE RESULT:")
    print(json.dumps(save_result, indent=2, default=str))

    recall_result = bridge.recall(
        query="workspace memory isolation",
        user_id="user_1",
        workspace_id="workspace_1",
        limit=10,
        task_id="task_memory_demo_002",
        agent_name="master_agent",
        metadata={"source": "local_self_test"},
    )

    print("\nRECALL RESULT:")
    print(json.dumps(recall_result, indent=2, default=str))

    list_result = bridge.list_memory(
        user_id="user_1",
        workspace_id="workspace_1",
        limit=10,
        metadata={"source": "local_self_test"},
    )

    print("\nLIST RESULT:")
    print(json.dumps(list_result, indent=2, default=str))