"""
agents/memory_agent/memory_agent.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    AI memory brain for short-term memory, long-term memory, project/client/team memory,
    embeddings, recall, privacy handling, SaaS isolation, and Master Agent compatibility.

This file is intentionally import-safe:
    - It works even if future William/Jarvis modules are not created yet.
    - It includes fallback BaseAgent behavior.
    - It avoids hard dependencies on databases, vector stores, or future memory submodules.
    - It provides clear structured JSON-style results.

Connections:
    Master Agent:
        Routes memory-related tasks to MemoryAgent.run_task() or public methods.

    Security Agent:
        Sensitive memory actions can be checked through _requires_security_check()
        and _request_security_approval().

    Verification Agent:
        Completed actions prepare verification payloads using _prepare_verification_payload().

    Dashboard/API:
        Public methods return structured dicts with success, message, data, error, metadata.

    Agent Registry / Loader / Router:
        Exposes MemoryAgent with safe initialization and registry metadata.

    Future Memory Submodules:
        short_term.py, long_term.py, embeddings.py, recall_engine.py, privacy_guard.py, etc.
        can later replace internal fallback implementations without changing public interfaces.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import math
import re
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Safe optional BaseAgent import
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps memory_agent.py import-safe before the full William/Jarvis
        BaseAgent implementation exists.
        """

        def __init__(
            self,
            agent_name: str = "memory_agent",
            agent_type: str = "memory",
            version: str = "1.0.0",
            **kwargs: Any,
        ) -> None:
            self.agent_name = agent_name
            self.agent_type = agent_type
            self.version = version
            self.base_config = kwargs

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            return None

        def log_audit(self, payload: Dict[str, Any]) -> None:
            return None


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger("william.memory_agent")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)


# ---------------------------------------------------------------------------
# Enums and data structures
# ---------------------------------------------------------------------------

class MemoryScope(str, Enum):
    """Supported memory scopes."""

    SHORT_TERM = "short_term"
    LONG_TERM = "long_term"
    PROJECT = "project"
    CLIENT = "client"
    TEAM = "team"
    PREFERENCE = "preference"
    SYSTEM = "system"


class MemorySensitivity(str, Enum):
    """Privacy/sensitivity level for memories."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    SENSITIVE = "sensitive"
    SECRET = "secret"


class MemoryAction(str, Enum):
    """Supported memory task actions."""

    STORE = "store"
    RECALL = "recall"
    SEARCH = "search"
    UPDATE = "update"
    DELETE = "delete"
    FORGET = "forget"
    SUMMARIZE = "summarize"
    CLEAN = "clean"
    EXPORT = "export"
    STATS = "stats"


@dataclass
class MemoryRecord:
    """
    Internal memory record.

    Every record is always tied to user_id and workspace_id for SaaS isolation.
    """

    memory_id: str
    user_id: str
    workspace_id: str
    scope: str
    content: str
    summary: str = ""
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    sensitivity: str = MemorySensitivity.INTERNAL.value
    source_agent: str = "unknown"
    source_task_id: Optional[str] = None
    project_id: Optional[str] = None
    client_id: Optional[str] = None
    team_id: Optional[str] = None
    embedding: Optional[List[float]] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    expires_at: Optional[str] = None
    access_count: int = 0
    last_accessed_at: Optional[str] = None
    is_deleted: bool = False

    def to_public_dict(self, include_embedding: bool = False) -> Dict[str, Any]:
        data = asdict(self)
        if not include_embedding:
            data.pop("embedding", None)
        return data


@dataclass
class MemoryAgentConfig:
    """Safe default configuration for MemoryAgent."""

    enable_embeddings: bool = True
    enable_privacy_guard: bool = True
    enable_audit_log: bool = True
    enable_agent_events: bool = True
    enable_verification_payloads: bool = True
    default_short_term_ttl_seconds: int = 60 * 60 * 24
    max_short_term_records_per_user_workspace: int = 500
    max_long_term_records_per_user_workspace: int = 10000
    max_content_chars: int = 20000
    min_search_score: float = 0.05
    default_recall_limit: int = 10
    embedding_dimensions: int = 128
    agent_version: str = "1.0.0"


# ---------------------------------------------------------------------------
# Memory Agent
# ---------------------------------------------------------------------------

class MemoryAgent(BaseAgent):
    """
    Main AI Memory Brain for William / Jarvis.

    Responsibilities:
        - Store user/workspace-isolated memory.
        - Maintain short-term and long-term memory.
        - Support project/client/team/preference memory.
        - Generate safe deterministic fallback embeddings.
        - Recall/search memories using text and embedding similarity.
        - Enforce privacy checks before sensitive operations.
        - Prepare payloads for Security Agent, Verification Agent, Master Agent,
          Dashboard/API, and future Memory submodules.

    Storage:
        This file uses an in-memory store by default so it is testable and import-safe.
        Future files can replace this with database/vector-store adapters.
    """

    def __init__(
        self,
        config: Optional[Union[MemoryAgentConfig, Dict[str, Any]]] = None,
        storage_backend: Optional[Any] = None,
        security_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            agent_name="memory_agent",
            agent_type="memory",
            version="1.0.0",
            **kwargs,
        )

        if isinstance(config, MemoryAgentConfig):
            self.config = config
        elif isinstance(config, dict):
            self.config = MemoryAgentConfig(**{
                **asdict(MemoryAgentConfig()),
                **config,
            })
        else:
            self.config = MemoryAgentConfig()

        self.storage_backend = storage_backend
        self.security_agent = security_agent
        self.verification_agent = verification_agent
        self.event_bus = event_bus
        self.audit_logger = audit_logger

        self._lock = threading.RLock()
        self._memory_store: Dict[str, MemoryRecord] = {}
        self._agent_started_at = datetime.now(timezone.utc).isoformat()

        self.registry_metadata = {
            "agent_name": "memory_agent",
            "class_name": "MemoryAgent",
            "module": "agents.memory_agent.memory_agent",
            "version": self.config.agent_version,
            "capabilities": [
                "short_term_memory",
                "long_term_memory",
                "project_memory",
                "client_memory",
                "team_memory",
                "preference_memory",
                "memory_recall",
                "memory_search",
                "privacy_guard",
                "fallback_embeddings",
                "audit_logging",
                "verification_payloads",
            ],
            "safe_import": True,
            "requires_user_context": True,
            "requires_workspace_context": True,
        }

    # -----------------------------------------------------------------------
    # Required compatibility hooks
    # -----------------------------------------------------------------------

    def _validate_task_context(self, task_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate SaaS task context.

        Required:
            - user_id
            - workspace_id

        Optional:
            - role
            - permissions
            - task_id
            - source_agent
        """

        if not isinstance(task_context, dict):
            return self._error_result(
                message="Invalid task context.",
                error="task_context must be a dictionary.",
                metadata={"hook": "_validate_task_context"},
            )

        user_id = self._clean_identifier(task_context.get("user_id"))
        workspace_id = self._clean_identifier(task_context.get("workspace_id"))

        if not user_id:
            return self._error_result(
                message="Missing user context.",
                error="user_id is required for Memory Agent operations.",
                metadata={"hook": "_validate_task_context"},
            )

        if not workspace_id:
            return self._error_result(
                message="Missing workspace context.",
                error="workspace_id is required for Memory Agent operations.",
                metadata={"hook": "_validate_task_context"},
            )

        normalized = copy.deepcopy(task_context)
        normalized["user_id"] = user_id
        normalized["workspace_id"] = workspace_id
        normalized.setdefault("role", "user")
        normalized.setdefault("permissions", [])
        normalized.setdefault("task_id", str(uuid.uuid4()))
        normalized.setdefault("source_agent", "unknown")

        return self._safe_result(
            message="Task context validated.",
            data=normalized,
            metadata={"hook": "_validate_task_context"},
        )

    def _requires_security_check(
        self,
        action: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Decide whether an action should go through Security Agent.

        Sensitive operations:
            - delete / forget / export
            - secret memory
            - cross-scope bulk actions
            - suspicious content containing secrets
        """

        payload = payload or {}
        action_value = str(action or "").lower().strip()

        if action_value in {
            MemoryAction.DELETE.value,
            MemoryAction.FORGET.value,
            MemoryAction.EXPORT.value,
            "bulk_delete",
            "bulk_forget",
            "privacy_override",
        }:
            return True

        sensitivity = str(payload.get("sensitivity", "")).lower().strip()
        if sensitivity in {
            MemorySensitivity.SENSITIVE.value,
            MemorySensitivity.SECRET.value,
            MemorySensitivity.CONFIDENTIAL.value,
        }:
            return True

        content = str(payload.get("content", ""))
        if self._detect_secret_like_content(content):
            return True

        if payload.get("include_deleted") is True:
            return True

        if payload.get("cross_workspace") is True or payload.get("cross_user") is True:
            return True

        return False

    def _request_security_approval(
        self,
        action: str,
        task_context: Dict[str, Any],
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Ask Security Agent for approval when available.

        Fallback behavior:
            - Allows non-destructive operations.
            - Allows sensitive store with redaction metadata.
            - Blocks cross-user/cross-workspace requests.
        """

        payload = payload or {}

        if payload.get("cross_user") is True or payload.get("cross_workspace") is True:
            return self._error_result(
                message="Security approval denied.",
                error="Cross-user or cross-workspace memory access is not allowed.",
                metadata={
                    "hook": "_request_security_approval",
                    "action": action,
                    "fallback": True,
                },
            )

        if self.security_agent and hasattr(self.security_agent, "approve"):
            try:
                approval = self.security_agent.approve(
                    action=action,
                    agent_name="memory_agent",
                    task_context=task_context,
                    payload=payload,
                )
                if isinstance(approval, dict):
                    return approval
            except Exception as exc:
                logger.exception("Security Agent approval failed: %s", exc)
                return self._error_result(
                    message="Security approval failed.",
                    error=str(exc),
                    metadata={"hook": "_request_security_approval"},
                )

        safe_actions = {
            MemoryAction.STORE.value,
            MemoryAction.RECALL.value,
            MemoryAction.SEARCH.value,
            MemoryAction.SUMMARIZE.value,
            MemoryAction.STATS.value,
            MemoryAction.CLEAN.value,
        }

        if str(action).lower().strip() in safe_actions:
            return self._safe_result(
                message="Security approval granted by safe fallback.",
                data={"approved": True, "fallback": True},
                metadata={"hook": "_request_security_approval", "action": action},
            )

        return self._error_result(
            message="Security approval required.",
            error="No Security Agent available for this sensitive memory action.",
            metadata={"hook": "_request_security_approval", "action": action},
        )

    def _prepare_verification_payload(
        self,
        action: str,
        task_context: Dict[str, Any],
        result: Dict[str, Any],
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload after a completed memory action.
        """

        payload = {
            "verification_id": str(uuid.uuid4()),
            "agent_name": "memory_agent",
            "agent_type": "memory",
            "action": action,
            "success": bool(result.get("success")),
            "message": result.get("message"),
            "user_id": task_context.get("user_id"),
            "workspace_id": task_context.get("workspace_id"),
            "task_id": task_context.get("task_id"),
            "source_agent": task_context.get("source_agent"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "checks": {
                "saas_isolation_checked": True,
                "security_check_considered": True,
                "structured_result": True,
                "memory_payload_ready": True,
            },
            # A copy, not the live result["metadata"] reference: the call
            # site does `result["metadata"]["verification_payload"] =
            # <this payload>` right after this returns, which would
            # otherwise make result["metadata"] contain a
            # verification_payload whose own result_metadata points back
            # at result["metadata"] itself -- a direct reference cycle
            # that crashed every later redact()/json.dumps() pass over
            # the result with a RecursionError.
            "result_metadata": dict(result.get("metadata", {})),
            "extra": extra or {},
        }

        return payload

    def _prepare_memory_payload(
        self,
        content: str,
        task_context: Dict[str, Any],
        scope: str = MemoryScope.LONG_TERM.value,
        metadata: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
        sensitivity: str = MemorySensitivity.INTERNAL.value,
    ) -> Dict[str, Any]:
        """
        Prepare a normalized memory payload compatible with Memory Agent.
        """

        return {
            "payload_id": str(uuid.uuid4()),
            "user_id": task_context.get("user_id"),
            "workspace_id": task_context.get("workspace_id"),
            "scope": scope,
            "content": content,
            "summary": self._summarize_text(content),
            "tags": tags or [],
            "metadata": metadata or {},
            "sensitivity": sensitivity,
            "source_agent": task_context.get("source_agent", "unknown"),
            "source_task_id": task_context.get("task_id"),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

    def _emit_agent_event(
        self,
        event_name: str,
        payload: Dict[str, Any],
    ) -> None:
        """
        Emit agent event to event bus/BaseAgent/fallback logger.
        """

        if not self.config.enable_agent_events:
            return

        safe_payload = self._redact_payload(copy.deepcopy(payload))

        try:
            if self.event_bus and hasattr(self.event_bus, "emit"):
                self.event_bus.emit(event_name, safe_payload)
                return

            if hasattr(super(), "emit_event"):
                try:
                    super().emit_event(event_name, safe_payload)  # type: ignore
                    return
                except Exception:
                    pass

            logger.info("MemoryAgent event=%s payload=%s", event_name, safe_payload)
        except Exception as exc:
            logger.warning("Failed to emit MemoryAgent event: %s", exc)

    def _log_audit_event(
        self,
        action: str,
        task_context: Dict[str, Any],
        payload: Optional[Dict[str, Any]] = None,
        result: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log audit event safely.

        Does not log raw sensitive content.
        """

        if not self.config.enable_audit_log:
            return

        audit_payload = {
            "audit_id": str(uuid.uuid4()),
            "agent_name": "memory_agent",
            "action": action,
            "user_id": task_context.get("user_id"),
            "workspace_id": task_context.get("workspace_id"),
            "task_id": task_context.get("task_id"),
            "source_agent": task_context.get("source_agent"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "payload_summary": self._audit_payload_summary(payload or {}),
            "success": None if result is None else bool(result.get("success")),
            "message": None if result is None else result.get("message"),
        }

        try:
            if self.audit_logger and hasattr(self.audit_logger, "log"):
                self.audit_logger.log(audit_payload)
                return

            if hasattr(super(), "log_audit"):
                try:
                    super().log_audit(audit_payload)  # type: ignore
                    return
                except Exception:
                    pass

            logger.info("MemoryAgent audit=%s", audit_payload)
        except Exception as exc:
            logger.warning("Failed to log MemoryAgent audit event: %s", exc)

    def _safe_result(
        self,
        message: str,
        data: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard success result."""

        return {
            "success": True,
            "message": message,
            "data": data if data is not None else {},
            "error": None,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        message: str,
        error: Union[str, Exception],
        data: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard error result."""

        return {
            "success": False,
            "message": message,
            "data": data if data is not None else {},
            "error": str(error),
            "metadata": metadata or {},
        }

    # -----------------------------------------------------------------------
    # Master Agent / Router public entrypoint
    # -----------------------------------------------------------------------

    def run_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main router-compatible entry point.

        Expected task format:
            {
                "action": "store" | "recall" | "search" | "update" | "delete" | ...,
                "user_id": "1",
                "workspace_id": "main",
                "content": "...",
                "query": "...",
                "scope": "long_term",
                ...
            }
        """

        if not isinstance(task, dict):
            return self._error_result(
                message="Invalid memory task.",
                error="Task must be a dictionary.",
            )

        action = str(task.get("action", MemoryAction.RECALL.value)).lower().strip()
        context_result = self._validate_task_context(task)
        if not context_result["success"]:
            return context_result

        task_context = context_result["data"]
        self._log_audit_event(action=action, task_context=task_context, payload=task)

        try:
            if action == MemoryAction.STORE.value:
                result = self.store_memory(
                    task_context=task_context,
                    content=str(task.get("content", "")),
                    scope=str(task.get("scope", MemoryScope.LONG_TERM.value)),
                    tags=task.get("tags"),
                    metadata=task.get("metadata"),
                    sensitivity=str(task.get("sensitivity", MemorySensitivity.INTERNAL.value)),
                    project_id=task.get("project_id"),
                    client_id=task.get("client_id"),
                    team_id=task.get("team_id"),
                    expires_at=task.get("expires_at"),
                )

            elif action in {MemoryAction.RECALL.value, MemoryAction.SEARCH.value}:
                result = self.recall_memory(
                    task_context=task_context,
                    query=str(task.get("query", task.get("content", ""))),
                    scope=task.get("scope"),
                    limit=int(task.get("limit", self.config.default_recall_limit)),
                    tags=task.get("tags"),
                    project_id=task.get("project_id"),
                    client_id=task.get("client_id"),
                    team_id=task.get("team_id"),
                    include_metadata=bool(task.get("include_metadata", True)),
                )

            elif action == MemoryAction.UPDATE.value:
                result = self.update_memory(
                    task_context=task_context,
                    memory_id=str(task.get("memory_id", "")),
                    content=task.get("content"),
                    tags=task.get("tags"),
                    metadata=task.get("metadata"),
                    sensitivity=task.get("sensitivity"),
                )

            elif action in {MemoryAction.DELETE.value, MemoryAction.FORGET.value}:
                result = self.delete_memory(
                    task_context=task_context,
                    memory_id=str(task.get("memory_id", "")),
                    hard_delete=bool(task.get("hard_delete", False)),
                )

            elif action == MemoryAction.SUMMARIZE.value:
                result = self.summarize_memories(
                    task_context=task_context,
                    scope=task.get("scope"),
                    query=task.get("query"),
                    limit=int(task.get("limit", 50)),
                )

            elif action == MemoryAction.CLEAN.value:
                result = self.clean_expired_memories(task_context=task_context)

            elif action == MemoryAction.EXPORT.value:
                result = self.export_memories(
                    task_context=task_context,
                    scope=task.get("scope"),
                    include_sensitive=bool(task.get("include_sensitive", False)),
                )

            elif action == MemoryAction.STATS.value:
                result = self.get_memory_stats(task_context=task_context)

            else:
                result = self._error_result(
                    message="Unsupported memory action.",
                    error=f"Unsupported action: {action}",
                    metadata={"supported_actions": [item.value for item in MemoryAction]},
                )

            verification_payload = self._prepare_verification_payload(
                action=action,
                task_context=task_context,
                result=result,
            )
            result.setdefault("metadata", {})
            result["metadata"]["verification_payload"] = verification_payload

            self._log_audit_event(
                action=action,
                task_context=task_context,
                payload=task,
                result=result,
            )

            self._emit_agent_event(
                event_name=f"memory_agent.{action}",
                payload={
                    "action": action,
                    "success": result.get("success"),
                    "user_id": task_context.get("user_id"),
                    "workspace_id": task_context.get("workspace_id"),
                    "task_id": task_context.get("task_id"),
                },
            )

            return result

        except Exception as exc:
            logger.exception("MemoryAgent task failed.")
            return self._error_result(
                message="Memory task failed.",
                error=exc,
                metadata={"action": action},
            )

    # -----------------------------------------------------------------------
    # Public memory methods
    # -----------------------------------------------------------------------

    def store_memory(
        self,
        task_context: Dict[str, Any],
        content: str,
        scope: str = MemoryScope.LONG_TERM.value,
        tags: Optional[Sequence[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        sensitivity: str = MemorySensitivity.INTERNAL.value,
        project_id: Optional[str] = None,
        client_id: Optional[str] = None,
        team_id: Optional[str] = None,
        expires_at: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Store a new memory record with SaaS isolation and privacy controls."""

        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        ctx = context_result["data"]
        content = self._normalize_content(content)

        if not content:
            return self._error_result(
                message="Memory content is required.",
                error="content cannot be empty.",
            )

        if len(content) > self.config.max_content_chars:
            return self._error_result(
                message="Memory content is too large.",
                error=f"content exceeds max_content_chars={self.config.max_content_chars}.",
            )

        scope = self._normalize_scope(scope)
        sensitivity = self._normalize_sensitivity(sensitivity)
        metadata = metadata or {}
        normalized_tags = self._normalize_tags(tags or [])

        payload = {
            "content": content,
            "scope": scope,
            "tags": normalized_tags,
            "metadata": metadata,
            "sensitivity": sensitivity,
            "project_id": project_id,
            "client_id": client_id,
            "team_id": team_id,
            "expires_at": expires_at,
        }

        if self._requires_security_check(MemoryAction.STORE.value, payload):
            approval = self._request_security_approval(MemoryAction.STORE.value, ctx, payload)
            if not approval.get("success"):
                return approval

        privacy_result = self._privacy_check_content(content, sensitivity)
        if not privacy_result["success"]:
            return privacy_result

        with self._lock:
            quota_result = self._enforce_scope_quota(ctx["user_id"], ctx["workspace_id"], scope)
            if not quota_result["success"]:
                return quota_result

            memory_id = self._generate_memory_id(ctx["user_id"], ctx["workspace_id"], content)
            embedding = self._embed_text(content) if self.config.enable_embeddings else None

            record = MemoryRecord(
                memory_id=memory_id,
                user_id=ctx["user_id"],
                workspace_id=ctx["workspace_id"],
                scope=scope,
                content=content,
                summary=self._summarize_text(content),
                tags=normalized_tags,
                metadata=self._safe_metadata(metadata),
                sensitivity=sensitivity,
                source_agent=ctx.get("source_agent", "unknown"),
                source_task_id=ctx.get("task_id"),
                project_id=self._clean_optional_identifier(project_id),
                client_id=self._clean_optional_identifier(client_id),
                team_id=self._clean_optional_identifier(team_id),
                embedding=embedding,
                expires_at=expires_at,
            )

            if self.storage_backend and hasattr(self.storage_backend, "save"):
                self.storage_backend.save(record.to_public_dict(include_embedding=True))

            self._memory_store[memory_id] = record

        memory_payload = self._prepare_memory_payload(
            content=content,
            task_context=ctx,
            scope=scope,
            metadata=metadata,
            tags=normalized_tags,
            sensitivity=sensitivity,
        )

        return self._safe_result(
            message="Memory stored successfully.",
            data={
                "memory": record.to_public_dict(include_embedding=False),
                "memory_payload": memory_payload,
            },
            metadata={
                "action": MemoryAction.STORE.value,
                "scope": scope,
                "sensitivity": sensitivity,
            },
        )

    def recall_memory(
        self,
        task_context: Dict[str, Any],
        query: str,
        scope: Optional[str] = None,
        limit: int = 10,
        tags: Optional[Sequence[str]] = None,
        project_id: Optional[str] = None,
        client_id: Optional[str] = None,
        team_id: Optional[str] = None,
        include_metadata: bool = True,
    ) -> Dict[str, Any]:
        """
        Recall relevant memories for a query.

        Ranking combines:
            - direct keyword score
            - tag match score
            - deterministic embedding similarity
            - recency/access bonus
        """

        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        ctx = context_result["data"]
        query = self._normalize_content(query)
        limit = max(1, min(int(limit or self.config.default_recall_limit), 100))

        if not query:
            return self._error_result(
                message="Recall query is required.",
                error="query cannot be empty.",
            )

        normalized_scope = self._normalize_scope(scope) if scope else None
        normalized_tags = self._normalize_tags(tags or [])
        query_embedding = self._embed_text(query) if self.config.enable_embeddings else None

        with self._lock:
            candidates = self._filter_records(
                user_id=ctx["user_id"],
                workspace_id=ctx["workspace_id"],
                scope=normalized_scope,
                tags=normalized_tags,
                project_id=project_id,
                client_id=client_id,
                team_id=team_id,
                include_deleted=False,
            )

            scored: List[Tuple[float, MemoryRecord, Dict[str, float]]] = []
            for record in candidates:
                score_breakdown = self._score_record(
                    query=query,
                    query_embedding=query_embedding,
                    record=record,
                    tags=normalized_tags,
                )
                score = sum(score_breakdown.values())

                if score >= self.config.min_search_score:
                    scored.append((score, record, score_breakdown))

            scored.sort(key=lambda item: item[0], reverse=True)
            selected = scored[:limit]

            results = []
            for score, record, breakdown in selected:
                record.access_count += 1
                record.last_accessed_at = datetime.now(timezone.utc).isoformat()

                item = record.to_public_dict(include_embedding=False)
                item["score"] = round(score, 6)
                item["score_breakdown"] = {k: round(v, 6) for k, v in breakdown.items()}

                if not include_metadata:
                    item["metadata"] = {}

                item = self._redact_memory_for_response(item)
                results.append(item)

        return self._safe_result(
            message="Memory recall completed.",
            data={
                "query": query,
                "count": len(results),
                "memories": results,
            },
            metadata={
                "action": MemoryAction.RECALL.value,
                "scope": normalized_scope,
                "limit": limit,
            },
        )

    def update_memory(
        self,
        task_context: Dict[str, Any],
        memory_id: str,
        content: Optional[str] = None,
        tags: Optional[Sequence[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        sensitivity: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update a memory owned by the same user/workspace."""

        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        ctx = context_result["data"]
        memory_id = self._clean_identifier(memory_id)

        if not memory_id:
            return self._error_result(
                message="memory_id is required.",
                error="memory_id cannot be empty.",
            )

        with self._lock:
            record = self._memory_store.get(memory_id)
            if not record or record.is_deleted:
                return self._error_result(
                    message="Memory not found.",
                    error="No active memory exists for the provided memory_id.",
                )

            if not self._owns_record(ctx, record):
                return self._error_result(
                    message="Memory access denied.",
                    error="Memory belongs to a different user/workspace.",
                )

            payload = {
                "memory_id": memory_id,
                "content": content,
                "tags": list(tags or []),
                "metadata": metadata or {},
                "sensitivity": sensitivity or record.sensitivity,
            }

            if self._requires_security_check(MemoryAction.UPDATE.value, payload):
                approval = self._request_security_approval(MemoryAction.UPDATE.value, ctx, payload)
                if not approval.get("success"):
                    return approval

            if content is not None:
                normalized_content = self._normalize_content(content)
                if not normalized_content:
                    return self._error_result(
                        message="Updated memory content cannot be empty.",
                        error="content cannot be empty.",
                    )

                if len(normalized_content) > self.config.max_content_chars:
                    return self._error_result(
                        message="Updated memory content is too large.",
                        error=f"content exceeds max_content_chars={self.config.max_content_chars}.",
                    )

                record.content = normalized_content
                record.summary = self._summarize_text(normalized_content)
                record.embedding = self._embed_text(normalized_content)

            if tags is not None:
                record.tags = self._normalize_tags(tags)

            if metadata is not None:
                merged = copy.deepcopy(record.metadata)
                merged.update(self._safe_metadata(metadata))
                record.metadata = merged

            if sensitivity is not None:
                record.sensitivity = self._normalize_sensitivity(sensitivity)

            record.updated_at = datetime.now(timezone.utc).isoformat()

            if self.storage_backend and hasattr(self.storage_backend, "save"):
                self.storage_backend.save(record.to_public_dict(include_embedding=True))

        return self._safe_result(
            message="Memory updated successfully.",
            data={"memory": self._redact_memory_for_response(record.to_public_dict(False))},
            metadata={"action": MemoryAction.UPDATE.value},
        )

    def delete_memory(
        self,
        task_context: Dict[str, Any],
        memory_id: str,
        hard_delete: bool = False,
    ) -> Dict[str, Any]:
        """Delete or forget a memory after permission/security checks."""

        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        ctx = context_result["data"]
        memory_id = self._clean_identifier(memory_id)

        if not memory_id:
            return self._error_result(
                message="memory_id is required.",
                error="memory_id cannot be empty.",
            )

        payload = {"memory_id": memory_id, "hard_delete": hard_delete}
        approval = self._request_security_approval(MemoryAction.DELETE.value, ctx, payload)
        if not approval.get("success"):
            return approval

        with self._lock:
            record = self._memory_store.get(memory_id)
            if not record:
                return self._error_result(
                    message="Memory not found.",
                    error="No memory exists for the provided memory_id.",
                )

            if not self._owns_record(ctx, record):
                return self._error_result(
                    message="Memory access denied.",
                    error="Memory belongs to a different user/workspace.",
                )

            if hard_delete:
                del self._memory_store[memory_id]
            else:
                record.is_deleted = True
                record.updated_at = datetime.now(timezone.utc).isoformat()

            if self.storage_backend and hasattr(self.storage_backend, "delete"):
                self.storage_backend.delete(memory_id=memory_id, hard_delete=hard_delete)

        return self._safe_result(
            message="Memory deleted successfully." if hard_delete else "Memory forgotten successfully.",
            data={
                "memory_id": memory_id,
                "hard_delete": hard_delete,
            },
            metadata={"action": MemoryAction.DELETE.value},
        )

    def summarize_memories(
        self,
        task_context: Dict[str, Any],
        scope: Optional[str] = None,
        query: Optional[str] = None,
        limit: int = 50,
    ) -> Dict[str, Any]:
        """Create a safe summary of relevant memories."""

        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        ctx = context_result["data"]
        normalized_scope = self._normalize_scope(scope) if scope else None
        limit = max(1, min(limit, 200))

        with self._lock:
            records = self._filter_records(
                user_id=ctx["user_id"],
                workspace_id=ctx["workspace_id"],
                scope=normalized_scope,
                include_deleted=False,
            )

            if query:
                recall = self.recall_memory(
                    task_context=ctx,
                    query=query,
                    scope=normalized_scope,
                    limit=limit,
                )
                if not recall["success"]:
                    return recall
                memories = recall["data"].get("memories", [])
                snippets = [item.get("summary") or item.get("content", "") for item in memories]
            else:
                records = sorted(records, key=lambda item: item.updated_at, reverse=True)[:limit]
                snippets = [record.summary or record.content for record in records]

        combined = " ".join(snippets)
        summary = self._summarize_text(combined, max_chars=1500)

        return self._safe_result(
            message="Memory summary created.",
            data={
                "summary": summary,
                "source_count": len(snippets),
                "scope": normalized_scope,
                "query": query,
            },
            metadata={"action": MemoryAction.SUMMARIZE.value},
        )

    def clean_expired_memories(self, task_context: Dict[str, Any]) -> Dict[str, Any]:
        """Soft-delete expired short-term or expiring memories for the same user/workspace."""

        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        ctx = context_result["data"]
        now = datetime.now(timezone.utc)
        cleaned_ids: List[str] = []

        with self._lock:
            for record in self._memory_store.values():
                if not self._owns_record(ctx, record):
                    continue
                if record.is_deleted:
                    continue
                if record.expires_at and self._parse_dt(record.expires_at) <= now:
                    record.is_deleted = True
                    record.updated_at = now.isoformat()
                    cleaned_ids.append(record.memory_id)

        return self._safe_result(
            message="Expired memories cleaned.",
            data={
                "cleaned_count": len(cleaned_ids),
                "memory_ids": cleaned_ids,
            },
            metadata={"action": MemoryAction.CLEAN.value},
        )

    def export_memories(
        self,
        task_context: Dict[str, Any],
        scope: Optional[str] = None,
        include_sensitive: bool = False,
    ) -> Dict[str, Any]:
        """
        Export memories for current user/workspace only.

        Sensitive export requires Security Agent approval.
        """

        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        ctx = context_result["data"]
        payload = {"scope": scope, "include_sensitive": include_sensitive}

        approval = self._request_security_approval(MemoryAction.EXPORT.value, ctx, payload)
        if not approval.get("success"):
            return approval

        normalized_scope = self._normalize_scope(scope) if scope else None

        with self._lock:
            records = self._filter_records(
                user_id=ctx["user_id"],
                workspace_id=ctx["workspace_id"],
                scope=normalized_scope,
                include_deleted=False,
            )

            exported = []
            for record in records:
                if not include_sensitive and record.sensitivity in {
                    MemorySensitivity.CONFIDENTIAL.value,
                    MemorySensitivity.SENSITIVE.value,
                    MemorySensitivity.SECRET.value,
                }:
                    continue
                exported.append(
                    self._redact_memory_for_response(record.to_public_dict(include_embedding=False))
                )

        return self._safe_result(
            message="Memories exported successfully.",
            data={
                "count": len(exported),
                "memories": exported,
            },
            metadata={"action": MemoryAction.EXPORT.value, "scope": normalized_scope},
        )

    def get_memory_stats(self, task_context: Dict[str, Any]) -> Dict[str, Any]:
        """Return memory stats for the current user/workspace only."""

        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        ctx = context_result["data"]

        stats = {
            "total_active": 0,
            "total_deleted": 0,
            "by_scope": {},
            "by_sensitivity": {},
            "short_term_count": 0,
            "long_term_count": 0,
            "project_count": 0,
            "client_count": 0,
            "team_count": 0,
        }

        with self._lock:
            for record in self._memory_store.values():
                if not self._owns_record(ctx, record):
                    continue

                if record.is_deleted:
                    stats["total_deleted"] += 1
                    continue

                stats["total_active"] += 1
                stats["by_scope"][record.scope] = stats["by_scope"].get(record.scope, 0) + 1
                stats["by_sensitivity"][record.sensitivity] = (
                    stats["by_sensitivity"].get(record.sensitivity, 0) + 1
                )

                if record.scope == MemoryScope.SHORT_TERM.value:
                    stats["short_term_count"] += 1
                elif record.scope == MemoryScope.LONG_TERM.value:
                    stats["long_term_count"] += 1
                elif record.scope == MemoryScope.PROJECT.value:
                    stats["project_count"] += 1
                elif record.scope == MemoryScope.CLIENT.value:
                    stats["client_count"] += 1
                elif record.scope == MemoryScope.TEAM.value:
                    stats["team_count"] += 1

        return self._safe_result(
            message="Memory stats loaded.",
            data=stats,
            metadata={"action": MemoryAction.STATS.value},
        )

    # -----------------------------------------------------------------------
    # Convenience public methods for future routers/API
    # -----------------------------------------------------------------------

    def remember_short_term(
        self,
        task_context: Dict[str, Any],
        content: str,
        tags: Optional[Sequence[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Store short-term memory with default expiry."""

        expires_at = datetime.fromtimestamp(
            time.time() + self.config.default_short_term_ttl_seconds,
            tz=timezone.utc,
        ).isoformat()

        return self.store_memory(
            task_context=task_context,
            content=content,
            scope=MemoryScope.SHORT_TERM.value,
            tags=tags,
            metadata=metadata,
            sensitivity=MemorySensitivity.INTERNAL.value,
            expires_at=expires_at,
        )

    def remember_long_term(
        self,
        task_context: Dict[str, Any],
        content: str,
        tags: Optional[Sequence[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        sensitivity: str = MemorySensitivity.INTERNAL.value,
    ) -> Dict[str, Any]:
        """Store durable long-term memory."""

        return self.store_memory(
            task_context=task_context,
            content=content,
            scope=MemoryScope.LONG_TERM.value,
            tags=tags,
            metadata=metadata,
            sensitivity=sensitivity,
        )

    def remember_project(
        self,
        task_context: Dict[str, Any],
        project_id: str,
        content: str,
        tags: Optional[Sequence[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Store project-specific memory."""

        return self.store_memory(
            task_context=task_context,
            content=content,
            scope=MemoryScope.PROJECT.value,
            tags=tags,
            metadata=metadata,
            project_id=project_id,
        )

    def remember_client(
        self,
        task_context: Dict[str, Any],
        client_id: str,
        content: str,
        tags: Optional[Sequence[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Store client-specific memory."""

        return self.store_memory(
            task_context=task_context,
            content=content,
            scope=MemoryScope.CLIENT.value,
            tags=tags,
            metadata=metadata,
            client_id=client_id,
            sensitivity=MemorySensitivity.CONFIDENTIAL.value,
        )

    def remember_team(
        self,
        task_context: Dict[str, Any],
        team_id: str,
        content: str,
        tags: Optional[Sequence[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Store team-specific memory."""

        return self.store_memory(
            task_context=task_context,
            content=content,
            scope=MemoryScope.TEAM.value,
            tags=tags,
            metadata=metadata,
            team_id=team_id,
        )

    def remember_preference(
        self,
        task_context: Dict[str, Any],
        content: str,
        tags: Optional[Sequence[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Store user/workspace preference memory."""

        normalized_tags = list(tags or [])
        if "preference" not in normalized_tags:
            normalized_tags.append("preference")

        return self.store_memory(
            task_context=task_context,
            content=content,
            scope=MemoryScope.PREFERENCE.value,
            tags=normalized_tags,
            metadata=metadata,
        )

    def get_registry_metadata(self) -> Dict[str, Any]:
        """Return Agent Registry-compatible metadata."""

        return copy.deepcopy(self.registry_metadata)

    def health_check(self) -> Dict[str, Any]:
        """Return simple health check for dashboard/API."""

        with self._lock:
            total = len(self._memory_store)
            active = sum(1 for item in self._memory_store.values() if not item.is_deleted)

        return self._safe_result(
            message="Memory Agent is healthy.",
            data={
                "agent_name": "memory_agent",
                "version": self.config.agent_version,
                "started_at": self._agent_started_at,
                "total_records": total,
                "active_records": active,
                "storage_backend": bool(self.storage_backend),
                "security_agent": bool(self.security_agent),
                "verification_agent": bool(self.verification_agent),
            },
        )

    # -----------------------------------------------------------------------
    # Internal filtering/scoring helpers
    # -----------------------------------------------------------------------

    def _filter_records(
        self,
        user_id: str,
        workspace_id: str,
        scope: Optional[str] = None,
        tags: Optional[Sequence[str]] = None,
        project_id: Optional[str] = None,
        client_id: Optional[str] = None,
        team_id: Optional[str] = None,
        include_deleted: bool = False,
    ) -> List[MemoryRecord]:
        """Filter records with strict user/workspace isolation."""

        normalized_tags = set(self._normalize_tags(tags or []))
        filtered: List[MemoryRecord] = []

        now = datetime.now(timezone.utc)

        for record in self._memory_store.values():
            if record.user_id != user_id or record.workspace_id != workspace_id:
                continue

            if not include_deleted and record.is_deleted:
                continue

            if record.expires_at and self._parse_dt(record.expires_at) <= now:
                continue

            if scope and record.scope != scope:
                continue

            if normalized_tags and not normalized_tags.intersection(set(record.tags)):
                continue

            if project_id and record.project_id != self._clean_optional_identifier(project_id):
                continue

            if client_id and record.client_id != self._clean_optional_identifier(client_id):
                continue

            if team_id and record.team_id != self._clean_optional_identifier(team_id):
                continue

            filtered.append(record)

        return filtered

    def _score_record(
        self,
        query: str,
        query_embedding: Optional[List[float]],
        record: MemoryRecord,
        tags: Optional[Sequence[str]] = None,
    ) -> Dict[str, float]:
        """Score one record against recall query."""

        keyword_score = self._keyword_score(query, record.content + " " + record.summary)
        tag_score = self._tag_score(tags or [], record.tags)
        embedding_score = 0.0
        recency_score = self._recency_score(record)
        access_score = min(float(record.access_count) * 0.005, 0.05)

        if query_embedding and record.embedding:
            embedding_score = self._cosine_similarity(query_embedding, record.embedding) * 0.45

        return {
            "keyword": keyword_score * 0.40,
            "embedding": embedding_score,
            "tags": tag_score * 0.10,
            "recency": recency_score * 0.03,
            "access": access_score,
        }

    def _keyword_score(self, query: str, text: str) -> float:
        """Simple token overlap score."""

        query_tokens = set(self._tokenize(query))
        text_tokens = set(self._tokenize(text))

        if not query_tokens or not text_tokens:
            return 0.0

        overlap = query_tokens.intersection(text_tokens)
        return len(overlap) / max(len(query_tokens), 1)

    def _tag_score(self, wanted_tags: Sequence[str], record_tags: Sequence[str]) -> float:
        """Score tag intersection."""

        wanted = set(self._normalize_tags(wanted_tags))
        current = set(self._normalize_tags(record_tags))

        if not wanted:
            return 0.0

        return len(wanted.intersection(current)) / max(len(wanted), 1)

    def _recency_score(self, record: MemoryRecord) -> float:
        """Small recency score."""

        updated = self._parse_dt(record.updated_at)
        age_seconds = max((datetime.now(timezone.utc) - updated).total_seconds(), 1)
        return 1.0 / (1.0 + math.log10(age_seconds + 10))

    def _embed_text(self, text: str) -> List[float]:
        """
        Deterministic fallback embedding.

        This is not a replacement for real embeddings, but keeps the file production-safe,
        testable, and vector-search-ready until embeddings.py is created.
        """

        dimensions = max(16, int(self.config.embedding_dimensions))
        vector = [0.0] * dimensions

        tokens = self._tokenize(text)
        if not tokens:
            return vector

        for token in tokens:
            digest = hashlib.sha256(token.encode("utf-8")).digest()
            for index, byte in enumerate(digest):
                pos = index % dimensions
                value = (byte / 255.0) - 0.5
                vector[pos] += value

        norm = math.sqrt(sum(item * item for item in vector)) or 1.0
        return [item / norm for item in vector]

    def _cosine_similarity(self, first: Sequence[float], second: Sequence[float]) -> float:
        """Cosine similarity normalized to 0..1-ish."""

        if not first or not second:
            return 0.0

        length = min(len(first), len(second))
        dot = sum(first[i] * second[i] for i in range(length))
        norm_a = math.sqrt(sum(first[i] * first[i] for i in range(length))) or 1.0
        norm_b = math.sqrt(sum(second[i] * second[i] for i in range(length))) or 1.0
        cosine = dot / (norm_a * norm_b)

        return max(0.0, min(1.0, (cosine + 1.0) / 2.0))

    # -----------------------------------------------------------------------
    # Privacy and safety helpers
    # -----------------------------------------------------------------------

    def _privacy_check_content(self, content: str, sensitivity: str) -> Dict[str, Any]:
        """Basic privacy guard before storing memory."""

        if not self.config.enable_privacy_guard:
            return self._safe_result(message="Privacy guard disabled by config.")

        if self._detect_secret_like_content(content) and sensitivity not in {
            MemorySensitivity.SENSITIVE.value,
            MemorySensitivity.SECRET.value,
            MemorySensitivity.CONFIDENTIAL.value,
        }:
            return self._error_result(
                message="Sensitive-looking memory requires explicit sensitivity.",
                error=(
                    "Content appears to contain secrets, tokens, passwords, or keys. "
                    "Set sensitivity to confidential, sensitive, or secret."
                ),
                metadata={"privacy_guard": True},
            )

        return self._safe_result(
            message="Privacy check passed.",
            metadata={"privacy_guard": True},
        )

    def _detect_secret_like_content(self, content: str) -> bool:
        """Detect obvious secret-like content patterns."""

        if not content:
            return False

        patterns = [
            r"(?i)\bapi[_-]?key\b\s*[:=]",
            r"(?i)\bsecret\b\s*[:=]",
            r"(?i)\bpassword\b\s*[:=]",
            r"(?i)\btoken\b\s*[:=]",
            r"(?i)\bprivate[_-]?key\b",
            r"-----BEGIN\s+(RSA|OPENSSH|PRIVATE)\s+KEY-----",
            r"\bAKIA[0-9A-Z]{16}\b",
            r"(?i)\bbearer\s+[a-z0-9._\-]{20,}",
        ]

        return any(re.search(pattern, content) for pattern in patterns)

    def _redact_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Redact sensitive fields in logs/events."""

        sensitive_keys = {
            "content",
            "password",
            "secret",
            "token",
            "api_key",
            "private_key",
            "authorization",
        }

        for key in list(payload.keys()):
            if key.lower() in sensitive_keys:
                payload[key] = "[REDACTED]"
            elif isinstance(payload[key], dict):
                payload[key] = self._redact_payload(payload[key])
            elif isinstance(payload[key], list):
                payload[key] = [
                    self._redact_payload(item) if isinstance(item, dict) else item
                    for item in payload[key]
                ]

        return payload

    def _redact_memory_for_response(self, memory: Dict[str, Any]) -> Dict[str, Any]:
        """Redact memory content if sensitivity is high."""

        sensitivity = str(memory.get("sensitivity", "")).lower()

        if sensitivity == MemorySensitivity.SECRET.value:
            memory["content"] = "[SECRET MEMORY REDACTED]"
            memory["summary"] = "[SECRET MEMORY REDACTED]"

        elif sensitivity == MemorySensitivity.SENSITIVE.value:
            memory["content"] = self._soft_redact_text(str(memory.get("content", "")))
            memory["summary"] = self._soft_redact_text(str(memory.get("summary", "")))

        return memory

    def _soft_redact_text(self, text: str) -> str:
        """Soft redact common sensitive tokens."""

        text = re.sub(r"(?i)(password|token|secret|api[_-]?key)\s*[:=]\s*\S+", r"\1=[REDACTED]", text)
        text = re.sub(r"(?i)bearer\s+[a-z0-9._\-]+", "Bearer [REDACTED]", text)
        return text

    # -----------------------------------------------------------------------
    # Normalization helpers
    # -----------------------------------------------------------------------

    def _normalize_content(self, content: Any) -> str:
        """Normalize text content."""

        if content is None:
            return ""

        text = str(content).replace("\x00", "").strip()
        text = re.sub(r"\s+", " ", text)
        return text

    def _normalize_scope(self, scope: Optional[str]) -> str:
        """Normalize memory scope."""

        value = str(scope or MemoryScope.LONG_TERM.value).lower().strip()
        valid = {item.value for item in MemoryScope}
        if value not in valid:
            return MemoryScope.LONG_TERM.value
        return value

    def _normalize_sensitivity(self, sensitivity: Optional[str]) -> str:
        """Normalize sensitivity."""

        value = str(sensitivity or MemorySensitivity.INTERNAL.value).lower().strip()
        valid = {item.value for item in MemorySensitivity}
        if value not in valid:
            return MemorySensitivity.INTERNAL.value
        return value

    def _normalize_tags(self, tags: Iterable[Any]) -> List[str]:
        """Normalize memory tags."""

        clean_tags: List[str] = []
        for tag in tags:
            value = str(tag).lower().strip()
            value = re.sub(r"[^a-z0-9_\- ]+", "", value)
            value = re.sub(r"\s+", "-", value)
            if value and value not in clean_tags:
                clean_tags.append(value)
        return clean_tags[:50]

    def _safe_metadata(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Keep metadata JSON-safe and redacted."""

        try:
            safe = json.loads(json.dumps(metadata, default=str))
            if isinstance(safe, dict):
                return self._redact_payload(safe)
            return {}
        except Exception:
            return {"raw_metadata_error": "metadata was not JSON serializable"}

    def _clean_identifier(self, value: Any) -> str:
        """Clean required identifier."""

        if value is None:
            return ""

        text = str(value).strip()
        text = re.sub(r"[^a-zA-Z0-9_\-:.@]", "", text)
        return text[:128]

    def _clean_optional_identifier(self, value: Any) -> Optional[str]:
        """Clean optional identifier."""

        cleaned = self._clean_identifier(value)
        return cleaned or None

    def _tokenize(self, text: str) -> List[str]:
        """Tokenize text for simple matching/embeddings."""

        text = str(text or "").lower()
        return re.findall(r"[a-z0-9][a-z0-9_\-]{1,}", text)

    def _summarize_text(self, text: str, max_chars: int = 500) -> str:
        """Fallback text summarizer."""

        text = self._normalize_content(text)
        if len(text) <= max_chars:
            return text

        clipped = text[:max_chars].rsplit(" ", 1)[0]
        return f"{clipped}..."

    def _parse_dt(self, value: Optional[str]) -> datetime:
        """Parse ISO datetime safely."""

        if not value:
            return datetime.min.replace(tzinfo=timezone.utc)

        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed
        except Exception:
            return datetime.min.replace(tzinfo=timezone.utc)

    def _generate_memory_id(self, user_id: str, workspace_id: str, content: str) -> str:
        """Generate stable unique memory id."""

        raw = f"{user_id}:{workspace_id}:{content}:{time.time_ns()}:{uuid.uuid4()}"
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]
        return f"mem_{digest}"

    def _owns_record(self, task_context: Dict[str, Any], record: MemoryRecord) -> bool:
        """Strict SaaS isolation check."""

        return (
            str(task_context.get("user_id")) == record.user_id
            and str(task_context.get("workspace_id")) == record.workspace_id
        )

    def _audit_payload_summary(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Create safe audit summary without raw memory content."""

        summary = {
            "keys": sorted(list(payload.keys())),
            "scope": payload.get("scope"),
            "sensitivity": payload.get("sensitivity"),
            "memory_id": payload.get("memory_id"),
            "has_content": bool(payload.get("content")),
            "content_length": len(str(payload.get("content", ""))) if payload.get("content") else 0,
        }
        return summary

    def _enforce_scope_quota(
        self,
        user_id: str,
        workspace_id: str,
        scope: str,
    ) -> Dict[str, Any]:
        """Enforce safe default memory quotas."""

        records = self._filter_records(
            user_id=user_id,
            workspace_id=workspace_id,
            scope=scope,
            include_deleted=False,
        )

        if scope == MemoryScope.SHORT_TERM.value:
            max_allowed = self.config.max_short_term_records_per_user_workspace
        else:
            max_allowed = self.config.max_long_term_records_per_user_workspace

        if len(records) >= max_allowed:
            return self._error_result(
                message="Memory quota exceeded.",
                error=f"Maximum active records reached for scope={scope}.",
                metadata={
                    "scope": scope,
                    "max_allowed": max_allowed,
                    "current_count": len(records),
                },
            )

        return self._safe_result(
            message="Memory quota check passed.",
            metadata={
                "scope": scope,
                "max_allowed": max_allowed,
                "current_count": len(records),
            },
        )


# ---------------------------------------------------------------------------
# Module-level helpers for Agent Loader compatibility
# ---------------------------------------------------------------------------

def create_agent(**kwargs: Any) -> MemoryAgent:
    """
    Factory used by Agent Loader / Registry.

    Example:
        agent = create_agent()
    """

    return MemoryAgent(**kwargs)


def get_agent_metadata() -> Dict[str, Any]:
    """Return static metadata without requiring full agent startup."""

    return {
        "agent_name": "memory_agent",
        "class_name": "MemoryAgent",
        "module": "agents.memory_agent.memory_agent",
        "version": "1.0.0",
        "safe_import": True,
        "requires_user_context": True,
        "requires_workspace_context": True,
        "capabilities": [
            "short_term_memory",
            "long_term_memory",
            "project_memory",
            "client_memory",
            "team_memory",
            "preference_memory",
            "memory_recall",
            "memory_search",
            "privacy_guard",
            "fallback_embeddings",
        ],
    }


__all__ = [
    "MemoryAgent",
    "MemoryAgentConfig",
    "MemoryRecord",
    "MemoryScope",
    "MemorySensitivity",
    "MemoryAction",
    "create_agent",
    "get_agent_metadata",
]