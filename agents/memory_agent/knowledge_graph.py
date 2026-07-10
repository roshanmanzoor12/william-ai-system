"""
agents/memory_agent/knowledge_graph.py

William / Jarvis Multi-Agent AI SaaS System - Digital Promotix

Purpose:
    Nodes/edges connecting users, projects, files, agents, tasks, decisions.

This file implements the Memory Agent knowledge graph layer. It stores and queries
relationships between SaaS-scoped entities such as users, workspaces, projects,
clients, files, agents, tasks, decisions, memories, and events.

Architecture Connections:
    - Master Agent:
        Can route graph tasks here for relationship storage, lookup, path search,
        decision tracing, and dashboard-ready graph summaries.

    - Memory Agent:
        Uses this class to connect short-term memory, long-term memory, project
        memory, client memory, team memory, embeddings, recall, preferences,
        and decisions into a structured graph.

    - Security Agent:
        Sensitive operations such as deleting/purging/exporting full graph data
        can request security approval through _request_security_approval().

    - Verification Agent:
        Completed graph mutations prepare verification payloads through
        _prepare_verification_payload().

    - Dashboard/API:
        Public methods return structured dict results:
            {
                "success": bool,
                "message": str,
                "data": dict/list/None,
                "error": str/None,
                "metadata": dict
            }

    - Agent Registry / Loader / Router:
        This file is import-safe. If BaseAgent or future modules are missing,
        local fallback stubs allow this file to load without crashing.

Safety Rules:
    - Every user-specific action requires user_id and workspace_id.
    - No graph data is mixed across users/workspaces.
    - Destructive or full-export actions are marked as security-sensitive.
    - No real system, browser, financial, call, message, or destructive external
      actions are executed directly from this file.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import uuid
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Deque, Dict, Iterable, List, Optional, Set, Tuple, Union


# ---------------------------------------------------------------------------
# Optional / Safe Imports
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for future/import-safe builds
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps knowledge_graph.py import-safe even when the final William
        BaseAgent has not been created yet.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())
            self.logger = logging.getLogger(self.agent_name)

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback emit_event: %s %s", event_name, payload)

        def log_audit(self, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback log_audit: %s", payload)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_AGENT_NAME = "KnowledgeGraph"
DEFAULT_AGENT_ID = "memory_agent.knowledge_graph"

DEFAULT_GRAPH_DIR = Path("data/memory_agent/knowledge_graph")
DEFAULT_GRAPH_FILE = "knowledge_graph.json"

SAFE_NODE_TYPES: Set[str] = {
    "user",
    "workspace",
    "project",
    "client",
    "file",
    "agent",
    "task",
    "decision",
    "memory",
    "note",
    "campaign",
    "proposal",
    "deadline",
    "document",
    "endpoint",
    "bug",
    "feature",
    "subscription",
    "role",
    "permission",
    "audit_event",
    "workflow",
    "integration",
    "tool",
    "source",
    "custom",
}

SAFE_EDGE_TYPES: Set[str] = {
    "owns",
    "belongs_to",
    "member_of",
    "created",
    "updated",
    "deleted",
    "assigned_to",
    "depends_on",
    "blocks",
    "relates_to",
    "references",
    "mentions",
    "decided",
    "caused_by",
    "resolved_by",
    "stored_in",
    "uses",
    "connected_to",
    "derived_from",
    "similar_to",
    "part_of",
    "has_file",
    "has_task",
    "has_decision",
    "has_memory",
    "managed_by",
    "authorized_by",
    "triggered",
    "custom",
}

SENSITIVE_ACTIONS: Set[str] = {
    "delete_node",
    "delete_edge",
    "purge_workspace_graph",
    "export_workspace_graph",
    "import_workspace_graph",
    "clear_all",
}

DEFAULT_MAX_GRAPH_DEPTH = 5
DEFAULT_PATH_LIMIT = 25
DEFAULT_SEARCH_LIMIT = 50


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class GraphContext:
    """
    SaaS isolation context for every graph operation.

    user_id:
        The authenticated SaaS user performing the action.

    workspace_id:
        Workspace boundary. All graph operations must remain inside this scope.

    actor_agent:
        Optional agent name/id initiating the request.

    request_id:
        Correlation ID for audit/dashboard tracing.
    """

    user_id: str
    workspace_id: str
    actor_agent: str = DEFAULT_AGENT_ID
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    role: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphNode:
    """
    Knowledge graph node.

    All nodes are scoped by user_id and workspace_id to avoid cross-tenant data
    leakage in the William/Jarvis SaaS environment.
    """

    node_id: str
    node_type: str
    label: str
    user_id: str
    workspace_id: str
    properties: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    source: Optional[str] = None
    created_by: Optional[str] = None
    updated_by: Optional[str] = None
    created_at: str = field(default_factory=lambda: KnowledgeGraph.utcnow())
    updated_at: str = field(default_factory=lambda: KnowledgeGraph.utcnow())
    is_active: bool = True


@dataclass
class GraphEdge:
    """
    Knowledge graph edge connecting two scoped nodes.
    """

    edge_id: str
    source_node_id: str
    target_node_id: str
    edge_type: str
    user_id: str
    workspace_id: str
    weight: float = 1.0
    properties: Dict[str, Any] = field(default_factory=dict)
    source: Optional[str] = None
    created_by: Optional[str] = None
    updated_by: Optional[str] = None
    created_at: str = field(default_factory=lambda: KnowledgeGraph.utcnow())
    updated_at: str = field(default_factory=lambda: KnowledgeGraph.utcnow())
    is_active: bool = True


# ---------------------------------------------------------------------------
# KnowledgeGraph
# ---------------------------------------------------------------------------

class KnowledgeGraph(BaseAgent):
    """
    Memory Agent knowledge graph.

    Public responsibilities:
        - Add/update/delete scoped nodes.
        - Add/update/delete scoped edges.
        - Link users, projects, files, agents, tasks, decisions, memories.
        - Query neighbors, subgraphs, paths, decisions, project timelines.
        - Export/import workspace graph snapshots.
        - Prepare memory and verification payloads.
        - Emit audit/dashboard events.

    Import-safety:
        Uses fallback BaseAgent if William's BaseAgent is not yet available.

    Storage:
        Defaults to JSON file persistence. A future database/vector/graph backend
        can be integrated by replacing persistence methods while keeping public
        method signatures stable.
    """

    def __init__(
        self,
        storage_dir: Union[str, Path] = DEFAULT_GRAPH_DIR,
        storage_file: str = DEFAULT_GRAPH_FILE,
        autosave: bool = True,
        security_approval_callback: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        event_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        audit_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        logger: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name=DEFAULT_AGENT_NAME, agent_id=DEFAULT_AGENT_ID, **kwargs)

        self.agent_name = DEFAULT_AGENT_NAME
        self.agent_id = DEFAULT_AGENT_ID
        self.storage_dir = Path(storage_dir)
        self.storage_file = storage_file
        self.storage_path = self.storage_dir / self.storage_file
        self.autosave = autosave

        self.security_approval_callback = security_approval_callback
        self.event_callback = event_callback
        self.audit_callback = audit_callback

        self.logger = logger or logging.getLogger(self.agent_name)
        self._lock = threading.RLock()

        self._nodes: Dict[str, GraphNode] = {}
        self._edges: Dict[str, GraphEdge] = {}

        self._load_from_disk()

    # -----------------------------------------------------------------------
    # Time / Utility
    # -----------------------------------------------------------------------

    @staticmethod
    def utcnow() -> str:
        """Return timezone-aware UTC timestamp as ISO string."""
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _normalize(value: Any) -> str:
        """Normalize values for simple text matching."""
        return str(value or "").strip().lower()

    @staticmethod
    def _new_id(prefix: str) -> str:
        """Create stable readable IDs for graph records."""
        return f"{prefix}_{uuid.uuid4().hex}"

    def _safe_result(
        self,
        success: bool = True,
        message: str = "OK",
        data: Optional[Any] = None,
        error: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return William/Jarvis-compatible structured result."""
        return {
            "success": bool(success),
            "message": message,
            "data": data if data is not None else {},
            "error": None if error is None else str(error),
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return structured error result."""
        return self._safe_result(
            success=False,
            message=message,
            data={},
            error=error or message,
            metadata=metadata or {},
        )

    def _node_to_dict(self, node: GraphNode) -> Dict[str, Any]:
        return asdict(node)

    def _edge_to_dict(self, edge: GraphEdge) -> Dict[str, Any]:
        return asdict(edge)

    def _context_from_kwargs(
        self,
        user_id: str,
        workspace_id: str,
        actor_agent: str = DEFAULT_AGENT_ID,
        request_id: Optional[str] = None,
        role: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> GraphContext:
        return GraphContext(
            user_id=str(user_id or "").strip(),
            workspace_id=str(workspace_id or "").strip(),
            actor_agent=str(actor_agent or DEFAULT_AGENT_ID).strip(),
            request_id=request_id or str(uuid.uuid4()),
            role=role,
            permissions=permissions or [],
            metadata=metadata or {},
        )

    # -----------------------------------------------------------------------
    # Compatibility Hooks
    # -----------------------------------------------------------------------

    def _validate_task_context(self, context: Union[GraphContext, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Validate SaaS isolation fields.

        Every user/workspace-scoped operation must provide both user_id and
        workspace_id. This prevents memory, files, logs, tasks, analytics,
        audit data, and graph data from mixing across tenants.
        """
        try:
            if isinstance(context, dict):
                user_id = str(context.get("user_id", "")).strip()
                workspace_id = str(context.get("workspace_id", "")).strip()
                request_id = str(context.get("request_id") or uuid.uuid4())
            else:
                user_id = str(context.user_id).strip()
                workspace_id = str(context.workspace_id).strip()
                request_id = str(context.request_id or uuid.uuid4())

            if not user_id:
                return self._error_result(
                    "Missing required user_id for KnowledgeGraph operation.",
                    metadata={"request_id": request_id},
                )

            if not workspace_id:
                return self._error_result(
                    "Missing required workspace_id for KnowledgeGraph operation.",
                    metadata={"request_id": request_id, "user_id": user_id},
                )

            return self._safe_result(
                message="Task context validated.",
                data={"user_id": user_id, "workspace_id": workspace_id, "request_id": request_id},
                metadata={"request_id": request_id},
            )
        except Exception as exc:
            self.logger.exception("Context validation failed.")
            return self._error_result("Context validation failed.", exc)

    def _requires_security_check(self, action: str, payload: Optional[Dict[str, Any]] = None) -> bool:
        """
        Decide whether an action must go through Security Agent.

        The Security Agent can later plug into this hook. For now, destructive
        and full export/import actions are treated as sensitive.
        """
        action_key = self._normalize(action)
        if action_key in SENSITIVE_ACTIONS:
            return True

        payload = payload or {}
        if payload.get("force_security_check") is True:
            return True

        return False

    def _request_security_approval(
        self,
        action: str,
        context: GraphContext,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request approval from Security Agent or a callback.

        This method does not perform real destructive/external actions. It only
        returns approval metadata. In production, the Security Agent can be
        injected using security_approval_callback.
        """
        approval_payload = {
            "action": action,
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "actor_agent": context.actor_agent,
            "request_id": context.request_id,
            "payload": payload or {},
            "timestamp": self.utcnow(),
        }

        if not self._requires_security_check(action, payload):
            return self._safe_result(
                message="Security approval not required.",
                data={"approved": True, "approval_type": "not_required"},
                metadata={"request_id": context.request_id},
            )

        try:
            if self.security_approval_callback:
                response = self.security_approval_callback(approval_payload)
                approved = bool(response.get("approved", False))
                return self._safe_result(
                    success=approved,
                    message="Security approval granted." if approved else "Security approval denied.",
                    data=response,
                    error=None if approved else response.get("reason", "Denied by Security Agent."),
                    metadata={"request_id": context.request_id},
                )

            # Safe default for import/testing:
            # destructive operations are denied unless explicitly allowed by permission.
            allowed_by_permission = "knowledge_graph:admin" in context.permissions
            return self._safe_result(
                success=allowed_by_permission,
                message=(
                    "Security approval granted by admin permission."
                    if allowed_by_permission
                    else "Security approval required and no Security Agent callback is configured."
                ),
                data={
                    "approved": allowed_by_permission,
                    "approval_type": "permission_fallback",
                    "required_permission": "knowledge_graph:admin",
                },
                error=None if allowed_by_permission else "Security approval unavailable.",
                metadata={"request_id": context.request_id},
            )
        except Exception as exc:
            self.logger.exception("Security approval request failed.")
            return self._error_result(
                "Security approval request failed.",
                exc,
                metadata={"request_id": context.request_id},
            )

    def _prepare_verification_payload(
        self,
        action: str,
        context: GraphContext,
        result_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Build Verification Agent payload after successful graph actions.
        """
        return {
            "verification_type": "knowledge_graph_action",
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "action": action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "result_data": result_data or {},
            "checks": {
                "saas_context_present": bool(context.user_id and context.workspace_id),
                "workspace_isolated": True,
                "import_safe": True,
                "structured_result": True,
            },
            "created_at": self.utcnow(),
        }

    def _prepare_memory_payload(
        self,
        action: str,
        context: GraphContext,
        summary: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Build Memory Agent-compatible payload.

        This allows other memory files to store useful graph context without
        depending on this class internals.
        """
        return {
            "memory_type": "knowledge_graph_event",
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "action": action,
            "summary": summary,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "data": data or {},
            "created_at": self.utcnow(),
        }

    def _emit_agent_event(
        self,
        event_name: str,
        payload: Dict[str, Any],
    ) -> None:
        """
        Emit dashboard/registry/router event.

        Uses callback if supplied, otherwise tries BaseAgent.emit_event fallback.
        """
        try:
            safe_payload = dict(payload or {})
            safe_payload.setdefault("agent_id", self.agent_id)
            safe_payload.setdefault("agent_name", self.agent_name)
            safe_payload.setdefault("timestamp", self.utcnow())

            if self.event_callback:
                self.event_callback(event_name, safe_payload)
                return

            if hasattr(super(), "emit_event"):
                try:
                    super().emit_event(event_name, safe_payload)  # type: ignore[misc]
                    return
                except Exception:
                    pass

            self.logger.debug("Agent event: %s %s", event_name, safe_payload)
        except Exception:
            self.logger.exception("Failed to emit agent event.")

    def _log_audit_event(
        self,
        action: str,
        context: GraphContext,
        details: Optional[Dict[str, Any]] = None,
        success: bool = True,
        error: Optional[str] = None,
    ) -> None:
        """
        Log audit event for Security Agent / dashboard / compliance.
        """
        try:
            payload = {
                "agent_id": self.agent_id,
                "agent_name": self.agent_name,
                "action": action,
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
                "actor_agent": context.actor_agent,
                "request_id": context.request_id,
                "success": success,
                "error": error,
                "details": details or {},
                "timestamp": self.utcnow(),
            }

            if self.audit_callback:
                self.audit_callback(payload)
                return

            if hasattr(super(), "log_audit"):
                try:
                    super().log_audit(payload)  # type: ignore[misc]
                    return
                except Exception:
                    pass

            self.logger.info("KnowledgeGraph audit: %s", payload)
        except Exception:
            self.logger.exception("Failed to log audit event.")

    # -----------------------------------------------------------------------
    # Persistence
    # -----------------------------------------------------------------------

    def _ensure_storage_dir(self) -> None:
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def _load_from_disk(self) -> None:
        """Load graph data from JSON storage if available."""
        with self._lock:
            try:
                self._ensure_storage_dir()
                if not self.storage_path.exists():
                    self._nodes = {}
                    self._edges = {}
                    return

                with self.storage_path.open("r", encoding="utf-8") as file:
                    raw = json.load(file)

                nodes = raw.get("nodes", {})
                edges = raw.get("edges", {})

                self._nodes = {
                    node_id: GraphNode(**node_data)
                    for node_id, node_data in nodes.items()
                    if isinstance(node_data, dict)
                }
                self._edges = {
                    edge_id: GraphEdge(**edge_data)
                    for edge_id, edge_data in edges.items()
                    if isinstance(edge_data, dict)
                }

                self.logger.info(
                    "KnowledgeGraph loaded: %s nodes, %s edges",
                    len(self._nodes),
                    len(self._edges),
                )
            except Exception as exc:
                self.logger.exception("Failed to load knowledge graph from disk: %s", exc)
                self._nodes = {}
                self._edges = {}

    def save(self) -> Dict[str, Any]:
        """Persist graph data to disk."""
        with self._lock:
            try:
                self._ensure_storage_dir()
                payload = {
                    "metadata": {
                        "agent_id": self.agent_id,
                        "agent_name": self.agent_name,
                        "saved_at": self.utcnow(),
                        "node_count": len(self._nodes),
                        "edge_count": len(self._edges),
                    },
                    "nodes": {node_id: self._node_to_dict(node) for node_id, node in self._nodes.items()},
                    "edges": {edge_id: self._edge_to_dict(edge) for edge_id, edge in self._edges.items()},
                }

                temp_path = self.storage_path.with_suffix(".tmp")
                with temp_path.open("w", encoding="utf-8") as file:
                    json.dump(payload, file, ensure_ascii=False, indent=2, sort_keys=True)

                os.replace(temp_path, self.storage_path)

                return self._safe_result(
                    message="Knowledge graph saved.",
                    data={"path": str(self.storage_path), "node_count": len(self._nodes), "edge_count": len(self._edges)},
                )
            except Exception as exc:
                self.logger.exception("Failed to save knowledge graph.")
                return self._error_result("Failed to save knowledge graph.", exc)

    def _autosave(self) -> None:
        if self.autosave:
            result = self.save()
            if not result.get("success"):
                self.logger.warning("Autosave failed: %s", result.get("error"))

    # -----------------------------------------------------------------------
    # Validation
    # -----------------------------------------------------------------------

    def _validate_node_type(self, node_type: str) -> str:
        node_type = self._normalize(node_type) or "custom"
        return node_type if node_type in SAFE_NODE_TYPES else "custom"

    def _validate_edge_type(self, edge_type: str) -> str:
        edge_type = self._normalize(edge_type) or "custom"
        return edge_type if edge_type in SAFE_EDGE_TYPES else "custom"

    def _is_node_visible_to_context(self, node: GraphNode, context: GraphContext) -> bool:
        return (
            node.user_id == context.user_id
            and node.workspace_id == context.workspace_id
            and node.is_active
        )

    def _is_edge_visible_to_context(self, edge: GraphEdge, context: GraphContext) -> bool:
        return (
            edge.user_id == context.user_id
            and edge.workspace_id == context.workspace_id
            and edge.is_active
        )

    def _get_node_or_error(self, node_id: str, context: GraphContext) -> Tuple[Optional[GraphNode], Optional[Dict[str, Any]]]:
        node = self._nodes.get(node_id)
        if not node or not self._is_node_visible_to_context(node, context):
            return None, self._error_result(
                "Node not found in this user/workspace scope.",
                metadata={"node_id": node_id, "request_id": context.request_id},
            )
        return node, None

    def _get_edge_or_error(self, edge_id: str, context: GraphContext) -> Tuple[Optional[GraphEdge], Optional[Dict[str, Any]]]:
        edge = self._edges.get(edge_id)
        if not edge or not self._is_edge_visible_to_context(edge, context):
            return None, self._error_result(
                "Edge not found in this user/workspace scope.",
                metadata={"edge_id": edge_id, "request_id": context.request_id},
            )
        return edge, None

    # -----------------------------------------------------------------------
    # Node Methods
    # -----------------------------------------------------------------------

    def add_node(
        self,
        user_id: str,
        workspace_id: str,
        node_type: str,
        label: str,
        properties: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
        node_id: Optional[str] = None,
        source: Optional[str] = None,
        actor_agent: str = DEFAULT_AGENT_ID,
        request_id: Optional[str] = None,
        role: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Add a scoped graph node.

        Example:
            add_node(
                user_id="u1",
                workspace_id="w1",
                node_type="project",
                label="William SaaS",
                properties={"status": "active"}
            )
        """
        context = self._context_from_kwargs(
            user_id=user_id,
            workspace_id=workspace_id,
            actor_agent=actor_agent,
            request_id=request_id,
            role=role,
            permissions=permissions,
            metadata=metadata,
        )
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        clean_label = str(label or "").strip()
        if not clean_label:
            return self._error_result("Node label is required.", metadata={"request_id": context.request_id})

        with self._lock:
            try:
                clean_node_type = self._validate_node_type(node_type)
                node_id = node_id or self._new_id("node")

                existing = self._nodes.get(node_id)
                if existing and existing.is_active:
                    if existing.user_id != context.user_id or existing.workspace_id != context.workspace_id:
                        return self._error_result(
                            "Node ID already exists in another scope.",
                            metadata={"node_id": node_id, "request_id": context.request_id},
                        )
                    return self._error_result(
                        "Node ID already exists.",
                        metadata={"node_id": node_id, "request_id": context.request_id},
                    )

                now = self.utcnow()
                node = GraphNode(
                    node_id=node_id,
                    node_type=clean_node_type,
                    label=clean_label,
                    user_id=context.user_id,
                    workspace_id=context.workspace_id,
                    properties=properties or {},
                    tags=tags or [],
                    source=source,
                    created_by=context.actor_agent,
                    updated_by=context.actor_agent,
                    created_at=now,
                    updated_at=now,
                    is_active=True,
                )

                self._nodes[node_id] = node
                self._autosave()

                node_dict = self._node_to_dict(node)
                verification_payload = self._prepare_verification_payload("add_node", context, {"node": node_dict})
                memory_payload = self._prepare_memory_payload(
                    "add_node",
                    context,
                    f"Added {clean_node_type} node: {clean_label}",
                    {"node": node_dict},
                )

                self._emit_agent_event(
                    "knowledge_graph.node_added",
                    {"node": node_dict, "request_id": context.request_id},
                )
                self._log_audit_event("add_node", context, {"node_id": node_id, "node_type": clean_node_type})

                return self._safe_result(
                    message="Node added successfully.",
                    data={
                        "node": node_dict,
                        "verification_payload": verification_payload,
                        "memory_payload": memory_payload,
                    },
                    metadata={"request_id": context.request_id},
                )
            except Exception as exc:
                self.logger.exception("Failed to add node.")
                self._log_audit_event("add_node", context, success=False, error=str(exc))
                return self._error_result("Failed to add node.", exc, metadata={"request_id": context.request_id})

    def upsert_node(
        self,
        user_id: str,
        workspace_id: str,
        node_type: str,
        label: str,
        unique_key: Optional[str] = None,
        properties: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
        source: Optional[str] = None,
        actor_agent: str = DEFAULT_AGENT_ID,
        request_id: Optional[str] = None,
        role: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Add or update a node by unique_key inside user/workspace scope.

        If unique_key is not provided, label + node_type is used.
        """
        context = self._context_from_kwargs(
            user_id=user_id,
            workspace_id=workspace_id,
            actor_agent=actor_agent,
            request_id=request_id,
            role=role,
            permissions=permissions,
            metadata=metadata,
        )
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        clean_node_type = self._validate_node_type(node_type)
        clean_label = str(label or "").strip()
        clean_unique_key = str(unique_key or f"{clean_node_type}:{clean_label}").strip()

        if not clean_label:
            return self._error_result("Node label is required.", metadata={"request_id": context.request_id})

        with self._lock:
            try:
                matched_node = None
                for node in self._nodes.values():
                    if not self._is_node_visible_to_context(node, context):
                        continue
                    node_unique_key = str(node.properties.get("unique_key", f"{node.node_type}:{node.label}"))
                    if node_unique_key == clean_unique_key:
                        matched_node = node
                        break

                if matched_node:
                    return self.update_node(
                        user_id=context.user_id,
                        workspace_id=context.workspace_id,
                        node_id=matched_node.node_id,
                        label=clean_label,
                        properties={**matched_node.properties, **(properties or {}), "unique_key": clean_unique_key},
                        tags=tags if tags is not None else matched_node.tags,
                        actor_agent=context.actor_agent,
                        request_id=context.request_id,
                        role=context.role,
                        permissions=context.permissions,
                        metadata=context.metadata,
                    )

                final_properties = dict(properties or {})
                final_properties["unique_key"] = clean_unique_key

                return self.add_node(
                    user_id=context.user_id,
                    workspace_id=context.workspace_id,
                    node_type=clean_node_type,
                    label=clean_label,
                    properties=final_properties,
                    tags=tags,
                    source=source,
                    actor_agent=context.actor_agent,
                    request_id=context.request_id,
                    role=context.role,
                    permissions=context.permissions,
                    metadata=context.metadata,
                )
            except Exception as exc:
                self.logger.exception("Failed to upsert node.")
                return self._error_result("Failed to upsert node.", exc, metadata={"request_id": context.request_id})

    def update_node(
        self,
        user_id: str,
        workspace_id: str,
        node_id: str,
        label: Optional[str] = None,
        properties: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
        node_type: Optional[str] = None,
        source: Optional[str] = None,
        actor_agent: str = DEFAULT_AGENT_ID,
        request_id: Optional[str] = None,
        role: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Update a scoped node."""
        context = self._context_from_kwargs(
            user_id, workspace_id, actor_agent, request_id, role, permissions, metadata
        )
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        with self._lock:
            try:
                node, error = self._get_node_or_error(node_id, context)
                if error:
                    return error
                assert node is not None

                if label is not None:
                    clean_label = str(label).strip()
                    if not clean_label:
                        return self._error_result("Node label cannot be empty.", metadata={"request_id": context.request_id})
                    node.label = clean_label

                if node_type is not None:
                    node.node_type = self._validate_node_type(node_type)

                if properties is not None:
                    node.properties = dict(properties)

                if tags is not None:
                    node.tags = list(tags)

                if source is not None:
                    node.source = source

                node.updated_by = context.actor_agent
                node.updated_at = self.utcnow()

                self._autosave()

                node_dict = self._node_to_dict(node)
                verification_payload = self._prepare_verification_payload("update_node", context, {"node": node_dict})
                memory_payload = self._prepare_memory_payload(
                    "update_node",
                    context,
                    f"Updated node: {node.label}",
                    {"node": node_dict},
                )

                self._emit_agent_event(
                    "knowledge_graph.node_updated",
                    {"node": node_dict, "request_id": context.request_id},
                )
                self._log_audit_event("update_node", context, {"node_id": node_id})

                return self._safe_result(
                    message="Node updated successfully.",
                    data={
                        "node": node_dict,
                        "verification_payload": verification_payload,
                        "memory_payload": memory_payload,
                    },
                    metadata={"request_id": context.request_id},
                )
            except Exception as exc:
                self.logger.exception("Failed to update node.")
                self._log_audit_event("update_node", context, success=False, error=str(exc))
                return self._error_result("Failed to update node.", exc, metadata={"request_id": context.request_id})

    def get_node(
        self,
        user_id: str,
        workspace_id: str,
        node_id: str,
        actor_agent: str = DEFAULT_AGENT_ID,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Get one scoped node by ID."""
        context = self._context_from_kwargs(user_id, workspace_id, actor_agent, request_id)
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        with self._lock:
            node, error = self._get_node_or_error(node_id, context)
            if error:
                return error

            return self._safe_result(
                message="Node found.",
                data={"node": self._node_to_dict(node)},  # type: ignore[arg-type]
                metadata={"request_id": context.request_id},
            )

    def delete_node(
        self,
        user_id: str,
        workspace_id: str,
        node_id: str,
        soft_delete: bool = True,
        delete_attached_edges: bool = True,
        actor_agent: str = DEFAULT_AGENT_ID,
        request_id: Optional[str] = None,
        role: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Delete a scoped node.

        By default this performs a soft delete. Hard delete requires Security
        Agent approval or knowledge_graph:admin permission.
        """
        context = self._context_from_kwargs(
            user_id, workspace_id, actor_agent, request_id, role, permissions, metadata
        )
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        approval = self._request_security_approval(
            "delete_node",
            context,
            {"node_id": node_id, "soft_delete": soft_delete, "delete_attached_edges": delete_attached_edges},
        )
        if not approval["success"]:
            return approval

        with self._lock:
            try:
                node, error = self._get_node_or_error(node_id, context)
                if error:
                    return error
                assert node is not None

                affected_edges: List[str] = []
                for edge_id, edge in list(self._edges.items()):
                    if not self._is_edge_visible_to_context(edge, context):
                        continue
                    if edge.source_node_id == node_id or edge.target_node_id == node_id:
                        affected_edges.append(edge_id)
                        if delete_attached_edges:
                            if soft_delete:
                                edge.is_active = False
                                edge.updated_at = self.utcnow()
                                edge.updated_by = context.actor_agent
                            else:
                                del self._edges[edge_id]

                if soft_delete:
                    node.is_active = False
                    node.updated_at = self.utcnow()
                    node.updated_by = context.actor_agent
                else:
                    del self._nodes[node_id]

                self._autosave()

                self._emit_agent_event(
                    "knowledge_graph.node_deleted",
                    {
                        "node_id": node_id,
                        "soft_delete": soft_delete,
                        "affected_edges": affected_edges,
                        "request_id": context.request_id,
                    },
                )
                self._log_audit_event(
                    "delete_node",
                    context,
                    {"node_id": node_id, "soft_delete": soft_delete, "affected_edges": affected_edges},
                )

                verification_payload = self._prepare_verification_payload(
                    "delete_node",
                    context,
                    {"node_id": node_id, "affected_edges": affected_edges},
                )

                return self._safe_result(
                    message="Node deleted successfully.",
                    data={
                        "node_id": node_id,
                        "soft_delete": soft_delete,
                        "affected_edges": affected_edges,
                        "verification_payload": verification_payload,
                    },
                    metadata={"request_id": context.request_id},
                )
            except Exception as exc:
                self.logger.exception("Failed to delete node.")
                self._log_audit_event("delete_node", context, success=False, error=str(exc))
                return self._error_result("Failed to delete node.", exc, metadata={"request_id": context.request_id})

    # -----------------------------------------------------------------------
    # Edge Methods
    # -----------------------------------------------------------------------

    def add_edge(
        self,
        user_id: str,
        workspace_id: str,
        source_node_id: str,
        target_node_id: str,
        edge_type: str,
        weight: float = 1.0,
        properties: Optional[Dict[str, Any]] = None,
        edge_id: Optional[str] = None,
        source: Optional[str] = None,
        actor_agent: str = DEFAULT_AGENT_ID,
        request_id: Optional[str] = None,
        role: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Add a scoped edge between two scoped nodes."""
        context = self._context_from_kwargs(
            user_id, workspace_id, actor_agent, request_id, role, permissions, metadata
        )
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        with self._lock:
            try:
                source_node, source_error = self._get_node_or_error(source_node_id, context)
                if source_error:
                    return source_error

                target_node, target_error = self._get_node_or_error(target_node_id, context)
                if target_error:
                    return target_error

                assert source_node is not None
                assert target_node is not None

                clean_edge_type = self._validate_edge_type(edge_type)
                edge_id = edge_id or self._new_id("edge")

                if edge_id in self._edges and self._edges[edge_id].is_active:
                    return self._error_result(
                        "Edge ID already exists.",
                        metadata={"edge_id": edge_id, "request_id": context.request_id},
                    )

                clean_weight = float(weight)
                now = self.utcnow()

                edge = GraphEdge(
                    edge_id=edge_id,
                    source_node_id=source_node_id,
                    target_node_id=target_node_id,
                    edge_type=clean_edge_type,
                    user_id=context.user_id,
                    workspace_id=context.workspace_id,
                    weight=clean_weight,
                    properties=properties or {},
                    source=source,
                    created_by=context.actor_agent,
                    updated_by=context.actor_agent,
                    created_at=now,
                    updated_at=now,
                    is_active=True,
                )

                self._edges[edge_id] = edge
                self._autosave()

                edge_dict = self._edge_to_dict(edge)
                verification_payload = self._prepare_verification_payload("add_edge", context, {"edge": edge_dict})
                memory_payload = self._prepare_memory_payload(
                    "add_edge",
                    context,
                    f"Linked {source_node.label} -> {target_node.label} using {clean_edge_type}",
                    {
                        "edge": edge_dict,
                        "source_node": self._node_to_dict(source_node),
                        "target_node": self._node_to_dict(target_node),
                    },
                )

                self._emit_agent_event(
                    "knowledge_graph.edge_added",
                    {"edge": edge_dict, "request_id": context.request_id},
                )
                self._log_audit_event(
                    "add_edge",
                    context,
                    {"edge_id": edge_id, "source_node_id": source_node_id, "target_node_id": target_node_id},
                )

                return self._safe_result(
                    message="Edge added successfully.",
                    data={
                        "edge": edge_dict,
                        "verification_payload": verification_payload,
                        "memory_payload": memory_payload,
                    },
                    metadata={"request_id": context.request_id},
                )
            except Exception as exc:
                self.logger.exception("Failed to add edge.")
                self._log_audit_event("add_edge", context, success=False, error=str(exc))
                return self._error_result("Failed to add edge.", exc, metadata={"request_id": context.request_id})

    def link_entities(
        self,
        user_id: str,
        workspace_id: str,
        source_node: Dict[str, Any],
        target_node: Dict[str, Any],
        edge_type: str = "relates_to",
        edge_properties: Optional[Dict[str, Any]] = None,
        weight: float = 1.0,
        actor_agent: str = DEFAULT_AGENT_ID,
        request_id: Optional[str] = None,
        role: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Upsert two nodes and create an edge between them.

        source_node/target_node format:
            {
                "node_type": "project",
                "label": "William SaaS",
                "unique_key": "project:william",
                "properties": {},
                "tags": []
            }
        """
        context = self._context_from_kwargs(
            user_id, workspace_id, actor_agent, request_id, role, permissions, metadata
        )
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        try:
            source_result = self.upsert_node(
                user_id=context.user_id,
                workspace_id=context.workspace_id,
                node_type=source_node.get("node_type", "custom"),
                label=source_node.get("label", ""),
                unique_key=source_node.get("unique_key"),
                properties=source_node.get("properties", {}),
                tags=source_node.get("tags", []),
                source=source_node.get("source"),
                actor_agent=context.actor_agent,
                request_id=context.request_id,
                role=context.role,
                permissions=context.permissions,
                metadata=context.metadata,
            )
            if not source_result["success"]:
                return source_result

            target_result = self.upsert_node(
                user_id=context.user_id,
                workspace_id=context.workspace_id,
                node_type=target_node.get("node_type", "custom"),
                label=target_node.get("label", ""),
                unique_key=target_node.get("unique_key"),
                properties=target_node.get("properties", {}),
                tags=target_node.get("tags", []),
                source=target_node.get("source"),
                actor_agent=context.actor_agent,
                request_id=context.request_id,
                role=context.role,
                permissions=context.permissions,
                metadata=context.metadata,
            )
            if not target_result["success"]:
                return target_result

            source_node_id = source_result["data"]["node"]["node_id"]
            target_node_id = target_result["data"]["node"]["node_id"]

            existing_edge = self._find_existing_edge(
                context=context,
                source_node_id=source_node_id,
                target_node_id=target_node_id,
                edge_type=edge_type,
            )
            if existing_edge:
                return self.update_edge(
                    user_id=context.user_id,
                    workspace_id=context.workspace_id,
                    edge_id=existing_edge.edge_id,
                    weight=weight,
                    properties={**existing_edge.properties, **(edge_properties or {})},
                    actor_agent=context.actor_agent,
                    request_id=context.request_id,
                    role=context.role,
                    permissions=context.permissions,
                    metadata=context.metadata,
                )

            edge_result = self.add_edge(
                user_id=context.user_id,
                workspace_id=context.workspace_id,
                source_node_id=source_node_id,
                target_node_id=target_node_id,
                edge_type=edge_type,
                weight=weight,
                properties=edge_properties or {},
                actor_agent=context.actor_agent,
                request_id=context.request_id,
                role=context.role,
                permissions=context.permissions,
                metadata=context.metadata,
            )
            if not edge_result["success"]:
                return edge_result

            return self._safe_result(
                message="Entities linked successfully.",
                data={
                    "source_node": source_result["data"]["node"],
                    "target_node": target_result["data"]["node"],
                    "edge": edge_result["data"]["edge"],
                    "verification_payload": self._prepare_verification_payload(
                        "link_entities",
                        context,
                        {
                            "source_node_id": source_node_id,
                            "target_node_id": target_node_id,
                            "edge_type": edge_type,
                        },
                    ),
                },
                metadata={"request_id": context.request_id},
            )
        except Exception as exc:
            self.logger.exception("Failed to link entities.")
            return self._error_result("Failed to link entities.", exc, metadata={"request_id": context.request_id})

    def _find_existing_edge(
        self,
        context: GraphContext,
        source_node_id: str,
        target_node_id: str,
        edge_type: str,
    ) -> Optional[GraphEdge]:
        clean_edge_type = self._validate_edge_type(edge_type)
        for edge in self._edges.values():
            if not self._is_edge_visible_to_context(edge, context):
                continue
            if (
                edge.source_node_id == source_node_id
                and edge.target_node_id == target_node_id
                and edge.edge_type == clean_edge_type
            ):
                return edge
        return None

    def update_edge(
        self,
        user_id: str,
        workspace_id: str,
        edge_id: str,
        edge_type: Optional[str] = None,
        weight: Optional[float] = None,
        properties: Optional[Dict[str, Any]] = None,
        source: Optional[str] = None,
        actor_agent: str = DEFAULT_AGENT_ID,
        request_id: Optional[str] = None,
        role: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Update a scoped edge."""
        context = self._context_from_kwargs(
            user_id, workspace_id, actor_agent, request_id, role, permissions, metadata
        )
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        with self._lock:
            try:
                edge, error = self._get_edge_or_error(edge_id, context)
                if error:
                    return error
                assert edge is not None

                if edge_type is not None:
                    edge.edge_type = self._validate_edge_type(edge_type)

                if weight is not None:
                    edge.weight = float(weight)

                if properties is not None:
                    edge.properties = dict(properties)

                if source is not None:
                    edge.source = source

                edge.updated_by = context.actor_agent
                edge.updated_at = self.utcnow()

                self._autosave()

                edge_dict = self._edge_to_dict(edge)
                verification_payload = self._prepare_verification_payload("update_edge", context, {"edge": edge_dict})
                memory_payload = self._prepare_memory_payload(
                    "update_edge",
                    context,
                    f"Updated edge: {edge.edge_type}",
                    {"edge": edge_dict},
                )

                self._emit_agent_event(
                    "knowledge_graph.edge_updated",
                    {"edge": edge_dict, "request_id": context.request_id},
                )
                self._log_audit_event("update_edge", context, {"edge_id": edge_id})

                return self._safe_result(
                    message="Edge updated successfully.",
                    data={
                        "edge": edge_dict,
                        "verification_payload": verification_payload,
                        "memory_payload": memory_payload,
                    },
                    metadata={"request_id": context.request_id},
                )
            except Exception as exc:
                self.logger.exception("Failed to update edge.")
                self._log_audit_event("update_edge", context, success=False, error=str(exc))
                return self._error_result("Failed to update edge.", exc, metadata={"request_id": context.request_id})

    def get_edge(
        self,
        user_id: str,
        workspace_id: str,
        edge_id: str,
        actor_agent: str = DEFAULT_AGENT_ID,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Get one scoped edge by ID."""
        context = self._context_from_kwargs(user_id, workspace_id, actor_agent, request_id)
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        with self._lock:
            edge, error = self._get_edge_or_error(edge_id, context)
            if error:
                return error

            return self._safe_result(
                message="Edge found.",
                data={"edge": self._edge_to_dict(edge)},  # type: ignore[arg-type]
                metadata={"request_id": context.request_id},
            )

    def delete_edge(
        self,
        user_id: str,
        workspace_id: str,
        edge_id: str,
        soft_delete: bool = True,
        actor_agent: str = DEFAULT_AGENT_ID,
        request_id: Optional[str] = None,
        role: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Delete a scoped edge."""
        context = self._context_from_kwargs(
            user_id, workspace_id, actor_agent, request_id, role, permissions, metadata
        )
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        approval = self._request_security_approval(
            "delete_edge",
            context,
            {"edge_id": edge_id, "soft_delete": soft_delete},
        )
        if not approval["success"]:
            return approval

        with self._lock:
            try:
                edge, error = self._get_edge_or_error(edge_id, context)
                if error:
                    return error
                assert edge is not None

                if soft_delete:
                    edge.is_active = False
                    edge.updated_by = context.actor_agent
                    edge.updated_at = self.utcnow()
                else:
                    del self._edges[edge_id]

                self._autosave()

                self._emit_agent_event(
                    "knowledge_graph.edge_deleted",
                    {"edge_id": edge_id, "soft_delete": soft_delete, "request_id": context.request_id},
                )
                self._log_audit_event("delete_edge", context, {"edge_id": edge_id, "soft_delete": soft_delete})

                verification_payload = self._prepare_verification_payload(
                    "delete_edge",
                    context,
                    {"edge_id": edge_id, "soft_delete": soft_delete},
                )

                return self._safe_result(
                    message="Edge deleted successfully.",
                    data={
                        "edge_id": edge_id,
                        "soft_delete": soft_delete,
                        "verification_payload": verification_payload,
                    },
                    metadata={"request_id": context.request_id},
                )
            except Exception as exc:
                self.logger.exception("Failed to delete edge.")
                self._log_audit_event("delete_edge", context, success=False, error=str(exc))
                return self._error_result("Failed to delete edge.", exc, metadata={"request_id": context.request_id})

    # -----------------------------------------------------------------------
    # Query Methods
    # -----------------------------------------------------------------------

    def list_nodes(
        self,
        user_id: str,
        workspace_id: str,
        node_type: Optional[str] = None,
        tag: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = DEFAULT_SEARCH_LIMIT,
        offset: int = 0,
        actor_agent: str = DEFAULT_AGENT_ID,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """List scoped nodes with optional filters."""
        context = self._context_from_kwargs(user_id, workspace_id, actor_agent, request_id)
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        with self._lock:
            try:
                filtered: List[GraphNode] = []
                clean_type = self._validate_node_type(node_type) if node_type else None
                clean_tag = self._normalize(tag) if tag else None
                clean_search = self._normalize(search) if search else None

                for node in self._nodes.values():
                    if not self._is_node_visible_to_context(node, context):
                        continue

                    if clean_type and node.node_type != clean_type:
                        continue

                    if clean_tag and clean_tag not in {self._normalize(t) for t in node.tags}:
                        continue

                    if clean_search:
                        haystack = " ".join(
                            [
                                node.node_id,
                                node.node_type,
                                node.label,
                                json.dumps(node.properties, ensure_ascii=False, default=str),
                                " ".join(node.tags),
                            ]
                        ).lower()
                        if clean_search not in haystack:
                            continue

                    filtered.append(node)

                filtered.sort(key=lambda n: n.updated_at, reverse=True)
                total = len(filtered)
                sliced = filtered[max(offset, 0): max(offset, 0) + max(limit, 1)]

                return self._safe_result(
                    message="Nodes listed successfully.",
                    data={
                        "nodes": [self._node_to_dict(node) for node in sliced],
                        "total": total,
                        "limit": limit,
                        "offset": offset,
                    },
                    metadata={"request_id": context.request_id},
                )
            except Exception as exc:
                self.logger.exception("Failed to list nodes.")
                return self._error_result("Failed to list nodes.", exc, metadata={"request_id": context.request_id})

    def list_edges(
        self,
        user_id: str,
        workspace_id: str,
        edge_type: Optional[str] = None,
        source_node_id: Optional[str] = None,
        target_node_id: Optional[str] = None,
        limit: int = DEFAULT_SEARCH_LIMIT,
        offset: int = 0,
        actor_agent: str = DEFAULT_AGENT_ID,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """List scoped edges with optional filters."""
        context = self._context_from_kwargs(user_id, workspace_id, actor_agent, request_id)
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        with self._lock:
            try:
                clean_type = self._validate_edge_type(edge_type) if edge_type else None
                filtered: List[GraphEdge] = []

                for edge in self._edges.values():
                    if not self._is_edge_visible_to_context(edge, context):
                        continue

                    if clean_type and edge.edge_type != clean_type:
                        continue

                    if source_node_id and edge.source_node_id != source_node_id:
                        continue

                    if target_node_id and edge.target_node_id != target_node_id:
                        continue

                    filtered.append(edge)

                filtered.sort(key=lambda e: e.updated_at, reverse=True)
                total = len(filtered)
                sliced = filtered[max(offset, 0): max(offset, 0) + max(limit, 1)]

                return self._safe_result(
                    message="Edges listed successfully.",
                    data={
                        "edges": [self._edge_to_dict(edge) for edge in sliced],
                        "total": total,
                        "limit": limit,
                        "offset": offset,
                    },
                    metadata={"request_id": context.request_id},
                )
            except Exception as exc:
                self.logger.exception("Failed to list edges.")
                return self._error_result("Failed to list edges.", exc, metadata={"request_id": context.request_id})

    def get_neighbors(
        self,
        user_id: str,
        workspace_id: str,
        node_id: str,
        direction: str = "both",
        edge_type: Optional[str] = None,
        limit: int = DEFAULT_SEARCH_LIMIT,
        actor_agent: str = DEFAULT_AGENT_ID,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Get neighboring nodes.

        direction:
            "out"  - source_node_id == node_id
            "in"   - target_node_id == node_id
            "both" - either side
        """
        context = self._context_from_kwargs(user_id, workspace_id, actor_agent, request_id)
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        direction = self._normalize(direction) or "both"
        if direction not in {"in", "out", "both"}:
            return self._error_result("Invalid direction. Use in, out, or both.", metadata={"request_id": context.request_id})

        with self._lock:
            try:
                node, error = self._get_node_or_error(node_id, context)
                if error:
                    return error

                clean_edge_type = self._validate_edge_type(edge_type) if edge_type else None
                neighbors: List[Dict[str, Any]] = []

                for edge in self._edges.values():
                    if not self._is_edge_visible_to_context(edge, context):
                        continue

                    if clean_edge_type and edge.edge_type != clean_edge_type:
                        continue

                    neighbor_id: Optional[str] = None
                    relation_direction: Optional[str] = None

                    if direction in {"out", "both"} and edge.source_node_id == node_id:
                        neighbor_id = edge.target_node_id
                        relation_direction = "out"

                    elif direction in {"in", "both"} and edge.target_node_id == node_id:
                        neighbor_id = edge.source_node_id
                        relation_direction = "in"

                    if not neighbor_id:
                        continue

                    neighbor = self._nodes.get(neighbor_id)
                    if not neighbor or not self._is_node_visible_to_context(neighbor, context):
                        continue

                    neighbors.append(
                        {
                            "node": self._node_to_dict(neighbor),
                            "edge": self._edge_to_dict(edge),
                            "direction": relation_direction,
                        }
                    )

                    if len(neighbors) >= max(limit, 1):
                        break

                return self._safe_result(
                    message="Neighbors retrieved successfully.",
                    data={
                        "node": self._node_to_dict(node),  # type: ignore[arg-type]
                        "neighbors": neighbors,
                        "total": len(neighbors),
                    },
                    metadata={"request_id": context.request_id},
                )
            except Exception as exc:
                self.logger.exception("Failed to get neighbors.")
                return self._error_result("Failed to get neighbors.", exc, metadata={"request_id": context.request_id})

    def get_subgraph(
        self,
        user_id: str,
        workspace_id: str,
        start_node_id: str,
        depth: int = DEFAULT_MAX_GRAPH_DEPTH,
        edge_types: Optional[List[str]] = None,
        node_types: Optional[List[str]] = None,
        max_nodes: int = 250,
        actor_agent: str = DEFAULT_AGENT_ID,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return BFS subgraph from a start node within scope."""
        context = self._context_from_kwargs(user_id, workspace_id, actor_agent, request_id)
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        with self._lock:
            try:
                start_node, error = self._get_node_or_error(start_node_id, context)
                if error:
                    return error

                allowed_edge_types = {self._validate_edge_type(e) for e in edge_types} if edge_types else None
                allowed_node_types = {self._validate_node_type(n) for n in node_types} if node_types else None

                depth = max(0, min(int(depth), 10))
                max_nodes = max(1, min(int(max_nodes), 1000))

                visited_nodes: Set[str] = set()
                included_edges: Set[str] = set()
                queue: Deque[Tuple[str, int]] = deque([(start_node_id, 0)])

                while queue and len(visited_nodes) < max_nodes:
                    current_id, current_depth = queue.popleft()
                    if current_id in visited_nodes:
                        continue

                    current_node = self._nodes.get(current_id)
                    if not current_node or not self._is_node_visible_to_context(current_node, context):
                        continue

                    if allowed_node_types and current_node.node_type not in allowed_node_types and current_id != start_node_id:
                        continue

                    visited_nodes.add(current_id)

                    if current_depth >= depth:
                        continue

                    for edge in self._edges.values():
                        if not self._is_edge_visible_to_context(edge, context):
                            continue

                        if allowed_edge_types and edge.edge_type not in allowed_edge_types:
                            continue

                        next_id = None
                        if edge.source_node_id == current_id:
                            next_id = edge.target_node_id
                        elif edge.target_node_id == current_id:
                            next_id = edge.source_node_id

                        if not next_id or next_id in visited_nodes:
                            continue

                        next_node = self._nodes.get(next_id)
                        if not next_node or not self._is_node_visible_to_context(next_node, context):
                            continue

                        included_edges.add(edge.edge_id)
                        queue.append((next_id, current_depth + 1))

                nodes = [self._node_to_dict(self._nodes[nid]) for nid in visited_nodes if nid in self._nodes]
                edges = [self._edge_to_dict(self._edges[eid]) for eid in included_edges if eid in self._edges]

                return self._safe_result(
                    message="Subgraph retrieved successfully.",
                    data={
                        "start_node": self._node_to_dict(start_node),  # type: ignore[arg-type]
                        "nodes": nodes,
                        "edges": edges,
                        "depth": depth,
                        "node_count": len(nodes),
                        "edge_count": len(edges),
                    },
                    metadata={"request_id": context.request_id},
                )
            except Exception as exc:
                self.logger.exception("Failed to get subgraph.")
                return self._error_result("Failed to get subgraph.", exc, metadata={"request_id": context.request_id})

    def find_paths(
        self,
        user_id: str,
        workspace_id: str,
        source_node_id: str,
        target_node_id: str,
        max_depth: int = DEFAULT_MAX_GRAPH_DEPTH,
        max_paths: int = DEFAULT_PATH_LIMIT,
        edge_types: Optional[List[str]] = None,
        actor_agent: str = DEFAULT_AGENT_ID,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Find simple paths between two scoped nodes."""
        context = self._context_from_kwargs(user_id, workspace_id, actor_agent, request_id)
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        with self._lock:
            try:
                _, source_error = self._get_node_or_error(source_node_id, context)
                if source_error:
                    return source_error

                _, target_error = self._get_node_or_error(target_node_id, context)
                if target_error:
                    return target_error

                max_depth = max(1, min(int(max_depth), 10))
                max_paths = max(1, min(int(max_paths), 100))
                allowed_edge_types = {self._validate_edge_type(e) for e in edge_types} if edge_types else None

                adjacency: Dict[str, List[Tuple[str, GraphEdge]]] = {}
                for edge in self._edges.values():
                    if not self._is_edge_visible_to_context(edge, context):
                        continue
                    if allowed_edge_types and edge.edge_type not in allowed_edge_types:
                        continue

                    adjacency.setdefault(edge.source_node_id, []).append((edge.target_node_id, edge))
                    adjacency.setdefault(edge.target_node_id, []).append((edge.source_node_id, edge))

                paths: List[Dict[str, Any]] = []
                queue: Deque[Tuple[str, List[str], List[str]]] = deque([(source_node_id, [source_node_id], [])])

                while queue and len(paths) < max_paths:
                    current_id, node_path, edge_path = queue.popleft()

                    if len(node_path) - 1 > max_depth:
                        continue

                    if current_id == target_node_id:
                        paths.append(
                            {
                                "nodes": [
                                    self._node_to_dict(self._nodes[nid])
                                    for nid in node_path
                                    if nid in self._nodes and self._is_node_visible_to_context(self._nodes[nid], context)
                                ],
                                "edges": [
                                    self._edge_to_dict(self._edges[eid])
                                    for eid in edge_path
                                    if eid in self._edges and self._is_edge_visible_to_context(self._edges[eid], context)
                                ],
                                "length": len(node_path) - 1,
                            }
                        )
                        continue

                    for next_id, edge in adjacency.get(current_id, []):
                        if next_id in node_path:
                            continue
                        next_node = self._nodes.get(next_id)
                        if not next_node or not self._is_node_visible_to_context(next_node, context):
                            continue
                        queue.append((next_id, node_path + [next_id], edge_path + [edge.edge_id]))

                return self._safe_result(
                    message="Paths retrieved successfully.",
                    data={
                        "source_node_id": source_node_id,
                        "target_node_id": target_node_id,
                        "paths": paths,
                        "total": len(paths),
                    },
                    metadata={"request_id": context.request_id},
                )
            except Exception as exc:
                self.logger.exception("Failed to find paths.")
                return self._error_result("Failed to find paths.", exc, metadata={"request_id": context.request_id})

    def search_graph(
        self,
        user_id: str,
        workspace_id: str,
        query: str,
        node_types: Optional[List[str]] = None,
        edge_types: Optional[List[str]] = None,
        limit: int = DEFAULT_SEARCH_LIMIT,
        actor_agent: str = DEFAULT_AGENT_ID,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Search nodes and edges by text within user/workspace scope."""
        context = self._context_from_kwargs(user_id, workspace_id, actor_agent, request_id)
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        clean_query = self._normalize(query)
        if not clean_query:
            return self._error_result("Search query is required.", metadata={"request_id": context.request_id})

        with self._lock:
            try:
                allowed_node_types = {self._validate_node_type(n) for n in node_types} if node_types else None
                allowed_edge_types = {self._validate_edge_type(e) for e in edge_types} if edge_types else None

                node_results: List[Dict[str, Any]] = []
                edge_results: List[Dict[str, Any]] = []

                for node in self._nodes.values():
                    if not self._is_node_visible_to_context(node, context):
                        continue
                    if allowed_node_types and node.node_type not in allowed_node_types:
                        continue

                    haystack = " ".join(
                        [
                            node.node_id,
                            node.node_type,
                            node.label,
                            " ".join(node.tags),
                            json.dumps(node.properties, ensure_ascii=False, default=str),
                        ]
                    ).lower()

                    if clean_query in haystack:
                        node_results.append({"score": self._score_match(clean_query, haystack, node.label), "node": self._node_to_dict(node)})

                for edge in self._edges.values():
                    if not self._is_edge_visible_to_context(edge, context):
                        continue
                    if allowed_edge_types and edge.edge_type not in allowed_edge_types:
                        continue

                    haystack = " ".join(
                        [
                            edge.edge_id,
                            edge.edge_type,
                            edge.source_node_id,
                            edge.target_node_id,
                            json.dumps(edge.properties, ensure_ascii=False, default=str),
                        ]
                    ).lower()

                    if clean_query in haystack:
                        edge_results.append({"score": self._score_match(clean_query, haystack, edge.edge_type), "edge": self._edge_to_dict(edge)})

                node_results.sort(key=lambda item: item["score"], reverse=True)
                edge_results.sort(key=lambda item: item["score"], reverse=True)

                limit = max(1, min(int(limit), 500))

                return self._safe_result(
                    message="Graph search completed.",
                    data={
                        "query": query,
                        "nodes": node_results[:limit],
                        "edges": edge_results[:limit],
                        "node_total": len(node_results),
                        "edge_total": len(edge_results),
                    },
                    metadata={"request_id": context.request_id},
                )
            except Exception as exc:
                self.logger.exception("Failed to search graph.")
                return self._error_result("Failed to search graph.", exc, metadata={"request_id": context.request_id})

    def _score_match(self, query: str, haystack: str, label: str) -> float:
        """Simple deterministic score for dashboard ranking."""
        score = 1.0
        label_norm = self._normalize(label)
        if query == label_norm:
            score += 5.0
        elif label_norm.startswith(query):
            score += 3.0
        elif query in label_norm:
            score += 2.0
        score += min(haystack.count(query), 10) * 0.2
        return score

    # -----------------------------------------------------------------------
    # File / Project / Agent / Task / Decision Convenience Methods
    # -----------------------------------------------------------------------

    def connect_project_file(
        self,
        user_id: str,
        workspace_id: str,
        project_name: str,
        file_path: str,
        file_role: Optional[str] = None,
        properties: Optional[Dict[str, Any]] = None,
        actor_agent: str = DEFAULT_AGENT_ID,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Connect a project node to a file node."""
        return self.link_entities(
            user_id=user_id,
            workspace_id=workspace_id,
            source_node={
                "node_type": "project",
                "label": project_name,
                "unique_key": f"project:{project_name}",
                "properties": {"project_name": project_name},
            },
            target_node={
                "node_type": "file",
                "label": file_path,
                "unique_key": f"file:{file_path}",
                "properties": {"file_path": file_path, "file_role": file_role, **(properties or {})},
            },
            edge_type="has_file",
            edge_properties={"file_role": file_role},
            actor_agent=actor_agent,
            request_id=request_id,
        )

    def connect_agent_task(
        self,
        user_id: str,
        workspace_id: str,
        agent_name: str,
        task_title: str,
        task_status: str = "pending",
        properties: Optional[Dict[str, Any]] = None,
        actor_agent: str = DEFAULT_AGENT_ID,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Connect an agent node to a task node."""
        return self.link_entities(
            user_id=user_id,
            workspace_id=workspace_id,
            source_node={
                "node_type": "agent",
                "label": agent_name,
                "unique_key": f"agent:{agent_name}",
                "properties": {"agent_name": agent_name},
            },
            target_node={
                "node_type": "task",
                "label": task_title,
                "unique_key": f"task:{task_title}",
                "properties": {"task_title": task_title, "task_status": task_status, **(properties or {})},
            },
            edge_type="assigned_to",
            edge_properties={"task_status": task_status},
            actor_agent=actor_agent,
            request_id=request_id,
        )

    def record_decision(
        self,
        user_id: str,
        workspace_id: str,
        decision_title: str,
        decision_summary: str,
        related_node_ids: Optional[List[str]] = None,
        properties: Optional[Dict[str, Any]] = None,
        actor_agent: str = DEFAULT_AGENT_ID,
        request_id: Optional[str] = None,
        role: Optional[str] = None,
        permissions: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Store a decision node and optionally link it to existing nodes.
        """
        context = self._context_from_kwargs(
            user_id=user_id,
            workspace_id=workspace_id,
            actor_agent=actor_agent,
            request_id=request_id,
            role=role,
            permissions=permissions,
        )
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        try:
            decision_result = self.add_node(
                user_id=context.user_id,
                workspace_id=context.workspace_id,
                node_type="decision",
                label=decision_title,
                properties={
                    "decision_title": decision_title,
                    "decision_summary": decision_summary,
                    "decided_at": self.utcnow(),
                    **(properties or {}),
                },
                tags=["decision"],
                actor_agent=context.actor_agent,
                request_id=context.request_id,
                role=context.role,
                permissions=context.permissions,
            )
            if not decision_result["success"]:
                return decision_result

            decision_node = decision_result["data"]["node"]
            linked_edges: List[Dict[str, Any]] = []

            for related_node_id in related_node_ids or []:
                edge_result = self.add_edge(
                    user_id=context.user_id,
                    workspace_id=context.workspace_id,
                    source_node_id=decision_node["node_id"],
                    target_node_id=related_node_id,
                    edge_type="decided",
                    properties={"decision_summary": decision_summary},
                    actor_agent=context.actor_agent,
                    request_id=context.request_id,
                    role=context.role,
                    permissions=context.permissions,
                )
                if edge_result["success"]:
                    linked_edges.append(edge_result["data"]["edge"])

            verification_payload = self._prepare_verification_payload(
                "record_decision",
                context,
                {"decision_node": decision_node, "linked_edges": linked_edges},
            )

            return self._safe_result(
                message="Decision recorded successfully.",
                data={
                    "decision_node": decision_node,
                    "linked_edges": linked_edges,
                    "verification_payload": verification_payload,
                },
                metadata={"request_id": context.request_id},
            )
        except Exception as exc:
            self.logger.exception("Failed to record decision.")
            return self._error_result("Failed to record decision.", exc, metadata={"request_id": context.request_id})

    def get_project_timeline(
        self,
        user_id: str,
        workspace_id: str,
        project_name: Optional[str] = None,
        project_node_id: Optional[str] = None,
        actor_agent: str = DEFAULT_AGENT_ID,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Build a timeline of files, tasks, decisions, notes, bugs, and features
        connected to a project.
        """
        context = self._context_from_kwargs(user_id, workspace_id, actor_agent, request_id)
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        with self._lock:
            try:
                project_node: Optional[GraphNode] = None

                if project_node_id:
                    project_node, error = self._get_node_or_error(project_node_id, context)
                    if error:
                        return error
                else:
                    target_key = self._normalize(project_name)
                    for node in self._nodes.values():
                        if not self._is_node_visible_to_context(node, context):
                            continue
                        if node.node_type == "project" and self._normalize(node.label) == target_key:
                            project_node = node
                            break

                if not project_node:
                    return self._error_result(
                        "Project node not found.",
                        metadata={"project_name": project_name, "project_node_id": project_node_id, "request_id": context.request_id},
                    )

                subgraph = self.get_subgraph(
                    user_id=context.user_id,
                    workspace_id=context.workspace_id,
                    start_node_id=project_node.node_id,
                    depth=2,
                    max_nodes=500,
                    actor_agent=context.actor_agent,
                    request_id=context.request_id,
                )
                if not subgraph["success"]:
                    return subgraph

                timeline_items = []
                for node_data in subgraph["data"]["nodes"]:
                    if node_data["node_id"] == project_node.node_id:
                        continue
                    if node_data["node_type"] in {"file", "task", "decision", "note", "bug", "feature", "memory", "deadline"}:
                        timeline_items.append(
                            {
                                "node_id": node_data["node_id"],
                                "node_type": node_data["node_type"],
                                "label": node_data["label"],
                                "created_at": node_data["created_at"],
                                "updated_at": node_data["updated_at"],
                                "properties": node_data.get("properties", {}),
                            }
                        )

                timeline_items.sort(key=lambda item: item["updated_at"], reverse=True)

                return self._safe_result(
                    message="Project timeline generated successfully.",
                    data={
                        "project": self._node_to_dict(project_node),
                        "timeline": timeline_items,
                        "total": len(timeline_items),
                    },
                    metadata={"request_id": context.request_id},
                )
            except Exception as exc:
                self.logger.exception("Failed to get project timeline.")
                return self._error_result("Failed to get project timeline.", exc, metadata={"request_id": context.request_id})

    # -----------------------------------------------------------------------
    # Analytics / Summary
    # -----------------------------------------------------------------------

    def get_workspace_summary(
        self,
        user_id: str,
        workspace_id: str,
        actor_agent: str = DEFAULT_AGENT_ID,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return dashboard-ready graph summary for one user/workspace."""
        context = self._context_from_kwargs(user_id, workspace_id, actor_agent, request_id)
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        with self._lock:
            try:
                nodes = [node for node in self._nodes.values() if self._is_node_visible_to_context(node, context)]
                edges = [edge for edge in self._edges.values() if self._is_edge_visible_to_context(edge, context)]

                node_counts: Dict[str, int] = {}
                edge_counts: Dict[str, int] = {}

                for node in nodes:
                    node_counts[node.node_type] = node_counts.get(node.node_type, 0) + 1

                for edge in edges:
                    edge_counts[edge.edge_type] = edge_counts.get(edge.edge_type, 0) + 1

                recent_nodes = sorted(nodes, key=lambda n: n.updated_at, reverse=True)[:10]
                recent_edges = sorted(edges, key=lambda e: e.updated_at, reverse=True)[:10]

                return self._safe_result(
                    message="Workspace graph summary generated.",
                    data={
                        "node_count": len(nodes),
                        "edge_count": len(edges),
                        "node_counts_by_type": node_counts,
                        "edge_counts_by_type": edge_counts,
                        "recent_nodes": [self._node_to_dict(node) for node in recent_nodes],
                        "recent_edges": [self._edge_to_dict(edge) for edge in recent_edges],
                    },
                    metadata={"request_id": context.request_id},
                )
            except Exception as exc:
                self.logger.exception("Failed to generate workspace summary.")
                return self._error_result("Failed to generate workspace summary.", exc, metadata={"request_id": context.request_id})

    # -----------------------------------------------------------------------
    # Export / Import / Purge
    # -----------------------------------------------------------------------

    def export_workspace_graph(
        self,
        user_id: str,
        workspace_id: str,
        include_inactive: bool = False,
        actor_agent: str = DEFAULT_AGENT_ID,
        request_id: Optional[str] = None,
        role: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Export a workspace-scoped graph snapshot.

        Security-sensitive because it can expose connected memory/project data.
        """
        context = self._context_from_kwargs(
            user_id, workspace_id, actor_agent, request_id, role, permissions, metadata
        )
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        approval = self._request_security_approval(
            "export_workspace_graph",
            context,
            {"include_inactive": include_inactive},
        )
        if not approval["success"]:
            return approval

        with self._lock:
            try:
                nodes = [
                    node
                    for node in self._nodes.values()
                    if node.user_id == context.user_id
                    and node.workspace_id == context.workspace_id
                    and (include_inactive or node.is_active)
                ]
                edges = [
                    edge
                    for edge in self._edges.values()
                    if edge.user_id == context.user_id
                    and edge.workspace_id == context.workspace_id
                    and (include_inactive or edge.is_active)
                ]

                export_payload = {
                    "metadata": {
                        "agent_id": self.agent_id,
                        "agent_name": self.agent_name,
                        "user_id": context.user_id,
                        "workspace_id": context.workspace_id,
                        "request_id": context.request_id,
                        "include_inactive": include_inactive,
                        "exported_at": self.utcnow(),
                        "node_count": len(nodes),
                        "edge_count": len(edges),
                    },
                    "nodes": [self._node_to_dict(node) for node in nodes],
                    "edges": [self._edge_to_dict(edge) for edge in edges],
                }

                self._log_audit_event(
                    "export_workspace_graph",
                    context,
                    {"node_count": len(nodes), "edge_count": len(edges), "include_inactive": include_inactive},
                )

                return self._safe_result(
                    message="Workspace graph exported successfully.",
                    data=export_payload,
                    metadata={"request_id": context.request_id},
                )
            except Exception as exc:
                self.logger.exception("Failed to export workspace graph.")
                self._log_audit_event("export_workspace_graph", context, success=False, error=str(exc))
                return self._error_result("Failed to export workspace graph.", exc, metadata={"request_id": context.request_id})

    def import_workspace_graph(
        self,
        user_id: str,
        workspace_id: str,
        payload: Dict[str, Any],
        overwrite_existing: bool = False,
        actor_agent: str = DEFAULT_AGENT_ID,
        request_id: Optional[str] = None,
        role: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Import nodes/edges into a workspace scope.

        Incoming user_id/workspace_id are forcibly scoped to the provided context.
        This prevents importing records into another tenant's scope.
        """
        context = self._context_from_kwargs(
            user_id, workspace_id, actor_agent, request_id, role, permissions, metadata
        )
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        approval = self._request_security_approval(
            "import_workspace_graph",
            context,
            {"overwrite_existing": overwrite_existing},
        )
        if not approval["success"]:
            return approval

        with self._lock:
            try:
                raw_nodes = payload.get("nodes", [])
                raw_edges = payload.get("edges", [])

                if not isinstance(raw_nodes, list) or not isinstance(raw_edges, list):
                    return self._error_result(
                        "Invalid import payload. nodes and edges must be lists.",
                        metadata={"request_id": context.request_id},
                    )

                imported_nodes = 0
                imported_edges = 0
                skipped_nodes = 0
                skipped_edges = 0

                node_id_map: Dict[str, str] = {}

                for raw_node in raw_nodes:
                    if not isinstance(raw_node, dict):
                        skipped_nodes += 1
                        continue

                    original_id = str(raw_node.get("node_id") or self._new_id("node"))
                    node_id = original_id if overwrite_existing else self._new_id("node")
                    node_id_map[original_id] = node_id

                    if not overwrite_existing and node_id in self._nodes:
                        node_id = self._new_id("node")
                        node_id_map[original_id] = node_id

                    if overwrite_existing and node_id in self._nodes:
                        existing = self._nodes[node_id]
                        if existing.user_id != context.user_id or existing.workspace_id != context.workspace_id:
                            skipped_nodes += 1
                            continue

                    label = str(raw_node.get("label") or "").strip()
                    if not label:
                        skipped_nodes += 1
                        continue

                    node = GraphNode(
                        node_id=node_id,
                        node_type=self._validate_node_type(raw_node.get("node_type", "custom")),
                        label=label,
                        user_id=context.user_id,
                        workspace_id=context.workspace_id,
                        properties=dict(raw_node.get("properties", {})),
                        tags=list(raw_node.get("tags", [])),
                        source=raw_node.get("source", "import"),
                        created_by=context.actor_agent,
                        updated_by=context.actor_agent,
                        created_at=raw_node.get("created_at") or self.utcnow(),
                        updated_at=self.utcnow(),
                        is_active=bool(raw_node.get("is_active", True)),
                    )
                    self._nodes[node.node_id] = node
                    imported_nodes += 1

                for raw_edge in raw_edges:
                    if not isinstance(raw_edge, dict):
                        skipped_edges += 1
                        continue

                    original_source = str(raw_edge.get("source_node_id") or "")
                    original_target = str(raw_edge.get("target_node_id") or "")

                    source_node_id = node_id_map.get(original_source, original_source)
                    target_node_id = node_id_map.get(original_target, original_target)

                    if source_node_id not in self._nodes or target_node_id not in self._nodes:
                        skipped_edges += 1
                        continue

                    source_node = self._nodes[source_node_id]
                    target_node = self._nodes[target_node_id]
                    if not self._is_node_visible_to_context(source_node, context):
                        skipped_edges += 1
                        continue
                    if not self._is_node_visible_to_context(target_node, context):
                        skipped_edges += 1
                        continue

                    original_edge_id = str(raw_edge.get("edge_id") or self._new_id("edge"))
                    edge_id = original_edge_id if overwrite_existing else self._new_id("edge")

                    if overwrite_existing and edge_id in self._edges:
                        existing_edge = self._edges[edge_id]
                        if existing_edge.user_id != context.user_id or existing_edge.workspace_id != context.workspace_id:
                            skipped_edges += 1
                            continue

                    edge = GraphEdge(
                        edge_id=edge_id,
                        source_node_id=source_node_id,
                        target_node_id=target_node_id,
                        edge_type=self._validate_edge_type(raw_edge.get("edge_type", "relates_to")),
                        user_id=context.user_id,
                        workspace_id=context.workspace_id,
                        weight=float(raw_edge.get("weight", 1.0)),
                        properties=dict(raw_edge.get("properties", {})),
                        source=raw_edge.get("source", "import"),
                        created_by=context.actor_agent,
                        updated_by=context.actor_agent,
                        created_at=raw_edge.get("created_at") or self.utcnow(),
                        updated_at=self.utcnow(),
                        is_active=bool(raw_edge.get("is_active", True)),
                    )
                    self._edges[edge.edge_id] = edge
                    imported_edges += 1

                self._autosave()

                self._log_audit_event(
                    "import_workspace_graph",
                    context,
                    {
                        "imported_nodes": imported_nodes,
                        "imported_edges": imported_edges,
                        "skipped_nodes": skipped_nodes,
                        "skipped_edges": skipped_edges,
                        "overwrite_existing": overwrite_existing,
                    },
                )

                verification_payload = self._prepare_verification_payload(
                    "import_workspace_graph",
                    context,
                    {
                        "imported_nodes": imported_nodes,
                        "imported_edges": imported_edges,
                        "skipped_nodes": skipped_nodes,
                        "skipped_edges": skipped_edges,
                    },
                )

                return self._safe_result(
                    message="Workspace graph imported successfully.",
                    data={
                        "imported_nodes": imported_nodes,
                        "imported_edges": imported_edges,
                        "skipped_nodes": skipped_nodes,
                        "skipped_edges": skipped_edges,
                        "verification_payload": verification_payload,
                    },
                    metadata={"request_id": context.request_id},
                )
            except Exception as exc:
                self.logger.exception("Failed to import workspace graph.")
                self._log_audit_event("import_workspace_graph", context, success=False, error=str(exc))
                return self._error_result("Failed to import workspace graph.", exc, metadata={"request_id": context.request_id})

    def purge_workspace_graph(
        self,
        user_id: str,
        workspace_id: str,
        soft_delete: bool = True,
        actor_agent: str = DEFAULT_AGENT_ID,
        request_id: Optional[str] = None,
        role: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Purge all graph records in a workspace scope.

        Security-sensitive. Defaults to soft delete.
        """
        context = self._context_from_kwargs(
            user_id, workspace_id, actor_agent, request_id, role, permissions, metadata
        )
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        approval = self._request_security_approval(
            "purge_workspace_graph",
            context,
            {"soft_delete": soft_delete},
        )
        if not approval["success"]:
            return approval

        with self._lock:
            try:
                affected_nodes = 0
                affected_edges = 0

                for edge_id, edge in list(self._edges.items()):
                    if edge.user_id == context.user_id and edge.workspace_id == context.workspace_id:
                        affected_edges += 1
                        if soft_delete:
                            edge.is_active = False
                            edge.updated_at = self.utcnow()
                            edge.updated_by = context.actor_agent
                        else:
                            del self._edges[edge_id]

                for node_id, node in list(self._nodes.items()):
                    if node.user_id == context.user_id and node.workspace_id == context.workspace_id:
                        affected_nodes += 1
                        if soft_delete:
                            node.is_active = False
                            node.updated_at = self.utcnow()
                            node.updated_by = context.actor_agent
                        else:
                            del self._nodes[node_id]

                self._autosave()

                self._log_audit_event(
                    "purge_workspace_graph",
                    context,
                    {"affected_nodes": affected_nodes, "affected_edges": affected_edges, "soft_delete": soft_delete},
                )
                self._emit_agent_event(
                    "knowledge_graph.workspace_purged",
                    {
                        "user_id": context.user_id,
                        "workspace_id": context.workspace_id,
                        "affected_nodes": affected_nodes,
                        "affected_edges": affected_edges,
                        "soft_delete": soft_delete,
                        "request_id": context.request_id,
                    },
                )

                verification_payload = self._prepare_verification_payload(
                    "purge_workspace_graph",
                    context,
                    {"affected_nodes": affected_nodes, "affected_edges": affected_edges},
                )

                return self._safe_result(
                    message="Workspace graph purged successfully.",
                    data={
                        "affected_nodes": affected_nodes,
                        "affected_edges": affected_edges,
                        "soft_delete": soft_delete,
                        "verification_payload": verification_payload,
                    },
                    metadata={"request_id": context.request_id},
                )
            except Exception as exc:
                self.logger.exception("Failed to purge workspace graph.")
                self._log_audit_event("purge_workspace_graph", context, success=False, error=str(exc))
                return self._error_result("Failed to purge workspace graph.", exc, metadata={"request_id": context.request_id})

    # -----------------------------------------------------------------------
    # Agent Router Entry Point
    # -----------------------------------------------------------------------

    def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generic Agent Router / Master Agent entry point.

        Expected task:
            {
                "action": "add_node" | "add_edge" | "search_graph" | ...,
                "user_id": "...",
                "workspace_id": "...",
                "payload": {...},
                "actor_agent": "master_agent"
            }
        """
        if not isinstance(task, dict):
            return self._error_result("Task must be a dictionary.")

        action = self._normalize(task.get("action"))
        user_id = str(task.get("user_id", "")).strip()
        workspace_id = str(task.get("workspace_id", "")).strip()
        actor_agent = str(task.get("actor_agent") or DEFAULT_AGENT_ID)
        request_id = task.get("request_id") or str(uuid.uuid4())
        payload = task.get("payload") or {}

        if not isinstance(payload, dict):
            return self._error_result("Task payload must be a dictionary.", metadata={"request_id": request_id})

        common = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "actor_agent": actor_agent,
            "request_id": request_id,
            "role": task.get("role"),
            "permissions": task.get("permissions") or [],
            "metadata": task.get("metadata") or {},
        }

        try:
            if action == "add_node":
                return self.add_node(**common, **payload)

            if action == "upsert_node":
                return self.upsert_node(**common, **payload)

            if action == "update_node":
                return self.update_node(**common, **payload)

            if action == "get_node":
                return self.get_node(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    node_id=payload.get("node_id", ""),
                    actor_agent=actor_agent,
                    request_id=request_id,
                )

            if action == "delete_node":
                return self.delete_node(**common, **payload)

            if action == "add_edge":
                return self.add_edge(**common, **payload)

            if action == "update_edge":
                return self.update_edge(**common, **payload)

            if action == "get_edge":
                return self.get_edge(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    edge_id=payload.get("edge_id", ""),
                    actor_agent=actor_agent,
                    request_id=request_id,
                )

            if action == "delete_edge":
                return self.delete_edge(**common, **payload)

            if action == "link_entities":
                return self.link_entities(**common, **payload)

            if action == "list_nodes":
                return self.list_nodes(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    actor_agent=actor_agent,
                    request_id=request_id,
                    **payload,
                )

            if action == "list_edges":
                return self.list_edges(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    actor_agent=actor_agent,
                    request_id=request_id,
                    **payload,
                )

            if action == "get_neighbors":
                return self.get_neighbors(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    actor_agent=actor_agent,
                    request_id=request_id,
                    **payload,
                )

            if action == "get_subgraph":
                return self.get_subgraph(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    actor_agent=actor_agent,
                    request_id=request_id,
                    **payload,
                )

            if action == "find_paths":
                return self.find_paths(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    actor_agent=actor_agent,
                    request_id=request_id,
                    **payload,
                )

            if action == "search_graph":
                return self.search_graph(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    actor_agent=actor_agent,
                    request_id=request_id,
                    **payload,
                )

            if action == "record_decision":
                return self.record_decision(**common, **payload)

            if action == "connect_project_file":
                return self.connect_project_file(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    actor_agent=actor_agent,
                    request_id=request_id,
                    **payload,
                )

            if action == "connect_agent_task":
                return self.connect_agent_task(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    actor_agent=actor_agent,
                    request_id=request_id,
                    **payload,
                )

            if action == "get_project_timeline":
                return self.get_project_timeline(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    actor_agent=actor_agent,
                    request_id=request_id,
                    **payload,
                )

            if action == "get_workspace_summary":
                return self.get_workspace_summary(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    actor_agent=actor_agent,
                    request_id=request_id,
                )

            if action == "export_workspace_graph":
                return self.export_workspace_graph(**common, **payload)

            if action == "import_workspace_graph":
                return self.import_workspace_graph(**common, **payload)

            if action == "purge_workspace_graph":
                return self.purge_workspace_graph(**common, **payload)

            if action == "save":
                return self.save()

            return self._error_result(
                "Unsupported KnowledgeGraph action.",
                error=f"Unsupported action: {action}",
                metadata={"request_id": request_id, "supported_actions": self.supported_actions()},
            )
        except TypeError as exc:
            self.logger.exception("Invalid task payload for action %s.", action)
            return self._error_result(
                "Invalid task payload for KnowledgeGraph action.",
                exc,
                metadata={"request_id": request_id, "action": action},
            )
        except Exception as exc:
            self.logger.exception("KnowledgeGraph run failed.")
            return self._error_result(
                "KnowledgeGraph run failed.",
                exc,
                metadata={"request_id": request_id, "action": action},
            )

    def supported_actions(self) -> List[str]:
        """Return public actions supported by Master Agent / Agent Router."""
        return [
            "add_node",
            "upsert_node",
            "update_node",
            "get_node",
            "delete_node",
            "add_edge",
            "update_edge",
            "get_edge",
            "delete_edge",
            "link_entities",
            "list_nodes",
            "list_edges",
            "get_neighbors",
            "get_subgraph",
            "find_paths",
            "search_graph",
            "record_decision",
            "connect_project_file",
            "connect_agent_task",
            "get_project_timeline",
            "get_workspace_summary",
            "export_workspace_graph",
            "import_workspace_graph",
            "purge_workspace_graph",
            "save",
        ]

    # -----------------------------------------------------------------------
    # Health / Registry Metadata
    # -----------------------------------------------------------------------

    def health_check(self) -> Dict[str, Any]:
        """Return registry/dashboard health status."""
        with self._lock:
            return self._safe_result(
                message="KnowledgeGraph is healthy.",
                data={
                    "agent_id": self.agent_id,
                    "agent_name": self.agent_name,
                    "storage_path": str(self.storage_path),
                    "autosave": self.autosave,
                    "node_count": len(self._nodes),
                    "edge_count": len(self._edges),
                    "supported_actions": self.supported_actions(),
                },
            )

    def get_registry_metadata(self) -> Dict[str, Any]:
        """Return Agent Registry-compatible metadata."""
        return {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "module": "Memory Agent",
            "file_path": "agents/memory_agent/knowledge_graph.py",
            "class_name": "KnowledgeGraph",
            "purpose": "Nodes/edges connecting users, projects, files, agents, tasks, decisions.",
            "requires_user_id": True,
            "requires_workspace_id": True,
            "security_sensitive_actions": sorted(SENSITIVE_ACTIONS),
            "supported_actions": self.supported_actions(),
            "safe_to_import": True,
            "created_for": "William / Jarvis Multi-Agent AI SaaS System by Digital Promotix",
        }


__all__ = [
    "KnowledgeGraph",
    "GraphContext",
    "GraphNode",
    "GraphEdge",
]