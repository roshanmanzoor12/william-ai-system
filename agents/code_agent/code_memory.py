"""
agents/code_agent/code_memory.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    CodeMemory remembers project rules, architecture decisions, file roles,
    naming conventions, prior fixes, compatibility notes, and implementation
    context for the Code Agent module.

Architecture Role:
    - Used by Code Agent to preserve project-specific development context.
    - Compatible with Master Agent routing through structured task handling.
    - Compatible with Memory Agent through memory payload preparation.
    - Compatible with Verification Agent through verification payload preparation.
    - Compatible with Security Agent through sensitive-action hooks.
    - Compatible with SaaS dashboards/APIs through structured result objects.
    - Compatible with future registry/loader systems through clear public methods.

Safety / SaaS Rules:
    - Every memory record is isolated by user_id and workspace_id.
    - No memory, file data, audit logs, events, or task context is mixed across users.
    - Sensitive memory actions can be routed through Security Agent hooks.
    - Import-safe even if other William/Jarvis modules are not created yet.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import os
import re
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union


# =============================================================================
# Safe Optional Imports
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for early project generation
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps the file import-safe before the full William/Jarvis
        BaseAgent exists. When the real BaseAgent is available, it will be used.
        """

        def __init__(
            self,
            agent_name: str = "CodeMemory",
            agent_type: str = "code_memory",
            **kwargs: Any,
        ) -> None:
            self.agent_name = agent_name
            self.agent_type = agent_type
            self.config = kwargs

        def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent run() called directly.",
                "data": {},
                "error": "BaseAgent is not fully implemented yet.",
                "metadata": {
                    "agent_name": self.agent_name,
                    "agent_type": self.agent_type,
                },
            }


try:
    from agents.security_agent.security_agent import SecurityAgent  # type: ignore
except Exception:  # pragma: no cover
    SecurityAgent = None  # type: ignore


try:
    from agents.verification_agent.verification_agent import VerificationAgent  # type: ignore
except Exception:  # pragma: no cover
    VerificationAgent = None  # type: ignore


try:
    from agents.memory_agent.memory_agent import MemoryAgent  # type: ignore
except Exception:  # pragma: no cover
    MemoryAgent = None  # type: ignore


# =============================================================================
# Logging
# =============================================================================

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# =============================================================================
# Constants
# =============================================================================

DEFAULT_AGENT_NAME = "CodeMemory"
DEFAULT_AGENT_TYPE = "code_memory"
DEFAULT_MODULE_NAME = "Code Agent"
DEFAULT_SYSTEM_NAME = "William / Jarvis Multi-Agent AI SaaS System"
DEFAULT_BRAND_NAME = "Digital Promotix"

ALLOWED_MEMORY_TYPES = {
    "project_rule",
    "architecture",
    "file_role",
    "naming",
    "prior_fix",
    "dependency",
    "route",
    "api_contract",
    "database_contract",
    "security_note",
    "verification_note",
    "memory_note",
    "registry_note",
    "dashboard_note",
    "task_note",
    "implementation_note",
    "compatibility_note",
}

SENSITIVE_MEMORY_TYPES = {
    "security_note",
    "api_contract",
    "database_contract",
}

DEFAULT_STORAGE_DIR = Path(
    os.getenv(
        "WILLIAM_CODE_MEMORY_DIR",
        ".william/code_memory",
    )
)

MAX_TEXT_LENGTH = 50_000
MAX_TAG_LENGTH = 80
MAX_TAGS = 30
MAX_SEARCH_RESULTS = 100


# =============================================================================
# Utility Functions
# =============================================================================

def _utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def _safe_json_dumps(value: Any) -> str:
    """Safely serialize data to JSON string."""
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    except Exception:
        return json.dumps(str(value), ensure_ascii=False)


def _stable_hash(value: Any) -> str:
    """Generate a stable short hash for any JSON-like value."""
    raw = _safe_json_dumps(value)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _slugify(value: str, fallback: str = "item") -> str:
    """Convert a string into a safe slug."""
    cleaned = re.sub(r"[^a-zA-Z0-9._-]+", "-", str(value).strip().lower())
    cleaned = re.sub(r"-+", "-", cleaned).strip("-")
    return cleaned or fallback


def _normalize_text(value: Any) -> str:
    """Normalize user/project text."""
    if value is None:
        return ""
    text = str(value)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[ \t]+", " ", text)
    return text.strip()


def _normalize_tags(tags: Optional[Iterable[Any]]) -> List[str]:
    """Normalize, deduplicate, and limit tags."""
    if not tags:
        return []

    cleaned: List[str] = []
    seen = set()

    for tag in tags:
        safe_tag = _slugify(str(tag), fallback="")
        if not safe_tag:
            continue

        safe_tag = safe_tag[:MAX_TAG_LENGTH]

        if safe_tag not in seen:
            cleaned.append(safe_tag)
            seen.add(safe_tag)

        if len(cleaned) >= MAX_TAGS:
            break

    return cleaned


def _safe_deepcopy(value: Any) -> Any:
    """Safely deep-copy a value."""
    try:
        return copy.deepcopy(value)
    except Exception:
        return value


def _coerce_dict(value: Any) -> Dict[str, Any]:
    """Return value if it is a dict, otherwise return empty dict."""
    return value if isinstance(value, dict) else {}


# =============================================================================
# Data Structures
# =============================================================================

@dataclass
class CodeMemoryRecord:
    """
    A single isolated Code Agent memory record.

    Every record belongs to exactly one user/workspace pair.
    """

    memory_id: str
    user_id: str
    workspace_id: str
    memory_type: str
    title: str
    content: str
    tags: List[str] = field(default_factory=list)
    file_path: Optional[str] = None
    module_name: str = DEFAULT_MODULE_NAME
    priority: int = 5
    source: str = "code_agent"
    created_at: str = field(default_factory=_utc_now_iso)
    updated_at: str = field(default_factory=_utc_now_iso)
    version: int = 1
    is_active: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert record to a dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "CodeMemoryRecord":
        """Build record from dictionary with safe defaults."""
        return cls(
            memory_id=str(payload.get("memory_id") or str(uuid.uuid4())),
            user_id=str(payload.get("user_id") or ""),
            workspace_id=str(payload.get("workspace_id") or ""),
            memory_type=str(payload.get("memory_type") or "implementation_note"),
            title=str(payload.get("title") or "Untitled Memory"),
            content=str(payload.get("content") or ""),
            tags=list(payload.get("tags") or []),
            file_path=payload.get("file_path"),
            module_name=str(payload.get("module_name") or DEFAULT_MODULE_NAME),
            priority=int(payload.get("priority") or 5),
            source=str(payload.get("source") or "code_agent"),
            created_at=str(payload.get("created_at") or _utc_now_iso()),
            updated_at=str(payload.get("updated_at") or _utc_now_iso()),
            version=int(payload.get("version") or 1),
            is_active=bool(payload.get("is_active", True)),
            metadata=_coerce_dict(payload.get("metadata")),
        )


@dataclass
class CodeFileRole:
    """
    Describes the role of a project file inside William/Jarvis architecture.
    """

    file_path: str
    file_name: str
    module_name: str
    purpose: str
    public_classes: List[str] = field(default_factory=list)
    public_methods: List[str] = field(default_factory=list)
    depends_on: List[str] = field(default_factory=list)
    used_by: List[str] = field(default_factory=list)
    integration_notes: List[str] = field(default_factory=list)
    security_level: str = "normal"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert file role to dictionary."""
        return asdict(self)


@dataclass
class CodeArchitectureRule:
    """
    Project architecture rule used by the Code Agent.
    """

    rule_id: str
    title: str
    description: str
    priority: int = 5
    applies_to: List[str] = field(default_factory=list)
    conflict_order: int = 999
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert rule to dictionary."""
        return asdict(self)


# =============================================================================
# CodeMemory
# =============================================================================

class CodeMemory(BaseAgent):
    """
    Production-safe Code Agent memory manager.

    Main Responsibilities:
        - Remember project rules.
        - Remember architecture decisions.
        - Remember file roles.
        - Remember naming conventions.
        - Remember prior fixes and debugging history.
        - Provide isolated search/retrieval per user/workspace.
        - Export useful context for Master Agent routing, Memory Agent,
          Verification Agent, dashboard/API, and future plugin agents.

    Compatibility:
        - BaseAgent-compatible constructor and run() method.
        - Agent Registry-friendly metadata through get_agent_manifest().
        - Agent Router-friendly action dispatch through handle_task().
        - Master Agent-friendly structured result format.
    """

    def __init__(
        self,
        storage_dir: Optional[Union[str, Path]] = None,
        agent_name: str = DEFAULT_AGENT_NAME,
        agent_type: str = DEFAULT_AGENT_TYPE,
        auto_persist: bool = True,
        enable_security_checks: bool = True,
        enable_audit_log: bool = True,
        enable_events: bool = True,
        security_agent: Any = None,
        memory_agent: Any = None,
        verification_agent: Any = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize CodeMemory.

        Args:
            storage_dir:
                Directory for lightweight JSON persistence.
            agent_name:
                Registry-facing agent name.
            agent_type:
                Registry-facing agent type.
            auto_persist:
                Whether records are persisted to JSON files.
            enable_security_checks:
                Whether sensitive actions require Security Agent approval.
            enable_audit_log:
                Whether audit records are kept in memory.
            enable_events:
                Whether agent events are emitted to local event history.
            security_agent:
                Optional injected Security Agent.
            memory_agent:
                Optional injected Memory Agent.
            verification_agent:
                Optional injected Verification Agent.
            **kwargs:
                Future BaseAgent/registry configuration.
        """
        try:
            super().__init__(
                agent_name=agent_name,
                agent_type=agent_type,
                **kwargs,
            )
        except TypeError:
            super().__init__()

        self.agent_name = agent_name
        self.agent_type = agent_type
        self.system_name = DEFAULT_SYSTEM_NAME
        self.brand_name = DEFAULT_BRAND_NAME
        self.module_name = DEFAULT_MODULE_NAME

        self.storage_dir = Path(storage_dir) if storage_dir else DEFAULT_STORAGE_DIR
        self.auto_persist = bool(auto_persist)
        self.enable_security_checks = bool(enable_security_checks)
        self.enable_audit_log = bool(enable_audit_log)
        self.enable_events = bool(enable_events)

        self.security_agent = security_agent
        self.memory_agent = memory_agent
        self.verification_agent = verification_agent

        self._lock = threading.RLock()
        self._records: Dict[str, Dict[str, CodeMemoryRecord]] = {}
        self._audit_events: List[Dict[str, Any]] = []
        self._agent_events: List[Dict[str, Any]] = []

        self._default_architecture_rules = self._build_default_architecture_rules()

        if self.auto_persist:
            self._ensure_storage_dir()
            self._load_all_records()

    # -------------------------------------------------------------------------
    # BaseAgent / Router Entry Points
    # -------------------------------------------------------------------------

    def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        BaseAgent-compatible run method.

        Expected task shape:
            {
                "action": "remember" | "search" | "get" | "update" | "delete" | ...,
                "user_id": "...",
                "workspace_id": "...",
                "data": {...},
                "metadata": {...}
            }
        """
        return self.handle_task(task)

    def handle_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Master Agent / Router-compatible task handler.
        """
        context_result = self._validate_task_context(task)
        if not context_result["success"]:
            return context_result

        action = str(task.get("action") or "").strip().lower()
        data = _coerce_dict(task.get("data"))
        user_id = str(task.get("user_id"))
        workspace_id = str(task.get("workspace_id"))

        try:
            if self._requires_security_check(action=action, payload=task):
                approval = self._request_security_approval(
                    action=action,
                    payload=task,
                    user_id=user_id,
                    workspace_id=workspace_id,
                )
                if not approval.get("approved", False):
                    return self._error_result(
                        message="Security approval denied for CodeMemory action.",
                        error=approval.get("reason") or "security_denied",
                        data={"action": action},
                        metadata={
                            "user_id": user_id,
                            "workspace_id": workspace_id,
                        },
                    )

            if action in {"remember", "create", "add"}:
                result = self.remember(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    memory_type=data.get("memory_type", "implementation_note"),
                    title=data.get("title", "Untitled Memory"),
                    content=data.get("content", ""),
                    tags=data.get("tags"),
                    file_path=data.get("file_path"),
                    module_name=data.get("module_name", DEFAULT_MODULE_NAME),
                    priority=data.get("priority", 5),
                    source=data.get("source", "code_agent"),
                    metadata=_coerce_dict(data.get("metadata")),
                )

            elif action in {"search", "query"}:
                result = self.search(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    query=data.get("query", ""),
                    memory_types=data.get("memory_types"),
                    tags=data.get("tags"),
                    file_path=data.get("file_path"),
                    include_inactive=bool(data.get("include_inactive", False)),
                    limit=int(data.get("limit") or 20),
                )

            elif action in {"get", "retrieve"}:
                result = self.get_memory(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    memory_id=str(data.get("memory_id") or ""),
                )

            elif action in {"update", "edit"}:
                result = self.update_memory(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    memory_id=str(data.get("memory_id") or ""),
                    updates=_coerce_dict(data.get("updates")),
                )

            elif action in {"delete", "remove", "deactivate"}:
                result = self.delete_memory(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    memory_id=str(data.get("memory_id") or ""),
                    hard_delete=bool(data.get("hard_delete", False)),
                )

            elif action == "remember_project_rule":
                result = self.remember_project_rule(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    title=data.get("title", ""),
                    description=data.get("description", ""),
                    priority=data.get("priority", 5),
                    applies_to=data.get("applies_to"),
                    metadata=_coerce_dict(data.get("metadata")),
                )

            elif action == "remember_file_role":
                result = self.remember_file_role(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    file_path=data.get("file_path", ""),
                    purpose=data.get("purpose", ""),
                    module_name=data.get("module_name", DEFAULT_MODULE_NAME),
                    public_classes=data.get("public_classes"),
                    public_methods=data.get("public_methods"),
                    depends_on=data.get("depends_on"),
                    used_by=data.get("used_by"),
                    integration_notes=data.get("integration_notes"),
                    security_level=data.get("security_level", "normal"),
                    metadata=_coerce_dict(data.get("metadata")),
                )

            elif action == "remember_prior_fix":
                result = self.remember_prior_fix(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    title=data.get("title", ""),
                    problem=data.get("problem", ""),
                    fix=data.get("fix", ""),
                    file_path=data.get("file_path"),
                    tags=data.get("tags"),
                    metadata=_coerce_dict(data.get("metadata")),
                )

            elif action == "get_context_bundle":
                result = self.get_context_bundle(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    file_path=data.get("file_path"),
                    module_name=data.get("module_name"),
                    query=data.get("query", ""),
                    limit=int(data.get("limit") or 25),
                )

            elif action == "export_workspace_memory":
                result = self.export_workspace_memory(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    include_inactive=bool(data.get("include_inactive", False)),
                )

            elif action == "clear_workspace_memory":
                result = self.clear_workspace_memory(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    hard_delete=bool(data.get("hard_delete", False)),
                )

            elif action == "manifest":
                result = self.get_agent_manifest()

            else:
                result = self._error_result(
                    message="Unsupported CodeMemory action.",
                    error="unsupported_action",
                    data={"action": action},
                    metadata={
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                    },
                )

            self._emit_agent_event(
                event_type="task_handled",
                user_id=user_id,
                workspace_id=workspace_id,
                payload={
                    "action": action,
                    "success": result.get("success", False),
                },
            )

            return result

        except Exception as exc:
            logger.exception("CodeMemory task failed.")
            return self._error_result(
                message="CodeMemory task failed.",
                error=str(exc),
                data={"action": action},
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )

    # -------------------------------------------------------------------------
    # Public Memory Methods
    # -------------------------------------------------------------------------

    def remember(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        memory_type: str,
        title: str,
        content: str,
        tags: Optional[Iterable[Any]] = None,
        file_path: Optional[str] = None,
        module_name: str = DEFAULT_MODULE_NAME,
        priority: int = 5,
        source: str = "code_agent",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Store a Code Agent memory record for a user/workspace.
        """
        user_id_str, workspace_id_str = self._normalize_scope(user_id, workspace_id)

        validation = self._validate_memory_input(
            memory_type=memory_type,
            title=title,
            content=content,
            priority=priority,
        )
        if not validation["success"]:
            return validation

        safe_memory_type = str(memory_type).strip()
        safe_title = _normalize_text(title)
        safe_content = _normalize_text(content)
        safe_tags = _normalize_tags(tags)
        safe_file_path = self._normalize_file_path(file_path)
        safe_module_name = _normalize_text(module_name) or DEFAULT_MODULE_NAME
        safe_priority = self._normalize_priority(priority)

        record_payload = {
            "user_id": user_id_str,
            "workspace_id": workspace_id_str,
            "memory_type": safe_memory_type,
            "title": safe_title,
            "content": safe_content,
            "tags": safe_tags,
            "file_path": safe_file_path,
            "module_name": safe_module_name,
            "priority": safe_priority,
            "source": source,
            "metadata": metadata or {},
        }

        memory_id = self._build_memory_id(record_payload)

        with self._lock:
            scope_key = self._scope_key(user_id_str, workspace_id_str)
            self._records.setdefault(scope_key, {})

            existing = self._records[scope_key].get(memory_id)
            now = _utc_now_iso()

            if existing:
                existing.content = safe_content
                existing.title = safe_title
                existing.tags = safe_tags
                existing.file_path = safe_file_path
                existing.module_name = safe_module_name
                existing.priority = safe_priority
                existing.source = str(source or "code_agent")
                existing.updated_at = now
                existing.version += 1
                existing.is_active = True
                existing.metadata = self._merge_metadata(existing.metadata, metadata or {})
                record = existing
                action = "updated"
            else:
                record = CodeMemoryRecord(
                    memory_id=memory_id,
                    user_id=user_id_str,
                    workspace_id=workspace_id_str,
                    memory_type=safe_memory_type,
                    title=safe_title,
                    content=safe_content,
                    tags=safe_tags,
                    file_path=safe_file_path,
                    module_name=safe_module_name,
                    priority=safe_priority,
                    source=str(source or "code_agent"),
                    metadata=metadata or {},
                )
                self._records[scope_key][memory_id] = record
                action = "created"

            if self.auto_persist:
                self._persist_scope(user_id_str, workspace_id_str)

        audit_payload = self._log_audit_event(
            action=f"code_memory_{action}",
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            payload={
                "memory_id": memory_id,
                "memory_type": safe_memory_type,
                "file_path": safe_file_path,
            },
        )

        verification_payload = self._prepare_verification_payload(
            action=f"code_memory_{action}",
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            data=record.to_dict(),
        )

        memory_payload = self._prepare_memory_payload(
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            data=record.to_dict(),
        )

        return self._safe_result(
            message=f"Code memory {action} successfully.",
            data={
                "memory": record.to_dict(),
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
                "audit_event": audit_payload,
            },
            metadata={
                "user_id": user_id_str,
                "workspace_id": workspace_id_str,
                "agent": self.agent_name,
                "action": action,
            },
        )

    def remember_project_rule(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        title: str,
        description: str,
        priority: int = 5,
        applies_to: Optional[Iterable[Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Remember a project rule for future Code Agent decisions.
        """
        content = _normalize_text(description)
        applies = [str(item).strip() for item in (applies_to or []) if str(item).strip()]

        return self.remember(
            user_id=user_id,
            workspace_id=workspace_id,
            memory_type="project_rule",
            title=title,
            content=content,
            tags=["project-rule", "architecture", *applies],
            module_name=DEFAULT_MODULE_NAME,
            priority=priority,
            source="code_memory.remember_project_rule",
            metadata={
                **(metadata or {}),
                "applies_to": applies,
            },
        )

    def remember_architecture_decision(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        title: str,
        decision: str,
        rationale: str = "",
        affected_modules: Optional[Iterable[Any]] = None,
        priority: int = 5,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Remember an architecture decision.
        """
        affected = [str(item).strip() for item in (affected_modules or []) if str(item).strip()]
        content_parts = [
            f"Decision: {_normalize_text(decision)}",
        ]
        if rationale:
            content_parts.append(f"Rationale: {_normalize_text(rationale)}")
        if affected:
            content_parts.append(f"Affected Modules: {', '.join(affected)}")

        return self.remember(
            user_id=user_id,
            workspace_id=workspace_id,
            memory_type="architecture",
            title=title,
            content="\n".join(content_parts),
            tags=["architecture", "decision", *affected],
            module_name=DEFAULT_MODULE_NAME,
            priority=priority,
            source="code_memory.remember_architecture_decision",
            metadata={
                **(metadata or {}),
                "affected_modules": affected,
                "rationale": rationale,
            },
        )

    def remember_file_role(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        file_path: str,
        purpose: str,
        module_name: str = DEFAULT_MODULE_NAME,
        public_classes: Optional[Iterable[Any]] = None,
        public_methods: Optional[Iterable[Any]] = None,
        depends_on: Optional[Iterable[Any]] = None,
        used_by: Optional[Iterable[Any]] = None,
        integration_notes: Optional[Iterable[Any]] = None,
        security_level: str = "normal",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Remember a file's role in the William/Jarvis architecture.
        """
        safe_file_path = self._normalize_file_path(file_path)
        if not safe_file_path:
            return self._error_result(
                message="file_path is required for remember_file_role.",
                error="missing_file_path",
            )

        role = CodeFileRole(
            file_path=safe_file_path,
            file_name=Path(safe_file_path).name,
            module_name=_normalize_text(module_name) or DEFAULT_MODULE_NAME,
            purpose=_normalize_text(purpose),
            public_classes=[str(x).strip() for x in (public_classes or []) if str(x).strip()],
            public_methods=[str(x).strip() for x in (public_methods or []) if str(x).strip()],
            depends_on=[str(x).strip() for x in (depends_on or []) if str(x).strip()],
            used_by=[str(x).strip() for x in (used_by or []) if str(x).strip()],
            integration_notes=[str(x).strip() for x in (integration_notes or []) if str(x).strip()],
            security_level=_slugify(security_level, fallback="normal"),
            metadata=metadata or {},
        )

        content = _safe_json_dumps(role.to_dict())

        return self.remember(
            user_id=user_id,
            workspace_id=workspace_id,
            memory_type="file_role",
            title=f"File role: {safe_file_path}",
            content=content,
            tags=[
                "file-role",
                _slugify(role.module_name),
                _slugify(role.file_name),
                role.security_level,
            ],
            file_path=safe_file_path,
            module_name=role.module_name,
            priority=7,
            source="code_memory.remember_file_role",
            metadata={
                **(metadata or {}),
                "file_role": role.to_dict(),
            },
        )

    def remember_naming_convention(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        title: str,
        convention: str,
        applies_to: Optional[Iterable[Any]] = None,
        examples: Optional[Iterable[Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Remember naming rules for files, classes, methods, variables, routes, etc.
        """
        applies = [str(item).strip() for item in (applies_to or []) if str(item).strip()]
        example_list = [str(item).strip() for item in (examples or []) if str(item).strip()]

        content_parts = [f"Convention: {_normalize_text(convention)}"]
        if applies:
            content_parts.append(f"Applies To: {', '.join(applies)}")
        if example_list:
            content_parts.append("Examples:")
            content_parts.extend([f"- {example}" for example in example_list])

        return self.remember(
            user_id=user_id,
            workspace_id=workspace_id,
            memory_type="naming",
            title=title,
            content="\n".join(content_parts),
            tags=["naming", "convention", *applies],
            module_name=DEFAULT_MODULE_NAME,
            priority=6,
            source="code_memory.remember_naming_convention",
            metadata={
                **(metadata or {}),
                "applies_to": applies,
                "examples": example_list,
            },
        )

    def remember_prior_fix(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        title: str,
        problem: str,
        fix: str,
        file_path: Optional[str] = None,
        tags: Optional[Iterable[Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Remember a prior bug, error, or implementation fix.
        """
        safe_problem = _normalize_text(problem)
        safe_fix = _normalize_text(fix)
        safe_file_path = self._normalize_file_path(file_path)

        content = (
            f"Problem:\n{safe_problem}\n\n"
            f"Fix:\n{safe_fix}"
        )

        base_tags = ["prior-fix", "debugging", "implementation"]
        if safe_file_path:
            base_tags.append(_slugify(Path(safe_file_path).name))

        return self.remember(
            user_id=user_id,
            workspace_id=workspace_id,
            memory_type="prior_fix",
            title=title,
            content=content,
            tags=[*base_tags, *list(tags or [])],
            file_path=safe_file_path,
            module_name=DEFAULT_MODULE_NAME,
            priority=8,
            source="code_memory.remember_prior_fix",
            metadata={
                **(metadata or {}),
                "problem": safe_problem,
                "fix": safe_fix,
            },
        )

    def get_memory(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        memory_id: str,
    ) -> Dict[str, Any]:
        """
        Retrieve one memory record by ID inside a user/workspace scope.
        """
        user_id_str, workspace_id_str = self._normalize_scope(user_id, workspace_id)
        safe_memory_id = str(memory_id or "").strip()

        if not safe_memory_id:
            return self._error_result(
                message="memory_id is required.",
                error="missing_memory_id",
                metadata={
                    "user_id": user_id_str,
                    "workspace_id": workspace_id_str,
                },
            )

        with self._lock:
            record = self._records.get(
                self._scope_key(user_id_str, workspace_id_str),
                {},
            ).get(safe_memory_id)

        if not record:
            return self._error_result(
                message="Code memory record not found.",
                error="not_found",
                data={"memory_id": safe_memory_id},
                metadata={
                    "user_id": user_id_str,
                    "workspace_id": workspace_id_str,
                },
            )

        return self._safe_result(
            message="Code memory record retrieved.",
            data={"memory": record.to_dict()},
            metadata={
                "user_id": user_id_str,
                "workspace_id": workspace_id_str,
            },
        )

    def search(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        query: str = "",
        memory_types: Optional[Iterable[Any]] = None,
        tags: Optional[Iterable[Any]] = None,
        file_path: Optional[str] = None,
        include_inactive: bool = False,
        limit: int = 20,
    ) -> Dict[str, Any]:
        """
        Search memory inside one user/workspace only.
        """
        user_id_str, workspace_id_str = self._normalize_scope(user_id, workspace_id)
        safe_query = _normalize_text(query).lower()
        safe_types = {
            str(item).strip()
            for item in (memory_types or [])
            if str(item).strip()
        }
        safe_tags = set(_normalize_tags(tags))
        safe_file_path = self._normalize_file_path(file_path)
        safe_limit = max(1, min(int(limit or 20), MAX_SEARCH_RESULTS))

        with self._lock:
            records = list(
                self._records.get(
                    self._scope_key(user_id_str, workspace_id_str),
                    {},
                ).values()
            )

        matched: List[Tuple[int, CodeMemoryRecord]] = []

        for record in records:
            if not include_inactive and not record.is_active:
                continue

            if safe_types and record.memory_type not in safe_types:
                continue

            if safe_file_path and record.file_path != safe_file_path:
                continue

            record_tags = set(record.tags or [])
            if safe_tags and not safe_tags.issubset(record_tags):
                continue

            score = self._score_record(record, safe_query, safe_tags, safe_file_path)
            if safe_query and score <= 0:
                continue

            matched.append((score, record))

        matched.sort(
            key=lambda item: (
                item[0],
                item[1].priority,
                item[1].updated_at,
            ),
            reverse=True,
        )

        result_records = [record.to_dict() for _, record in matched[:safe_limit]]

        return self._safe_result(
            message="Code memory search completed.",
            data={
                "query": query,
                "count": len(result_records),
                "results": result_records,
            },
            metadata={
                "user_id": user_id_str,
                "workspace_id": workspace_id_str,
                "limit": safe_limit,
                "include_inactive": include_inactive,
            },
        )

    def update_memory(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        memory_id: str,
        updates: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Update a memory record inside a user/workspace scope.
        """
        user_id_str, workspace_id_str = self._normalize_scope(user_id, workspace_id)
        safe_memory_id = str(memory_id or "").strip()

        if not safe_memory_id:
            return self._error_result(
                message="memory_id is required for update.",
                error="missing_memory_id",
            )

        allowed_fields = {
            "memory_type",
            "title",
            "content",
            "tags",
            "file_path",
            "module_name",
            "priority",
            "source",
            "is_active",
            "metadata",
        }

        safe_updates = {
            key: value
            for key, value in (updates or {}).items()
            if key in allowed_fields
        }

        if not safe_updates:
            return self._error_result(
                message="No valid update fields provided.",
                error="empty_updates",
                data={"allowed_fields": sorted(allowed_fields)},
            )

        with self._lock:
            scope_key = self._scope_key(user_id_str, workspace_id_str)
            record = self._records.get(scope_key, {}).get(safe_memory_id)

            if not record:
                return self._error_result(
                    message="Code memory record not found for update.",
                    error="not_found",
                    data={"memory_id": safe_memory_id},
                    metadata={
                        "user_id": user_id_str,
                        "workspace_id": workspace_id_str,
                    },
                )

            if "memory_type" in safe_updates:
                memory_type = str(safe_updates["memory_type"]).strip()
                if memory_type not in ALLOWED_MEMORY_TYPES:
                    return self._error_result(
                        message="Invalid memory_type.",
                        error="invalid_memory_type",
                        data={
                            "memory_type": memory_type,
                            "allowed_memory_types": sorted(ALLOWED_MEMORY_TYPES),
                        },
                    )
                record.memory_type = memory_type

            if "title" in safe_updates:
                title = _normalize_text(safe_updates["title"])
                if not title:
                    return self._error_result(
                        message="title cannot be empty.",
                        error="invalid_title",
                    )
                record.title = title

            if "content" in safe_updates:
                content = _normalize_text(safe_updates["content"])
                if len(content) > MAX_TEXT_LENGTH:
                    return self._error_result(
                        message="content exceeds maximum allowed length.",
                        error="content_too_large",
                    )
                record.content = content

            if "tags" in safe_updates:
                record.tags = _normalize_tags(safe_updates["tags"])

            if "file_path" in safe_updates:
                record.file_path = self._normalize_file_path(safe_updates["file_path"])

            if "module_name" in safe_updates:
                record.module_name = _normalize_text(safe_updates["module_name"]) or DEFAULT_MODULE_NAME

            if "priority" in safe_updates:
                record.priority = self._normalize_priority(safe_updates["priority"])

            if "source" in safe_updates:
                record.source = str(safe_updates["source"] or "code_agent")

            if "is_active" in safe_updates:
                record.is_active = bool(safe_updates["is_active"])

            if "metadata" in safe_updates:
                record.metadata = self._merge_metadata(
                    record.metadata,
                    _coerce_dict(safe_updates["metadata"]),
                )

            record.updated_at = _utc_now_iso()
            record.version += 1

            if self.auto_persist:
                self._persist_scope(user_id_str, workspace_id_str)

        audit_payload = self._log_audit_event(
            action="code_memory_updated",
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            payload={
                "memory_id": safe_memory_id,
                "updated_fields": sorted(safe_updates.keys()),
            },
        )

        verification_payload = self._prepare_verification_payload(
            action="code_memory_updated",
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            data=record.to_dict(),
        )

        return self._safe_result(
            message="Code memory updated successfully.",
            data={
                "memory": record.to_dict(),
                "verification_payload": verification_payload,
                "audit_event": audit_payload,
            },
            metadata={
                "user_id": user_id_str,
                "workspace_id": workspace_id_str,
            },
        )

    def delete_memory(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        memory_id: str,
        hard_delete: bool = False,
    ) -> Dict[str, Any]:
        """
        Delete or deactivate a memory record.

        By default this performs a soft delete by setting is_active=False.
        Hard delete removes the record from storage.
        """
        user_id_str, workspace_id_str = self._normalize_scope(user_id, workspace_id)
        safe_memory_id = str(memory_id or "").strip()

        if not safe_memory_id:
            return self._error_result(
                message="memory_id is required for delete.",
                error="missing_memory_id",
            )

        with self._lock:
            scope_key = self._scope_key(user_id_str, workspace_id_str)
            record = self._records.get(scope_key, {}).get(safe_memory_id)

            if not record:
                return self._error_result(
                    message="Code memory record not found for delete.",
                    error="not_found",
                    data={"memory_id": safe_memory_id},
                    metadata={
                        "user_id": user_id_str,
                        "workspace_id": workspace_id_str,
                    },
                )

            record_snapshot = record.to_dict()

            if hard_delete:
                del self._records[scope_key][safe_memory_id]
                delete_type = "hard_deleted"
            else:
                record.is_active = False
                record.updated_at = _utc_now_iso()
                record.version += 1
                delete_type = "deactivated"

            if self.auto_persist:
                self._persist_scope(user_id_str, workspace_id_str)

        audit_payload = self._log_audit_event(
            action=f"code_memory_{delete_type}",
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            payload={
                "memory_id": safe_memory_id,
                "hard_delete": hard_delete,
            },
        )

        verification_payload = self._prepare_verification_payload(
            action=f"code_memory_{delete_type}",
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            data=record_snapshot,
        )

        return self._safe_result(
            message=f"Code memory {delete_type} successfully.",
            data={
                "memory_id": safe_memory_id,
                "memory": record_snapshot,
                "verification_payload": verification_payload,
                "audit_event": audit_payload,
            },
            metadata={
                "user_id": user_id_str,
                "workspace_id": workspace_id_str,
            },
        )

    def clear_workspace_memory(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        hard_delete: bool = False,
    ) -> Dict[str, Any]:
        """
        Clear all CodeMemory records for a single user/workspace only.
        """
        user_id_str, workspace_id_str = self._normalize_scope(user_id, workspace_id)
        scope_key = self._scope_key(user_id_str, workspace_id_str)

        with self._lock:
            existing_count = len(self._records.get(scope_key, {}))

            if hard_delete:
                self._records[scope_key] = {}
                clear_type = "hard_deleted"
            else:
                for record in self._records.get(scope_key, {}).values():
                    record.is_active = False
                    record.updated_at = _utc_now_iso()
                    record.version += 1
                clear_type = "deactivated"

            if self.auto_persist:
                self._persist_scope(user_id_str, workspace_id_str)

        audit_payload = self._log_audit_event(
            action=f"code_memory_workspace_{clear_type}",
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            payload={
                "count": existing_count,
                "hard_delete": hard_delete,
            },
        )

        return self._safe_result(
            message=f"Workspace CodeMemory records {clear_type} successfully.",
            data={
                "count": existing_count,
                "hard_delete": hard_delete,
                "audit_event": audit_payload,
            },
            metadata={
                "user_id": user_id_str,
                "workspace_id": workspace_id_str,
            },
        )

    # -------------------------------------------------------------------------
    # Context Bundle / Export Methods
    # -------------------------------------------------------------------------

    def get_context_bundle(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        file_path: Optional[str] = None,
        module_name: Optional[str] = None,
        query: str = "",
        limit: int = 25,
    ) -> Dict[str, Any]:
        """
        Build a useful context bundle for Code Agent, Master Agent, or API.

        This method combines:
            - Default global architecture rules.
            - User/workspace-specific project memories.
            - File-specific memories.
            - Prior fixes.
            - Naming conventions.
        """
        user_id_str, workspace_id_str = self._normalize_scope(user_id, workspace_id)
        safe_file_path = self._normalize_file_path(file_path)
        safe_module_name = _normalize_text(module_name or "")
        safe_limit = max(1, min(int(limit or 25), MAX_SEARCH_RESULTS))

        search_result = self.search(
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            query=query,
            file_path=safe_file_path,
            include_inactive=False,
            limit=safe_limit,
        )

        if not search_result["success"]:
            return search_result

        records = search_result["data"]["results"]

        if safe_module_name:
            records = [
                record
                for record in records
                if record.get("module_name") == safe_module_name
                or safe_module_name.lower() in _safe_json_dumps(record).lower()
            ]

        bundle = {
            "system": {
                "name": self.system_name,
                "brand": self.brand_name,
                "module": self.module_name,
                "agent": self.agent_name,
            },
            "scope": {
                "user_id": user_id_str,
                "workspace_id": workspace_id_str,
            },
            "filters": {
                "file_path": safe_file_path,
                "module_name": safe_module_name,
                "query": query,
                "limit": safe_limit,
            },
            "default_architecture_rules": [
                rule.to_dict() for rule in self._default_architecture_rules
            ],
            "memories": records,
            "summary": self._summarize_records(records),
            "verification_payload": self._prepare_verification_payload(
                action="code_memory_context_bundle_prepared",
                user_id=user_id_str,
                workspace_id=workspace_id_str,
                data={
                    "record_count": len(records),
                    "file_path": safe_file_path,
                    "module_name": safe_module_name,
                },
            ),
            "memory_payload": self._prepare_memory_payload(
                user_id=user_id_str,
                workspace_id=workspace_id_str,
                data={
                    "type": "code_context_bundle",
                    "record_count": len(records),
                    "file_path": safe_file_path,
                    "module_name": safe_module_name,
                    "query": query,
                },
            ),
        }

        return self._safe_result(
            message="Code context bundle prepared.",
            data=bundle,
            metadata={
                "user_id": user_id_str,
                "workspace_id": workspace_id_str,
                "record_count": len(records),
            },
        )

    def export_workspace_memory(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        include_inactive: bool = False,
    ) -> Dict[str, Any]:
        """
        Export all memory for a specific user/workspace.
        """
        user_id_str, workspace_id_str = self._normalize_scope(user_id, workspace_id)

        with self._lock:
            records = list(
                self._records.get(
                    self._scope_key(user_id_str, workspace_id_str),
                    {},
                ).values()
            )

        if not include_inactive:
            records = [record for record in records if record.is_active]

        export_data = {
            "system": self.system_name,
            "brand": self.brand_name,
            "agent": self.agent_name,
            "module": self.module_name,
            "exported_at": _utc_now_iso(),
            "user_id": user_id_str,
            "workspace_id": workspace_id_str,
            "include_inactive": include_inactive,
            "count": len(records),
            "records": [record.to_dict() for record in records],
        }

        return self._safe_result(
            message="Workspace CodeMemory exported.",
            data=export_data,
            metadata={
                "user_id": user_id_str,
                "workspace_id": workspace_id_str,
                "count": len(records),
            },
        )

    def get_agent_manifest(self) -> Dict[str, Any]:
        """
        Return registry/loader-compatible manifest for this file.
        """
        return self._safe_result(
            message="CodeMemory manifest prepared.",
            data={
                "agent_name": self.agent_name,
                "agent_type": self.agent_type,
                "module_name": self.module_name,
                "system_name": self.system_name,
                "brand_name": self.brand_name,
                "class_name": self.__class__.__name__,
                "file_path": "agents/code_agent/code_memory.py",
                "capabilities": [
                    "remember_project_rules",
                    "remember_architecture_decisions",
                    "remember_file_roles",
                    "remember_naming_conventions",
                    "remember_prior_fixes",
                    "search_code_memory",
                    "prepare_context_bundle",
                    "export_workspace_memory",
                    "audit_memory_actions",
                    "prepare_verification_payloads",
                    "prepare_memory_agent_payloads",
                ],
                "supported_actions": [
                    "remember",
                    "create",
                    "add",
                    "search",
                    "query",
                    "get",
                    "retrieve",
                    "update",
                    "edit",
                    "delete",
                    "remove",
                    "deactivate",
                    "remember_project_rule",
                    "remember_file_role",
                    "remember_prior_fix",
                    "get_context_bundle",
                    "export_workspace_memory",
                    "clear_workspace_memory",
                    "manifest",
                ],
                "requires_user_id": True,
                "requires_workspace_id": True,
                "security_sensitive_actions": [
                    "delete",
                    "remove",
                    "clear_workspace_memory",
                ],
                "memory_types": sorted(ALLOWED_MEMORY_TYPES),
                "integration_hooks": [
                    "_validate_task_context",
                    "_requires_security_check",
                    "_request_security_approval",
                    "_prepare_verification_payload",
                    "_prepare_memory_payload",
                    "_emit_agent_event",
                    "_log_audit_event",
                    "_safe_result",
                    "_error_result",
                ],
                "safe_to_import_without_dependencies": True,
            },
            metadata={
                "agent": self.agent_name,
                "generated_at": _utc_now_iso(),
            },
        )

    # -------------------------------------------------------------------------
    # Required Compatibility Hooks
    # -------------------------------------------------------------------------

    def _validate_task_context(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate SaaS task context.

        Every user-specific execution must include user_id and workspace_id.
        """
        if not isinstance(task, dict):
            return self._error_result(
                message="Task must be a dictionary.",
                error="invalid_task_type",
            )

        action = str(task.get("action") or "").strip()
        if not action:
            return self._error_result(
                message="Task action is required.",
                error="missing_action",
            )

        if action == "manifest":
            return self._safe_result(
                message="Task context valid for manifest action.",
                data={},
            )

        user_id = str(task.get("user_id") or "").strip()
        workspace_id = str(task.get("workspace_id") or "").strip()

        if not user_id:
            return self._error_result(
                message="user_id is required for CodeMemory task isolation.",
                error="missing_user_id",
            )

        if not workspace_id:
            return self._error_result(
                message="workspace_id is required for CodeMemory task isolation.",
                error="missing_workspace_id",
            )

        return self._safe_result(
            message="Task context valid.",
            data={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "action": action,
            },
        )

    def _requires_security_check(
        self,
        action: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Decide whether an action should go through Security Agent.

        Sensitive examples:
            - Hard delete memory.
            - Clear workspace memory.
            - Store sensitive security/API/database notes.
        """
        if not self.enable_security_checks:
            return False

        safe_action = str(action or "").strip().lower()
        payload = payload or {}
        data = _coerce_dict(payload.get("data"))

        if safe_action in {
            "delete",
            "remove",
            "clear_workspace_memory",
        }:
            return True

        if safe_action in {"remember", "create", "add", "update", "edit"}:
            memory_type = str(data.get("memory_type") or "").strip()
            if memory_type in SENSITIVE_MEMORY_TYPES:
                return True

        if bool(data.get("hard_delete", False)):
            return True

        return False

    def _request_security_approval(
        self,
        action: str,
        payload: Dict[str, Any],
        user_id: str,
        workspace_id: str,
    ) -> Dict[str, Any]:
        """
        Request approval from Security Agent when available.

        Fallback behavior:
            - Allows non-destructive actions.
            - Allows soft delete.
            - Blocks hard delete only if explicitly configured through payload metadata.
        """
        request_payload = {
            "action": action,
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "payload_summary": self._sanitize_for_security(payload),
            "requested_at": _utc_now_iso(),
        }

        agent = self.security_agent
        if agent is None and SecurityAgent is not None:
            try:
                agent = SecurityAgent()
            except Exception:
                agent = None

        if agent is not None:
            for method_name in ("approve_action", "check_permission", "validate_action", "run"):
                method = getattr(agent, method_name, None)
                if not callable(method):
                    continue

                try:
                    if method_name == "run":
                        response = method(
                            {
                                "action": "approve_code_memory_action",
                                "user_id": user_id,
                                "workspace_id": workspace_id,
                                "data": request_payload,
                            }
                        )
                    else:
                        response = method(request_payload)

                    if isinstance(response, dict):
                        if response.get("approved") is True:
                            return {
                                "approved": True,
                                "reason": "approved_by_security_agent",
                                "raw": response,
                            }

                        if response.get("success") is True and response.get("data", {}).get("approved", False):
                            return {
                                "approved": True,
                                "reason": "approved_by_security_agent",
                                "raw": response,
                            }

                        if response.get("approved") is False:
                            return {
                                "approved": False,
                                "reason": response.get("reason") or "security_agent_denied",
                                "raw": response,
                            }

                except Exception as exc:
                    logger.warning("Security Agent approval method failed: %s", exc)

        metadata = _coerce_dict(payload.get("metadata"))
        data = _coerce_dict(payload.get("data"))

        if metadata.get("block_without_security_agent") is True:
            return {
                "approved": False,
                "reason": "security_agent_unavailable_and_block_required",
            }

        if data.get("hard_delete") is True and metadata.get("allow_hard_delete_without_security") is not True:
            return {
                "approved": False,
                "reason": "hard_delete_requires_security_agent_or_explicit_override",
            }

        return {
            "approved": True,
            "reason": "fallback_security_policy_allowed",
        }

    def _prepare_verification_payload(
        self,
        action: str,
        user_id: str,
        workspace_id: str,
        data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent-compatible payload after completed actions.
        """
        payload = {
            "verification_type": "code_memory_action",
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "data_hash": _stable_hash(data),
            "data_preview": self._preview_payload(data),
            "created_at": _utc_now_iso(),
            "checks": [
                "scope_isolation_confirmed",
                "structured_result_confirmed",
                "memory_payload_compatible",
                "audit_event_available",
            ],
        }

        return payload

    def _prepare_memory_payload(
        self,
        user_id: str,
        workspace_id: str,
        data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent-compatible payload.
        """
        return {
            "memory_scope": "workspace",
            "memory_category": "code_agent_context",
            "source_agent": self.agent_name,
            "source_agent_type": self.agent_type,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "content": data,
            "content_hash": _stable_hash(data),
            "created_at": _utc_now_iso(),
            "tags": [
                "code-agent",
                "project-memory",
                "william-jarvis",
                "digital-promotix",
            ],
        }

    def _emit_agent_event(
        self,
        event_type: str,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Emit local event for dashboard/API integration.

        In future this can be connected to Redis, Kafka, database events,
        WebSocket dashboard streams, or the central Agent Event Bus.
        """
        event = {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "payload": payload or {},
            "created_at": _utc_now_iso(),
        }

        if self.enable_events:
            with self._lock:
                self._agent_events.append(event)
                self._agent_events = self._agent_events[-1000:]

        return event

    def _log_audit_event(
        self,
        action: str,
        user_id: str,
        workspace_id: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Log an audit event for dashboard/API/security visibility.
        """
        event = {
            "audit_id": str(uuid.uuid4()),
            "action": action,
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "payload": payload or {},
            "created_at": _utc_now_iso(),
        }

        if self.enable_audit_log:
            with self._lock:
                self._audit_events.append(event)
                self._audit_events = self._audit_events[-2000:]

        return event

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Return standard William/Jarvis success result.
        """
        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": {
                "agent": self.agent_name,
                "agent_type": self.agent_type,
                "timestamp": _utc_now_iso(),
                **(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str,
        error: Any,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Return standard William/Jarvis error result.
        """
        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": str(error) if error is not None else "unknown_error",
            "metadata": {
                "agent": self.agent_name,
                "agent_type": self.agent_type,
                "timestamp": _utc_now_iso(),
                **(metadata or {}),
            },
        }

    # -------------------------------------------------------------------------
    # Internal Helpers
    # -------------------------------------------------------------------------

    def _normalize_scope(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
    ) -> Tuple[str, str]:
        """Normalize and validate user/workspace scope."""
        user_id_str = str(user_id or "").strip()
        workspace_id_str = str(workspace_id or "").strip()

        if not user_id_str:
            raise ValueError("user_id is required.")
        if not workspace_id_str:
            raise ValueError("workspace_id is required.")

        return user_id_str, workspace_id_str

    def _scope_key(self, user_id: str, workspace_id: str) -> str:
        """Create an internal isolated scope key."""
        return f"user:{_slugify(user_id)}::workspace:{_slugify(workspace_id)}"

    def _scope_file_path(self, user_id: str, workspace_id: str) -> Path:
        """Get persistence path for a user/workspace scope."""
        scope_hash = _stable_hash(
            {
                "user_id": user_id,
                "workspace_id": workspace_id,
            }
        )[:24]
        return self.storage_dir / f"{scope_hash}.json"

    def _ensure_storage_dir(self) -> None:
        """Create storage directory if needed."""
        try:
            self.storage_dir.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            logger.warning("Could not create CodeMemory storage directory: %s", exc)

    def _load_all_records(self) -> None:
        """
        Load persisted memory records.

        Files are loaded into in-memory isolated scopes.
        """
        if not self.storage_dir.exists():
            return

        for file_path in self.storage_dir.glob("*.json"):
            try:
                with file_path.open("r", encoding="utf-8") as handle:
                    payload = json.load(handle)

                user_id = str(payload.get("user_id") or "").strip()
                workspace_id = str(payload.get("workspace_id") or "").strip()
                if not user_id or not workspace_id:
                    continue

                scope_key = self._scope_key(user_id, workspace_id)
                self._records.setdefault(scope_key, {})

                for item in payload.get("records", []):
                    record = CodeMemoryRecord.from_dict(item)
                    if record.user_id == user_id and record.workspace_id == workspace_id:
                        self._records[scope_key][record.memory_id] = record

            except Exception as exc:
                logger.warning("Failed to load CodeMemory file %s: %s", file_path, exc)

    def _persist_scope(self, user_id: str, workspace_id: str) -> None:
        """Persist one user/workspace scope safely."""
        self._ensure_storage_dir()

        scope_key = self._scope_key(user_id, workspace_id)
        file_path = self._scope_file_path(user_id, workspace_id)
        temp_path = file_path.with_suffix(".tmp")

        records = [
            record.to_dict()
            for record in self._records.get(scope_key, {}).values()
        ]

        payload = {
            "system": self.system_name,
            "brand": self.brand_name,
            "agent": self.agent_name,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "updated_at": _utc_now_iso(),
            "count": len(records),
            "records": records,
        }

        try:
            with temp_path.open("w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, ensure_ascii=False)

            temp_path.replace(file_path)

        except Exception as exc:
            logger.warning("Failed to persist CodeMemory scope: %s", exc)
            try:
                if temp_path.exists():
                    temp_path.unlink()
            except Exception:
                pass

    def _build_memory_id(self, payload: Dict[str, Any]) -> str:
        """
        Build deterministic memory ID to prevent duplicate project memory spam.
        """
        stable = {
            "user_id": payload.get("user_id"),
            "workspace_id": payload.get("workspace_id"),
            "memory_type": payload.get("memory_type"),
            "title": payload.get("title"),
            "file_path": payload.get("file_path"),
        }
        return f"cmem_{_stable_hash(stable)[:24]}"

    def _validate_memory_input(
        self,
        memory_type: str,
        title: str,
        content: str,
        priority: Any,
    ) -> Dict[str, Any]:
        """Validate memory input."""
        safe_type = str(memory_type or "").strip()

        if safe_type not in ALLOWED_MEMORY_TYPES:
            return self._error_result(
                message="Invalid CodeMemory memory_type.",
                error="invalid_memory_type",
                data={
                    "memory_type": safe_type,
                    "allowed_memory_types": sorted(ALLOWED_MEMORY_TYPES),
                },
            )

        if not _normalize_text(title):
            return self._error_result(
                message="Memory title is required.",
                error="missing_title",
            )

        safe_content = _normalize_text(content)
        if not safe_content:
            return self._error_result(
                message="Memory content is required.",
                error="missing_content",
            )

        if len(safe_content) > MAX_TEXT_LENGTH:
            return self._error_result(
                message="Memory content exceeds maximum length.",
                error="content_too_large",
                data={
                    "max_length": MAX_TEXT_LENGTH,
                    "actual_length": len(safe_content),
                },
            )

        try:
            self._normalize_priority(priority)
        except Exception:
            return self._error_result(
                message="Priority must be an integer between 1 and 10.",
                error="invalid_priority",
            )

        return self._safe_result(
            message="Memory input valid.",
            data={},
        )

    def _normalize_priority(self, priority: Any) -> int:
        """Normalize priority into 1-10 scale."""
        value = int(priority)
        return max(1, min(value, 10))

    def _normalize_file_path(self, file_path: Optional[Any]) -> Optional[str]:
        """
        Normalize file path without requiring file existence.

        This prevents path execution or file reads. It only stores the path string.
        """
        if file_path is None:
            return None

        text = str(file_path).strip().replace("\\", "/")
        text = re.sub(r"/+", "/", text)

        if not text:
            return None

        parts = []
        for part in text.split("/"):
            if part in {"", "."}:
                continue
            if part == "..":
                continue
            parts.append(part)

        return "/".join(parts)

    def _merge_metadata(
        self,
        existing: Optional[Dict[str, Any]],
        incoming: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Merge metadata safely."""
        merged = _safe_deepcopy(existing or {})
        for key, value in (incoming or {}).items():
            if isinstance(key, str):
                merged[key] = value
        return merged

    def _score_record(
        self,
        record: CodeMemoryRecord,
        query: str,
        tags: set,
        file_path: Optional[str],
    ) -> int:
        """
        Score search relevance.
        """
        score = int(record.priority)

        if tags:
            score += len(tags.intersection(set(record.tags or []))) * 5

        if file_path and record.file_path == file_path:
            score += 20

        if not query:
            return score

        haystack = " ".join(
            [
                record.title,
                record.content,
                record.memory_type,
                record.module_name,
                record.file_path or "",
                " ".join(record.tags or []),
                _safe_json_dumps(record.metadata),
            ]
        ).lower()

        query_terms = [term for term in re.split(r"\s+", query.lower()) if term]

        for term in query_terms:
            if term in haystack:
                score += 10
            if term in record.title.lower():
                score += 15
            if record.file_path and term in record.file_path.lower():
                score += 12
            if term in record.memory_type.lower():
                score += 8

        if query.lower() in haystack:
            score += 25

        return score

    def _summarize_records(self, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Summarize retrieved records for dashboard/API/Master Agent."""
        by_type: Dict[str, int] = {}
        by_file: Dict[str, int] = {}
        high_priority: List[Dict[str, Any]] = []

        for record in records:
            memory_type = str(record.get("memory_type") or "unknown")
            by_type[memory_type] = by_type.get(memory_type, 0) + 1

            file_path = record.get("file_path")
            if file_path:
                by_file[file_path] = by_file.get(file_path, 0) + 1

            if int(record.get("priority") or 0) >= 8:
                high_priority.append(
                    {
                        "memory_id": record.get("memory_id"),
                        "title": record.get("title"),
                        "memory_type": memory_type,
                        "priority": record.get("priority"),
                        "file_path": file_path,
                    }
                )

        return {
            "total_records": len(records),
            "by_type": by_type,
            "by_file": by_file,
            "high_priority": high_priority[:10],
        }

    def _preview_payload(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Return safe small preview of payload."""
        preview = _safe_deepcopy(data)

        if isinstance(preview, dict):
            for key in list(preview.keys()):
                value = preview[key]
                if isinstance(value, str) and len(value) > 500:
                    preview[key] = value[:500] + "...[truncated]"
                elif isinstance(value, (dict, list)):
                    text = _safe_json_dumps(value)
                    if len(text) > 800:
                        preview[key] = text[:800] + "...[truncated]"

        return preview

    def _sanitize_for_security(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Remove overly large or sensitive-looking values before sending to Security Agent.
        """
        cloned = self._preview_payload(payload)
        secret_keys = {
            "secret",
            "token",
            "password",
            "api_key",
            "private_key",
            "access_key",
            "refresh_token",
        }

        def scrub(value: Any) -> Any:
            if isinstance(value, dict):
                cleaned = {}
                for key, item in value.items():
                    key_str = str(key).lower()
                    if any(secret in key_str for secret in secret_keys):
                        cleaned[key] = "[REDACTED]"
                    else:
                        cleaned[key] = scrub(item)
                return cleaned
            if isinstance(value, list):
                return [scrub(item) for item in value[:50]]
            return value

        return scrub(cloned)

    def _build_default_architecture_rules(self) -> List[CodeArchitectureRule]:
        """
        Default William/Jarvis architecture rules used by CodeMemory.
        """
        return [
            CodeArchitectureRule(
                rule_id="safety_first",
                title="Safety and permission rules come first.",
                description=(
                    "Sensitive actions must go through Security Agent hooks before execution."
                ),
                priority=10,
                applies_to=["all_agents", "code_agent", "master_agent"],
                conflict_order=1,
            ),
            CodeArchitectureRule(
                rule_id="saas_isolation_second",
                title="SaaS user/workspace isolation comes second.",
                description=(
                    "Never mix memory, files, logs, tasks, analytics, or audit data "
                    "between users or workspaces."
                ),
                priority=10,
                applies_to=["memory", "files", "logs", "tasks", "analytics", "audit"],
                conflict_order=2,
            ),
            CodeArchitectureRule(
                rule_id="base_agent_compatibility_third",
                title="BaseAgent compatibility comes third.",
                description=(
                    "Agent/helper files should remain compatible with BaseAgent patterns, "
                    "including run/task handling where relevant."
                ),
                priority=9,
                applies_to=["agents", "registry", "loader"],
                conflict_order=3,
            ),
            CodeArchitectureRule(
                rule_id="master_registry_compatibility_fourth",
                title="MasterAgent and Registry compatibility comes fourth.",
                description=(
                    "Agent files should expose clear manifest/action capabilities for routing, "
                    "registry loading, and future plugin-style agents."
                ),
                priority=9,
                applies_to=["master_agent", "agent_registry", "agent_router"],
                conflict_order=4,
            ),
            CodeArchitectureRule(
                rule_id="structured_results",
                title="Every result must be structured.",
                description=(
                    "Return dictionaries with success, message, data, error, and metadata."
                ),
                priority=10,
                applies_to=["all_public_methods", "api", "dashboard"],
                conflict_order=5,
            ),
            CodeArchitectureRule(
                rule_id="verification_payload",
                title="Completed actions prepare Verification Agent payloads.",
                description=(
                    "Completed useful actions should expose verification payload data "
                    "for the Verification Agent."
                ),
                priority=8,
                applies_to=["completed_actions", "verification_agent"],
                conflict_order=6,
            ),
            CodeArchitectureRule(
                rule_id="memory_payload",
                title="Useful context should be Memory Agent compatible.",
                description=(
                    "Important context should be prepared in a Memory Agent-compatible payload."
                ),
                priority=8,
                applies_to=["memory_agent", "code_agent", "master_agent"],
                conflict_order=7,
            ),
        ]

    # -------------------------------------------------------------------------
    # Diagnostics / Dashboard Helpers
    # -------------------------------------------------------------------------

    def get_audit_events(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """
        Return local audit events, optionally filtered by scope.
        """
        safe_limit = max(1, min(int(limit or 100), 500))
        user_filter = str(user_id).strip() if user_id is not None else None
        workspace_filter = str(workspace_id).strip() if workspace_id is not None else None

        with self._lock:
            events = list(self._audit_events)

        if user_filter:
            events = [event for event in events if str(event.get("user_id")) == user_filter]

        if workspace_filter:
            events = [
                event
                for event in events
                if str(event.get("workspace_id")) == workspace_filter
            ]

        events = events[-safe_limit:]

        return self._safe_result(
            message="Audit events retrieved.",
            data={
                "count": len(events),
                "events": events,
            },
            metadata={
                "user_id": user_filter,
                "workspace_id": workspace_filter,
            },
        )

    def get_agent_events(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """
        Return local agent events, optionally filtered by scope.
        """
        safe_limit = max(1, min(int(limit or 100), 500))
        user_filter = str(user_id).strip() if user_id is not None else None
        workspace_filter = str(workspace_id).strip() if workspace_id is not None else None

        with self._lock:
            events = list(self._agent_events)

        if user_filter:
            events = [event for event in events if str(event.get("user_id")) == user_filter]

        if workspace_filter:
            events = [
                event
                for event in events
                if str(event.get("workspace_id")) == workspace_filter
            ]

        events = events[-safe_limit:]

        return self._safe_result(
            message="Agent events retrieved.",
            data={
                "count": len(events),
                "events": events,
            },
            metadata={
                "user_id": user_filter,
                "workspace_id": workspace_filter,
            },
        )

    def health_check(self) -> Dict[str, Any]:
        """
        Basic health check for API/dashboard.
        """
        with self._lock:
            scope_count = len(self._records)
            record_count = sum(len(scope_records) for scope_records in self._records.values())

        return self._safe_result(
            message="CodeMemory health check passed.",
            data={
                "agent_name": self.agent_name,
                "agent_type": self.agent_type,
                "storage_dir": str(self.storage_dir),
                "auto_persist": self.auto_persist,
                "enable_security_checks": self.enable_security_checks,
                "scope_count": scope_count,
                "record_count": record_count,
                "audit_event_count": len(self._audit_events),
                "agent_event_count": len(self._agent_events),
                "memory_types": sorted(ALLOWED_MEMORY_TYPES),
            },
        )


# =============================================================================
# Optional Factory
# =============================================================================

def create_code_memory(
    storage_dir: Optional[Union[str, Path]] = None,
    **kwargs: Any,
) -> CodeMemory:
    """
    Factory helper for Agent Loader / Registry.

    Example:
        code_memory = create_code_memory()
    """
    return CodeMemory(storage_dir=storage_dir, **kwargs)


# =============================================================================
# Minimal Manual Test
# =============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    memory = CodeMemory(
        storage_dir=".william/dev_code_memory",
        auto_persist=False,
        enable_security_checks=False,
    )

    create_result = memory.remember_project_rule(
        user_id="demo_user",
        workspace_id="demo_workspace",
        title="Always isolate workspace data",
        description="Never mix memory, files, logs, tasks, analytics, or audit data between users/workspaces.",
        priority=10,
        applies_to=["saas", "memory", "audit"],
    )

    print(json.dumps(create_result, indent=2, ensure_ascii=False))

    search_result = memory.search(
        user_id="demo_user",
        workspace_id="demo_workspace",
        query="isolate workspace",
    )

    print(json.dumps(search_result, indent=2, ensure_ascii=False))

    bundle_result = memory.get_context_bundle(
        user_id="demo_user",
        workspace_id="demo_workspace",
        query="workspace",
    )

    print(json.dumps(bundle_result, indent=2, ensure_ascii=False))