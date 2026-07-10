"""
agents/memory_agent/team_memory.py

Purpose:
    Shared workspace memory with role-based access for the William / Jarvis
    Multi-Agent AI SaaS System by Digital Promotix.

This module provides the TeamMemory class, responsible for storing and managing
workspace-level shared memory that can be accessed by team members according to
role, permission, visibility, and SaaS isolation rules.

Architecture Connections:
    - Master Agent:
        Can route memory-related team/workspace tasks to this class.
    - Memory Agent:
        Uses this helper to manage shared workspace memory.
    - Security Agent:
        Sensitive memory operations can request approval before execution.
    - Verification Agent:
        Every completed operation prepares a verification payload.
    - Dashboard/API:
        Structured result format is ready for FastAPI/dashboard integration.
    - Agent Registry / Loader / Router:
        Import-safe, BaseAgent-compatible, and exposes clear public methods.

Design Priorities:
    1. Safety and permission rules
    2. SaaS user/workspace isolation
    3. BaseAgent compatibility
    4. MasterAgent / Registry compatibility
    5. Team memory functionality
    6. Future extensibility
"""

from __future__ import annotations

import copy
import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union


logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps the file import-safe even if the real William/Jarvis BaseAgent
        has not been created yet.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)

        async def run(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent does not implement run().",
                "data": None,
                "error": "BASE_AGENT_NOT_AVAILABLE",
                "metadata": {},
            }


class TeamMemoryError(Exception):
    """Base exception for TeamMemory."""


class TeamMemoryPermissionError(TeamMemoryError):
    """Raised when a user is not allowed to perform a memory operation."""


class TeamMemoryValidationError(TeamMemoryError):
    """Raised when task context or payload validation fails."""


class TeamMemoryVisibility(str, Enum):
    """
    Visibility levels for shared team memory.

    PRIVATE:
        Only creator and explicitly allowed users can access.
    TEAM:
        Workspace members with valid role access can access.
    ROLE:
        Users with allowed roles can access.
    WORKSPACE:
        Broader workspace memory available to normal workspace members.
    ADMIN:
        Only owners/admins and explicitly allowed users can access.
    """

    PRIVATE = "private"
    TEAM = "team"
    ROLE = "role"
    WORKSPACE = "workspace"
    ADMIN = "admin"


class TeamMemoryAction(str, Enum):
    """Supported actions against shared team memory."""

    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    SEARCH = "search"
    LIST = "list"
    SHARE = "share"
    UNSHARE = "unshare"
    ARCHIVE = "archive"
    RESTORE = "restore"
    EXPORT = "export"


class TeamRole(str, Enum):
    """Default William/Jarvis workspace roles."""

    OWNER = "owner"
    ADMIN = "admin"
    MANAGER = "manager"
    MEMBER = "member"
    VIEWER = "viewer"
    CLIENT = "client"
    AGENT = "agent"
    GUEST = "guest"


DEFAULT_ROLE_PERMISSIONS: Dict[str, Set[str]] = {
    TeamRole.OWNER.value: {
        TeamMemoryAction.CREATE.value,
        TeamMemoryAction.READ.value,
        TeamMemoryAction.UPDATE.value,
        TeamMemoryAction.DELETE.value,
        TeamMemoryAction.SEARCH.value,
        TeamMemoryAction.LIST.value,
        TeamMemoryAction.SHARE.value,
        TeamMemoryAction.UNSHARE.value,
        TeamMemoryAction.ARCHIVE.value,
        TeamMemoryAction.RESTORE.value,
        TeamMemoryAction.EXPORT.value,
    },
    TeamRole.ADMIN.value: {
        TeamMemoryAction.CREATE.value,
        TeamMemoryAction.READ.value,
        TeamMemoryAction.UPDATE.value,
        TeamMemoryAction.DELETE.value,
        TeamMemoryAction.SEARCH.value,
        TeamMemoryAction.LIST.value,
        TeamMemoryAction.SHARE.value,
        TeamMemoryAction.UNSHARE.value,
        TeamMemoryAction.ARCHIVE.value,
        TeamMemoryAction.RESTORE.value,
        TeamMemoryAction.EXPORT.value,
    },
    TeamRole.MANAGER.value: {
        TeamMemoryAction.CREATE.value,
        TeamMemoryAction.READ.value,
        TeamMemoryAction.UPDATE.value,
        TeamMemoryAction.SEARCH.value,
        TeamMemoryAction.LIST.value,
        TeamMemoryAction.SHARE.value,
        TeamMemoryAction.ARCHIVE.value,
        TeamMemoryAction.RESTORE.value,
        TeamMemoryAction.EXPORT.value,
    },
    TeamRole.MEMBER.value: {
        TeamMemoryAction.CREATE.value,
        TeamMemoryAction.READ.value,
        TeamMemoryAction.UPDATE.value,
        TeamMemoryAction.SEARCH.value,
        TeamMemoryAction.LIST.value,
    },
    TeamRole.VIEWER.value: {
        TeamMemoryAction.READ.value,
        TeamMemoryAction.SEARCH.value,
        TeamMemoryAction.LIST.value,
    },
    TeamRole.CLIENT.value: {
        TeamMemoryAction.READ.value,
        TeamMemoryAction.SEARCH.value,
        TeamMemoryAction.LIST.value,
    },
    TeamRole.AGENT.value: {
        TeamMemoryAction.CREATE.value,
        TeamMemoryAction.READ.value,
        TeamMemoryAction.SEARCH.value,
        TeamMemoryAction.LIST.value,
    },
    TeamRole.GUEST.value: {
        TeamMemoryAction.READ.value,
    },
}


SENSITIVE_TAGS: Set[str] = {
    "secret",
    "credential",
    "credentials",
    "password",
    "token",
    "api_key",
    "private_key",
    "payment",
    "billing",
    "financial",
    "legal",
    "security",
    "personal_data",
    "pii",
    "confidential",
    "client_sensitive",
}


DANGEROUS_CONTENT_MARKERS: Tuple[str, ...] = (
    "-----BEGIN PRIVATE KEY-----",
    "aws_secret_access_key",
    "stripe_live",
    "sk_live_",
    "password=",
    "authorization: bearer",
)


def _utc_now_iso() -> str:
    """Return current UTC datetime in ISO format."""
    return datetime.now(timezone.utc).isoformat()


def _safe_uuid(prefix: str = "tm") -> str:
    """Generate a safe unique id."""
    return f"{prefix}_{uuid.uuid4().hex}"


def _normalize_string(value: Any, default: str = "") -> str:
    """Convert any input to a clean string."""
    if value is None:
        return default
    return str(value).strip()


def _normalize_list(value: Any) -> List[str]:
    """Normalize input into a list of clean strings."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, Iterable):
        result: List[str] = []
        for item in value:
            text = _normalize_string(item)
            if text:
                result.append(text)
        return result
    return []


def _json_safe(value: Any) -> Any:
    """Return a JSON-serializable version of a value."""
    try:
        json.dumps(value)
        return value
    except Exception:
        if isinstance(value, dict):
            return {str(k): _json_safe(v) for k, v in value.items()}
        if isinstance(value, (list, tuple, set)):
            return [_json_safe(v) for v in value]
        return str(value)


@dataclass
class TeamMemoryRecord:
    """
    Data structure for one shared team memory record.

    Every record is isolated by workspace_id. user_id is the actor/creator id.
    """

    memory_id: str
    workspace_id: str
    created_by: str
    title: str
    content: str
    visibility: str = TeamMemoryVisibility.TEAM.value
    allowed_roles: List[str] = field(default_factory=list)
    allowed_user_ids: List[str] = field(default_factory=list)
    denied_user_ids: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    category: str = "team"
    priority: int = 3
    source: str = "manual"
    project_id: Optional[str] = None
    client_id: Optional[str] = None
    agent_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    archived: bool = False
    version: int = 1
    created_at: str = field(default_factory=_utc_now_iso)
    updated_at: str = field(default_factory=_utc_now_iso)
    updated_by: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert record to dict."""
        return asdict(self)


class InMemoryTeamMemoryStore:
    """
    Safe default in-memory storage adapter.

    This adapter is designed for tests, local development, and import safety.
    Production can inject a database-backed adapter with the same methods:
        - create(record)
        - get(memory_id)
        - update(memory_id, updates)
        - delete(memory_id)
        - list_by_workspace(workspace_id)
    """

    def __init__(self) -> None:
        self._records: Dict[str, Dict[str, Any]] = {}

    def create(self, record: Dict[str, Any]) -> Dict[str, Any]:
        memory_id = record["memory_id"]
        self._records[memory_id] = copy.deepcopy(record)
        return copy.deepcopy(self._records[memory_id])

    def get(self, memory_id: str) -> Optional[Dict[str, Any]]:
        record = self._records.get(memory_id)
        return copy.deepcopy(record) if record else None

    def update(self, memory_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if memory_id not in self._records:
            return None
        self._records[memory_id].update(copy.deepcopy(updates))
        return copy.deepcopy(self._records[memory_id])

    def delete(self, memory_id: str) -> bool:
        if memory_id not in self._records:
            return False
        del self._records[memory_id]
        return True

    def list_by_workspace(self, workspace_id: str) -> List[Dict[str, Any]]:
        return [
            copy.deepcopy(record)
            for record in self._records.values()
            if record.get("workspace_id") == workspace_id
        ]


class TeamMemory(BaseAgent):
    """
    Shared workspace memory manager with role-based access.

    Public Methods:
        - create_memory()
        - get_memory()
        - update_memory()
        - delete_memory()
        - archive_memory()
        - restore_memory()
        - list_memories()
        - search_memories()
        - share_memory()
        - unshare_memory()
        - export_workspace_memory()
        - run()

    Result Shape:
        {
            "success": bool,
            "message": str,
            "data": Any,
            "error": Optional[str],
            "metadata": dict
        }
    """

    agent_name = "TeamMemory"
    agent_type = "memory_agent_helper"
    file_path = "agents/memory_agent/team_memory.py"

    def __init__(
        self,
        storage: Optional[Any] = None,
        security_client: Optional[Any] = None,
        verification_client: Optional[Any] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], None]] = None,
        event_emitter: Optional[Callable[[Dict[str, Any]], None]] = None,
        role_permissions: Optional[Dict[str, Union[Set[str], Sequence[str]]]] = None,
        strict_security: bool = False,
        max_content_length: int = 100_000,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, agent_name=self.agent_name, **kwargs)

        self.storage = storage or InMemoryTeamMemoryStore()
        self.security_client = security_client
        self.verification_client = verification_client
        self.audit_logger = audit_logger
        self.event_emitter = event_emitter
        self.strict_security = strict_security
        self.max_content_length = max_content_length

        permissions = role_permissions or DEFAULT_ROLE_PERMISSIONS
        self.role_permissions: Dict[str, Set[str]] = {
            str(role): set(actions)
            for role, actions in permissions.items()
        }

    # -------------------------------------------------------------------------
    # Compatibility Hooks
    # -------------------------------------------------------------------------

    def _safe_result(
        self,
        message: str,
        data: Any = None,
        metadata: Optional[Dict[str, Any]] = None,
        success: bool = True,
    ) -> Dict[str, Any]:
        """Return a safe structured success result."""
        return {
            "success": success,
            "message": message,
            "data": _json_safe(data),
            "error": None,
            "metadata": _json_safe(metadata or {}),
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Union[str, Exception]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        data: Any = None,
    ) -> Dict[str, Any]:
        """Return a safe structured error result."""
        error_text = str(error) if error else message
        return {
            "success": False,
            "message": message,
            "data": _json_safe(data),
            "error": error_text,
            "metadata": _json_safe(metadata or {}),
        }

    def _validate_task_context(
        self,
        user_id: str,
        workspace_id: str,
        role: Optional[str] = None,
        action: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Validate SaaS execution context.

        user_id and workspace_id are mandatory where user-specific execution
        is involved. This prevents cross-user and cross-workspace memory leaks.
        """
        clean_user_id = _normalize_string(user_id)
        clean_workspace_id = _normalize_string(workspace_id)
        clean_role = _normalize_string(role, TeamRole.MEMBER.value).lower()
        clean_action = _normalize_string(action).lower()

        if not clean_user_id:
            raise TeamMemoryValidationError("user_id is required.")
        if not clean_workspace_id:
            raise TeamMemoryValidationError("workspace_id is required.")
        if clean_role not in self.role_permissions:
            clean_role = TeamRole.MEMBER.value

        return {
            "user_id": clean_user_id,
            "workspace_id": clean_workspace_id,
            "role": clean_role,
            "action": clean_action,
            "validated_at": _utc_now_iso(),
        }

    def _requires_security_check(
        self,
        action: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Determine whether an operation should go through Security Agent.

        Sensitive operations:
            - delete, export, share to explicit users, admin memory
            - sensitive tags
            - dangerous content markers
        """
        payload = payload or {}
        action = _normalize_string(action).lower()

        if action in {
            TeamMemoryAction.DELETE.value,
            TeamMemoryAction.EXPORT.value,
            TeamMemoryAction.SHARE.value,
            TeamMemoryAction.UNSHARE.value,
        }:
            return True

        visibility = _normalize_string(payload.get("visibility")).lower()
        if visibility == TeamMemoryVisibility.ADMIN.value:
            return True

        tags = {tag.lower() for tag in _normalize_list(payload.get("tags"))}
        if tags.intersection(SENSITIVE_TAGS):
            return True

        content = _normalize_string(payload.get("content")).lower()
        if any(marker.lower() in content for marker in DANGEROUS_CONTENT_MARKERS):
            return True

        return False

    def _request_security_approval(
        self,
        action: str,
        context: Dict[str, Any],
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request approval from Security Agent when available.

        Safe fallback:
            - If strict_security=False and no security client exists, allow with
              metadata note.
            - If strict_security=True and no security client exists, deny.
        """
        payload = payload or {}
        approval_request = {
            "request_id": _safe_uuid("sec_req"),
            "agent": self.agent_name,
            "action": action,
            "context": _json_safe(context),
            "payload_summary": self._redact_sensitive_payload(payload),
            "created_at": _utc_now_iso(),
        }

        if self.security_client is None:
            if self.strict_security:
                return {
                    "approved": False,
                    "reason": "Security client unavailable and strict_security=True.",
                    "request": approval_request,
                }
            return {
                "approved": True,
                "reason": "Security client unavailable; allowed by safe fallback.",
                "request": approval_request,
                "fallback": True,
            }

        try:
            if hasattr(self.security_client, "approve"):
                response = self.security_client.approve(approval_request)
            elif hasattr(self.security_client, "request_approval"):
                response = self.security_client.request_approval(approval_request)
            else:
                response = {
                    "approved": not self.strict_security,
                    "reason": "Security client has no approval method.",
                }

            if isinstance(response, dict):
                return {
                    "approved": bool(response.get("approved", False)),
                    "reason": response.get("reason", "Security decision returned."),
                    "request": approval_request,
                    "response": _json_safe(response),
                }

            return {
                "approved": bool(response),
                "reason": "Security client returned boolean-like approval.",
                "request": approval_request,
            }
        except Exception as exc:
            logger.exception("Security approval failed.")
            return {
                "approved": False if self.strict_security else True,
                "reason": f"Security approval error: {exc}",
                "request": approval_request,
                "fallback": not self.strict_security,
            }

    def _prepare_verification_payload(
        self,
        action: str,
        context: Dict[str, Any],
        result_data: Any = None,
        success: bool = True,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload after completed operations.
        """
        return {
            "verification_id": _safe_uuid("verify"),
            "agent": self.agent_name,
            "action": action,
            "success": success,
            "context": _json_safe(context),
            "result_data": _json_safe(result_data),
            "created_at": _utc_now_iso(),
        }

    def _prepare_memory_payload(
        self,
        record: Dict[str, Any],
        action: str,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent-compatible payload.

        This allows the parent Memory Agent, recall engine, embeddings, or
        future knowledge graph file to consume the shared memory record.
        """
        return {
            "memory_payload_id": _safe_uuid("memory_payload"),
            "source_agent": self.agent_name,
            "action": action,
            "memory_type": "team_memory",
            "workspace_id": record.get("workspace_id"),
            "user_id": record.get("created_by"),
            "memory_id": record.get("memory_id"),
            "title": record.get("title"),
            "content": record.get("content"),
            "tags": record.get("tags", []),
            "category": record.get("category", "team"),
            "visibility": record.get("visibility", TeamMemoryVisibility.TEAM.value),
            "project_id": record.get("project_id"),
            "client_id": record.get("client_id"),
            "agent_id": record.get("agent_id"),
            "metadata": record.get("metadata", {}),
            "created_at": record.get("created_at"),
            "updated_at": record.get("updated_at"),
        }

    def _emit_agent_event(
        self,
        event_type: str,
        context: Dict[str, Any],
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Emit event for dashboard, analytics, registry, task history, or logs.
        """
        event = {
            "event_id": _safe_uuid("event"),
            "agent": self.agent_name,
            "event_type": event_type,
            "context": _json_safe(context),
            "payload": _json_safe(payload or {}),
            "created_at": _utc_now_iso(),
        }

        if self.event_emitter:
            try:
                self.event_emitter(event)
                return
            except Exception:
                logger.exception("TeamMemory event emitter failed.")

        logger.info("TeamMemory event: %s", json.dumps(event, default=str))

    def _log_audit_event(
        self,
        action: str,
        context: Dict[str, Any],
        target_id: Optional[str] = None,
        success: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log audit event for compliance, dashboard history, and workspace safety.
        """
        audit_event = {
            "audit_id": _safe_uuid("audit"),
            "agent": self.agent_name,
            "action": action,
            "target_id": target_id,
            "success": success,
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "role": context.get("role"),
            "metadata": _json_safe(metadata or {}),
            "created_at": _utc_now_iso(),
        }

        if self.audit_logger:
            try:
                self.audit_logger(audit_event)
                return
            except Exception:
                logger.exception("TeamMemory audit logger failed.")

        logger.info("TeamMemory audit: %s", json.dumps(audit_event, default=str))

    # -------------------------------------------------------------------------
    # Permission / Access Control
    # -------------------------------------------------------------------------

    def _role_can(self, role: str, action: str) -> bool:
        """Check if role has permission for action."""
        role = _normalize_string(role, TeamRole.MEMBER.value).lower()
        action = _normalize_string(action).lower()
        return action in self.role_permissions.get(role, set())

    def _assert_action_allowed(self, context: Dict[str, Any], action: str) -> None:
        """Raise if user's role cannot perform action."""
        role = context.get("role", TeamRole.MEMBER.value)
        if not self._role_can(role, action):
            raise TeamMemoryPermissionError(
                f"Role '{role}' is not allowed to perform action '{action}'."
            )

    def _can_access_record(
        self,
        record: Dict[str, Any],
        context: Dict[str, Any],
        action: str = TeamMemoryAction.READ.value,
    ) -> bool:
        """
        Check full SaaS isolation and record-level access.

        This method ensures:
            - workspace_id must match
            - denied users are blocked
            - owner/admin can access
            - creator can access
            - explicit allowed users can access
            - visibility and allowed_roles are respected
        """
        if not record:
            return False

        workspace_id = context.get("workspace_id")
        user_id = context.get("user_id")
        role = context.get("role", TeamRole.MEMBER.value)

        if record.get("workspace_id") != workspace_id:
            return False

        if user_id in set(record.get("denied_user_ids", [])):
            return False

        if not self._role_can(role, action):
            return False

        if role in {TeamRole.OWNER.value, TeamRole.ADMIN.value}:
            return True

        if record.get("created_by") == user_id:
            return True

        if user_id in set(record.get("allowed_user_ids", [])):
            return True

        visibility = record.get("visibility", TeamMemoryVisibility.TEAM.value)
        allowed_roles = set(record.get("allowed_roles", []))

        if visibility == TeamMemoryVisibility.PRIVATE.value:
            return False

        if visibility == TeamMemoryVisibility.ADMIN.value:
            return role in {TeamRole.OWNER.value, TeamRole.ADMIN.value}

        if visibility == TeamMemoryVisibility.ROLE.value:
            return role in allowed_roles

        if visibility in {
            TeamMemoryVisibility.TEAM.value,
            TeamMemoryVisibility.WORKSPACE.value,
        }:
            if allowed_roles:
                return role in allowed_roles
            return role not in {TeamRole.GUEST.value}

        return False

    def _redact_sensitive_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Redact risky values before passing payload into audit/security logs."""
        redacted = copy.deepcopy(payload)
        sensitive_keys = {
            "password",
            "token",
            "api_key",
            "secret",
            "private_key",
            "credential",
            "credentials",
            "authorization",
        }

        def redact(obj: Any) -> Any:
            if isinstance(obj, dict):
                safe: Dict[str, Any] = {}
                for key, value in obj.items():
                    if str(key).lower() in sensitive_keys:
                        safe[key] = "***REDACTED***"
                    else:
                        safe[key] = redact(value)
                return safe
            if isinstance(obj, list):
                return [redact(item) for item in obj]
            if isinstance(obj, str):
                lowered = obj.lower()
                if any(marker.lower() in lowered for marker in DANGEROUS_CONTENT_MARKERS):
                    return "***REDACTED_CONTENT***"
            return obj

        return _json_safe(redact(redacted))

    def _sanitize_record_for_response(
        self,
        record: Dict[str, Any],
        include_content: bool = True,
    ) -> Dict[str, Any]:
        """Return safe record response."""
        safe = copy.deepcopy(record)
        safe["metadata"] = _json_safe(safe.get("metadata", {}))
        if not include_content:
            safe.pop("content", None)
            safe["content_preview"] = _normalize_string(record.get("content"))[:300]
        return safe

    def _validate_memory_payload(
        self,
        title: str,
        content: str,
        visibility: str,
        priority: int,
    ) -> Tuple[str, str, str, int]:
        """Validate and normalize memory payload."""
        clean_title = _normalize_string(title)
        clean_content = _normalize_string(content)
        clean_visibility = _normalize_string(visibility, TeamMemoryVisibility.TEAM.value).lower()

        if not clean_title:
            raise TeamMemoryValidationError("title is required.")
        if not clean_content:
            raise TeamMemoryValidationError("content is required.")
        if len(clean_content) > self.max_content_length:
            raise TeamMemoryValidationError(
                f"content exceeds max length of {self.max_content_length} characters."
            )
        if clean_visibility not in {item.value for item in TeamMemoryVisibility}:
            clean_visibility = TeamMemoryVisibility.TEAM.value

        try:
            clean_priority = int(priority)
        except Exception:
            clean_priority = 3

        clean_priority = max(1, min(5, clean_priority))
        return clean_title, clean_content, clean_visibility, clean_priority

    # -------------------------------------------------------------------------
    # Public Methods
    # -------------------------------------------------------------------------

    def create_memory(
        self,
        user_id: str,
        workspace_id: str,
        title: str,
        content: str,
        role: str = TeamRole.MEMBER.value,
        visibility: str = TeamMemoryVisibility.TEAM.value,
        allowed_roles: Optional[Sequence[str]] = None,
        allowed_user_ids: Optional[Sequence[str]] = None,
        denied_user_ids: Optional[Sequence[str]] = None,
        tags: Optional[Sequence[str]] = None,
        category: str = "team",
        priority: int = 3,
        source: str = "manual",
        project_id: Optional[str] = None,
        client_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create a shared workspace memory record."""
        action = TeamMemoryAction.CREATE.value

        try:
            context = self._validate_task_context(user_id, workspace_id, role, action)
            self._assert_action_allowed(context, action)

            clean_title, clean_content, clean_visibility, clean_priority = self._validate_memory_payload(
                title=title,
                content=content,
                visibility=visibility,
                priority=priority,
            )

            payload = {
                "title": clean_title,
                "content": clean_content,
                "visibility": clean_visibility,
                "allowed_roles": _normalize_list(allowed_roles),
                "allowed_user_ids": _normalize_list(allowed_user_ids),
                "denied_user_ids": _normalize_list(denied_user_ids),
                "tags": _normalize_list(tags),
                "category": _normalize_string(category, "team"),
                "priority": clean_priority,
                "metadata": metadata or {},
            }

            if self._requires_security_check(action, payload):
                approval = self._request_security_approval(action, context, payload)
                if not approval.get("approved"):
                    self._log_audit_event(action, context, success=False, metadata=approval)
                    return self._error_result(
                        "Security approval denied for creating team memory.",
                        error=approval.get("reason", "SECURITY_DENIED"),
                        metadata={"security": approval},
                    )

            record = TeamMemoryRecord(
                memory_id=_safe_uuid("team_mem"),
                workspace_id=context["workspace_id"],
                created_by=context["user_id"],
                title=clean_title,
                content=clean_content,
                visibility=clean_visibility,
                allowed_roles=_normalize_list(allowed_roles),
                allowed_user_ids=_normalize_list(allowed_user_ids),
                denied_user_ids=_normalize_list(denied_user_ids),
                tags=_normalize_list(tags),
                category=_normalize_string(category, "team"),
                priority=clean_priority,
                source=_normalize_string(source, "manual"),
                project_id=_normalize_string(project_id) or None,
                client_id=_normalize_string(client_id) or None,
                agent_id=_normalize_string(agent_id) or None,
                metadata=_json_safe(metadata or {}),
            )

            saved = self.storage.create(record.to_dict())

            memory_payload = self._prepare_memory_payload(saved, action)
            verification_payload = self._prepare_verification_payload(action, context, saved, True)

            self._emit_agent_event("team_memory.created", context, {"memory_id": saved["memory_id"]})
            self._log_audit_event(action, context, target_id=saved["memory_id"], success=True)

            return self._safe_result(
                "Team memory created successfully.",
                data={
                    "record": self._sanitize_record_for_response(saved),
                    "memory_payload": memory_payload,
                    "verification_payload": verification_payload,
                },
                metadata={
                    "agent": self.agent_name,
                    "action": action,
                    "workspace_id": context["workspace_id"],
                },
            )

        except Exception as exc:
            logger.exception("Failed to create team memory.")
            return self._error_result(
                "Failed to create team memory.",
                error=exc,
                metadata={"action": action},
            )

    def get_memory(
        self,
        user_id: str,
        workspace_id: str,
        memory_id: str,
        role: str = TeamRole.MEMBER.value,
        include_content: bool = True,
    ) -> Dict[str, Any]:
        """Read one team memory record by id."""
        action = TeamMemoryAction.READ.value

        try:
            context = self._validate_task_context(user_id, workspace_id, role, action)
            self._assert_action_allowed(context, action)

            clean_memory_id = _normalize_string(memory_id)
            if not clean_memory_id:
                raise TeamMemoryValidationError("memory_id is required.")

            record = self.storage.get(clean_memory_id)
            if not record:
                return self._error_result(
                    "Team memory not found.",
                    error="TEAM_MEMORY_NOT_FOUND",
                    metadata={"memory_id": clean_memory_id},
                )

            if not self._can_access_record(record, context, action):
                self._log_audit_event(action, context, target_id=clean_memory_id, success=False)
                return self._error_result(
                    "Access denied for this team memory.",
                    error="ACCESS_DENIED",
                    metadata={"memory_id": clean_memory_id},
                )

            verification_payload = self._prepare_verification_payload(action, context, record, True)

            self._log_audit_event(action, context, target_id=clean_memory_id, success=True)

            return self._safe_result(
                "Team memory retrieved successfully.",
                data={
                    "record": self._sanitize_record_for_response(record, include_content=include_content),
                    "verification_payload": verification_payload,
                },
                metadata={"memory_id": clean_memory_id},
            )

        except Exception as exc:
            logger.exception("Failed to get team memory.")
            return self._error_result(
                "Failed to get team memory.",
                error=exc,
                metadata={"action": action, "memory_id": memory_id},
            )

    def update_memory(
        self,
        user_id: str,
        workspace_id: str,
        memory_id: str,
        role: str = TeamRole.MEMBER.value,
        title: Optional[str] = None,
        content: Optional[str] = None,
        visibility: Optional[str] = None,
        allowed_roles: Optional[Sequence[str]] = None,
        allowed_user_ids: Optional[Sequence[str]] = None,
        denied_user_ids: Optional[Sequence[str]] = None,
        tags: Optional[Sequence[str]] = None,
        category: Optional[str] = None,
        priority: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Update an existing team memory record."""
        action = TeamMemoryAction.UPDATE.value

        try:
            context = self._validate_task_context(user_id, workspace_id, role, action)
            self._assert_action_allowed(context, action)

            clean_memory_id = _normalize_string(memory_id)
            if not clean_memory_id:
                raise TeamMemoryValidationError("memory_id is required.")

            existing = self.storage.get(clean_memory_id)
            if not existing:
                return self._error_result(
                    "Team memory not found.",
                    error="TEAM_MEMORY_NOT_FOUND",
                    metadata={"memory_id": clean_memory_id},
                )

            if not self._can_access_record(existing, context, action):
                self._log_audit_event(action, context, target_id=clean_memory_id, success=False)
                return self._error_result(
                    "Access denied for updating this team memory.",
                    error="ACCESS_DENIED",
                    metadata={"memory_id": clean_memory_id},
                )

            updates: Dict[str, Any] = {
                "updated_at": _utc_now_iso(),
                "updated_by": context["user_id"],
                "version": int(existing.get("version", 1)) + 1,
            }

            if title is not None:
                clean_title = _normalize_string(title)
                if not clean_title:
                    raise TeamMemoryValidationError("title cannot be empty.")
                updates["title"] = clean_title

            if content is not None:
                clean_content = _normalize_string(content)
                if not clean_content:
                    raise TeamMemoryValidationError("content cannot be empty.")
                if len(clean_content) > self.max_content_length:
                    raise TeamMemoryValidationError(
                        f"content exceeds max length of {self.max_content_length} characters."
                    )
                updates["content"] = clean_content

            if visibility is not None:
                clean_visibility = _normalize_string(visibility).lower()
                if clean_visibility not in {item.value for item in TeamMemoryVisibility}:
                    raise TeamMemoryValidationError(f"Invalid visibility: {visibility}")
                updates["visibility"] = clean_visibility

            if allowed_roles is not None:
                updates["allowed_roles"] = _normalize_list(allowed_roles)

            if allowed_user_ids is not None:
                updates["allowed_user_ids"] = _normalize_list(allowed_user_ids)

            if denied_user_ids is not None:
                updates["denied_user_ids"] = _normalize_list(denied_user_ids)

            if tags is not None:
                updates["tags"] = _normalize_list(tags)

            if category is not None:
                updates["category"] = _normalize_string(category, "team")

            if priority is not None:
                try:
                    updates["priority"] = max(1, min(5, int(priority)))
                except Exception:
                    updates["priority"] = existing.get("priority", 3)

            if metadata is not None:
                merged_metadata = dict(existing.get("metadata", {}))
                merged_metadata.update(_json_safe(metadata))
                updates["metadata"] = merged_metadata

            security_payload = {**existing, **updates}
            if self._requires_security_check(action, security_payload):
                approval = self._request_security_approval(action, context, security_payload)
                if not approval.get("approved"):
                    self._log_audit_event(action, context, target_id=clean_memory_id, success=False, metadata=approval)
                    return self._error_result(
                        "Security approval denied for updating team memory.",
                        error=approval.get("reason", "SECURITY_DENIED"),
                        metadata={"security": approval},
                    )

            updated = self.storage.update(clean_memory_id, updates)
            if not updated:
                return self._error_result(
                    "Team memory update failed.",
                    error="UPDATE_FAILED",
                    metadata={"memory_id": clean_memory_id},
                )

            memory_payload = self._prepare_memory_payload(updated, action)
            verification_payload = self._prepare_verification_payload(action, context, updated, True)

            self._emit_agent_event("team_memory.updated", context, {"memory_id": clean_memory_id})
            self._log_audit_event(action, context, target_id=clean_memory_id, success=True)

            return self._safe_result(
                "Team memory updated successfully.",
                data={
                    "record": self._sanitize_record_for_response(updated),
                    "memory_payload": memory_payload,
                    "verification_payload": verification_payload,
                },
                metadata={"memory_id": clean_memory_id},
            )

        except Exception as exc:
            logger.exception("Failed to update team memory.")
            return self._error_result(
                "Failed to update team memory.",
                error=exc,
                metadata={"action": action, "memory_id": memory_id},
            )

    def delete_memory(
        self,
        user_id: str,
        workspace_id: str,
        memory_id: str,
        role: str = TeamRole.ADMIN.value,
        hard_delete: bool = False,
    ) -> Dict[str, Any]:
        """
        Delete team memory.

        Safe default:
            hard_delete=False archives the record.
            hard_delete=True removes it from storage after security approval.
        """
        action = TeamMemoryAction.DELETE.value

        try:
            context = self._validate_task_context(user_id, workspace_id, role, action)
            self._assert_action_allowed(context, action)

            clean_memory_id = _normalize_string(memory_id)
            if not clean_memory_id:
                raise TeamMemoryValidationError("memory_id is required.")

            existing = self.storage.get(clean_memory_id)
            if not existing:
                return self._error_result(
                    "Team memory not found.",
                    error="TEAM_MEMORY_NOT_FOUND",
                    metadata={"memory_id": clean_memory_id},
                )

            if not self._can_access_record(existing, context, action):
                self._log_audit_event(action, context, target_id=clean_memory_id, success=False)
                return self._error_result(
                    "Access denied for deleting this team memory.",
                    error="ACCESS_DENIED",
                    metadata={"memory_id": clean_memory_id},
                )

            approval = self._request_security_approval(
                action,
                context,
                {"memory_id": clean_memory_id, "hard_delete": hard_delete, "record": existing},
            )
            if not approval.get("approved"):
                self._log_audit_event(action, context, target_id=clean_memory_id, success=False, metadata=approval)
                return self._error_result(
                    "Security approval denied for deleting team memory.",
                    error=approval.get("reason", "SECURITY_DENIED"),
                    metadata={"security": approval},
                )

            if hard_delete:
                deleted = self.storage.delete(clean_memory_id)
                result_data = {
                    "memory_id": clean_memory_id,
                    "hard_deleted": deleted,
                    "archived": False,
                }
            else:
                updated = self.storage.update(
                    clean_memory_id,
                    {
                        "archived": True,
                        "updated_at": _utc_now_iso(),
                        "updated_by": context["user_id"],
                        "version": int(existing.get("version", 1)) + 1,
                    },
                )
                result_data = {
                    "memory_id": clean_memory_id,
                    "hard_deleted": False,
                    "archived": bool(updated),
                    "record": self._sanitize_record_for_response(updated) if updated else None,
                }

            verification_payload = self._prepare_verification_payload(action, context, result_data, True)
            self._emit_agent_event("team_memory.deleted", context, result_data)
            self._log_audit_event(action, context, target_id=clean_memory_id, success=True, metadata={"hard_delete": hard_delete})

            return self._safe_result(
                "Team memory deleted successfully." if hard_delete else "Team memory archived successfully.",
                data={
                    **result_data,
                    "verification_payload": verification_payload,
                },
                metadata={"memory_id": clean_memory_id},
            )

        except Exception as exc:
            logger.exception("Failed to delete team memory.")
            return self._error_result(
                "Failed to delete team memory.",
                error=exc,
                metadata={"action": action, "memory_id": memory_id},
            )

    def archive_memory(
        self,
        user_id: str,
        workspace_id: str,
        memory_id: str,
        role: str = TeamRole.MANAGER.value,
    ) -> Dict[str, Any]:
        """Archive a team memory record."""
        action = TeamMemoryAction.ARCHIVE.value

        try:
            context = self._validate_task_context(user_id, workspace_id, role, action)
            self._assert_action_allowed(context, action)

            existing = self.storage.get(_normalize_string(memory_id))
            if not existing:
                return self._error_result("Team memory not found.", "TEAM_MEMORY_NOT_FOUND")

            if not self._can_access_record(existing, context, action):
                return self._error_result("Access denied for archiving this team memory.", "ACCESS_DENIED")

            updated = self.storage.update(
                memory_id,
                {
                    "archived": True,
                    "updated_at": _utc_now_iso(),
                    "updated_by": context["user_id"],
                    "version": int(existing.get("version", 1)) + 1,
                },
            )

            verification_payload = self._prepare_verification_payload(action, context, updated, True)
            self._emit_agent_event("team_memory.archived", context, {"memory_id": memory_id})
            self._log_audit_event(action, context, target_id=memory_id, success=True)

            return self._safe_result(
                "Team memory archived successfully.",
                data={
                    "record": self._sanitize_record_for_response(updated),
                    "verification_payload": verification_payload,
                },
                metadata={"memory_id": memory_id},
            )

        except Exception as exc:
            logger.exception("Failed to archive team memory.")
            return self._error_result("Failed to archive team memory.", exc)

    def restore_memory(
        self,
        user_id: str,
        workspace_id: str,
        memory_id: str,
        role: str = TeamRole.MANAGER.value,
    ) -> Dict[str, Any]:
        """Restore an archived team memory record."""
        action = TeamMemoryAction.RESTORE.value

        try:
            context = self._validate_task_context(user_id, workspace_id, role, action)
            self._assert_action_allowed(context, action)

            existing = self.storage.get(_normalize_string(memory_id))
            if not existing:
                return self._error_result("Team memory not found.", "TEAM_MEMORY_NOT_FOUND")

            if not self._can_access_record(existing, context, action):
                return self._error_result("Access denied for restoring this team memory.", "ACCESS_DENIED")

            updated = self.storage.update(
                memory_id,
                {
                    "archived": False,
                    "updated_at": _utc_now_iso(),
                    "updated_by": context["user_id"],
                    "version": int(existing.get("version", 1)) + 1,
                },
            )

            verification_payload = self._prepare_verification_payload(action, context, updated, True)
            self._emit_agent_event("team_memory.restored", context, {"memory_id": memory_id})
            self._log_audit_event(action, context, target_id=memory_id, success=True)

            return self._safe_result(
                "Team memory restored successfully.",
                data={
                    "record": self._sanitize_record_for_response(updated),
                    "verification_payload": verification_payload,
                },
                metadata={"memory_id": memory_id},
            )

        except Exception as exc:
            logger.exception("Failed to restore team memory.")
            return self._error_result("Failed to restore team memory.", exc)

    def list_memories(
        self,
        user_id: str,
        workspace_id: str,
        role: str = TeamRole.MEMBER.value,
        include_archived: bool = False,
        tags: Optional[Sequence[str]] = None,
        category: Optional[str] = None,
        project_id: Optional[str] = None,
        client_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
        include_content: bool = False,
    ) -> Dict[str, Any]:
        """List accessible team memory records for a workspace."""
        action = TeamMemoryAction.LIST.value

        try:
            context = self._validate_task_context(user_id, workspace_id, role, action)
            self._assert_action_allowed(context, action)

            clean_limit = max(1, min(500, int(limit or 50)))
            clean_offset = max(0, int(offset or 0))
            requested_tags = {tag.lower() for tag in _normalize_list(tags)}

            records = self.storage.list_by_workspace(context["workspace_id"])
            accessible: List[Dict[str, Any]] = []

            for record in records:
                if not include_archived and bool(record.get("archived", False)):
                    continue

                if not self._can_access_record(record, context, TeamMemoryAction.READ.value):
                    continue

                if requested_tags:
                    record_tags = {tag.lower() for tag in record.get("tags", [])}
                    if not requested_tags.intersection(record_tags):
                        continue

                if category and record.get("category") != category:
                    continue

                if project_id and record.get("project_id") != project_id:
                    continue

                if client_id and record.get("client_id") != client_id:
                    continue

                accessible.append(record)

            accessible.sort(key=lambda item: item.get("updated_at", ""), reverse=True)

            total = len(accessible)
            paginated = accessible[clean_offset: clean_offset + clean_limit]

            response_records = [
                self._sanitize_record_for_response(record, include_content=include_content)
                for record in paginated
            ]

            verification_payload = self._prepare_verification_payload(
                action,
                context,
                {"count": len(response_records), "total": total},
                True,
            )

            self._log_audit_event(action, context, success=True, metadata={"total": total})

            return self._safe_result(
                "Team memories listed successfully.",
                data={
                    "records": response_records,
                    "pagination": {
                        "total": total,
                        "limit": clean_limit,
                        "offset": clean_offset,
                        "returned": len(response_records),
                    },
                    "verification_payload": verification_payload,
                },
                metadata={"workspace_id": context["workspace_id"]},
            )

        except Exception as exc:
            logger.exception("Failed to list team memories.")
            return self._error_result(
                "Failed to list team memories.",
                error=exc,
                metadata={"action": action},
            )

    def search_memories(
        self,
        user_id: str,
        workspace_id: str,
        query: str,
        role: str = TeamRole.MEMBER.value,
        include_archived: bool = False,
        tags: Optional[Sequence[str]] = None,
        category: Optional[str] = None,
        limit: int = 20,
        include_content: bool = False,
    ) -> Dict[str, Any]:
        """
        Search accessible workspace memories.

        This is keyword search by default. A future memory_search.py or embeddings.py
        layer can call this method or replace the scoring strategy.
        """
        action = TeamMemoryAction.SEARCH.value

        try:
            context = self._validate_task_context(user_id, workspace_id, role, action)
            self._assert_action_allowed(context, action)

            clean_query = _normalize_string(query).lower()
            clean_limit = max(1, min(100, int(limit or 20)))
            requested_tags = {tag.lower() for tag in _normalize_list(tags)}

            if not clean_query and not requested_tags and not category:
                return self.list_memories(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    role=role,
                    include_archived=include_archived,
                    tags=tags,
                    category=category,
                    limit=clean_limit,
                    include_content=include_content,
                )

            records = self.storage.list_by_workspace(context["workspace_id"])
            scored: List[Tuple[int, Dict[str, Any]]] = []

            for record in records:
                if not include_archived and bool(record.get("archived", False)):
                    continue

                if not self._can_access_record(record, context, TeamMemoryAction.READ.value):
                    continue

                if category and record.get("category") != category:
                    continue

                record_tags = {tag.lower() for tag in record.get("tags", [])}
                if requested_tags and not requested_tags.intersection(record_tags):
                    continue

                haystack_parts = [
                    record.get("title", ""),
                    record.get("content", ""),
                    record.get("category", ""),
                    " ".join(record.get("tags", [])),
                    str(record.get("metadata", "")),
                ]
                haystack = " ".join(haystack_parts).lower()

                score = 0
                if clean_query:
                    query_terms = [term for term in clean_query.split() if term]
                    for term in query_terms:
                        if term in record.get("title", "").lower():
                            score += 5
                        if term in haystack:
                            score += 2

                    if clean_query in record.get("title", "").lower():
                        score += 10
                    if clean_query in haystack:
                        score += 4

                if requested_tags:
                    score += len(requested_tags.intersection(record_tags)) * 3

                if score > 0 or requested_tags or category:
                    scored.append((score, record))

            scored.sort(
                key=lambda item: (
                    item[0],
                    item[1].get("priority", 3),
                    item[1].get("updated_at", ""),
                ),
                reverse=True,
            )

            selected = [record for _, record in scored[:clean_limit]]
            response_records = [
                self._sanitize_record_for_response(record, include_content=include_content)
                for record in selected
            ]

            verification_payload = self._prepare_verification_payload(
                action,
                context,
                {"query": query, "returned": len(response_records)},
                True,
            )

            self._log_audit_event(
                action,
                context,
                success=True,
                metadata={"query": query, "returned": len(response_records)},
            )

            return self._safe_result(
                "Team memories searched successfully.",
                data={
                    "records": response_records,
                    "query": query,
                    "returned": len(response_records),
                    "verification_payload": verification_payload,
                },
                metadata={"workspace_id": context["workspace_id"]},
            )

        except Exception as exc:
            logger.exception("Failed to search team memories.")
            return self._error_result(
                "Failed to search team memories.",
                error=exc,
                metadata={"action": action, "query": query},
            )

    def share_memory(
        self,
        user_id: str,
        workspace_id: str,
        memory_id: str,
        role: str = TeamRole.MANAGER.value,
        add_user_ids: Optional[Sequence[str]] = None,
        add_roles: Optional[Sequence[str]] = None,
        visibility: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Share team memory with specific users or roles."""
        action = TeamMemoryAction.SHARE.value

        try:
            context = self._validate_task_context(user_id, workspace_id, role, action)
            self._assert_action_allowed(context, action)

            clean_memory_id = _normalize_string(memory_id)
            existing = self.storage.get(clean_memory_id)

            if not existing:
                return self._error_result("Team memory not found.", "TEAM_MEMORY_NOT_FOUND")

            if not self._can_access_record(existing, context, action):
                return self._error_result("Access denied for sharing this team memory.", "ACCESS_DENIED")

            approval = self._request_security_approval(
                action,
                context,
                {
                    "memory_id": clean_memory_id,
                    "add_user_ids": _normalize_list(add_user_ids),
                    "add_roles": _normalize_list(add_roles),
                    "visibility": visibility,
                },
            )
            if not approval.get("approved"):
                return self._error_result(
                    "Security approval denied for sharing team memory.",
                    error=approval.get("reason", "SECURITY_DENIED"),
                    metadata={"security": approval},
                )

            current_users = set(existing.get("allowed_user_ids", []))
            current_roles = set(existing.get("allowed_roles", []))

            current_users.update(_normalize_list(add_user_ids))
            current_roles.update(_normalize_list(add_roles))

            updates: Dict[str, Any] = {
                "allowed_user_ids": sorted(current_users),
                "allowed_roles": sorted(current_roles),
                "updated_at": _utc_now_iso(),
                "updated_by": context["user_id"],
                "version": int(existing.get("version", 1)) + 1,
            }

            if visibility is not None:
                clean_visibility = _normalize_string(visibility).lower()
                if clean_visibility not in {item.value for item in TeamMemoryVisibility}:
                    raise TeamMemoryValidationError(f"Invalid visibility: {visibility}")
                updates["visibility"] = clean_visibility

            updated = self.storage.update(clean_memory_id, updates)
            verification_payload = self._prepare_verification_payload(action, context, updated, True)

            self._emit_agent_event("team_memory.shared", context, {"memory_id": clean_memory_id})
            self._log_audit_event(action, context, target_id=clean_memory_id, success=True)

            return self._safe_result(
                "Team memory shared successfully.",
                data={
                    "record": self._sanitize_record_for_response(updated),
                    "verification_payload": verification_payload,
                },
                metadata={"memory_id": clean_memory_id},
            )

        except Exception as exc:
            logger.exception("Failed to share team memory.")
            return self._error_result("Failed to share team memory.", exc)

    def unshare_memory(
        self,
        user_id: str,
        workspace_id: str,
        memory_id: str,
        role: str = TeamRole.MANAGER.value,
        remove_user_ids: Optional[Sequence[str]] = None,
        remove_roles: Optional[Sequence[str]] = None,
        deny_user_ids: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        """Remove users/roles from a shared memory or explicitly deny users."""
        action = TeamMemoryAction.UNSHARE.value

        try:
            context = self._validate_task_context(user_id, workspace_id, role, action)
            self._assert_action_allowed(context, action)

            clean_memory_id = _normalize_string(memory_id)
            existing = self.storage.get(clean_memory_id)

            if not existing:
                return self._error_result("Team memory not found.", "TEAM_MEMORY_NOT_FOUND")

            if not self._can_access_record(existing, context, action):
                return self._error_result("Access denied for unsharing this team memory.", "ACCESS_DENIED")

            approval = self._request_security_approval(
                action,
                context,
                {
                    "memory_id": clean_memory_id,
                    "remove_user_ids": _normalize_list(remove_user_ids),
                    "remove_roles": _normalize_list(remove_roles),
                    "deny_user_ids": _normalize_list(deny_user_ids),
                },
            )
            if not approval.get("approved"):
                return self._error_result(
                    "Security approval denied for unsharing team memory.",
                    error=approval.get("reason", "SECURITY_DENIED"),
                    metadata={"security": approval},
                )

            allowed_users = set(existing.get("allowed_user_ids", []))
            allowed_roles = set(existing.get("allowed_roles", []))
            denied_users = set(existing.get("denied_user_ids", []))

            allowed_users.difference_update(_normalize_list(remove_user_ids))
            allowed_roles.difference_update(_normalize_list(remove_roles))
            denied_users.update(_normalize_list(deny_user_ids))

            updates = {
                "allowed_user_ids": sorted(allowed_users),
                "allowed_roles": sorted(allowed_roles),
                "denied_user_ids": sorted(denied_users),
                "updated_at": _utc_now_iso(),
                "updated_by": context["user_id"],
                "version": int(existing.get("version", 1)) + 1,
            }

            updated = self.storage.update(clean_memory_id, updates)
            verification_payload = self._prepare_verification_payload(action, context, updated, True)

            self._emit_agent_event("team_memory.unshared", context, {"memory_id": clean_memory_id})
            self._log_audit_event(action, context, target_id=clean_memory_id, success=True)

            return self._safe_result(
                "Team memory unshared successfully.",
                data={
                    "record": self._sanitize_record_for_response(updated),
                    "verification_payload": verification_payload,
                },
                metadata={"memory_id": clean_memory_id},
            )

        except Exception as exc:
            logger.exception("Failed to unshare team memory.")
            return self._error_result("Failed to unshare team memory.", exc)

    def export_workspace_memory(
        self,
        user_id: str,
        workspace_id: str,
        role: str = TeamRole.ADMIN.value,
        include_archived: bool = False,
        include_content: bool = True,
    ) -> Dict[str, Any]:
        """
        Export accessible workspace memory.

        This is protected by Security Agent because export may contain sensitive
        client/project/team knowledge.
        """
        action = TeamMemoryAction.EXPORT.value

        try:
            context = self._validate_task_context(user_id, workspace_id, role, action)
            self._assert_action_allowed(context, action)

            approval = self._request_security_approval(
                action,
                context,
                {"workspace_id": workspace_id, "include_archived": include_archived},
            )
            if not approval.get("approved"):
                return self._error_result(
                    "Security approval denied for exporting team memory.",
                    error=approval.get("reason", "SECURITY_DENIED"),
                    metadata={"security": approval},
                )

            list_result = self.list_memories(
                user_id=user_id,
                workspace_id=workspace_id,
                role=role,
                include_archived=include_archived,
                limit=500,
                offset=0,
                include_content=include_content,
            )

            if not list_result.get("success"):
                return list_result

            records = list_result.get("data", {}).get("records", [])
            export_data = {
                "export_id": _safe_uuid("team_memory_export"),
                "workspace_id": workspace_id,
                "exported_by": user_id,
                "record_count": len(records),
                "records": records,
                "created_at": _utc_now_iso(),
            }

            verification_payload = self._prepare_verification_payload(action, context, export_data, True)
            self._emit_agent_event("team_memory.exported", context, {"record_count": len(records)})
            self._log_audit_event(action, context, success=True, metadata={"record_count": len(records)})

            return self._safe_result(
                "Workspace team memory exported successfully.",
                data={
                    "export": export_data,
                    "verification_payload": verification_payload,
                },
                metadata={"workspace_id": workspace_id},
            )

        except Exception as exc:
            logger.exception("Failed to export workspace team memory.")
            return self._error_result("Failed to export workspace team memory.", exc)

    # -------------------------------------------------------------------------
    # Master Agent / Router Entry Point
    # -------------------------------------------------------------------------

    async def run(
        self,
        task: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Generic async entry point for Master Agent / Agent Router.

        Expected task shape:
            {
                "action": "create|read|update|delete|archive|restore|list|search|share|unshare|export",
                "user_id": "...",
                "workspace_id": "...",
                "role": "member",
                "payload": {...}
            }
        """
        started_at = time.time()
        task = task or {}
        payload = task.get("payload", {}) or {}

        action = _normalize_string(task.get("action") or payload.get("action")).lower()
        user_id = task.get("user_id") or payload.get("user_id")
        workspace_id = task.get("workspace_id") or payload.get("workspace_id")
        role = task.get("role") or payload.get("role") or TeamRole.MEMBER.value

        try:
            if action in {"create", TeamMemoryAction.CREATE.value}:
                result = self.create_memory(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    role=role,
                    title=payload.get("title", ""),
                    content=payload.get("content", ""),
                    visibility=payload.get("visibility", TeamMemoryVisibility.TEAM.value),
                    allowed_roles=payload.get("allowed_roles"),
                    allowed_user_ids=payload.get("allowed_user_ids"),
                    denied_user_ids=payload.get("denied_user_ids"),
                    tags=payload.get("tags"),
                    category=payload.get("category", "team"),
                    priority=payload.get("priority", 3),
                    source=payload.get("source", "manual"),
                    project_id=payload.get("project_id"),
                    client_id=payload.get("client_id"),
                    agent_id=payload.get("agent_id"),
                    metadata=payload.get("metadata"),
                )

            elif action in {"read", "get", TeamMemoryAction.READ.value}:
                result = self.get_memory(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    role=role,
                    memory_id=payload.get("memory_id", ""),
                    include_content=payload.get("include_content", True),
                )

            elif action in {"update", TeamMemoryAction.UPDATE.value}:
                result = self.update_memory(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    role=role,
                    memory_id=payload.get("memory_id", ""),
                    title=payload.get("title"),
                    content=payload.get("content"),
                    visibility=payload.get("visibility"),
                    allowed_roles=payload.get("allowed_roles"),
                    allowed_user_ids=payload.get("allowed_user_ids"),
                    denied_user_ids=payload.get("denied_user_ids"),
                    tags=payload.get("tags"),
                    category=payload.get("category"),
                    priority=payload.get("priority"),
                    metadata=payload.get("metadata"),
                )

            elif action in {"delete", TeamMemoryAction.DELETE.value}:
                result = self.delete_memory(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    role=role,
                    memory_id=payload.get("memory_id", ""),
                    hard_delete=bool(payload.get("hard_delete", False)),
                )

            elif action in {"archive", TeamMemoryAction.ARCHIVE.value}:
                result = self.archive_memory(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    role=role,
                    memory_id=payload.get("memory_id", ""),
                )

            elif action in {"restore", TeamMemoryAction.RESTORE.value}:
                result = self.restore_memory(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    role=role,
                    memory_id=payload.get("memory_id", ""),
                )

            elif action in {"list", TeamMemoryAction.LIST.value}:
                result = self.list_memories(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    role=role,
                    include_archived=bool(payload.get("include_archived", False)),
                    tags=payload.get("tags"),
                    category=payload.get("category"),
                    project_id=payload.get("project_id"),
                    client_id=payload.get("client_id"),
                    limit=payload.get("limit", 50),
                    offset=payload.get("offset", 0),
                    include_content=bool(payload.get("include_content", False)),
                )

            elif action in {"search", TeamMemoryAction.SEARCH.value}:
                result = self.search_memories(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    role=role,
                    query=payload.get("query", ""),
                    include_archived=bool(payload.get("include_archived", False)),
                    tags=payload.get("tags"),
                    category=payload.get("category"),
                    limit=payload.get("limit", 20),
                    include_content=bool(payload.get("include_content", False)),
                )

            elif action in {"share", TeamMemoryAction.SHARE.value}:
                result = self.share_memory(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    role=role,
                    memory_id=payload.get("memory_id", ""),
                    add_user_ids=payload.get("add_user_ids"),
                    add_roles=payload.get("add_roles"),
                    visibility=payload.get("visibility"),
                )

            elif action in {"unshare", TeamMemoryAction.UNSHARE.value}:
                result = self.unshare_memory(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    role=role,
                    memory_id=payload.get("memory_id", ""),
                    remove_user_ids=payload.get("remove_user_ids"),
                    remove_roles=payload.get("remove_roles"),
                    deny_user_ids=payload.get("deny_user_ids"),
                )

            elif action in {"export", TeamMemoryAction.EXPORT.value}:
                result = self.export_workspace_memory(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    role=role,
                    include_archived=bool(payload.get("include_archived", False)),
                    include_content=bool(payload.get("include_content", True)),
                )

            else:
                result = self._error_result(
                    "Unsupported TeamMemory action.",
                    error="UNSUPPORTED_ACTION",
                    metadata={
                        "action": action,
                        "supported_actions": [item.value for item in TeamMemoryAction],
                    },
                )

            result.setdefault("metadata", {})
            result["metadata"]["runtime_ms"] = round((time.time() - started_at) * 1000, 3)
            result["metadata"]["agent"] = self.agent_name
            return result

        except Exception as exc:
            logger.exception("TeamMemory run failed.")
            return self._error_result(
                "TeamMemory run failed.",
                error=exc,
                metadata={
                    "action": action,
                    "runtime_ms": round((time.time() - started_at) * 1000, 3),
                    "agent": self.agent_name,
                },
            )


__all__ = [
    "TeamMemory",
    "TeamMemoryRecord",
    "TeamMemoryVisibility",
    "TeamMemoryAction",
    "TeamRole",
    "InMemoryTeamMemoryStore",
    "TeamMemoryError",
    "TeamMemoryPermissionError",
    "TeamMemoryValidationError",
]