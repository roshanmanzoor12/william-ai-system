"""
William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

File: core/context.py
Module: Core Master Control Files
Purpose:
    Shared SaaS task context for user_id, workspace_id, role, plan,
    permissions, request_id, session_id, and trace metadata.

This file is designed to be:
    - Import-safe
    - Framework-independent
    - FastAPI/dashboard ready
    - Compatible with Master Agent routing
    - Compatible with BaseAgent, Agent Registry, Agent Loader, Agent Router
    - Compatible with Security Agent, Verification Agent, and Memory Agent
    - Safe for SaaS user/workspace isolation

Core Safety Rule:
    Any user-specific task must include both user_id and workspace_id.
    No agent should execute a user/workspace scoped task without a valid TaskContext.
"""

from __future__ import annotations

import copy
import json
import logging
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple, Union


logger = logging.getLogger(__name__)


JsonDict = Dict[str, Any]
PermissionInput = Union[None, Sequence[str], Set[str], Tuple[str, ...], Mapping[str, Any]]


DEFAULT_ROLE = "member"
DEFAULT_PLAN = "free"
DEFAULT_SOURCE = "unknown"
DEFAULT_CHANNEL = "api"

SUPPORTED_ROLES: Set[str] = {
    "owner",
    "admin",
    "manager",
    "member",
    "viewer",
    "guest",
    "system",
}

SUPPORTED_PLANS: Set[str] = {
    "free",
    "starter",
    "pro",
    "business",
    "enterprise",
}

SENSITIVE_CONTEXT_KEYS: Set[str] = {
    "password",
    "passwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "authorization",
    "auth",
    "cookie",
    "session_cookie",
    "private_key",
    "client_secret",
    "jwt",
}


class TaskContextError(ValueError):
    """
    Raised when a TaskContext is invalid.

    This exception is intentionally simple and local to this file so
    core/context.py remains import-safe even before the full exception
    module exists.
    """


def _utc_now_iso() -> str:
    """
    Return current UTC time in ISO-8601 format.
    """
    return datetime.now(timezone.utc).isoformat()


def _generate_id(prefix: str) -> str:
    """
    Generate a stable readable ID for tracing, requests, sessions, and tasks.
    """
    safe_prefix = str(prefix or "id").strip().lower().replace(" ", "_")
    return f"{safe_prefix}_{uuid.uuid4().hex}"


def _clean_string(value: Any) -> Optional[str]:
    """
    Convert a value into a clean string or None.

    Empty strings become None.
    """
    if value is None:
        return None

    cleaned = str(value).strip()
    return cleaned if cleaned else None


def _normalize_role(role: Any) -> str:
    """
    Normalize role safely.

    Unknown roles are allowed as strings for future compatibility,
    but empty role values fall back to DEFAULT_ROLE.
    """
    cleaned = _clean_string(role)
    if not cleaned:
        return DEFAULT_ROLE
    return cleaned.lower()


def _normalize_plan(plan: Any) -> str:
    """
    Normalize subscription plan safely.

    Unknown plan values are allowed for future compatibility,
    but empty plan values fall back to DEFAULT_PLAN.
    """
    cleaned = _clean_string(plan)
    if not cleaned:
        return DEFAULT_PLAN
    return cleaned.lower()


def _normalize_permissions(permissions: PermissionInput) -> Set[str]:
    """
    Normalize permissions into a set of lowercase permission strings.

    Supported input:
        - None
        - list/tuple/set of strings
        - dict mapping permission -> bool/value

    Dict behavior:
        {"creator.run": True}  -> include creator.run
        {"creator.run": False} -> do not include creator.run
    """
    normalized: Set[str] = set()

    if permissions is None:
        return normalized

    if isinstance(permissions, Mapping):
        for key, allowed in permissions.items():
            permission = _clean_string(key)
            if permission and bool(allowed):
                normalized.add(permission.lower())
        return normalized

    if isinstance(permissions, (list, tuple, set)):
        for item in permissions:
            permission = _clean_string(item)
            if permission:
                normalized.add(permission.lower())
        return normalized

    permission = _clean_string(permissions)
    if permission:
        normalized.add(permission.lower())

    return normalized


def _redact_value(key: str, value: Any) -> Any:
    """
    Redact sensitive values based on key name.

    This protects audit logs, dashboard traces, verification payloads,
    and memory payload metadata from accidentally exposing secrets.
    """
    lowered_key = str(key or "").lower()

    if any(secret_key in lowered_key for secret_key in SENSITIVE_CONTEXT_KEYS):
        if value in (None, "", [], {}, ()):
            return value
        return "***REDACTED***"

    return value


def _redact_mapping(data: Optional[Mapping[str, Any]]) -> JsonDict:
    """
    Recursively redact sensitive keys from dictionaries/lists.
    """
    if not data:
        return {}

    def redact(obj: Any) -> Any:
        if isinstance(obj, Mapping):
            output: JsonDict = {}
            for key, value in obj.items():
                safe_key = str(key)
                safe_value = _redact_value(safe_key, value)
                if safe_value is value:
                    output[safe_key] = redact(value)
                else:
                    output[safe_key] = safe_value
            return output

        if isinstance(obj, list):
            return [redact(item) for item in obj]

        if isinstance(obj, tuple):
            return tuple(redact(item) for item in obj)

        return obj

    return redact(dict(data))


def _safe_copy_mapping(data: Optional[Mapping[str, Any]]) -> JsonDict:
    """
    Safely deep-copy a dictionary-like object.

    If deep copy fails, fallback to JSON serialization when possible,
    then fallback to string representation.
    """
    if not data:
        return {}

    try:
        return copy.deepcopy(dict(data))
    except Exception:
        try:
            return json.loads(json.dumps(dict(data), default=str))
        except Exception:
            return {"raw": str(data)}


@dataclass
class TaskContext:
    """
    Shared SaaS task context for all William/Jarvis agents.

    This context object travels through:
        Dashboard/API
            -> Master Agent
            -> Agent Router
            -> Specialized Agent
            -> Security Agent
            -> Verification Agent
            -> Memory Agent
            -> Audit Logs

    Required for user/workspace scoped execution:
        - user_id
        - workspace_id

    Main responsibilities:
        - Keep user/workspace isolation clear
        - Carry role and plan data
        - Carry permission data
        - Carry request/session/trace metadata
        - Provide safe dict/JSON serialization
        - Provide audit-safe redacted output
        - Provide helper checks for agents and routes
    """

    user_id: Optional[str] = None
    workspace_id: Optional[str] = None

    role: str = DEFAULT_ROLE
    plan: str = DEFAULT_PLAN

    permissions: Set[str] = field(default_factory=set)

    request_id: str = field(default_factory=lambda: _generate_id("req"))
    session_id: Optional[str] = None
    trace_id: str = field(default_factory=lambda: _generate_id("trace"))
    task_id: Optional[str] = None

    source: str = DEFAULT_SOURCE
    channel: str = DEFAULT_CHANNEL

    ip_address: Optional[str] = None
    user_agent: Optional[str] = None

    metadata: JsonDict = field(default_factory=dict)
    trace_metadata: JsonDict = field(default_factory=dict)

    created_at: str = field(default_factory=_utc_now_iso)

    is_system_context: bool = False
    is_service_context: bool = False

    def __post_init__(self) -> None:
        """
        Normalize context after initialization.
        """
        self.user_id = _clean_string(self.user_id)
        self.workspace_id = _clean_string(self.workspace_id)

        self.role = _normalize_role(self.role)
        self.plan = _normalize_plan(self.plan)

        self.permissions = _normalize_permissions(self.permissions)

        self.request_id = _clean_string(self.request_id) or _generate_id("req")
        self.session_id = _clean_string(self.session_id)
        self.trace_id = _clean_string(self.trace_id) or _generate_id("trace")
        self.task_id = _clean_string(self.task_id)

        self.source = _clean_string(self.source) or DEFAULT_SOURCE
        self.channel = _clean_string(self.channel) or DEFAULT_CHANNEL

        self.ip_address = _clean_string(self.ip_address)
        self.user_agent = _clean_string(self.user_agent)

        self.metadata = _safe_copy_mapping(self.metadata)
        self.trace_metadata = _safe_copy_mapping(self.trace_metadata)

        self.created_at = _clean_string(self.created_at) or _utc_now_iso()

        self.is_system_context = bool(self.is_system_context)
        self.is_service_context = bool(self.is_service_context)

    # ------------------------------------------------------------------
    # Constructors
    # ------------------------------------------------------------------

    @classmethod
    def create(
        cls,
        user_id: Optional[Any] = None,
        workspace_id: Optional[Any] = None,
        role: Any = DEFAULT_ROLE,
        plan: Any = DEFAULT_PLAN,
        permissions: PermissionInput = None,
        request_id: Optional[Any] = None,
        session_id: Optional[Any] = None,
        trace_id: Optional[Any] = None,
        task_id: Optional[Any] = None,
        source: Any = DEFAULT_SOURCE,
        channel: Any = DEFAULT_CHANNEL,
        ip_address: Optional[Any] = None,
        user_agent: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        trace_metadata: Optional[Mapping[str, Any]] = None,
        is_system_context: bool = False,
        is_service_context: bool = False,
    ) -> "TaskContext":
        """
        Create a TaskContext using explicit values.

        This is the preferred constructor for Master Agent, API routes,
        dashboard tasks, and service layer functions.
        """
        return cls(
            user_id=_clean_string(user_id),
            workspace_id=_clean_string(workspace_id),
            role=_normalize_role(role),
            plan=_normalize_plan(plan),
            permissions=_normalize_permissions(permissions),
            request_id=_clean_string(request_id) or _generate_id("req"),
            session_id=_clean_string(session_id),
            trace_id=_clean_string(trace_id) or _generate_id("trace"),
            task_id=_clean_string(task_id),
            source=_clean_string(source) or DEFAULT_SOURCE,
            channel=_clean_string(channel) or DEFAULT_CHANNEL,
            ip_address=_clean_string(ip_address),
            user_agent=_clean_string(user_agent),
            metadata=_safe_copy_mapping(metadata),
            trace_metadata=_safe_copy_mapping(trace_metadata),
            is_system_context=bool(is_system_context),
            is_service_context=bool(is_service_context),
        )

    @classmethod
    def from_dict(cls, data: Optional[Mapping[str, Any]]) -> "TaskContext":
        """
        Create TaskContext from a dictionary.

        Useful for:
            - FastAPI request body
            - dashboard payload
            - task queue payload
            - agent-to-agent internal payload
        """
        payload = _safe_copy_mapping(data)

        return cls.create(
            user_id=payload.get("user_id"),
            workspace_id=payload.get("workspace_id"),
            role=payload.get("role", DEFAULT_ROLE),
            plan=payload.get("plan", DEFAULT_PLAN),
            permissions=payload.get("permissions"),
            request_id=payload.get("request_id"),
            session_id=payload.get("session_id"),
            trace_id=payload.get("trace_id"),
            task_id=payload.get("task_id"),
            source=payload.get("source", DEFAULT_SOURCE),
            channel=payload.get("channel", DEFAULT_CHANNEL),
            ip_address=payload.get("ip_address"),
            user_agent=payload.get("user_agent"),
            metadata=payload.get("metadata") or {},
            trace_metadata=payload.get("trace_metadata") or {},
            is_system_context=bool(payload.get("is_system_context", False)),
            is_service_context=bool(payload.get("is_service_context", False)),
        )

    @classmethod
    def from_headers(
        cls,
        headers: Optional[Mapping[str, Any]],
        default_role: str = DEFAULT_ROLE,
        default_plan: str = DEFAULT_PLAN,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> "TaskContext":
        """
        Create TaskContext from API headers.

        Expected compatible headers:
            X-User-ID
            X-Workspace-ID
            X-Request-ID
            X-Session-ID
            X-Trace-ID
            X-Role
            X-Plan
            X-Source
            X-Channel

        This is useful for FastAPI/Starlette integration.
        """
        safe_headers = {
            str(k).lower(): v for k, v in dict(headers or {}).items()
        }

        def get_header(name: str, fallback: Optional[str] = None) -> Optional[Any]:
            return safe_headers.get(name.lower(), fallback)

        return cls.create(
            user_id=get_header("x-user-id"),
            workspace_id=get_header("x-workspace-id"),
            role=get_header("x-role", default_role),
            plan=get_header("x-plan", default_plan),
            request_id=get_header("x-request-id"),
            session_id=get_header("x-session-id"),
            trace_id=get_header("x-trace-id"),
            source=get_header("x-source", "api"),
            channel=get_header("x-channel", "api"),
            user_agent=get_header("user-agent"),
            metadata=metadata or {},
            trace_metadata={
                "headers_loaded": True,
                "created_from": "headers",
            },
        )

    @classmethod
    def system(
        cls,
        source: str = "system",
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> "TaskContext":
        """
        Create a controlled system context.

        This should be used only for internal health checks,
        boot tasks, registry loading, and non-user scoped operations.

        Important:
            This does not bypass security for sensitive user actions.
        """
        return cls.create(
            user_id="system",
            workspace_id="system",
            role="system",
            plan="enterprise",
            permissions={"system.internal"},
            source=source,
            channel="internal",
            metadata=metadata or {},
            trace_metadata={"context_type": "system"},
            is_system_context=True,
            is_service_context=True,
        )

    @classmethod
    def anonymous(
        cls,
        source: str = "public",
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> "TaskContext":
        """
        Create an anonymous context for public, non-sensitive actions.

        Anonymous contexts should not execute user-scoped agent tasks.
        """
        return cls.create(
            user_id=None,
            workspace_id=None,
            role="guest",
            plan="free",
            permissions=set(),
            source=source,
            channel="public",
            metadata=metadata or {},
            trace_metadata={"context_type": "anonymous"},
        )

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate(
        self,
        require_user: bool = True,
        require_workspace: bool = True,
        require_permissions: Optional[Sequence[str]] = None,
        raise_error: bool = False,
    ) -> bool:
        """
        Validate the task context.

        Args:
            require_user:
                Require user_id when task is user-specific.
            require_workspace:
                Require workspace_id when task is workspace-specific.
            require_permissions:
                Optional list of permissions that must exist.
            raise_error:
                If True, raises TaskContextError on failure.

        Returns:
            bool
        """
        errors = self.validation_errors(
            require_user=require_user,
            require_workspace=require_workspace,
            require_permissions=require_permissions,
        )

        if errors and raise_error:
            raise TaskContextError("; ".join(errors))

        return not errors

    def validation_errors(
        self,
        require_user: bool = True,
        require_workspace: bool = True,
        require_permissions: Optional[Sequence[str]] = None,
    ) -> List[str]:
        """
        Return validation errors without throwing.

        This is safe for agents that need structured error responses.
        """
        errors: List[str] = []

        if require_user and not self.user_id:
            errors.append("TaskContext missing required user_id.")

        if require_workspace and not self.workspace_id:
            errors.append("TaskContext missing required workspace_id.")

        if self.role and not isinstance(self.role, str):
            errors.append("TaskContext role must be a string.")

        if self.plan and not isinstance(self.plan, str):
            errors.append("TaskContext plan must be a string.")

        required_permissions = _normalize_permissions(require_permissions)
        missing_permissions = sorted(
            permission
            for permission in required_permissions
            if not self.has_permission(permission)
        )

        if missing_permissions:
            errors.append(
                "TaskContext missing required permissions: "
                + ", ".join(missing_permissions)
            )

        return errors

    def is_valid(
        self,
        require_user: bool = True,
        require_workspace: bool = True,
    ) -> bool:
        """
        Short validation helper.
        """
        return self.validate(
            require_user=require_user,
            require_workspace=require_workspace,
            raise_error=False,
        )

    def require_valid(
        self,
        require_user: bool = True,
        require_workspace: bool = True,
        require_permissions: Optional[Sequence[str]] = None,
    ) -> None:
        """
        Raise TaskContextError if invalid.

        Useful inside service methods where immediate failure is preferred.
        """
        self.validate(
            require_user=require_user,
            require_workspace=require_workspace,
            require_permissions=require_permissions,
            raise_error=True,
        )

    # ------------------------------------------------------------------
    # Permission helpers
    # ------------------------------------------------------------------

    def has_permission(self, permission: str) -> bool:
        """
        Check if context has a permission.

        Supports wildcard permissions:
            "*"                 -> all permissions
            "agent.*"           -> all permissions under agent namespace
            "creator.run"       -> exact permission
        """
        cleaned = _clean_string(permission)
        if not cleaned:
            return False

        permission_key = cleaned.lower()

        if "*" in self.permissions:
            return True

        if permission_key in self.permissions:
            return True

        parts = permission_key.split(".")
        for index in range(1, len(parts)):
            wildcard = ".".join(parts[:index]) + ".*"
            if wildcard in self.permissions:
                return True

        return False

    def has_any_permission(self, permissions: Sequence[str]) -> bool:
        """
        Return True if at least one permission is present.
        """
        return any(self.has_permission(permission) for permission in permissions or [])

    def has_all_permissions(self, permissions: Sequence[str]) -> bool:
        """
        Return True if all permissions are present.
        """
        return all(self.has_permission(permission) for permission in permissions or [])

    def add_permission(self, permission: str) -> "TaskContext":
        """
        Add one permission and return self for chaining.
        """
        cleaned = _clean_string(permission)
        if cleaned:
            self.permissions.add(cleaned.lower())
        return self

    def remove_permission(self, permission: str) -> "TaskContext":
        """
        Remove one permission and return self for chaining.
        """
        cleaned = _clean_string(permission)
        if cleaned:
            self.permissions.discard(cleaned.lower())
        return self

    def with_permissions(self, permissions: PermissionInput) -> "TaskContext":
        """
        Return a cloned context with added permissions.
        """
        cloned = self.clone()
        cloned.permissions.update(_normalize_permissions(permissions))
        return cloned

    # ------------------------------------------------------------------
    # Role and plan helpers
    # ------------------------------------------------------------------

    def is_owner(self) -> bool:
        return self.role == "owner"

    def is_admin(self) -> bool:
        return self.role in {"owner", "admin"}

    def is_manager_or_above(self) -> bool:
        return self.role in {"owner", "admin", "manager"}

    def is_viewer(self) -> bool:
        return self.role == "viewer"

    def is_guest(self) -> bool:
        return self.role == "guest"

    def is_paid_plan(self) -> bool:
        return self.plan in {"starter", "pro", "business", "enterprise"}

    def is_enterprise_plan(self) -> bool:
        return self.plan == "enterprise"

    # ------------------------------------------------------------------
    # Scope and identity helpers
    # ------------------------------------------------------------------

    def has_user_scope(self) -> bool:
        return bool(self.user_id)

    def has_workspace_scope(self) -> bool:
        return bool(self.workspace_id)

    def has_saas_scope(self) -> bool:
        return bool(self.user_id and self.workspace_id)

    def scope_key(self) -> str:
        """
        Return a stable scope key for logs/cache/memory lookups.

        This should not be used as a secret.
        """
        return f"user:{self.user_id or 'none'}|workspace:{self.workspace_id or 'none'}"

    def trace_key(self) -> str:
        """
        Return trace key for logs and event correlation.
        """
        return f"request:{self.request_id}|trace:{self.trace_id}"

    def same_scope_as(self, other: "TaskContext") -> bool:
        """
        Check if another TaskContext belongs to the same user/workspace scope.
        """
        if not isinstance(other, TaskContext):
            return False

        return (
            self.user_id == other.user_id
            and self.workspace_id == other.workspace_id
        )

    # ------------------------------------------------------------------
    # Metadata helpers
    # ------------------------------------------------------------------

    def get_metadata(self, key: str, default: Any = None) -> Any:
        """
        Read metadata value safely.
        """
        return self.metadata.get(key, default)

    def set_metadata(self, key: str, value: Any) -> "TaskContext":
        """
        Set metadata value and return self for chaining.
        """
        cleaned = _clean_string(key)
        if cleaned:
            self.metadata[cleaned] = value
        return self

    def get_trace_metadata(self, key: str, default: Any = None) -> Any:
        """
        Read trace metadata value safely.
        """
        return self.trace_metadata.get(key, default)

    def set_trace_metadata(self, key: str, value: Any) -> "TaskContext":
        """
        Set trace metadata value and return self for chaining.
        """
        cleaned = _clean_string(key)
        if cleaned:
            self.trace_metadata[cleaned] = value
        return self

    def append_trace_event(
        self,
        event: str,
        data: Optional[Mapping[str, Any]] = None,
    ) -> "TaskContext":
        """
        Append a lightweight trace event.

        Useful for Master Agent, Router, Security Agent, Verification Agent,
        and Memory Agent debugging.
        """
        cleaned_event = _clean_string(event) or "unknown_event"

        events = self.trace_metadata.get("events")
        if not isinstance(events, list):
            events = []

        events.append(
            {
                "event": cleaned_event,
                "data": _redact_mapping(data or {}),
                "timestamp": _utc_now_iso(),
            }
        )

        self.trace_metadata["events"] = events
        return self

    # ------------------------------------------------------------------
    # Clone / mutation helpers
    # ------------------------------------------------------------------

    def clone(self, **overrides: Any) -> "TaskContext":
        """
        Return a cloned TaskContext with optional overrides.
        """
        data = self.to_dict(redact=False)
        data.update(overrides)
        return TaskContext.from_dict(data)

    def with_task_id(self, task_id: Optional[str] = None) -> "TaskContext":
        """
        Return cloned context with a task_id.
        """
        return self.clone(task_id=_clean_string(task_id) or _generate_id("task"))

    def with_request_id(self, request_id: Optional[str] = None) -> "TaskContext":
        """
        Return cloned context with a request_id.
        """
        return self.clone(request_id=_clean_string(request_id) or _generate_id("req"))

    def with_trace_id(self, trace_id: Optional[str] = None) -> "TaskContext":
        """
        Return cloned context with a trace_id.
        """
        return self.clone(trace_id=_clean_string(trace_id) or _generate_id("trace"))

    def for_agent(
        self,
        agent_name: str,
        action: Optional[str] = None,
        extra_metadata: Optional[Mapping[str, Any]] = None,
    ) -> "TaskContext":
        """
        Create a cloned context enriched for a specific agent call.

        Useful when Master Agent routes to a specialized agent.
        """
        metadata = _safe_copy_mapping(self.metadata)
        metadata["target_agent"] = _clean_string(agent_name) or "unknown_agent"

        if action:
            metadata["target_action"] = _clean_string(action)

        if extra_metadata:
            metadata.update(_safe_copy_mapping(extra_metadata))

        cloned = self.clone(metadata=metadata)
        cloned.append_trace_event(
            "context_for_agent",
            {
                "agent_name": agent_name,
                "action": action,
            },
        )
        return cloned

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self, redact: bool = False) -> JsonDict:
        """
        Convert context into JSON-safe dictionary.

        Args:
            redact:
                If True, sensitive fields inside metadata and trace metadata
                are redacted.
        """
        payload: JsonDict = {
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "role": self.role,
            "plan": self.plan,
            "permissions": sorted(self.permissions),
            "request_id": self.request_id,
            "session_id": self.session_id,
            "trace_id": self.trace_id,
            "task_id": self.task_id,
            "source": self.source,
            "channel": self.channel,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "metadata": _safe_copy_mapping(self.metadata),
            "trace_metadata": _safe_copy_mapping(self.trace_metadata),
            "created_at": self.created_at,
            "is_system_context": self.is_system_context,
            "is_service_context": self.is_service_context,
        }

        if redact:
            payload["metadata"] = _redact_mapping(payload["metadata"])
            payload["trace_metadata"] = _redact_mapping(payload["trace_metadata"])
            payload["ip_address"] = "***REDACTED***" if payload["ip_address"] else None
            payload["user_agent"] = (
                "***REDACTED***" if payload["user_agent"] else None
            )

        return payload

    def to_json(self, redact: bool = False, indent: Optional[int] = None) -> str:
        """
        Convert context into JSON string.
        """
        return json.dumps(self.to_dict(redact=redact), default=str, indent=indent)

    def to_audit_metadata(self) -> JsonDict:
        """
        Create audit-safe metadata.

        Used by:
            - Audit service
            - Security Agent
            - Dashboard logs
            - Agent event emitter
        """
        return {
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "role": self.role,
            "plan": self.plan,
            "request_id": self.request_id,
            "session_id": self.session_id,
            "trace_id": self.trace_id,
            "task_id": self.task_id,
            "source": self.source,
            "channel": self.channel,
            "scope_key": self.scope_key(),
            "trace_key": self.trace_key(),
            "metadata": _redact_mapping(self.metadata),
            "trace_metadata": _redact_mapping(self.trace_metadata),
            "created_at": self.created_at,
        }

    def to_memory_metadata(self) -> JsonDict:
        """
        Create memory-compatible metadata.

        This does not store full task content. It only carries scope and trace
        details needed for Memory Agent compatibility.
        """
        return {
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "role": self.role,
            "plan": self.plan,
            "source": self.source,
            "channel": self.channel,
            "task_id": self.task_id,
            "request_id": self.request_id,
            "trace_id": self.trace_id,
            "created_at": self.created_at,
        }

    def to_verification_metadata(self) -> JsonDict:
        """
        Create Verification Agent-compatible metadata.
        """
        return {
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "task_id": self.task_id,
            "request_id": self.request_id,
            "trace_id": self.trace_id,
            "source": self.source,
            "channel": self.channel,
            "context_valid": self.is_valid(),
            "validation_errors": self.validation_errors(),
            "created_at": self.created_at,
        }

    def to_response_metadata(self) -> JsonDict:
        """
        Create safe metadata for normal API/agent responses.
        """
        return {
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "request_id": self.request_id,
            "session_id": self.session_id,
            "trace_id": self.trace_id,
            "task_id": self.task_id,
            "source": self.source,
            "channel": self.channel,
        }

    # ------------------------------------------------------------------
    # Structured results
    # ------------------------------------------------------------------

    def safe_result(
        self,
        message: str = "Task context operation completed successfully.",
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> JsonDict:
        """
        Return standard success result.

        This mirrors the global William/Jarvis result contract:
            success, message, data, error, metadata
        """
        response_metadata = self.to_response_metadata()
        if metadata:
            response_metadata.update(_redact_mapping(metadata))

        return {
            "success": True,
            "message": message,
            "data": _safe_copy_mapping(data),
            "error": None,
            "metadata": response_metadata,
        }

    def error_result(
        self,
        message: str = "Task context operation failed.",
        code: str = "TASK_CONTEXT_ERROR",
        details: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> JsonDict:
        """
        Return standard error result.

        This mirrors the global William/Jarvis result contract:
            success, message, data, error, metadata
        """
        response_metadata = self.to_response_metadata()
        if metadata:
            response_metadata.update(_redact_mapping(metadata))

        return {
            "success": False,
            "message": message,
            "data": {},
            "error": {
                "code": code,
                "details": details,
            },
            "metadata": response_metadata,
        }

    def validation_result(
        self,
        require_user: bool = True,
        require_workspace: bool = True,
        require_permissions: Optional[Sequence[str]] = None,
    ) -> JsonDict:
        """
        Return structured validation result for API routes and agents.
        """
        errors = self.validation_errors(
            require_user=require_user,
            require_workspace=require_workspace,
            require_permissions=require_permissions,
        )

        if errors:
            return self.error_result(
                message="TaskContext validation failed.",
                code="INVALID_TASK_CONTEXT",
                details=errors,
                metadata={"context_valid": False},
            )

        return self.safe_result(
            message="TaskContext validation passed.",
            data={"context_valid": True},
            metadata={"context_valid": True},
        )

    # ------------------------------------------------------------------
    # Python helpers
    # ------------------------------------------------------------------

    def __contains__(self, permission: str) -> bool:
        return self.has_permission(permission)

    def __repr__(self) -> str:
        return (
            "TaskContext("
            f"user_id={self.user_id!r}, "
            f"workspace_id={self.workspace_id!r}, "
            f"role={self.role!r}, "
            f"plan={self.plan!r}, "
            f"request_id={self.request_id!r}, "
            f"trace_id={self.trace_id!r}, "
            f"task_id={self.task_id!r}"
            ")"
        )


# ----------------------------------------------------------------------
# Module-level helper functions
# ----------------------------------------------------------------------

def ensure_task_context(
    context: Optional[Union[TaskContext, Mapping[str, Any]]] = None,
    require_user: bool = True,
    require_workspace: bool = True,
) -> TaskContext:
    """
    Convert input into TaskContext and optionally validate it.

    Accepted input:
        - TaskContext
        - dict-like object
        - None

    If None is passed, an anonymous context is created.
    """
    if isinstance(context, TaskContext):
        task_context = context
    elif isinstance(context, Mapping):
        task_context = TaskContext.from_dict(context)
    elif context is None:
        task_context = TaskContext.anonymous()
    else:
        raise TaskContextError(
            f"Unsupported context type: {type(context).__name__}"
        )

    task_context.require_valid(
        require_user=require_user,
        require_workspace=require_workspace,
    )

    return task_context


def create_task_context(
    user_id: Optional[Any],
    workspace_id: Optional[Any],
    **kwargs: Any,
) -> TaskContext:
    """
    Convenience factory for creating a user/workspace scoped TaskContext.
    """
    return TaskContext.create(
        user_id=user_id,
        workspace_id=workspace_id,
        **kwargs,
    )


def context_from_request_like(
    request: Any,
    default_role: str = DEFAULT_ROLE,
    default_plan: str = DEFAULT_PLAN,
) -> TaskContext:
    """
    Create TaskContext from a FastAPI/Starlette-like request object.

    This function is intentionally defensive so the file remains import-safe
    without requiring FastAPI as a dependency.

    Supported request attributes:
        request.headers
        request.client.host
        request.state.user_id
        request.state.workspace_id
    """
    headers = getattr(request, "headers", {}) or {}
    context = TaskContext.from_headers(
        headers=headers,
        default_role=default_role,
        default_plan=default_plan,
    )

    try:
        client = getattr(request, "client", None)
        host = getattr(client, "host", None)
        if host:
            context.ip_address = str(host)
    except Exception:
        logger.debug("Unable to read request client host.", exc_info=True)

    try:
        state = getattr(request, "state", None)
        state_user_id = getattr(state, "user_id", None)
        state_workspace_id = getattr(state, "workspace_id", None)

        if state_user_id and not context.user_id:
            context.user_id = _clean_string(state_user_id)

        if state_workspace_id and not context.workspace_id:
            context.workspace_id = _clean_string(state_workspace_id)
    except Exception:
        logger.debug("Unable to read request state context.", exc_info=True)

    context.append_trace_event("context_created_from_request")
    return context


def merge_context_metadata(
    context: Union[TaskContext, Mapping[str, Any]],
    metadata: Optional[Mapping[str, Any]] = None,
    trace_metadata: Optional[Mapping[str, Any]] = None,
) -> TaskContext:
    """
    Return a cloned context with merged metadata and trace metadata.
    """
    task_context = (
        context if isinstance(context, TaskContext) else TaskContext.from_dict(context)
    )

    cloned = task_context.clone()

    if metadata:
        cloned.metadata.update(_safe_copy_mapping(metadata))

    if trace_metadata:
        cloned.trace_metadata.update(_safe_copy_mapping(trace_metadata))

    return cloned


def require_same_scope(
    left: Union[TaskContext, Mapping[str, Any]],
    right: Union[TaskContext, Mapping[str, Any]],
    raise_error: bool = True,
) -> bool:
    """
    Ensure two contexts belong to the same user/workspace scope.

    Useful to prevent cross-user or cross-workspace leaks.
    """
    left_context = left if isinstance(left, TaskContext) else TaskContext.from_dict(left)
    right_context = right if isinstance(right, TaskContext) else TaskContext.from_dict(right)

    same_scope = left_context.same_scope_as(right_context)

    if not same_scope and raise_error:
        raise TaskContextError(
            "Context scope mismatch. Refusing to mix user/workspace data."
        )

    return same_scope


__all__ = [
    "TaskContext",
    "TaskContextError",
    "create_task_context",
    "ensure_task_context",
    "context_from_request_like",
    "merge_context_metadata",
    "require_same_scope",
    "DEFAULT_ROLE",
    "DEFAULT_PLAN",
    "DEFAULT_SOURCE",
    "DEFAULT_CHANNEL",
    "SUPPORTED_ROLES",
    "SUPPORTED_PLANS",
]