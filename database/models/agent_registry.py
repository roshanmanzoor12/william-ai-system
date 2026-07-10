"""
database/models/agent_registry.py

William / Jarvis Multi-Agent AI SaaS System
Agent Registry Model & Registry Service

Purpose:
- Store agent metadata
- Track agent versions
- Store capabilities
- Manage enabled / disabled flags
- Support plugin-style future agents
- Enforce SaaS user_id / workspace_id isolation for agent access
- Prepare Security Agent approval payloads
- Prepare Verification Agent confirmation payloads
- Prepare Memory Agent compatible context payloads
- Provide safe structured responses
- Provide audit logging hooks for sensitive/state-changing actions

Author: Digital Promotix
"""

from __future__ import annotations

import json
import logging
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union

try:
    from sqlalchemy import (
        Boolean,
        Column,
        DateTime,
        Index,
        Integer,
        String,
        Text,
        UniqueConstraint,
    )
    from sqlalchemy.orm import Session
except Exception as exc:  # pragma: no cover
    raise ImportError(
        "SQLAlchemy is required for database/models/agent_registry.py. "
        "Install it with: pip install sqlalchemy"
    ) from exc


# ---------------------------------------------------------------------
# Safe Base Import
# ---------------------------------------------------------------------

try:
    from database.db import Base
except Exception:  # pragma: no cover
    try:
        from sqlalchemy.orm import declarative_base

        Base = declarative_base()
    except Exception as exc:
        raise ImportError(
            "Could not import SQLAlchemy Base. Ensure database/db.py exists "
            "or SQLAlchemy is installed correctly."
        ) from exc


# ---------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------

logger = logging.getLogger("william.database.models.agent_registry")

if not logger.handlers:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

logger.setLevel(os.getenv("AGENT_REGISTRY_LOG_LEVEL", "INFO"))


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

UTC = timezone.utc

DEFAULT_SYSTEM_USER_ID = "system"
DEFAULT_SYSTEM_WORKSPACE_ID = "system"

AGENT_STATUS_ACTIVE = "active"
AGENT_STATUS_DISABLED = "disabled"
AGENT_STATUS_DEPRECATED = "deprecated"
AGENT_STATUS_MAINTENANCE = "maintenance"

VALID_AGENT_STATUSES = {
    AGENT_STATUS_ACTIVE,
    AGENT_STATUS_DISABLED,
    AGENT_STATUS_DEPRECATED,
    AGENT_STATUS_MAINTENANCE,
}

DEFAULT_PLAN_TIERS = {
    "free": 0,
    "starter": 1,
    "growth": 2,
    "pro": 3,
    "business": 4,
    "enterprise": 5,
    "admin": 99,
    "system": 100,
}

DEFAULT_CORE_AGENTS = (
    "master",
    "voice",
    "system",
    "browser",
    "code",
    "memory",
    "security",
    "verification",
    "visual",
    "workflow",
    "hologram",
    "call",
    "business",
    "finance",
    "creator",
)


# ---------------------------------------------------------------------
# Utility Helpers
# ---------------------------------------------------------------------

def _utc_now() -> datetime:
    return datetime.now(UTC)


def _iso_now() -> str:
    return _utc_now().isoformat()


def _new_id(prefix: str = "agent_registry") -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def _safe_json_dumps(value: Any) -> str:
    try:
        return json.dumps(value if value is not None else {}, ensure_ascii=False, sort_keys=True)
    except TypeError:
        return json.dumps({"raw": str(value)}, ensure_ascii=False, sort_keys=True)


def _safe_json_loads(value: Optional[str], fallback: Any) -> Any:
    if value in (None, ""):
        return fallback

    try:
        return json.loads(value)
    except Exception:
        return fallback


def _normalize_slug(value: str) -> str:
    cleaned = str(value or "").strip().lower()
    cleaned = re.sub(r"[^a-z0-9_\\-\\s]", "", cleaned)
    cleaned = re.sub(r"\\s+", "_", cleaned)
    cleaned = cleaned.replace("-", "_")
    cleaned = re.sub(r"_+", "_", cleaned).strip("_")
    return cleaned


def _normalize_version(value: Optional[str]) -> str:
    version = str(value or "1.0.0").strip()
    if not version:
        return "1.0.0"
    return version[:50]


def _normalize_list(values: Optional[Union[str, Sequence[str]]]) -> List[str]:
    if values is None:
        return []

    if isinstance(values, str):
        raw_items = [item.strip() for item in values.split(",")]
    else:
        raw_items = [str(item).strip() for item in values]

    return sorted({item for item in raw_items if item})


def _normalize_dict(value: Optional[Union[str, Dict[str, Any]]]) -> Dict[str, Any]:
    if value is None:
        return {}

    if isinstance(value, dict):
        return value

    if isinstance(value, str):
        loaded = _safe_json_loads(value, {})
        return loaded if isinstance(loaded, dict) else {}

    return {}


def _mask_sensitive_metadata(metadata: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not metadata:
        return {}

    sensitive_keys = {
        "secret",
        "token",
        "api_key",
        "apikey",
        "password",
        "private_key",
        "access_token",
        "refresh_token",
    }

    clean: Dict[str, Any] = {}

    for key, value in metadata.items():
        key_lower = str(key).lower()
        if any(secret_key in key_lower for secret_key in sensitive_keys):
            clean[key] = "***masked***"
        elif isinstance(value, dict):
            clean[key] = _mask_sensitive_metadata(value)
        else:
            clean[key] = value

    return clean


# ---------------------------------------------------------------------
# Safe Integration Stubs
# ---------------------------------------------------------------------

class SecurityAgentStub:
    """
    Fallback security approval adapter.

    A real Security Agent can be injected later.
    """

    def authorize(self, **kwargs: Any) -> bool:
        logger.warning("SecurityAgentStub used. Approval allowed. kwargs=%s", kwargs)
        return True


class AuditLoggerStub:
    """
    Fallback audit logger.

    A real Audit Log service can be injected later.
    """

    def record(self, **kwargs: Any) -> None:
        logger.info("[AUDIT] %s", kwargs)


class MemoryAgentStub:
    """
    Fallback Memory Agent adapter.

    A real Memory Agent can be injected later.
    """

    def prepare_context(self, **kwargs: Any) -> Dict[str, Any]:
        return {
            "memory_ready": True,
            "payload": kwargs,
            "timestamp": _iso_now(),
        }


class VerificationAgentStub:
    """
    Fallback Verification Agent adapter.

    A real Verification Agent can be injected later.
    """

    def prepare_confirmation(self, **kwargs: Any) -> Dict[str, Any]:
        return {
            "verification_ready": True,
            "payload": kwargs,
            "timestamp": _iso_now(),
        }


# ---------------------------------------------------------------------
# ORM Model
# ---------------------------------------------------------------------

class AgentRegistry(Base):
    """
    SQLAlchemy model for registered William/Jarvis agents.

    This stores:
    - agent name / slug
    - version
    - capabilities
    - enabled flags
    - plan requirements
    - role requirements
    - workspace/user ownership
    - plugin metadata
    - health/status metadata

    Important:
    - user_id and workspace_id keep tenant-specific overrides isolated.
    - system-level agents use user_id='system' and workspace_id='system'.
    """

    __tablename__ = "agent_registry"

    id = Column(String(80), primary_key=True, default=lambda: _new_id("agent"))
    user_id = Column(String(80), nullable=False, index=True, default=DEFAULT_SYSTEM_USER_ID)
    workspace_id = Column(String(80), nullable=False, index=True, default=DEFAULT_SYSTEM_WORKSPACE_ID)

    agent_key = Column(String(120), nullable=False, index=True)
    agent_name = Column(String(160), nullable=False)
    display_name = Column(String(180), nullable=False)

    description = Column(Text, nullable=False, default="")
    version = Column(String(50), nullable=False, default="1.0.0")
    module_path = Column(String(255), nullable=False, default="")
    class_name = Column(String(160), nullable=False, default="")

    capabilities_json = Column(Text, nullable=False, default="[]")
    required_roles_json = Column(Text, nullable=False, default="[]")
    required_permissions_json = Column(Text, nullable=False, default="[]")
    metadata_json = Column(Text, nullable=False, default="{}")

    minimum_plan = Column(String(50), nullable=False, default="free")
    status = Column(String(40), nullable=False, default=AGENT_STATUS_ACTIVE)

    is_enabled = Column(Boolean, nullable=False, default=True)
    is_core_agent = Column(Boolean, nullable=False, default=False)
    is_public = Column(Boolean, nullable=False, default=False)
    requires_security_approval = Column(Boolean, nullable=False, default=True)
    requires_verification = Column(Boolean, nullable=False, default=True)
    memory_enabled = Column(Boolean, nullable=False, default=True)

    execution_priority = Column(Integer, nullable=False, default=100)
    max_concurrent_tasks = Column(Integer, nullable=False, default=1)

    last_heartbeat_at = Column(DateTime(timezone=True), nullable=True)
    last_loaded_at = Column(DateTime(timezone=True), nullable=True)
    last_error = Column(Text, nullable=False, default="")

    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now)
    disabled_at = Column(DateTime(timezone=True), nullable=True)
    deleted_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "user_id",
            "workspace_id",
            "agent_key",
            "version",
            name="uq_agent_registry_tenant_key_version",
        ),
        Index("ix_agent_registry_tenant_enabled", "user_id", "workspace_id", "is_enabled"),
        Index("ix_agent_registry_key_status", "agent_key", "status"),
    )

    # -----------------------------------------------------------------
    # JSON Properties
    # -----------------------------------------------------------------

    @property
    def capabilities(self) -> List[str]:
        data = _safe_json_loads(self.capabilities_json, [])
        return _normalize_list(data if isinstance(data, list) else [])

    @capabilities.setter
    def capabilities(self, value: Optional[Union[str, Sequence[str]]]) -> None:
        self.capabilities_json = _safe_json_dumps(_normalize_list(value))

    @property
    def required_roles(self) -> List[str]:
        data = _safe_json_loads(self.required_roles_json, [])
        return _normalize_list(data if isinstance(data, list) else [])

    @required_roles.setter
    def required_roles(self, value: Optional[Union[str, Sequence[str]]]) -> None:
        self.required_roles_json = _safe_json_dumps(_normalize_list(value))

    @property
    def required_permissions(self) -> List[str]:
        data = _safe_json_loads(self.required_permissions_json, [])
        return _normalize_list(data if isinstance(data, list) else [])

    @required_permissions.setter
    def required_permissions(self, value: Optional[Union[str, Sequence[str]]]) -> None:
        self.required_permissions_json = _safe_json_dumps(_normalize_list(value))

    @property
    def metadata(self) -> Dict[str, Any]:
        data = _safe_json_loads(self.metadata_json, {})
        return data if isinstance(data, dict) else {}

    @metadata.setter
    def metadata(self, value: Optional[Union[str, Dict[str, Any]]]) -> None:
        self.metadata_json = _safe_json_dumps(_mask_sensitive_metadata(_normalize_dict(value)))

    # -----------------------------------------------------------------
    # Model Helpers
    # -----------------------------------------------------------------

    def is_available(self) -> bool:
        return (
            bool(self.is_enabled)
            and self.status == AGENT_STATUS_ACTIVE
            and self.deleted_at is None
        )

    def mark_loaded(self) -> None:
        self.last_loaded_at = _utc_now()
        self.last_error = ""
        self.updated_at = _utc_now()

    def mark_heartbeat(self) -> None:
        self.last_heartbeat_at = _utc_now()
        self.updated_at = _utc_now()

    def mark_error(self, error: Any) -> None:
        self.last_error = str(error or "")[:4000]
        self.updated_at = _utc_now()

    def enable(self) -> None:
        self.is_enabled = True
        self.status = AGENT_STATUS_ACTIVE
        self.disabled_at = None
        self.updated_at = _utc_now()

    def disable(self, reason: Optional[str] = None) -> None:
        self.is_enabled = False
        self.status = AGENT_STATUS_DISABLED
        self.disabled_at = _utc_now()
        if reason:
            meta = self.metadata
            meta["disabled_reason"] = str(reason)[:1000]
            self.metadata = meta
        self.updated_at = _utc_now()

    def soft_delete(self, reason: Optional[str] = None) -> None:
        self.is_enabled = False
        self.deleted_at = _utc_now()
        self.status = AGENT_STATUS_DISABLED
        if reason:
            meta = self.metadata
            meta["delete_reason"] = str(reason)[:1000]
            self.metadata = meta
        self.updated_at = _utc_now()

    def to_dict(self, include_internal: bool = False) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "id": self.id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "agent_key": self.agent_key,
            "agent_name": self.agent_name,
            "display_name": self.display_name,
            "description": self.description,
            "version": self.version,
            "capabilities": self.capabilities,
            "required_roles": self.required_roles,
            "required_permissions": self.required_permissions,
            "minimum_plan": self.minimum_plan,
            "status": self.status,
            "is_enabled": self.is_enabled,
            "is_core_agent": self.is_core_agent,
            "is_public": self.is_public,
            "requires_security_approval": self.requires_security_approval,
            "requires_verification": self.requires_verification,
            "memory_enabled": self.memory_enabled,
            "execution_priority": self.execution_priority,
            "max_concurrent_tasks": self.max_concurrent_tasks,
            "last_heartbeat_at": self.last_heartbeat_at.isoformat() if self.last_heartbeat_at else None,
            "last_loaded_at": self.last_loaded_at.isoformat() if self.last_loaded_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "disabled_at": self.disabled_at.isoformat() if self.disabled_at else None,
            "deleted_at": self.deleted_at.isoformat() if self.deleted_at else None,
        }

        if include_internal:
            data.update(
                {
                    "module_path": self.module_path,
                    "class_name": self.class_name,
                    "metadata": self.metadata,
                    "last_error": self.last_error,
                }
            )

        return data

    def __repr__(self) -> str:
        return (
            f"<AgentRegistry agent_key={self.agent_key!r} "
            f"version={self.version!r} enabled={self.is_enabled!r}>"
        )


# ---------------------------------------------------------------------
# Registry Service
# ---------------------------------------------------------------------

class AgentRegistryService:
    """
    Service layer for AgentRegistry.

    This allows API/dashboard/MasterAgent usage without putting business
    logic directly inside routes.

    All user/workspace-specific access requires user_id and workspace_id.
    """

    def __init__(
        self,
        security_agent: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        plan_tiers: Optional[Dict[str, int]] = None,
    ) -> None:
        self.security_agent = security_agent or SecurityAgentStub()
        self.audit_logger = audit_logger or AuditLoggerStub()
        self.memory_agent = memory_agent or MemoryAgentStub()
        self.verification_agent = verification_agent or VerificationAgentStub()
        self.plan_tiers = plan_tiers or DEFAULT_PLAN_TIERS.copy()

    # -----------------------------------------------------------------
    # Structured Responses
    # -----------------------------------------------------------------

    def _success(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": metadata or {},
            "timestamp": _iso_now(),
        }

    def _error(
        self,
        message: str,
        error: Any = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "success": False,
            "message": message,
            "data": {},
            "error": str(error) if error else None,
            "metadata": metadata or {},
            "timestamp": _iso_now(),
        }

    # -----------------------------------------------------------------
    # Context / Access Validation
    # -----------------------------------------------------------------

    def validate_context(
        self,
        user_id: Optional[str],
        workspace_id: Optional[str],
    ) -> bool:
        return bool(str(user_id or "").strip()) and bool(str(workspace_id or "").strip())

    def _normalize_actor_context(
        self,
        user_id: Optional[str],
        workspace_id: Optional[str],
    ) -> Tuple[str, str]:
        return (
            str(user_id or DEFAULT_SYSTEM_USER_ID).strip(),
            str(workspace_id or DEFAULT_SYSTEM_WORKSPACE_ID).strip(),
        )

    def _plan_rank(self, plan: Optional[str]) -> int:
        return self.plan_tiers.get(str(plan or "free").lower(), 0)

    def _has_plan_access(
        self,
        user_plan: Optional[str],
        required_plan: Optional[str],
    ) -> bool:
        return self._plan_rank(user_plan) >= self._plan_rank(required_plan)

    def _has_role_access(
        self,
        user_roles: Optional[Sequence[str]],
        required_roles: Optional[Sequence[str]],
    ) -> bool:
        required = set(_normalize_list(required_roles))
        if not required:
            return True

        owned = set(_normalize_list(user_roles))
        return bool(required.intersection(owned)) or "admin" in owned or "owner" in owned

    def _has_permission_access(
        self,
        user_permissions: Optional[Sequence[str]],
        required_permissions: Optional[Sequence[str]],
    ) -> bool:
        required = set(_normalize_list(required_permissions))
        if not required:
            return True

        owned = set(_normalize_list(user_permissions))
        return required.issubset(owned) or "*" in owned or "admin:*" in owned

    def check_agent_access(
        self,
        agent: AgentRegistry,
        user_id: str,
        workspace_id: str,
        user_plan: Optional[str] = "free",
        user_roles: Optional[Sequence[str]] = None,
        user_permissions: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        """
        Check whether a user/workspace can access an agent.
        """
        if not self.validate_context(user_id, workspace_id):
            return self._error("Invalid SaaS context. user_id and workspace_id are required.")

        if not agent.is_available():
            return self._error(
                "Agent is not available.",
                metadata={"agent_key": agent.agent_key, "status": agent.status},
            )

        is_same_tenant = agent.user_id == user_id and agent.workspace_id == workspace_id
        is_system_agent = (
            agent.user_id == DEFAULT_SYSTEM_USER_ID
            and agent.workspace_id == DEFAULT_SYSTEM_WORKSPACE_ID
        )
        is_public_agent = bool(agent.is_public)

        if not (is_same_tenant or is_system_agent or is_public_agent):
            return self._error(
                "Agent access denied due to workspace isolation.",
                metadata={
                    "agent_key": agent.agent_key,
                    "requested_user_id": user_id,
                    "requested_workspace_id": workspace_id,
                },
            )

        if not self._has_plan_access(user_plan, agent.minimum_plan):
            return self._error(
                "Agent access denied by subscription plan.",
                metadata={
                    "agent_key": agent.agent_key,
                    "required_plan": agent.minimum_plan,
                    "user_plan": user_plan,
                },
            )

        if not self._has_role_access(user_roles, agent.required_roles):
            return self._error(
                "Agent access denied by role requirement.",
                metadata={
                    "agent_key": agent.agent_key,
                    "required_roles": agent.required_roles,
                    "user_roles": _normalize_list(user_roles),
                },
            )

        if not self._has_permission_access(user_permissions, agent.required_permissions):
            return self._error(
                "Agent access denied by permission requirement.",
                metadata={
                    "agent_key": agent.agent_key,
                    "required_permissions": agent.required_permissions,
                    "user_permissions": _normalize_list(user_permissions),
                },
            )

        return self._success(
            "Agent access granted.",
            data={"agent": agent.to_dict(include_internal=False)},
        )

    # -----------------------------------------------------------------
    # Integration Payloads
    # -----------------------------------------------------------------

    def _request_security_approval(
        self,
        action: str,
        user_id: str,
        workspace_id: str,
        agent_key: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        try:
            return bool(
                self.security_agent.authorize(
                    action=action,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    agent_key=agent_key,
                    metadata=_mask_sensitive_metadata(metadata or {}),
                    timestamp=_iso_now(),
                )
            )
        except Exception as exc:
            logger.exception("Security approval failed for action=%s", action)
            logger.error("Security error: %s", exc)
            return False

    def _audit(
        self,
        action: str,
        user_id: str,
        workspace_id: str,
        agent_key: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        try:
            self.audit_logger.record(
                action=action,
                user_id=user_id,
                workspace_id=workspace_id,
                agent_key=agent_key,
                metadata=_mask_sensitive_metadata(metadata or {}),
                timestamp=_iso_now(),
            )
        except Exception as exc:
            logger.exception("Audit logging failed for action=%s", action)
            logger.error("Audit error: %s", exc)

    def _memory_payload(
        self,
        action: str,
        user_id: str,
        workspace_id: str,
        agent: Optional[AgentRegistry] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        payload = {
            "source": "agent_registry",
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "agent": agent.to_dict(include_internal=False) if agent else None,
            "metadata": _mask_sensitive_metadata(metadata or {}),
            "timestamp": _iso_now(),
        }

        try:
            return self.memory_agent.prepare_context(**payload)
        except Exception:
            return payload

    def _verification_payload(
        self,
        action: str,
        user_id: str,
        workspace_id: str,
        agent: Optional[AgentRegistry] = None,
        result: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        payload = {
            "source": "agent_registry",
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "agent": agent.to_dict(include_internal=False) if agent else None,
            "result": result or {},
            "timestamp": _iso_now(),
        }

        try:
            return self.verification_agent.prepare_confirmation(**payload)
        except Exception:
            return payload

    # -----------------------------------------------------------------
    # Query Helpers
    # -----------------------------------------------------------------

    def get_agent(
        self,
        db: Session,
        agent_key: str,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        version: Optional[str] = None,
        include_system: bool = True,
        include_deleted: bool = False,
    ) -> Optional[AgentRegistry]:
        normalized_key = _normalize_slug(agent_key)

        if not normalized_key:
            return None

        query = db.query(AgentRegistry).filter(AgentRegistry.agent_key == normalized_key)

        if version:
            query = query.filter(AgentRegistry.version == _normalize_version(version))

        if not include_deleted:
            query = query.filter(AgentRegistry.deleted_at.is_(None))

        if user_id and workspace_id:
            tenant_user_id = str(user_id).strip()
            tenant_workspace_id = str(workspace_id).strip()

            tenant_query = query.filter(
                AgentRegistry.user_id == tenant_user_id,
                AgentRegistry.workspace_id == tenant_workspace_id,
            ).order_by(AgentRegistry.updated_at.desc())

            agent = tenant_query.first()
            if agent:
                return agent

        if include_system:
            return (
                query.filter(
                    AgentRegistry.user_id == DEFAULT_SYSTEM_USER_ID,
                    AgentRegistry.workspace_id == DEFAULT_SYSTEM_WORKSPACE_ID,
                )
                .order_by(AgentRegistry.updated_at.desc())
                .first()
            )

        return query.order_by(AgentRegistry.updated_at.desc()).first()

    def list_agents(
        self,
        db: Session,
        user_id: str,
        workspace_id: str,
        user_plan: Optional[str] = "free",
        user_roles: Optional[Sequence[str]] = None,
        user_permissions: Optional[Sequence[str]] = None,
        enabled_only: bool = True,
        include_system: bool = True,
        include_internal: bool = False,
        capability: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        if not self.validate_context(user_id, workspace_id):
            return self._error("Invalid SaaS context. user_id and workspace_id are required.")

        safe_limit = max(1, min(int(limit or 100), 500))

        try:
            query = db.query(AgentRegistry).filter(AgentRegistry.deleted_at.is_(None))

            if enabled_only:
                query = query.filter(AgentRegistry.is_enabled.is_(True))

            if status:
                query = query.filter(AgentRegistry.status == str(status).strip())

            tenant_filters = [
                (AgentRegistry.user_id == user_id)
                & (AgentRegistry.workspace_id == workspace_id)
            ]

            if include_system:
                tenant_filters.append(
                    (AgentRegistry.user_id == DEFAULT_SYSTEM_USER_ID)
                    & (AgentRegistry.workspace_id == DEFAULT_SYSTEM_WORKSPACE_ID)
                )

            query = query.filter(tenant_filters[0] if len(tenant_filters) == 1 else tenant_filters[0] | tenant_filters[1])
            query = query.order_by(AgentRegistry.execution_priority.asc(), AgentRegistry.agent_key.asc())
            rows = query.limit(safe_limit).all()

            filtered_agents: List[Dict[str, Any]] = []
            denied_agents: List[Dict[str, Any]] = []

            wanted_capability = str(capability or "").strip()

            for agent in rows:
                if wanted_capability and wanted_capability not in agent.capabilities:
                    continue

                access = self.check_agent_access(
                    agent=agent,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    user_plan=user_plan,
                    user_roles=user_roles,
                    user_permissions=user_permissions,
                )

                if access["success"]:
                    filtered_agents.append(agent.to_dict(include_internal=include_internal))
                else:
                    denied_agents.append(
                        {
                            "agent_key": agent.agent_key,
                            "reason": access["message"],
                            "metadata": access.get("metadata", {}),
                        }
                    )

            result = {
                "agents": filtered_agents,
                "count": len(filtered_agents),
                "denied_count": len(denied_agents),
                "denied": denied_agents,
            }

            return self._success(
                "Agents listed successfully.",
                data=result,
                metadata={
                    "memory_payload": self._memory_payload(
                        action="list_agents",
                        user_id=user_id,
                        workspace_id=workspace_id,
                        metadata={"count": len(filtered_agents)},
                    ),
                    "verification_payload": self._verification_payload(
                        action="list_agents",
                        user_id=user_id,
                        workspace_id=workspace_id,
                        result=result,
                    ),
                },
            )

        except Exception as exc:
            logger.exception("Failed to list agents.")
            return self._error("Failed to list agents.", exc)

    # -----------------------------------------------------------------
    # Registration / Updates
    # -----------------------------------------------------------------

    def register_agent(
        self,
        db: Session,
        agent_key: str,
        agent_name: str,
        display_name: Optional[str] = None,
        description: str = "",
        version: str = "1.0.0",
        module_path: str = "",
        class_name: str = "",
        capabilities: Optional[Sequence[str]] = None,
        required_roles: Optional[Sequence[str]] = None,
        required_permissions: Optional[Sequence[str]] = None,
        minimum_plan: str = "free",
        metadata: Optional[Dict[str, Any]] = None,
        user_id: Optional[str] = DEFAULT_SYSTEM_USER_ID,
        workspace_id: Optional[str] = DEFAULT_SYSTEM_WORKSPACE_ID,
        is_enabled: bool = True,
        is_core_agent: bool = False,
        is_public: bool = False,
        requires_security_approval: bool = True,
        requires_verification: bool = True,
        memory_enabled: bool = True,
        execution_priority: int = 100,
        max_concurrent_tasks: int = 1,
        actor_user_id: Optional[str] = None,
        actor_workspace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Register or update an agent.

        This is state-changing, so it routes through Security Agent and audit.
        """
        tenant_user_id, tenant_workspace_id = self._normalize_actor_context(user_id, workspace_id)
        actor_user, actor_workspace = self._normalize_actor_context(actor_user_id, actor_workspace_id)

        normalized_key = _normalize_slug(agent_key)
        normalized_version = _normalize_version(version)

        if not normalized_key:
            return self._error("agent_key is required.")

        if not str(agent_name or "").strip():
            return self._error("agent_name is required.")

        if not self.validate_context(tenant_user_id, tenant_workspace_id):
            return self._error("Invalid target SaaS context.")

        if not self.validate_context(actor_user, actor_workspace):
            return self._error("Invalid actor SaaS context.")

        if not self._request_security_approval(
            action="agent_registry.register_agent",
            user_id=actor_user,
            workspace_id=actor_workspace,
            agent_key=normalized_key,
            metadata={
                "target_user_id": tenant_user_id,
                "target_workspace_id": tenant_workspace_id,
                "version": normalized_version,
                "is_core_agent": is_core_agent,
                "is_public": is_public,
            },
        ):
            return self._error("Security approval denied for agent registration.")

        try:
            agent = (
                db.query(AgentRegistry)
                .filter(
                    AgentRegistry.user_id == tenant_user_id,
                    AgentRegistry.workspace_id == tenant_workspace_id,
                    AgentRegistry.agent_key == normalized_key,
                    AgentRegistry.version == normalized_version,
                )
                .first()
            )

            created = False

            if not agent:
                created = True
                agent = AgentRegistry(
                    id=_new_id("agent"),
                    user_id=tenant_user_id,
                    workspace_id=tenant_workspace_id,
                    agent_key=normalized_key,
                    version=normalized_version,
                )
                db.add(agent)

            agent.agent_name = str(agent_name).strip()
            agent.display_name = str(display_name or agent_name).strip()
            agent.description = str(description or "").strip()
            agent.module_path = str(module_path or "").strip()
            agent.class_name = str(class_name or "").strip()
            agent.capabilities = capabilities or []
            agent.required_roles = required_roles or []
            agent.required_permissions = required_permissions or []
            agent.minimum_plan = str(minimum_plan or "free").strip().lower()
            agent.metadata = metadata or {}
            agent.is_enabled = bool(is_enabled)
            agent.is_core_agent = bool(is_core_agent)
            agent.is_public = bool(is_public)
            agent.requires_security_approval = bool(requires_security_approval)
            agent.requires_verification = bool(requires_verification)
            agent.memory_enabled = bool(memory_enabled)
            agent.execution_priority = int(execution_priority or 100)
            agent.max_concurrent_tasks = max(1, int(max_concurrent_tasks or 1))
            agent.status = AGENT_STATUS_ACTIVE if is_enabled else AGENT_STATUS_DISABLED
            agent.disabled_at = None if is_enabled else _utc_now()
            agent.updated_at = _utc_now()

            db.commit()
            db.refresh(agent)

            action = "agent_registry.created" if created else "agent_registry.updated"

            self._audit(
                action=action,
                user_id=actor_user,
                workspace_id=actor_workspace,
                agent_key=agent.agent_key,
                metadata={
                    "agent_id": agent.id,
                    "target_user_id": tenant_user_id,
                    "target_workspace_id": tenant_workspace_id,
                    "version": agent.version,
                    "created": created,
                },
            )

            result = {
                "agent": agent.to_dict(include_internal=True),
                "created": created,
            }

            return self._success(
                "Agent registered successfully." if created else "Agent updated successfully.",
                data=result,
                metadata={
                    "memory_payload": self._memory_payload(
                        action=action,
                        user_id=actor_user,
                        workspace_id=actor_workspace,
                        agent=agent,
                        metadata={"created": created},
                    ),
                    "verification_payload": self._verification_payload(
                        action=action,
                        user_id=actor_user,
                        workspace_id=actor_workspace,
                        agent=agent,
                        result=result,
                    ),
                },
            )

        except Exception as exc:
            db.rollback()
            logger.exception("Failed to register agent.")
            return self._error("Failed to register agent.", exc)

    def set_agent_enabled(
        self,
        db: Session,
        agent_key: str,
        enabled: bool,
        user_id: str,
        workspace_id: str,
        reason: Optional[str] = None,
        version: Optional[str] = None,
        actor_user_id: Optional[str] = None,
        actor_workspace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Enable or disable an agent for a workspace.
        """
        actor_user, actor_workspace = self._normalize_actor_context(actor_user_id or user_id, actor_workspace_id or workspace_id)

        if not self.validate_context(user_id, workspace_id):
            return self._error("Invalid SaaS context. user_id and workspace_id are required.")

        normalized_key = _normalize_slug(agent_key)

        if not normalized_key:
            return self._error("agent_key is required.")

        action = "agent_registry.enable_agent" if enabled else "agent_registry.disable_agent"

        if not self._request_security_approval(
            action=action,
            user_id=actor_user,
            workspace_id=actor_workspace,
            agent_key=normalized_key,
            metadata={
                "target_user_id": user_id,
                "target_workspace_id": workspace_id,
                "enabled": enabled,
                "reason": reason,
            },
        ):
            return self._error("Security approval denied for agent enabled flag update.")

        try:
            agent = self.get_agent(
                db=db,
                agent_key=normalized_key,
                user_id=user_id,
                workspace_id=workspace_id,
                version=version,
                include_system=False,
            )

            if not agent:
                return self._error("Agent not found in this workspace.")

            if enabled:
                agent.enable()
            else:
                agent.disable(reason=reason)

            db.commit()
            db.refresh(agent)

            self._audit(
                action=action,
                user_id=actor_user,
                workspace_id=actor_workspace,
                agent_key=agent.agent_key,
                metadata={
                    "agent_id": agent.id,
                    "enabled": enabled,
                    "reason": reason,
                },
            )

            result = {"agent": agent.to_dict(include_internal=True)}

            return self._success(
                "Agent enabled successfully." if enabled else "Agent disabled successfully.",
                data=result,
                metadata={
                    "memory_payload": self._memory_payload(
                        action=action,
                        user_id=actor_user,
                        workspace_id=actor_workspace,
                        agent=agent,
                        metadata={"enabled": enabled, "reason": reason},
                    ),
                    "verification_payload": self._verification_payload(
                        action=action,
                        user_id=actor_user,
                        workspace_id=actor_workspace,
                        agent=agent,
                        result=result,
                    ),
                },
            )

        except Exception as exc:
            db.rollback()
            logger.exception("Failed to update agent enabled flag.")
            return self._error("Failed to update agent enabled flag.", exc)

    def update_agent_capabilities(
        self,
        db: Session,
        agent_key: str,
        capabilities: Sequence[str],
        user_id: str,
        workspace_id: str,
        version: Optional[str] = None,
        actor_user_id: Optional[str] = None,
        actor_workspace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Update capabilities for a workspace-owned agent.
        """
        actor_user, actor_workspace = self._normalize_actor_context(actor_user_id or user_id, actor_workspace_id or workspace_id)

        if not self.validate_context(user_id, workspace_id):
            return self._error("Invalid SaaS context. user_id and workspace_id are required.")

        normalized_key = _normalize_slug(agent_key)

        if not normalized_key:
            return self._error("agent_key is required.")

        normalized_capabilities = _normalize_list(capabilities)

        if not self._request_security_approval(
            action="agent_registry.update_capabilities",
            user_id=actor_user,
            workspace_id=actor_workspace,
            agent_key=normalized_key,
            metadata={"capabilities": normalized_capabilities},
        ):
            return self._error("Security approval denied for capability update.")

        try:
            agent = self.get_agent(
                db=db,
                agent_key=normalized_key,
                user_id=user_id,
                workspace_id=workspace_id,
                version=version,
                include_system=False,
            )

            if not agent:
                return self._error("Agent not found in this workspace.")

            agent.capabilities = normalized_capabilities
            agent.updated_at = _utc_now()

            db.commit()
            db.refresh(agent)

            self._audit(
                action="agent_registry.update_capabilities",
                user_id=actor_user,
                workspace_id=actor_workspace,
                agent_key=agent.agent_key,
                metadata={
                    "agent_id": agent.id,
                    "capabilities": normalized_capabilities,
                },
            )

            result = {"agent": agent.to_dict(include_internal=True)}

            return self._success(
                "Agent capabilities updated successfully.",
                data=result,
                metadata={
                    "memory_payload": self._memory_payload(
                        action="agent_registry.update_capabilities",
                        user_id=actor_user,
                        workspace_id=actor_workspace,
                        agent=agent,
                        metadata={"capabilities": normalized_capabilities},
                    ),
                    "verification_payload": self._verification_payload(
                        action="agent_registry.update_capabilities",
                        user_id=actor_user,
                        workspace_id=actor_workspace,
                        agent=agent,
                        result=result,
                    ),
                },
            )

        except Exception as exc:
            db.rollback()
            logger.exception("Failed to update agent capabilities.")
            return self._error("Failed to update agent capabilities.", exc)

    def record_heartbeat(
        self,
        db: Session,
        agent_key: str,
        user_id: str,
        workspace_id: str,
        version: Optional[str] = None,
        health_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Record an agent heartbeat.
        """
        if not self.validate_context(user_id, workspace_id):
            return self._error("Invalid SaaS context. user_id and workspace_id are required.")

        normalized_key = _normalize_slug(agent_key)

        if not normalized_key:
            return self._error("agent_key is required.")

        try:
            agent = self.get_agent(
                db=db,
                agent_key=normalized_key,
                user_id=user_id,
                workspace_id=workspace_id,
                version=version,
                include_system=True,
            )

            if not agent:
                return self._error("Agent not found.")

            access = self.check_agent_access(
                agent=agent,
                user_id=user_id,
                workspace_id=workspace_id,
                user_plan="system",
                user_roles=["system"],
                user_permissions=["*"],
            )

            if not access["success"]:
                return access

            agent.mark_heartbeat()

            if health_metadata:
                meta = agent.metadata
                meta["last_health"] = _mask_sensitive_metadata(health_metadata)
                agent.metadata = meta

            db.commit()
            db.refresh(agent)

            result = {"agent": agent.to_dict(include_internal=True)}

            return self._success(
                "Agent heartbeat recorded successfully.",
                data=result,
                metadata={
                    "verification_payload": self._verification_payload(
                        action="agent_registry.heartbeat",
                        user_id=user_id,
                        workspace_id=workspace_id,
                        agent=agent,
                        result=result,
                    )
                },
            )

        except Exception as exc:
            db.rollback()
            logger.exception("Failed to record agent heartbeat.")
            return self._error("Failed to record agent heartbeat.", exc)

    def mark_agent_loaded(
        self,
        db: Session,
        agent_key: str,
        user_id: str,
        workspace_id: str,
        version: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Mark an agent as successfully loaded by the registry/plugin loader.
        """
        if not self.validate_context(user_id, workspace_id):
            return self._error("Invalid SaaS context. user_id and workspace_id are required.")

        normalized_key = _normalize_slug(agent_key)

        try:
            agent = self.get_agent(
                db=db,
                agent_key=normalized_key,
                user_id=user_id,
                workspace_id=workspace_id,
                version=version,
                include_system=True,
            )

            if not agent:
                return self._error("Agent not found.")

            agent.mark_loaded()
            db.commit()
            db.refresh(agent)

            result = {"agent": agent.to_dict(include_internal=True)}

            return self._success(
                "Agent marked as loaded.",
                data=result,
                metadata={
                    "verification_payload": self._verification_payload(
                        action="agent_registry.loaded",
                        user_id=user_id,
                        workspace_id=workspace_id,
                        agent=agent,
                        result=result,
                    )
                },
            )

        except Exception as exc:
            db.rollback()
            logger.exception("Failed to mark agent loaded.")
            return self._error("Failed to mark agent loaded.", exc)

    def mark_agent_error(
        self,
        db: Session,
        agent_key: str,
        error: Any,
        user_id: str,
        workspace_id: str,
        version: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Store last error for an agent safely.
        """
        if not self.validate_context(user_id, workspace_id):
            return self._error("Invalid SaaS context. user_id and workspace_id are required.")

        normalized_key = _normalize_slug(agent_key)

        try:
            agent = self.get_agent(
                db=db,
                agent_key=normalized_key,
                user_id=user_id,
                workspace_id=workspace_id,
                version=version,
                include_system=True,
            )

            if not agent:
                return self._error("Agent not found.")

            agent.mark_error(error)
            db.commit()
            db.refresh(agent)

            result = {"agent": agent.to_dict(include_internal=True)}

            return self._success(
                "Agent error recorded.",
                data=result,
                metadata={
                    "verification_payload": self._verification_payload(
                        action="agent_registry.error",
                        user_id=user_id,
                        workspace_id=workspace_id,
                        agent=agent,
                        result={"error": str(error)},
                    )
                },
            )

        except Exception as exc:
            db.rollback()
            logger.exception("Failed to record agent error.")
            return self._error("Failed to record agent error.", exc)

    def soft_delete_agent(
        self,
        db: Session,
        agent_key: str,
        user_id: str,
        workspace_id: str,
        reason: Optional[str] = None,
        version: Optional[str] = None,
        actor_user_id: Optional[str] = None,
        actor_workspace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Soft delete an agent from a workspace.

        Core system agents should not be deleted from normal workspace flow.
        """
        actor_user, actor_workspace = self._normalize_actor_context(actor_user_id or user_id, actor_workspace_id or workspace_id)

        if not self.validate_context(user_id, workspace_id):
            return self._error("Invalid SaaS context. user_id and workspace_id are required.")

        normalized_key = _normalize_slug(agent_key)

        if not self._request_security_approval(
            action="agent_registry.soft_delete_agent",
            user_id=actor_user,
            workspace_id=actor_workspace,
            agent_key=normalized_key,
            metadata={"reason": reason},
        ):
            return self._error("Security approval denied for agent deletion.")

        try:
            agent = self.get_agent(
                db=db,
                agent_key=normalized_key,
                user_id=user_id,
                workspace_id=workspace_id,
                version=version,
                include_system=False,
            )

            if not agent:
                return self._error("Agent not found in this workspace.")

            if agent.is_core_agent:
                return self._error("Core agents cannot be deleted through this workflow.")

            agent.soft_delete(reason=reason)
            db.commit()
            db.refresh(agent)

            self._audit(
                action="agent_registry.soft_delete_agent",
                user_id=actor_user,
                workspace_id=actor_workspace,
                agent_key=agent.agent_key,
                metadata={
                    "agent_id": agent.id,
                    "reason": reason,
                },
            )

            result = {"agent": agent.to_dict(include_internal=True)}

            return self._success(
                "Agent deleted safely.",
                data=result,
                metadata={
                    "memory_payload": self._memory_payload(
                        action="agent_registry.soft_delete_agent",
                        user_id=actor_user,
                        workspace_id=actor_workspace,
                        agent=agent,
                        metadata={"reason": reason},
                    ),
                    "verification_payload": self._verification_payload(
                        action="agent_registry.soft_delete_agent",
                        user_id=actor_user,
                        workspace_id=actor_workspace,
                        agent=agent,
                        result=result,
                    ),
                },
            )

        except Exception as exc:
            db.rollback()
            logger.exception("Failed to delete agent.")
            return self._error("Failed to delete agent.", exc)

    # -----------------------------------------------------------------
    # Core Agent Seeding
    # -----------------------------------------------------------------

    def seed_core_agents(
        self,
        db: Session,
        actor_user_id: str = DEFAULT_SYSTEM_USER_ID,
        actor_workspace_id: str = DEFAULT_SYSTEM_WORKSPACE_ID,
    ) -> Dict[str, Any]:
        """
        Seed the 15 core William/Jarvis agents:
        Master + 14 agents.

        This is safe to run multiple times.
        """
        if not self.validate_context(actor_user_id, actor_workspace_id):
            return self._error("Invalid actor SaaS context.")

        if not self._request_security_approval(
            action="agent_registry.seed_core_agents",
            user_id=actor_user_id,
            workspace_id=actor_workspace_id,
            metadata={"core_agents": list(DEFAULT_CORE_AGENTS)},
        ):
            return self._error("Security approval denied for seeding core agents.")

        seeded: List[Dict[str, Any]] = []
        failed: List[Dict[str, Any]] = []

        core_agent_definitions = {
            "master": {
                "display_name": "Master Agent",
                "description": "Central routing, planning, orchestration, and delegation agent.",
                "capabilities": ["routing", "planning", "delegation", "orchestration"],
                "execution_priority": 1,
            },
            "voice": {
                "display_name": "Voice Agent",
                "description": "Handles speech input, voice output, and live voice interaction workflows.",
                "capabilities": ["speech_to_text", "text_to_speech", "voice_commands"],
                "execution_priority": 20,
            },
            "system": {
                "display_name": "System Agent",
                "description": "Handles safe system operations, app control requests, and device-level coordination.",
                "capabilities": ["system_control", "device_actions", "app_launch"],
                "execution_priority": 30,
            },
            "browser": {
                "display_name": "Browser Agent",
                "description": "Handles safe browser automation and web task coordination.",
                "capabilities": ["browser_automation", "web_navigation", "web_research"],
                "execution_priority": 40,
            },
            "code": {
                "display_name": "Code Agent",
                "description": "Handles code analysis, generation, repair, and development workflows.",
                "capabilities": ["code_generation", "code_review", "debugging"],
                "execution_priority": 50,
            },
            "memory": {
                "display_name": "Memory Agent",
                "description": "Handles user/workspace isolated memory storage, recall, and context preparation.",
                "capabilities": ["memory_write", "memory_read", "context_recall"],
                "execution_priority": 10,
            },
            "security": {
                "display_name": "Security Agent",
                "description": "Approves sensitive actions and enforces permission boundaries.",
                "capabilities": ["approval", "policy_check", "risk_scoring"],
                "execution_priority": 5,
            },
            "verification": {
                "display_name": "Verification Agent",
                "description": "Confirms task completion and validates completed action payloads.",
                "capabilities": ["verification", "confirmation", "quality_check"],
                "execution_priority": 6,
            },
            "visual": {
                "display_name": "Visual Agent",
                "description": "Handles image understanding, visual tasks, and design assistance.",
                "capabilities": ["image_analysis", "visual_reasoning", "design_review"],
                "execution_priority": 60,
            },
            "workflow": {
                "display_name": "Workflow Agent",
                "description": "Handles automation workflows, recurring processes, and task chains.",
                "capabilities": ["workflow_automation", "task_chains", "scheduling"],
                "execution_priority": 70,
            },
            "hologram": {
                "display_name": "Hologram Agent",
                "description": "Handles futuristic visual interface and hologram-style presentation workflows.",
                "capabilities": ["hologram_ui", "presentation_mode", "immersive_display"],
                "execution_priority": 90,
            },
            "call": {
                "display_name": "Call Agent",
                "description": "Handles call workflows, call summaries, and call-related automation.",
                "capabilities": ["call_handling", "call_summary", "call_workflows"],
                "execution_priority": 80,
            },
            "business": {
                "display_name": "Business Agent",
                "description": "Handles business planning, proposals, sales, operations, and growth workflows.",
                "capabilities": ["business_strategy", "sales", "proposal_generation"],
                "execution_priority": 55,
            },
            "finance": {
                "display_name": "Finance Agent",
                "description": "Handles finance workflows, reports, estimates, and business financial analysis.",
                "capabilities": ["finance_analysis", "budgeting", "reporting"],
                "execution_priority": 65,
            },
            "creator": {
                "display_name": "Creator Agent",
                "description": "Handles content creation, marketing assets, scripts, and creative workflows.",
                "capabilities": ["content_creation", "creative_strategy", "marketing_assets"],
                "execution_priority": 75,
            },
        }

        for agent_key, config in core_agent_definitions.items():
            response = self.register_agent(
                db=db,
                agent_key=agent_key,
                agent_name=f"{agent_key.title()}Agent",
                display_name=config["display_name"],
                description=config["description"],
                version="1.0.0",
                module_path=f"agents.{agent_key}_agent",
                class_name=f"{agent_key.title().replace('_', '')}Agent",
                capabilities=config["capabilities"],
                required_roles=["owner", "admin"],
                required_permissions=[f"agent:{agent_key}:use"],
                minimum_plan="free",
                metadata={
                    "seeded_by": "agent_registry.seed_core_agents",
                    "core_agent": True,
                },
                user_id=DEFAULT_SYSTEM_USER_ID,
                workspace_id=DEFAULT_SYSTEM_WORKSPACE_ID,
                is_enabled=True,
                is_core_agent=True,
                is_public=False,
                requires_security_approval=True,
                requires_verification=True,
                memory_enabled=True,
                execution_priority=config["execution_priority"],
                max_concurrent_tasks=1,
                actor_user_id=actor_user_id,
                actor_workspace_id=actor_workspace_id,
            )

            if response["success"]:
                seeded.append(response["data"]["agent"])
            else:
                failed.append(
                    {
                        "agent_key": agent_key,
                        "error": response["error"],
                        "message": response["message"],
                    }
                )

        result = {
            "seeded_count": len(seeded),
            "failed_count": len(failed),
            "seeded": seeded,
            "failed": failed,
        }

        self._audit(
            action="agent_registry.seed_core_agents",
            user_id=actor_user_id,
            workspace_id=actor_workspace_id,
            metadata={
                "seeded_count": len(seeded),
                "failed_count": len(failed),
            },
        )

        return self._success(
            "Core agents seeded successfully." if not failed else "Core agents seeded with some failures.",
            data=result,
            metadata={
                "memory_payload": self._memory_payload(
                    action="agent_registry.seed_core_agents",
                    user_id=actor_user_id,
                    workspace_id=actor_workspace_id,
                    metadata=result,
                ),
                "verification_payload": self._verification_payload(
                    action="agent_registry.seed_core_agents",
                    user_id=actor_user_id,
                    workspace_id=actor_workspace_id,
                    result=result,
                ),
            },
        )


# ---------------------------------------------------------------------
# Module-Level Service Singleton
# ---------------------------------------------------------------------

agent_registry_service = AgentRegistryService()


# ---------------------------------------------------------------------
# Convenience Functions
# ---------------------------------------------------------------------

def register_agent(
    db: Session,
    agent_key: str,
    agent_name: str,
    **kwargs: Any,
) -> Dict[str, Any]:
    return agent_registry_service.register_agent(
        db=db,
        agent_key=agent_key,
        agent_name=agent_name,
        **kwargs,
    )


def list_agents(
    db: Session,
    user_id: str,
    workspace_id: str,
    **kwargs: Any,
) -> Dict[str, Any]:
    return agent_registry_service.list_agents(
        db=db,
        user_id=user_id,
        workspace_id=workspace_id,
        **kwargs,
    )


def get_agent(
    db: Session,
    agent_key: str,
    user_id: Optional[str] = None,
    workspace_id: Optional[str] = None,
    **kwargs: Any,
) -> Optional[AgentRegistry]:
    return agent_registry_service.get_agent(
        db=db,
        agent_key=agent_key,
        user_id=user_id,
        workspace_id=workspace_id,
        **kwargs,
    )


def set_agent_enabled(
    db: Session,
    agent_key: str,
    enabled: bool,
    user_id: str,
    workspace_id: str,
    **kwargs: Any,
) -> Dict[str, Any]:
    return agent_registry_service.set_agent_enabled(
        db=db,
        agent_key=agent_key,
        enabled=enabled,
        user_id=user_id,
        workspace_id=workspace_id,
        **kwargs,
    )


def update_agent_capabilities(
    db: Session,
    agent_key: str,
    capabilities: Sequence[str],
    user_id: str,
    workspace_id: str,
    **kwargs: Any,
) -> Dict[str, Any]:
    return agent_registry_service.update_agent_capabilities(
        db=db,
        agent_key=agent_key,
        capabilities=capabilities,
        user_id=user_id,
        workspace_id=workspace_id,
        **kwargs,
    )


def record_agent_heartbeat(
    db: Session,
    agent_key: str,
    user_id: str,
    workspace_id: str,
    **kwargs: Any,
) -> Dict[str, Any]:
    return agent_registry_service.record_heartbeat(
        db=db,
        agent_key=agent_key,
        user_id=user_id,
        workspace_id=workspace_id,
        **kwargs,
    )


def seed_core_agents(
    db: Session,
    actor_user_id: str = DEFAULT_SYSTEM_USER_ID,
    actor_workspace_id: str = DEFAULT_SYSTEM_WORKSPACE_ID,
) -> Dict[str, Any]:
    return agent_registry_service.seed_core_agents(
        db=db,
        actor_user_id=actor_user_id,
        actor_workspace_id=actor_workspace_id,
    )


__all__ = [
    "AgentRegistry",
    "AgentRegistryService",
    "agent_registry_service",
    "register_agent",
    "list_agents",
    "get_agent",
    "set_agent_enabled",
    "update_agent_capabilities",
    "record_agent_heartbeat",
    "seed_core_agents",
    "AGENT_STATUS_ACTIVE",
    "AGENT_STATUS_DISABLED",
    "AGENT_STATUS_DEPRECATED",
    "AGENT_STATUS_MAINTENANCE",
    "DEFAULT_CORE_AGENTS",
]