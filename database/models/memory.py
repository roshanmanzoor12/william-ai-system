"""
William / Jarvis Multi-Agent AI SaaS System
Database Model: Memory
File: database/models/memory.py

Purpose:
    Defines short-term, long-term, project, client, team, and vector memory records
    for the William/Jarvis multi-agent SaaS platform.

Core Guarantees:
    - Every memory record is isolated by user_id and workspace_id.
    - No memory is shared across users/workspaces unless explicitly scoped and authorized.
    - Sensitive memory actions can produce Security Agent review payloads.
    - Completed memory operations can produce Verification Agent payloads.
    - Memory entries are compatible with Memory Agent indexing, Master Agent routing,
      dashboard analytics, audit logging, and future vector search integration.
    - This file imports safely even if future project files are not created yet.
"""

from __future__ import annotations

import enum
import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    Float,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON

try:
    from database.db import Base
except Exception:  # pragma: no cover
    from sqlalchemy.orm import declarative_base

    Base = declarative_base()


def utc_now() -> datetime:
    """
    Return a timezone-aware UTC datetime.
    """
    return datetime.now(timezone.utc)


def generate_uuid() -> str:
    """
    Generate a stable UUID string for primary keys.
    """
    return str(uuid.uuid4())


def safe_json_dumps(value: Any) -> str:
    """
    Convert a value into a safe JSON string.
    """
    try:
        return json.dumps(value, default=str, ensure_ascii=False, sort_keys=True)
    except TypeError:
        return json.dumps({"value": str(value)}, ensure_ascii=False, sort_keys=True)


def normalize_text(value: Optional[str]) -> str:
    """
    Normalize user-provided text for safe storage and searching.
    """
    if value is None:
        return ""
    return " ".join(str(value).strip().split())


def stable_hash(*parts: Any) -> str:
    """
    Create a deterministic SHA-256 hash for deduplication and integrity checks.
    """
    raw = "::".join(normalize_text(str(part)) for part in parts if part is not None)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class MemoryScope(str, enum.Enum):
    """
    Scope controls who or what a memory belongs to.
    """

    USER = "user"
    WORKSPACE = "workspace"
    PROJECT = "project"
    CLIENT = "client"
    TEAM = "team"
    AGENT = "agent"
    SYSTEM = "system"


class MemoryType(str, enum.Enum):
    """
    Type defines the kind of memory being stored.
    """

    SHORT_TERM = "short_term"
    LONG_TERM = "long_term"
    PROJECT = "project"
    CLIENT = "client"
    TEAM = "team"
    VECTOR = "vector"


class MemoryStatus(str, enum.Enum):
    """
    Status controls lifecycle and visibility of a memory item.
    """

    ACTIVE = "active"
    ARCHIVED = "archived"
    DELETED = "deleted"
    EXPIRED = "expired"
    PENDING_REVIEW = "pending_review"
    REJECTED = "rejected"


class MemorySensitivity(str, enum.Enum):
    """
    Sensitivity helps Security Agent decide whether review is required.
    """

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    SENSITIVE = "sensitive"
    RESTRICTED = "restricted"


class MemorySource(str, enum.Enum):
    """
    Source identifies where the memory came from.
    """

    USER_INPUT = "user_input"
    AGENT_OUTPUT = "agent_output"
    TASK_RESULT = "task_result"
    FILE_CONTEXT = "file_context"
    EMAIL_CONTEXT = "email_context"
    CALENDAR_CONTEXT = "calendar_context"
    DASHBOARD_NOTE = "dashboard_note"
    API_IMPORT = "api_import"
    SYSTEM_GENERATED = "system_generated"


class MemoryImportance(str, enum.Enum):
    """
    Importance assists ranking, summarization, and retention decisions.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Memory(Base):
    """
    Memory table for William/Jarvis.

    Stores isolated memory entries for:
        - Short-term memory
        - Long-term memory
        - Project memory
        - Client memory
        - Team memory
        - Vector memory metadata

    Vector storage strategy:
        This model stores vector metadata, embedding provider/model info,
        vector dimension, vector text, and optional embedding JSON for lightweight
        deployments. Production deployments can point `vector_ref` to a dedicated
        vector database record such as pgvector, Pinecone, Weaviate, Qdrant, or
        Milvus without changing the rest of the app.
    """

    __tablename__ = "memories"

    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
        default=generate_uuid,
        nullable=False,
    )

    user_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
        doc="Owner user ID. Required for strict SaaS isolation.",
    )

    workspace_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
        doc="Owner workspace ID. Required for strict SaaS isolation.",
    )

    memory_type: Mapped[MemoryType] = mapped_column(
        Enum(MemoryType, name="memory_type_enum"),
        nullable=False,
        default=MemoryType.SHORT_TERM,
        index=True,
    )

    scope: Mapped[MemoryScope] = mapped_column(
        Enum(MemoryScope, name="memory_scope_enum"),
        nullable=False,
        default=MemoryScope.USER,
        index=True,
    )

    status: Mapped[MemoryStatus] = mapped_column(
        Enum(MemoryStatus, name="memory_status_enum"),
        nullable=False,
        default=MemoryStatus.ACTIVE,
        index=True,
    )

    sensitivity: Mapped[MemorySensitivity] = mapped_column(
        Enum(MemorySensitivity, name="memory_sensitivity_enum"),
        nullable=False,
        default=MemorySensitivity.INTERNAL,
        index=True,
    )

    source: Mapped[MemorySource] = mapped_column(
        Enum(MemorySource, name="memory_source_enum"),
        nullable=False,
        default=MemorySource.USER_INPUT,
        index=True,
    )

    importance: Mapped[MemoryImportance] = mapped_column(
        Enum(MemoryImportance, name="memory_importance_enum"),
        nullable=False,
        default=MemoryImportance.MEDIUM,
        index=True,
    )

    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        default="Untitled Memory",
    )

    content: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="",
    )

    summary: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    keywords: Mapped[Optional[List[str]]] = mapped_column(
        JSON,
        nullable=True,
        default=list,
        doc="Searchable keyword list generated by Memory Agent or system logic.",
    )

    tags: Mapped[Optional[List[str]]] = mapped_column(
        JSON,
        nullable=True,
        default=list,
        doc="Human or agent-provided tags.",
    )

    metadata_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True,
        default=dict,
        doc="Safe extensible metadata. Never store raw secrets here.",
    )

    project_id: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        index=True,
        doc="Optional project scope ID.",
    )

    client_id: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        index=True,
        doc="Optional client scope ID.",
    )

    team_id: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        index=True,
        doc="Optional team scope ID.",
    )

    task_id: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        index=True,
        doc="Optional task that produced or used this memory.",
    )

    agent_name: Mapped[Optional[str]] = mapped_column(
        String(120),
        nullable=True,
        index=True,
        doc="Agent associated with the memory entry.",
    )

    agent_id: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        index=True,
        doc="Optional future registry/plugin agent ID.",
    )

    conversation_id: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        index=True,
    )

    message_id: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        index=True,
    )

    source_ref: Mapped[Optional[str]] = mapped_column(
        String(512),
        nullable=True,
        doc="Safe source reference, such as task ID, file ID, or external object reference.",
    )

    content_hash: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        index=True,
        default="",
        doc="Stable hash used for deduplication and integrity checks.",
    )

    dedupe_key: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        index=True,
        doc="Optional caller-provided key for preventing duplicate memory entries.",
    )

    vector_ref: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        index=True,
        doc="External vector database reference ID.",
    )

    vector_namespace: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        index=True,
        doc="Vector database namespace, usually workspace/user scoped.",
    )

    embedding_provider: Mapped[Optional[str]] = mapped_column(
        String(120),
        nullable=True,
        doc="Embedding provider name loaded from config/environment by caller.",
    )

    embedding_model: Mapped[Optional[str]] = mapped_column(
        String(160),
        nullable=True,
        doc="Embedding model name loaded from config/environment by caller.",
    )

    embedding_dimension: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
    )

    embedding_json: Mapped[Optional[List[float]]] = mapped_column(
        JSON,
        nullable=True,
        doc="Optional small/local embedding storage. Prefer dedicated vector DB in production.",
    )

    similarity_score: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
        doc="Runtime/search score when returned by retrieval. Not required for persistence.",
    )

    token_count: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
    )

    access_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    revision: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
    )

    is_pinned: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        index=True,
    )

    is_favorite: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        index=True,
    )

    is_user_editable: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )

    requires_security_review: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        index=True,
    )

    security_review_status: Mapped[Optional[str]] = mapped_column(
        String(80),
        nullable=True,
        index=True,
        doc="pending, approved, rejected, not_required, or future Security Agent status.",
    )

    security_review_reason: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    verification_status: Mapped[Optional[str]] = mapped_column(
        String(80),
        nullable=True,
        index=True,
        doc="pending, verified, failed, not_required, or future Verification Agent status.",
    )

    verification_payload_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True,
        default=dict,
    )

    audit_trace_id: Mapped[Optional[str]] = mapped_column(
        String(120),
        nullable=True,
        index=True,
    )

    created_by: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        index=True,
    )

    updated_by: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        index=True,
    )

    archived_by: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )

    deleted_by: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )

    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
    )

    last_accessed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        index=True,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
        index=True,
    )

    archived_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    deleted_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    __table_args__ = (
        Index(
            "ix_memories_workspace_user_type_status",
            "workspace_id",
            "user_id",
            "memory_type",
            "status",
        ),
        Index(
            "ix_memories_workspace_scope_entities",
            "workspace_id",
            "scope",
            "project_id",
            "client_id",
            "team_id",
        ),
        Index(
            "ix_memories_vector_lookup",
            "workspace_id",
            "user_id",
            "vector_namespace",
            "vector_ref",
        ),
        Index(
            "ix_memories_agent_task",
            "workspace_id",
            "agent_name",
            "task_id",
        ),
        UniqueConstraint(
            "workspace_id",
            "user_id",
            "dedupe_key",
            name="uq_memories_workspace_user_dedupe_key",
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<Memory id={self.id!r} user_id={self.user_id!r} "
            f"workspace_id={self.workspace_id!r} type={self.memory_type.value!r} "
            f"status={self.status.value!r}>"
        )

    @classmethod
    def create_short_term(
        cls,
        *,
        user_id: str,
        workspace_id: str,
        title: str,
        content: str,
        task_id: Optional[str] = None,
        agent_name: Optional[str] = None,
        metadata_json: Optional[Dict[str, Any]] = None,
    ) -> "Memory":
        """
        Create a short-term memory entry.
        """
        return cls.create_memory(
            user_id=user_id,
            workspace_id=workspace_id,
            memory_type=MemoryType.SHORT_TERM,
            scope=MemoryScope.USER,
            title=title,
            content=content,
            task_id=task_id,
            agent_name=agent_name,
            metadata_json=metadata_json,
            importance=MemoryImportance.MEDIUM,
            sensitivity=MemorySensitivity.INTERNAL,
            source=MemorySource.AGENT_OUTPUT if agent_name else MemorySource.USER_INPUT,
        )

    @classmethod
    def create_long_term(
        cls,
        *,
        user_id: str,
        workspace_id: str,
        title: str,
        content: str,
        importance: MemoryImportance = MemoryImportance.HIGH,
        source: MemorySource = MemorySource.USER_INPUT,
        metadata_json: Optional[Dict[str, Any]] = None,
    ) -> "Memory":
        """
        Create a long-term memory entry.
        """
        return cls.create_memory(
            user_id=user_id,
            workspace_id=workspace_id,
            memory_type=MemoryType.LONG_TERM,
            scope=MemoryScope.USER,
            title=title,
            content=content,
            importance=importance,
            source=source,
            metadata_json=metadata_json,
        )

    @classmethod
    def create_project_memory(
        cls,
        *,
        user_id: str,
        workspace_id: str,
        project_id: str,
        title: str,
        content: str,
        agent_name: Optional[str] = None,
        metadata_json: Optional[Dict[str, Any]] = None,
    ) -> "Memory":
        """
        Create a project-scoped memory entry.
        """
        return cls.create_memory(
            user_id=user_id,
            workspace_id=workspace_id,
            memory_type=MemoryType.PROJECT,
            scope=MemoryScope.PROJECT,
            project_id=project_id,
            title=title,
            content=content,
            agent_name=agent_name,
            metadata_json=metadata_json,
            importance=MemoryImportance.HIGH,
        )

    @classmethod
    def create_client_memory(
        cls,
        *,
        user_id: str,
        workspace_id: str,
        client_id: str,
        title: str,
        content: str,
        sensitivity: MemorySensitivity = MemorySensitivity.CONFIDENTIAL,
        metadata_json: Optional[Dict[str, Any]] = None,
    ) -> "Memory":
        """
        Create a client-scoped memory entry.
        """
        return cls.create_memory(
            user_id=user_id,
            workspace_id=workspace_id,
            memory_type=MemoryType.CLIENT,
            scope=MemoryScope.CLIENT,
            client_id=client_id,
            title=title,
            content=content,
            sensitivity=sensitivity,
            metadata_json=metadata_json,
            importance=MemoryImportance.HIGH,
        )

    @classmethod
    def create_team_memory(
        cls,
        *,
        user_id: str,
        workspace_id: str,
        team_id: str,
        title: str,
        content: str,
        metadata_json: Optional[Dict[str, Any]] = None,
    ) -> "Memory":
        """
        Create a team-scoped memory entry.
        """
        return cls.create_memory(
            user_id=user_id,
            workspace_id=workspace_id,
            memory_type=MemoryType.TEAM,
            scope=MemoryScope.TEAM,
            team_id=team_id,
            title=title,
            content=content,
            metadata_json=metadata_json,
            importance=MemoryImportance.MEDIUM,
        )

    @classmethod
    def create_vector_memory(
        cls,
        *,
        user_id: str,
        workspace_id: str,
        title: str,
        content: str,
        vector_ref: Optional[str] = None,
        vector_namespace: Optional[str] = None,
        embedding_provider: Optional[str] = None,
        embedding_model: Optional[str] = None,
        embedding_dimension: Optional[int] = None,
        embedding_json: Optional[List[float]] = None,
        metadata_json: Optional[Dict[str, Any]] = None,
    ) -> "Memory":
        """
        Create a vector-ready memory entry.
        """
        provider = embedding_provider or os.getenv("WILLIAM_EMBEDDING_PROVIDER", "local")
        model = embedding_model or os.getenv("WILLIAM_EMBEDDING_MODEL", "default")

        return cls.create_memory(
            user_id=user_id,
            workspace_id=workspace_id,
            memory_type=MemoryType.VECTOR,
            scope=MemoryScope.USER,
            title=title,
            content=content,
            vector_ref=vector_ref,
            vector_namespace=vector_namespace or cls.build_vector_namespace(
                workspace_id=workspace_id,
                user_id=user_id,
            ),
            embedding_provider=provider,
            embedding_model=model,
            embedding_dimension=embedding_dimension,
            embedding_json=embedding_json,
            metadata_json=metadata_json,
            importance=MemoryImportance.HIGH,
        )

    @classmethod
    def create_memory(
        cls,
        *,
        user_id: str,
        workspace_id: str,
        title: str,
        content: str,
        memory_type: MemoryType,
        scope: MemoryScope,
        status: MemoryStatus = MemoryStatus.ACTIVE,
        sensitivity: MemorySensitivity = MemorySensitivity.INTERNAL,
        source: MemorySource = MemorySource.USER_INPUT,
        importance: MemoryImportance = MemoryImportance.MEDIUM,
        summary: Optional[str] = None,
        keywords: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        metadata_json: Optional[Dict[str, Any]] = None,
        project_id: Optional[str] = None,
        client_id: Optional[str] = None,
        team_id: Optional[str] = None,
        task_id: Optional[str] = None,
        agent_name: Optional[str] = None,
        agent_id: Optional[str] = None,
        conversation_id: Optional[str] = None,
        message_id: Optional[str] = None,
        source_ref: Optional[str] = None,
        dedupe_key: Optional[str] = None,
        vector_ref: Optional[str] = None,
        vector_namespace: Optional[str] = None,
        embedding_provider: Optional[str] = None,
        embedding_model: Optional[str] = None,
        embedding_dimension: Optional[int] = None,
        embedding_json: Optional[List[float]] = None,
        token_count: Optional[int] = None,
        created_by: Optional[str] = None,
        expires_at: Optional[datetime] = None,
    ) -> "Memory":
        """
        Factory method that validates isolation and builds a complete Memory object.
        """
        safe_user_id = normalize_text(user_id)
        safe_workspace_id = normalize_text(workspace_id)
        safe_title = normalize_text(title) or "Untitled Memory"
        safe_content = normalize_text(content)

        if not safe_user_id:
            raise ValueError("Memory requires user_id for SaaS isolation.")
        if not safe_workspace_id:
            raise ValueError("Memory requires workspace_id for SaaS isolation.")
        if not safe_content:
            raise ValueError("Memory content cannot be empty.")

        hash_value = stable_hash(
            safe_workspace_id,
            safe_user_id,
            memory_type.value,
            scope.value,
            project_id,
            client_id,
            team_id,
            safe_title,
            safe_content,
        )

        calculated_dedupe_key = dedupe_key or hash_value

        requires_review = cls.should_require_security_review(
            sensitivity=sensitivity,
            content=safe_content,
            metadata_json=metadata_json,
        )

        verification_payload = {
            "memory_id": None,
            "user_id": safe_user_id,
            "workspace_id": safe_workspace_id,
            "memory_type": memory_type.value,
            "scope": scope.value,
            "status": status.value,
            "content_hash": hash_value,
            "created_at": utc_now().isoformat(),
            "requires_security_review": requires_review,
        }

        return cls(
            user_id=safe_user_id,
            workspace_id=safe_workspace_id,
            memory_type=memory_type,
            scope=scope,
            status=status,
            sensitivity=sensitivity,
            source=source,
            importance=importance,
            title=safe_title,
            content=safe_content,
            summary=normalize_text(summary) if summary else None,
            keywords=cls.normalize_string_list(keywords),
            tags=cls.normalize_string_list(tags),
            metadata_json=cls.safe_metadata(metadata_json),
            project_id=normalize_text(project_id) or None,
            client_id=normalize_text(client_id) or None,
            team_id=normalize_text(team_id) or None,
            task_id=normalize_text(task_id) or None,
            agent_name=normalize_text(agent_name) or None,
            agent_id=normalize_text(agent_id) or None,
            conversation_id=normalize_text(conversation_id) or None,
            message_id=normalize_text(message_id) or None,
            source_ref=normalize_text(source_ref) or None,
            content_hash=hash_value,
            dedupe_key=calculated_dedupe_key,
            vector_ref=normalize_text(vector_ref) or None,
            vector_namespace=normalize_text(vector_namespace) or None,
            embedding_provider=normalize_text(embedding_provider) or None,
            embedding_model=normalize_text(embedding_model) or None,
            embedding_dimension=embedding_dimension,
            embedding_json=embedding_json,
            token_count=token_count,
            created_by=normalize_text(created_by) or safe_user_id,
            updated_by=normalize_text(created_by) or safe_user_id,
            requires_security_review=requires_review,
            security_review_status="pending" if requires_review else "not_required",
            verification_status="pending",
            verification_payload_json=verification_payload,
            expires_at=expires_at,
        )

    @staticmethod
    def normalize_string_list(values: Optional[Sequence[str]]) -> List[str]:
        """
        Normalize a string sequence into a clean unique list.
        """
        if not values:
            return []

        cleaned: List[str] = []
        seen = set()

        for value in values:
            item = normalize_text(value)
            lowered = item.lower()
            if item and lowered not in seen:
                cleaned.append(item)
                seen.add(lowered)

        return cleaned

    @staticmethod
    def safe_metadata(metadata_json: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Clean metadata before storage and avoid obvious secret leakage.
        """
        if not metadata_json:
            return {}

        blocked_keys = {
            "password",
            "secret",
            "api_key",
            "apikey",
            "token",
            "access_token",
            "refresh_token",
            "private_key",
            "authorization",
            "cookie",
            "session",
        }

        safe: Dict[str, Any] = {}

        for key, value in metadata_json.items():
            clean_key = normalize_text(str(key))
            lowered = clean_key.lower()

            if lowered in blocked_keys or any(blocked in lowered for blocked in blocked_keys):
                safe[clean_key] = "[REDACTED]"
            else:
                safe[clean_key] = value

        return safe

    @staticmethod
    def build_vector_namespace(*, workspace_id: str, user_id: str) -> str:
        """
        Build a vector namespace that protects SaaS isolation.
        """
        safe_workspace_id = normalize_text(workspace_id)
        safe_user_id = normalize_text(user_id)

        if not safe_workspace_id:
            raise ValueError("workspace_id is required to build vector namespace.")
        if not safe_user_id:
            raise ValueError("user_id is required to build vector namespace.")

        return f"workspace:{safe_workspace_id}:user:{safe_user_id}"

    @staticmethod
    def should_require_security_review(
        *,
        sensitivity: MemorySensitivity,
        content: str,
        metadata_json: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Decide whether memory should be reviewed by Security Agent.
        """
        if sensitivity in {
            MemorySensitivity.SENSITIVE,
            MemorySensitivity.RESTRICTED,
            MemorySensitivity.CONFIDENTIAL,
        }:
            return True

        lowered_content = content.lower()
        risky_terms = {
            "password",
            "secret key",
            "api key",
            "private key",
            "access token",
            "refresh token",
            "credit card",
            "bank account",
            "ssn",
            "social security",
            "otp",
            "two factor",
            "2fa",
        }

        if any(term in lowered_content for term in risky_terms):
            return True

        if metadata_json:
            metadata_blob = safe_json_dumps(metadata_json).lower()
            if any(term in metadata_blob for term in risky_terms):
                return True

        return False

    def assert_same_tenant(self, *, user_id: str, workspace_id: str) -> None:
        """
        Enforce strict user/workspace isolation.
        """
        if self.user_id != normalize_text(user_id):
            raise PermissionError("Memory access denied: user_id mismatch.")
        if self.workspace_id != normalize_text(workspace_id):
            raise PermissionError("Memory access denied: workspace_id mismatch.")

    def can_be_accessed_by(
        self,
        *,
        user_id: str,
        workspace_id: str,
        role: Optional[str] = None,
        plan: Optional[str] = None,
        allowed_agent_names: Optional[Sequence[str]] = None,
        requesting_agent_name: Optional[str] = None,
    ) -> bool:
        """
        Check if a caller can access this memory.

        This method is intentionally local and import-safe.
        API/service layers can add deeper subscription/role checks later.
        """
        if self.user_id != normalize_text(user_id):
            return False

        if self.workspace_id != normalize_text(workspace_id):
            return False

        if self.status in {MemoryStatus.DELETED, MemoryStatus.REJECTED}:
            return False

        if self.expires_at and self.expires_at <= utc_now():
            return False

        normalized_role = normalize_text(role).lower()
        normalized_plan = normalize_text(plan).lower()

        if self.sensitivity == MemorySensitivity.RESTRICTED:
            if normalized_role not in {"owner", "admin", "security_admin"}:
                return False

        if self.memory_type == MemoryType.VECTOR:
            if normalized_plan in {"free", "starter_limited"}:
                return False

        if requesting_agent_name and allowed_agent_names is not None:
            allowed = {normalize_text(name).lower() for name in allowed_agent_names}
            if normalize_text(requesting_agent_name).lower() not in allowed:
                return False

        return True

    def update_content(
        self,
        *,
        new_content: str,
        updated_by: str,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Update memory content safely and return an audit-friendly response.
        """
        clean_content = normalize_text(new_content)
        clean_updated_by = normalize_text(updated_by)

        if not clean_content:
            raise ValueError("Updated memory content cannot be empty.")
        if not clean_updated_by:
            raise ValueError("updated_by is required for auditability.")
        if self.status == MemoryStatus.DELETED:
            raise ValueError("Deleted memory cannot be updated.")

        old_hash = self.content_hash

        self.content = clean_content
        self.content_hash = stable_hash(
            self.workspace_id,
            self.user_id,
            self.memory_type.value,
            self.scope.value,
            self.project_id,
            self.client_id,
            self.team_id,
            self.title,
            clean_content,
        )
        self.updated_by = clean_updated_by
        self.updated_at = utc_now()
        self.revision += 1
        self.requires_security_review = self.should_require_security_review(
            sensitivity=self.sensitivity,
            content=self.content,
            metadata_json=self.metadata_json,
        )
        self.security_review_status = "pending" if self.requires_security_review else "not_required"
        self.verification_status = "pending"
        self.verification_payload_json = self.build_verification_payload(
            action="memory.updated",
            actor_user_id=clean_updated_by,
            extra={
                "reason": normalize_text(reason) if reason else None,
                "old_content_hash": old_hash,
                "new_content_hash": self.content_hash,
            },
        )

        return self.structured_response(
            message="Memory updated successfully.",
            action="memory.updated",
        )

    def archive(
        self,
        *,
        archived_by: str,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Archive a memory item without deleting it.
        """
        actor = normalize_text(archived_by)
        if not actor:
            raise ValueError("archived_by is required for auditability.")

        self.status = MemoryStatus.ARCHIVED
        self.archived_by = actor
        self.archived_at = utc_now()
        self.updated_by = actor
        self.updated_at = utc_now()
        self.verification_status = "pending"
        self.verification_payload_json = self.build_verification_payload(
            action="memory.archived",
            actor_user_id=actor,
            extra={"reason": normalize_text(reason) if reason else None},
        )

        return self.structured_response(
            message="Memory archived successfully.",
            action="memory.archived",
        )

    def soft_delete(
        self,
        *,
        deleted_by: str,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Soft delete memory while preserving auditability.
        """
        actor = normalize_text(deleted_by)
        if not actor:
            raise ValueError("deleted_by is required for auditability.")

        self.status = MemoryStatus.DELETED
        self.deleted_by = actor
        self.deleted_at = utc_now()
        self.updated_by = actor
        self.updated_at = utc_now()
        self.verification_status = "pending"
        self.verification_payload_json = self.build_verification_payload(
            action="memory.deleted",
            actor_user_id=actor,
            extra={"reason": normalize_text(reason) if reason else None},
        )

        return self.structured_response(
            message="Memory deleted safely.",
            action="memory.deleted",
        )

    def mark_accessed(self, *, accessed_by: Optional[str] = None) -> Dict[str, Any]:
        """
        Track memory access for analytics and audit-friendly behavior.
        """
        self.access_count += 1
        self.last_accessed_at = utc_now()
        if accessed_by:
            self.updated_by = normalize_text(accessed_by)
        self.updated_at = utc_now()

        return self.structured_response(
            message="Memory access recorded.",
            action="memory.accessed",
        )

    def approve_security_review(
        self,
        *,
        reviewed_by: str,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Mark memory as approved by Security Agent or security reviewer.
        """
        actor = normalize_text(reviewed_by)
        if not actor:
            raise ValueError("reviewed_by is required.")

        self.security_review_status = "approved"
        self.security_review_reason = normalize_text(reason) if reason else "Approved."
        self.status = MemoryStatus.ACTIVE
        self.updated_by = actor
        self.updated_at = utc_now()

        return self.structured_response(
            message="Security review approved.",
            action="memory.security.approved",
        )

    def reject_security_review(
        self,
        *,
        reviewed_by: str,
        reason: str,
    ) -> Dict[str, Any]:
        """
        Mark memory as rejected by Security Agent or security reviewer.
        """
        actor = normalize_text(reviewed_by)
        clean_reason = normalize_text(reason)

        if not actor:
            raise ValueError("reviewed_by is required.")
        if not clean_reason:
            raise ValueError("Security rejection reason is required.")

        self.security_review_status = "rejected"
        self.security_review_reason = clean_reason
        self.status = MemoryStatus.REJECTED
        self.updated_by = actor
        self.updated_at = utc_now()

        return self.structured_response(
            message="Security review rejected.",
            action="memory.security.rejected",
        )

    def mark_verified(
        self,
        *,
        verified_by: str,
        notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Mark a memory operation as verified.
        """
        actor = normalize_text(verified_by)
        if not actor:
            raise ValueError("verified_by is required.")

        self.verification_status = "verified"
        self.updated_by = actor
        self.updated_at = utc_now()
        self.verification_payload_json = self.build_verification_payload(
            action="memory.verified",
            actor_user_id=actor,
            extra={"notes": normalize_text(notes) if notes else None},
        )

        return self.structured_response(
            message="Memory verification completed.",
            action="memory.verified",
        )

    def build_security_agent_payload(
        self,
        *,
        requested_action: str,
        actor_user_id: str,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Build payload for future Security Agent approval workflow.
        """
        return {
            "event": "security.review.memory",
            "requested_action": normalize_text(requested_action),
            "actor_user_id": normalize_text(actor_user_id),
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "memory_id": self.id,
            "memory_type": self.memory_type.value,
            "scope": self.scope.value,
            "sensitivity": self.sensitivity.value,
            "status": self.status.value,
            "title": self.title,
            "content_hash": self.content_hash,
            "requires_security_review": self.requires_security_review,
            "reason": normalize_text(reason) if reason else None,
            "created_at": utc_now().isoformat(),
            "metadata": self.safe_metadata(self.metadata_json),
        }

    def build_verification_payload(
        self,
        *,
        action: str,
        actor_user_id: str,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Build payload for future Verification Agent confirmation workflow.
        """
        payload = {
            "event": "verification.memory",
            "action": normalize_text(action),
            "actor_user_id": normalize_text(actor_user_id),
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "memory_id": self.id,
            "memory_type": self.memory_type.value,
            "scope": self.scope.value,
            "status": self.status.value,
            "content_hash": self.content_hash,
            "revision": self.revision,
            "timestamp": utc_now().isoformat(),
        }

        if extra:
            payload["extra"] = self.safe_metadata(extra)

        return payload

    def build_memory_agent_payload(self) -> Dict[str, Any]:
        """
        Build a Memory Agent compatible payload.
        """
        return {
            "memory_id": self.id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "memory_type": self.memory_type.value,
            "scope": self.scope.value,
            "status": self.status.value,
            "sensitivity": self.sensitivity.value,
            "source": self.source.value,
            "importance": self.importance.value,
            "title": self.title,
            "content": self.content,
            "summary": self.summary,
            "keywords": self.keywords or [],
            "tags": self.tags or [],
            "project_id": self.project_id,
            "client_id": self.client_id,
            "team_id": self.team_id,
            "task_id": self.task_id,
            "agent_name": self.agent_name,
            "vector": {
                "vector_ref": self.vector_ref,
                "vector_namespace": self.vector_namespace,
                "embedding_provider": self.embedding_provider,
                "embedding_model": self.embedding_model,
                "embedding_dimension": self.embedding_dimension,
                "has_embedding_json": bool(self.embedding_json),
            },
            "content_hash": self.content_hash,
            "metadata": self.safe_metadata(self.metadata_json),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }

    def build_master_agent_context(self) -> Dict[str, Any]:
        """
        Build compact context for Master Agent routing.
        """
        return {
            "memory_id": self.id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "type": self.memory_type.value,
            "scope": self.scope.value,
            "importance": self.importance.value,
            "title": self.title,
            "summary": self.summary or self.content[:500],
            "agent_name": self.agent_name,
            "project_id": self.project_id,
            "client_id": self.client_id,
            "team_id": self.team_id,
            "requires_security_review": self.requires_security_review,
            "security_review_status": self.security_review_status,
            "verification_status": self.verification_status,
        }

    def structured_response(
        self,
        *,
        message: str,
        action: str,
        success: bool = True,
    ) -> Dict[str, Any]:
        """
        Return a safe structured response for services, APIs, agents, and tests.
        """
        return {
            "success": success,
            "message": message,
            "action": action,
            "memory": {
                "id": self.id,
                "user_id": self.user_id,
                "workspace_id": self.workspace_id,
                "memory_type": self.memory_type.value,
                "scope": self.scope.value,
                "status": self.status.value,
                "sensitivity": self.sensitivity.value,
                "importance": self.importance.value,
                "title": self.title,
                "content_hash": self.content_hash,
                "revision": self.revision,
                "requires_security_review": self.requires_security_review,
                "security_review_status": self.security_review_status,
                "verification_status": self.verification_status,
                "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            },
        }

    def to_dict(
        self,
        *,
        include_content: bool = True,
        include_embedding: bool = False,
    ) -> Dict[str, Any]:
        """
        Serialize memory safely.
        """
        data = {
            "id": self.id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "memory_type": self.memory_type.value,
            "scope": self.scope.value,
            "status": self.status.value,
            "sensitivity": self.sensitivity.value,
            "source": self.source.value,
            "importance": self.importance.value,
            "title": self.title,
            "summary": self.summary,
            "keywords": self.keywords or [],
            "tags": self.tags or [],
            "metadata_json": self.safe_metadata(self.metadata_json),
            "project_id": self.project_id,
            "client_id": self.client_id,
            "team_id": self.team_id,
            "task_id": self.task_id,
            "agent_name": self.agent_name,
            "agent_id": self.agent_id,
            "conversation_id": self.conversation_id,
            "message_id": self.message_id,
            "source_ref": self.source_ref,
            "content_hash": self.content_hash,
            "dedupe_key": self.dedupe_key,
            "vector_ref": self.vector_ref,
            "vector_namespace": self.vector_namespace,
            "embedding_provider": self.embedding_provider,
            "embedding_model": self.embedding_model,
            "embedding_dimension": self.embedding_dimension,
            "token_count": self.token_count,
            "access_count": self.access_count,
            "revision": self.revision,
            "is_pinned": self.is_pinned,
            "is_favorite": self.is_favorite,
            "is_user_editable": self.is_user_editable,
            "requires_security_review": self.requires_security_review,
            "security_review_status": self.security_review_status,
            "security_review_reason": self.security_review_reason,
            "verification_status": self.verification_status,
            "audit_trace_id": self.audit_trace_id,
            "created_by": self.created_by,
            "updated_by": self.updated_by,
            "archived_by": self.archived_by,
            "deleted_by": self.deleted_by,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "last_accessed_at": self.last_accessed_at.isoformat() if self.last_accessed_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "archived_at": self.archived_at.isoformat() if self.archived_at else None,
            "deleted_at": self.deleted_at.isoformat() if self.deleted_at else None,
        }

        if include_content:
            data["content"] = self.content

        if include_embedding:
            data["embedding_json"] = self.embedding_json

        return data

    @classmethod
    def dashboard_filters(
        cls,
        *,
        user_id: str,
        workspace_id: str,
        memory_type: Optional[MemoryType] = None,
        status: MemoryStatus = MemoryStatus.ACTIVE,
        project_id: Optional[str] = None,
        client_id: Optional[str] = None,
        team_id: Optional[str] = None,
    ) -> List[Any]:
        """
        Build safe SQLAlchemy filters for dashboard/API queries.
        """
        safe_user_id = normalize_text(user_id)
        safe_workspace_id = normalize_text(workspace_id)

        if not safe_user_id:
            raise ValueError("user_id is required for memory dashboard filters.")
        if not safe_workspace_id:
            raise ValueError("workspace_id is required for memory dashboard filters.")

        filters: List[Any] = [
            cls.user_id == safe_user_id,
            cls.workspace_id == safe_workspace_id,
            cls.status == status,
        ]

        if memory_type:
            filters.append(cls.memory_type == memory_type)

        if project_id:
            filters.append(cls.project_id == normalize_text(project_id))

        if client_id:
            filters.append(cls.client_id == normalize_text(client_id))

        if team_id:
            filters.append(cls.team_id == normalize_text(team_id))

        return filters

    @classmethod
    def search_filters(
        cls,
        *,
        user_id: str,
        workspace_id: str,
        query: Optional[str] = None,
        memory_types: Optional[Sequence[MemoryType]] = None,
        tags: Optional[Sequence[str]] = None,
        include_archived: bool = False,
    ) -> List[Any]:
        """
        Build safe SQLAlchemy filters for memory search.
        """
        safe_user_id = normalize_text(user_id)
        safe_workspace_id = normalize_text(workspace_id)

        if not safe_user_id:
            raise ValueError("user_id is required for memory search.")
        if not safe_workspace_id:
            raise ValueError("workspace_id is required for memory search.")

        filters: List[Any] = [
            cls.user_id == safe_user_id,
            cls.workspace_id == safe_workspace_id,
        ]

        if include_archived:
            filters.append(cls.status.in_([MemoryStatus.ACTIVE, MemoryStatus.ARCHIVED]))
        else:
            filters.append(cls.status == MemoryStatus.ACTIVE)

        if memory_types:
            filters.append(cls.memory_type.in_(list(memory_types)))

        if query:
            safe_query = f"%{normalize_text(query)}%"
            filters.append(
                cls.title.ilike(safe_query) | cls.content.ilike(safe_query) | cls.summary.ilike(safe_query)
            )

        if tags:
            for tag in cls.normalize_string_list(tags):
                filters.append(cls.tags.contains([tag]))

        return filters

    @classmethod
    def safe_error_response(
        cls,
        *,
        message: str,
        action: str,
        error: Exception,
    ) -> Dict[str, Any]:
        """
        Create safe error responses without leaking secrets or internals.
        """
        return {
            "success": False,
            "message": normalize_text(message) or "Memory operation failed.",
            "action": normalize_text(action) or "memory.error",
            "error": {
                "type": error.__class__.__name__,
                "detail": normalize_text(str(error)),
            },
        }


__all__ = [
    "Memory",
    "MemoryScope",
    "MemoryType",
    "MemoryStatus",
    "MemorySensitivity",
    "MemorySource",
    "MemoryImportance",
]