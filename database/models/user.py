"""
database/models/user.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
Agent/Module: Database Prompt Bible
Purpose: Platform user account model.

This file previously contained a byte-for-byte copy of database/db.py
and defined no User class at all -- database/models/workspace.py's
WorkspaceMembership references users by a plain user_id string (see
that file for why membership, not a direct FK, is the isolation
boundary), but nothing anywhere in the codebase could actually create,
authenticate, or look up a user record. This file is the real model.

Critical SaaS rule:
Never mix users, workspaces, memory, files, logs, tasks, analytics,
billing, or agent access between users or workspaces. A user row only
ever describes the account itself (identity, credentials, profile);
workspace membership/role/plan all live in WorkspaceMembership.
"""

from __future__ import annotations

import enum
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

try:
    from sqlalchemy import Boolean, DateTime, Enum, Index, Integer, String, Text
    from sqlalchemy.orm import Mapped, mapped_column
except Exception as exc:  # pragma: no cover - import-safe fallback
    Boolean = DateTime = Enum = Index = Integer = String = Text = object  # type: ignore

    class Mapped:  # type: ignore
        def __class_getitem__(cls, item: Any) -> Any:
            return Any

    def mapped_column(*args: Any, **kwargs: Any) -> Any:
        return None

try:
    from database.db import Base
except Exception:  # pragma: no cover - emergency import-safe fallback
    from sqlalchemy.orm import declarative_base

    Base = declarative_base()


# =============================================================================
# Helpers
# =============================================================================

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def generate_id(prefix: str) -> str:
    cleaned_prefix = re.sub(r"[^a-zA-Z0-9_]", "", str(prefix)).lower() or "id"
    return f"{cleaned_prefix}_{uuid.uuid4().hex}"


def normalize_email(value: str) -> str:
    return str(value or "").strip().lower()


EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# =============================================================================
# Enums
# =============================================================================

class UserStatus(str, enum.Enum):
    ACTIVE = "active"
    PENDING_VERIFICATION = "pending_verification"
    SUSPENDED = "suspended"
    DEACTIVATED = "deactivated"


def enum_value(value: Any) -> str:
    return value.value if hasattr(value, "value") else str(value)


# =============================================================================
# User model
# =============================================================================

class User(Base):
    """
    A platform account. Authentication lives in apps/api/routes/auth.py
    (password hashing, token issuance); this model only stores the
    resulting state -- it never handles raw passwords.
    """

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(140), primary_key=True, default=lambda: generate_id("usr"))

    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    full_name: Mapped[Optional[str]] = mapped_column(String(180), nullable=True)

    # PBKDF2-HMAC-SHA256 hash + salt, see apps/api/routes/auth.py PasswordHasher.
    # Never store or log the raw password.
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    password_salt: Mapped[str] = mapped_column(String(255), nullable=False)
    password_algorithm: Mapped[str] = mapped_column(String(50), nullable=False, default="pbkdf2_sha256")
    password_updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)

    status: Mapped[UserStatus] = mapped_column(
        Enum(UserStatus, name="user_status"),
        nullable=False,
        default=UserStatus.PENDING_VERIFICATION,
        index=True,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_platform_admin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    default_workspace_id: Mapped[Optional[str]] = mapped_column(String(140), nullable=True, index=True)

    failed_login_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    metadata_json: Mapped[Dict[str, Any]] = mapped_column("metadata", Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)
    deactivated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_users_status_active", "status", "is_active"),
    )

    def __repr__(self) -> str:
        return f"User(id={self.id!r}, email={self.email!r}, status={enum_value(self.status)!r})"

    # -------------------------------------------------------------------
    # Construction / validation
    # -------------------------------------------------------------------

    @staticmethod
    def validate_email(value: str) -> str:
        cleaned = normalize_email(value)
        if not cleaned or not EMAIL_PATTERN.match(cleaned):
            raise ValueError("A valid email address is required.")
        return cleaned

    # -------------------------------------------------------------------
    # Safe serialization -- never include password_hash/password_salt
    # -------------------------------------------------------------------

    def safe_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "email": self.email,
            "full_name": self.full_name,
            "status": enum_value(self.status),
            "is_active": self.is_active,
            "is_platform_admin": self.is_platform_admin,
            "default_workspace_id": self.default_workspace_id,
            "last_login_at": self.last_login_at.isoformat() if self.last_login_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def to_dict(self) -> Dict[str, Any]:
        return self.safe_dict()

    # -------------------------------------------------------------------
    # Agent-contract compatible hooks
    # -------------------------------------------------------------------

    def _prepare_memory_payload(self) -> Dict[str, Any]:
        return {
            "user_id": self.id,
            "email": self.email,
            "default_workspace_id": self.default_workspace_id,
        }

    def _prepare_verification_payload(self) -> Dict[str, Any]:
        return {
            "entity": "user",
            "user_id": self.id,
            "status": enum_value(self.status),
            "timestamp": utc_now().isoformat(),
        }

    def _log_audit_event(self, action: str, actor_user_id: Optional[str] = None) -> Dict[str, Any]:
        return {
            "action": action,
            "user_id": self.id,
            "actor_user_id": actor_user_id or self.id,
            "timestamp": utc_now().isoformat(),
        }


__all__ = ["User", "UserStatus", "normalize_email", "generate_id", "utc_now"]
