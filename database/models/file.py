"""
database/models/file.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
Purpose: User/workspace-scoped uploaded file records, backing
apps/api/routes/files.py. No File/Document model existed anywhere in
the repo before this -- routes/files.py was a genuine unbuilt scaffold,
not a wiring bug like auth.py's stub was.

Storage: local disk under core.config.StorageConfig.uploads_dir,
namespaced per workspace/user (see routes/files.py). Real object
storage (S3/GCS/Azure) is a documented future upgrade, not faked here.

Critical SaaS rule:
Every row is scoped by user_id + workspace_id; never mix files between
users or workspaces.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

try:
    from sqlalchemy import Boolean, DateTime, Index, Integer, String, Text
    from sqlalchemy.orm import Mapped, mapped_column
except Exception as exc:  # pragma: no cover - import-safe fallback
    Boolean = DateTime = Index = Integer = String = Text = object  # type: ignore

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


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def generate_id(prefix: str) -> str:
    cleaned_prefix = re.sub(r"[^a-zA-Z0-9_]", "", str(prefix)).lower() or "id"
    return f"{cleaned_prefix}_{uuid.uuid4().hex}"


class UploadedFile(Base):
    """A single uploaded file, scoped to one user within one workspace."""

    __tablename__ = "files"

    id: Mapped[str] = mapped_column(String(140), primary_key=True, default=lambda: generate_id("file"))

    user_id: Mapped[str] = mapped_column(String(140), nullable=False, index=True)
    workspace_id: Mapped[str] = mapped_column(String(140), nullable=False, index=True)

    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    content_type: Mapped[str] = mapped_column(String(140), nullable=False, default="application/octet-stream")
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Path relative to StorageConfig.uploads_dir, never a raw absolute
    # path -- avoids leaking host filesystem layout through the API.
    storage_key: Mapped[str] = mapped_column(String(400), nullable=False, unique=True)

    category: Mapped[str] = mapped_column(String(60), nullable=False, default="upload")
    is_deleted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    uploaded_by: Mapped[str] = mapped_column(String(140), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_files_workspace_user", "workspace_id", "user_id"),
        Index("ix_files_workspace_category", "workspace_id", "category"),
    )

    def __repr__(self) -> str:
        return f"UploadedFile(id={self.id!r}, workspace_id={self.workspace_id!r}, name={self.original_filename!r})"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_id": self.id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "original_filename": self.original_filename,
            "content_type": self.content_type,
            "size_bytes": self.size_bytes,
            "category": self.category,
            "description": self.description,
            "uploaded_by": self.uploaded_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


__all__ = ["UploadedFile", "generate_id", "utc_now"]
