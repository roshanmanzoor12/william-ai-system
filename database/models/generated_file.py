"""
database/models/generated_file.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Real, persisted records for files William actually generated (PDF/DOCX
documents from Creator Agent's document_generator.py today; project ZIP
exports later) -- distinct from database/models/file.py's UploadedFile,
which is scoped to user-uploaded content only. Keeping generation
provenance (source_prompt, generated_by_agent, conversation_thread_id)
on a separate table avoids overloading UploadedFile's upload-shaped
schema with fields that make no sense for something nobody uploaded.

Storage: local disk under core.config.StorageConfig.generated_files_dir,
namespaced per workspace/user (see apps/api/routes/files.py's generated-
file routes). Mirrors database/models/system_worker_event.py's Column-
based style and SaaS-isolation convention exactly.

Critical SaaS rule:
Every row is scoped by user_id + workspace_id; never mix generated files
between users or workspaces. A download link is only ever built from a
real row that was actually written to disk -- never fabricated.
"""

from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    from sqlalchemy import Boolean, Column, DateTime, Index, Integer, String, Text
    from sqlalchemy.orm import Session
except Exception as exc:  # pragma: no cover
    raise ImportError(
        "SQLAlchemy is required for database/models/generated_file.py. "
        "Install it with: pip install sqlalchemy"
    ) from exc

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


logger = logging.getLogger("william.database.models.generated_file")
if not logger.handlers:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))


UTC = timezone.utc


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


FILE_TYPE_PDF = "pdf"
FILE_TYPE_DOCX = "docx"
VALID_FILE_TYPES = {FILE_TYPE_PDF, FILE_TYPE_DOCX}

_CONTENT_TYPE_BY_FILE_TYPE = {
    FILE_TYPE_PDF: "application/pdf",
    FILE_TYPE_DOCX: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}


def content_type_for(file_type: str) -> str:
    return _CONTENT_TYPE_BY_FILE_TYPE.get((file_type or "").strip().lower(), "application/octet-stream")


class GeneratedFile(Base):
    """One row per file William actually wrote to disk on the user's behalf."""

    __tablename__ = "generated_files"

    file_id = Column(String(140), primary_key=True, default=lambda: _new_id("genfile"))

    user_id = Column(String(140), nullable=False, index=True)
    workspace_id = Column(String(140), nullable=False, index=True)

    filename = Column(String(255), nullable=False)
    content_type = Column(String(140), nullable=False, default="application/octet-stream")
    file_type = Column(String(30), nullable=False, default=FILE_TYPE_PDF)
    size_bytes = Column(Integer, nullable=False, default=0)

    # Path relative to StorageConfig.generated_files_dir, never a raw
    # absolute path -- avoids leaking host filesystem layout through the API.
    storage_key = Column(String(400), nullable=False, unique=True)

    generated_by_agent = Column(String(60), nullable=False, default="creator")
    source_prompt = Column(Text, nullable=True)
    conversation_thread_id = Column(String(80), nullable=True, index=True)

    is_deleted = Column(Boolean, nullable=False, default=False)

    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)
    deleted_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_generated_files_workspace_user", "workspace_id", "user_id"),
        Index("ix_generated_files_workspace_created", "workspace_id", "created_at"),
    )

    def __repr__(self) -> str:
        return f"GeneratedFile(file_id={self.file_id!r}, workspace_id={self.workspace_id!r}, filename={self.filename!r})"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_id": self.file_id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "filename": self.filename,
            "content_type": self.content_type,
            "file_type": self.file_type,
            "size_bytes": self.size_bytes,
            "generated_by_agent": self.generated_by_agent,
            "source_prompt": self.source_prompt,
            "conversation_thread_id": self.conversation_thread_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class GeneratedFileService:
    """Thin, dependency-free create/get/list helper -- same shape as
    database/models/system_worker_event.py::SystemWorkerEventService."""

    @staticmethod
    def create(
        db: Session,
        *,
        user_id: str,
        workspace_id: str,
        filename: str,
        storage_key: str,
        file_type: str,
        size_bytes: int,
        generated_by_agent: str = "creator",
        content_type: Optional[str] = None,
        source_prompt: Optional[str] = None,
        conversation_thread_id: Optional[str] = None,
    ) -> GeneratedFile:
        clean_file_type = file_type if file_type in VALID_FILE_TYPES else FILE_TYPE_PDF
        record = GeneratedFile(
            file_id=_new_id("genfile"),
            user_id=user_id,
            workspace_id=workspace_id,
            filename=filename,
            content_type=content_type or content_type_for(clean_file_type),
            file_type=clean_file_type,
            size_bytes=size_bytes,
            storage_key=storage_key,
            generated_by_agent=generated_by_agent,
            source_prompt=source_prompt,
            conversation_thread_id=conversation_thread_id,
        )
        db.add(record)
        db.flush()
        return record

    @staticmethod
    def get(
        db: Session,
        *,
        file_id: str,
        workspace_id: str,
    ) -> Optional[GeneratedFile]:
        return (
            db.query(GeneratedFile)
            .filter(
                GeneratedFile.file_id == file_id,
                GeneratedFile.workspace_id == workspace_id,
                GeneratedFile.is_deleted.is_(False),
            )
            .first()
        )

    @staticmethod
    def list_for_workspace(
        db: Session,
        *,
        workspace_id: str,
        limit: int = 50,
    ) -> List[GeneratedFile]:
        return (
            db.query(GeneratedFile)
            .filter(
                GeneratedFile.workspace_id == workspace_id,
                GeneratedFile.is_deleted.is_(False),
            )
            .order_by(GeneratedFile.created_at.desc())
            .limit(max(1, min(limit, 200)))
            .all()
        )


__all__ = [
    "GeneratedFile",
    "GeneratedFileService",
    "FILE_TYPE_PDF",
    "FILE_TYPE_DOCX",
    "VALID_FILE_TYPES",
    "content_type_for",
]
