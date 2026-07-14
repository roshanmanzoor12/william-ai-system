"""
database/models/conversation_session.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Phase 1 (Conversational Assistant Brain) — durable state for a multi-turn
"William, do X" conversation that may need to ask the user a clarifying
question before it can execute (e.g. "William create a VEO prompt for
ClickRonix" needs style/duration/visual/CTA before anything can run).

This is intentionally a NEW, standalone table rather than a reuse of
apps/api/routes/tasks.py's in-memory TaskStore or an extension of
database/models/agent_task.py's AgentTask: those are two already-unreconciled
task-tracking systems, and layering conversation-thread state onto either
would make that worse. A conversation_sessions row is pure state tracking —
pending_task_id/parent_task_id are opaque display strings, not foreign keys
into either existing task system — so it can sit above both without needing
to unify them.

SaaS isolation: every row is scoped by (user_id, workspace_id). A thread must
never be readable/continuable by any other user or workspace, even if the
thread_id leaks — see ConversationSessionService.get()'s three-way filter.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    from sqlalchemy import Column, DateTime, Index, String, Text
    from sqlalchemy.orm import Session
except Exception as exc:  # pragma: no cover
    raise ImportError(
        "SQLAlchemy is required for database/models/conversation_session.py. "
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


logger = logging.getLogger("william.database.models.conversation_session")
if not logger.handlers:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))


UTC = timezone.utc


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def _json_dumps(value: Any) -> str:
    try:
        return json.dumps(value if value is not None else {}, ensure_ascii=False)
    except TypeError:
        return json.dumps(str(value), ensure_ascii=False)


def _json_loads(value: Optional[str], default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


# =============================================================================
# Status vocabulary (plain string constants — matches this codebase's
# Text-column-with-validated-choices convention rather than a native SQL
# enum type, for the same cross-dialect-portability reasons already
# established elsewhere in database/models/*.py)
# =============================================================================

SESSION_STATUS_WAITING_FOR_USER = "waiting_for_user"
SESSION_STATUS_RUNNING = "running"
SESSION_STATUS_COMPLETED = "completed"
SESSION_STATUS_FAILED = "failed"

VALID_SESSION_STATUSES = {
    SESSION_STATUS_WAITING_FOR_USER,
    SESSION_STATUS_RUNNING,
    SESSION_STATUS_COMPLETED,
    SESSION_STATUS_FAILED,
}


class ConversationSession(Base):
    """One row per conversation thread. A thread starts 'running', may move
    to 'waiting_for_user' zero or more times (each clarifying-question round),
    and ends 'completed' or 'failed'. Never reused across users/workspaces."""

    __tablename__ = "conversation_sessions"

    conversation_thread_id = Column(String(80), primary_key=True, default=lambda: _new_id("conv"))

    user_id = Column(String(140), nullable=False, index=True)
    workspace_id = Column(String(140), nullable=False, index=True)

    pending_task_id = Column(String(140), nullable=True)
    parent_task_id = Column(String(140), nullable=True)

    intent_category = Column(String(60), nullable=False)
    template_key = Column(String(60), nullable=True)

    required_inputs_json = Column(Text, nullable=True)
    collected_inputs_json = Column(Text, nullable=True)
    next_step = Column(Text, nullable=True)

    status = Column(String(30), nullable=False, default=SESSION_STATUS_RUNNING)

    last_message = Column(Text, nullable=True)
    final_answer = Column(Text, nullable=True)

    error_code = Column(String(120), nullable=True)
    error_message = Column(Text, nullable=True)

    metadata_json = Column(Text, nullable=True)

    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        # user_id/workspace_id already get single-column indexes from
        # Column(..., index=True) above -- only the composite index needs
        # to be declared explicitly here (declaring both forms for the same
        # column collides: "index ... already exists").
        Index("ix_conversation_sessions_workspace_user", "workspace_id", "user_id"),
    )

    @property
    def required_inputs(self) -> List[Dict[str, Any]]:
        return _json_loads(self.required_inputs_json, [])

    @required_inputs.setter
    def required_inputs(self, value: List[Dict[str, Any]]) -> None:
        self.required_inputs_json = _json_dumps(value)

    @property
    def collected_inputs(self) -> Dict[str, Any]:
        return _json_loads(self.collected_inputs_json, {})

    @collected_inputs.setter
    def collected_inputs(self, value: Dict[str, Any]) -> None:
        self.collected_inputs_json = _json_dumps(value)

    @property
    def extra_metadata(self) -> Dict[str, Any]:
        return _json_loads(self.metadata_json, {})

    @extra_metadata.setter
    def extra_metadata(self, value: Dict[str, Any]) -> None:
        self.metadata_json = _json_dumps(value)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "conversation_thread_id": self.conversation_thread_id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "pending_task_id": self.pending_task_id,
            "parent_task_id": self.parent_task_id,
            "intent_category": self.intent_category,
            "template_key": self.template_key,
            "required_inputs": self.required_inputs,
            "collected_inputs": self.collected_inputs,
            "next_step": self.next_step,
            "status": self.status,
            "last_message": self.last_message,
            "final_answer": self.final_answer,
            "error": (
                {"code": self.error_code, "message": self.error_message}
                if self.error_code or self.error_message
                else None
            ),
            "metadata": self.extra_metadata,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


class ConversationSessionService:
    """Thin, dependency-free state-transition helper. No security/memory/
    verification hooks here — this table is pure conversation-continuation
    bookkeeping; the actual task execution's own agent handles those
    concerns (see apps/api/routes/assistant.py)."""

    @staticmethod
    def create(
        db: Session,
        *,
        user_id: str,
        workspace_id: str,
        intent_category: str,
        required_inputs: List[Dict[str, Any]],
        collected_inputs: Dict[str, Any],
        status: str = SESSION_STATUS_RUNNING,
        template_key: Optional[str] = None,
        last_message: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        parent_task_id: Optional[str] = None,
    ) -> ConversationSession:
        if status not in VALID_SESSION_STATUSES:
            raise ValueError(f"Invalid conversation session status: {status!r}")

        session = ConversationSession(
            conversation_thread_id=_new_id("conv"),
            user_id=user_id,
            workspace_id=workspace_id,
            pending_task_id=_new_id("task"),
            parent_task_id=parent_task_id,
            intent_category=intent_category,
            template_key=template_key,
            status=status,
            last_message=last_message,
        )
        session.required_inputs = required_inputs
        session.collected_inputs = collected_inputs
        session.extra_metadata = metadata or {}
        db.add(session)
        db.flush()
        return session

    @staticmethod
    def get(
        db: Session,
        *,
        conversation_thread_id: str,
        user_id: str,
        workspace_id: str,
    ) -> Optional[ConversationSession]:
        return (
            db.query(ConversationSession)
            .filter(
                ConversationSession.conversation_thread_id == conversation_thread_id,
                ConversationSession.user_id == user_id,
                ConversationSession.workspace_id == workspace_id,
            )
            .first()
        )

    @staticmethod
    def update_collected_inputs(
        db: Session,
        session: ConversationSession,
        new_inputs: Dict[str, Any],
        *,
        last_message: Optional[str] = None,
    ) -> ConversationSession:
        merged = {**session.collected_inputs, **new_inputs}
        session.collected_inputs = merged
        if last_message is not None:
            session.last_message = last_message
        db.add(session)
        db.flush()
        return session

    @staticmethod
    def mark_waiting(
        db: Session,
        session: ConversationSession,
        required_inputs: List[Dict[str, Any]],
        *,
        next_step: Optional[str] = None,
    ) -> ConversationSession:
        session.required_inputs = required_inputs
        session.status = SESSION_STATUS_WAITING_FOR_USER
        session.next_step = next_step
        db.add(session)
        db.flush()
        return session

    @staticmethod
    def mark_completed(
        db: Session,
        session: ConversationSession,
        final_answer: str,
    ) -> ConversationSession:
        session.status = SESSION_STATUS_COMPLETED
        session.final_answer = final_answer
        session.next_step = None
        session.completed_at = _utc_now()
        db.add(session)
        db.flush()
        return session

    @staticmethod
    def mark_failed(
        db: Session,
        session: ConversationSession,
        error_code: str,
        error_message: str,
    ) -> ConversationSession:
        session.status = SESSION_STATUS_FAILED
        session.error_code = error_code
        session.error_message = error_message
        session.completed_at = _utc_now()
        db.add(session)
        db.flush()
        return session


__all__ = [
    "ConversationSession",
    "ConversationSessionService",
    "SESSION_STATUS_WAITING_FOR_USER",
    "SESSION_STATUS_RUNNING",
    "SESSION_STATUS_COMPLETED",
    "SESSION_STATUS_FAILED",
    "VALID_SESSION_STATUSES",
]
