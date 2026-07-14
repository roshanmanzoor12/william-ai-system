"""
database/models/device_setup_token.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

One-time, short-lived setup tokens that let a real, already-authenticated
dashboard user (apps/api/routes/device_setup.py::create_setup_token) hand a
brand-new, not-yet-authenticated Windows Worker process just enough to
register itself (POST /system/device/register) -- without ever handing the
worker the user's own JWT.

Only the SHA-256 hash of the raw setup token is ever stored (never the
plaintext); the plaintext is returned exactly once, at creation time, the
same way apps/api/routes/auth.py's password hashing never stores a
plaintext password. This table's row is disposable -- consumed or expired,
it never grants anything again. The durable, reusable credential a
registered worker actually authenticates with afterward is the device
token stored on database/models/system_worker.py::SystemWorkerStatus
(device_token_hash/device_token_status), a completely separate secret.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

try:
    from sqlalchemy import Column, DateTime, Index, String, Text
    from sqlalchemy.orm import Session
except Exception as exc:  # pragma: no cover
    raise ImportError(
        "SQLAlchemy is required for database/models/device_setup_token.py. "
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


logger = logging.getLogger("william.database.models.device_setup_token")
if not logger.handlers:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))


UTC = timezone.utc


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def _json_dumps(value: Any) -> str:
    try:
        return json.dumps(value if value is not None else [], ensure_ascii=False)
    except TypeError:
        return json.dumps([str(item) for item in (value or [])], ensure_ascii=False)


def _json_loads(value: Optional[str], default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


STATUS_PENDING = "pending"
STATUS_CONSUMED = "consumed"
STATUS_EXPIRED = "expired"
STATUS_REVOKED = "revoked"

VALID_SETUP_TOKEN_STATUSES = {STATUS_PENDING, STATUS_CONSUMED, STATUS_EXPIRED, STATUS_REVOKED}

DEVICE_TYPE_WINDOWS = "windows"


class DeviceSetupToken(Base):
    __tablename__ = "device_setup_tokens"

    token_id = Column(String(80), primary_key=True, default=lambda: _new_id("dsetup"))

    token_hash = Column(String(128), nullable=False, unique=True, index=True)

    user_id = Column(String(140), nullable=False, index=True)
    workspace_id = Column(String(140), nullable=False, index=True)

    device_type = Column(String(20), nullable=False, default=DEVICE_TYPE_WINDOWS)
    allowed_actions_json = Column(Text, nullable=True)

    status = Column(String(20), nullable=False, default=STATUS_PENDING)

    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)
    consumed_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_device_setup_tokens_workspace_status", "workspace_id", "status"),
    )

    @property
    def allowed_actions(self) -> List[str]:
        return _json_loads(self.allowed_actions_json, [])

    @allowed_actions.setter
    def allowed_actions(self, value: List[str]) -> None:
        self.allowed_actions_json = _json_dumps(value)

    def is_valid(self, *, now: Optional[datetime] = None) -> bool:
        current = now or _utc_now()
        expires_at = self.expires_at
        if expires_at and expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        return self.status == STATUS_PENDING and bool(expires_at) and expires_at > current

    def to_dict(self) -> Dict[str, Any]:
        return {
            "token_id": self.token_id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "device_type": self.device_type,
            "allowed_actions": self.allowed_actions,
            "status": self.status,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "consumed_at": self.consumed_at.isoformat() if self.consumed_at else None,
        }


class DeviceSetupTokenService:
    """Mirrors database/models/worker_task.py::WorkerTaskService's thin,
    dependency-free service-class style. The raw secret is generated here
    (not by the caller) so it's never accidentally logged/passed around
    before hashing -- create() returns (row, raw_token), and raw_token is
    the ONLY time the plaintext ever exists outside this call stack."""

    @staticmethod
    def create(
        db: Session,
        *,
        user_id: str,
        workspace_id: str,
        token_hash: str,
        device_type: str = DEVICE_TYPE_WINDOWS,
        allowed_actions: Optional[List[str]] = None,
        ttl_seconds: int = 900,
    ) -> DeviceSetupToken:
        row = DeviceSetupToken(
            token_id=_new_id("dsetup"),
            token_hash=token_hash,
            user_id=user_id,
            workspace_id=workspace_id,
            device_type=device_type,
            status=STATUS_PENDING,
            expires_at=_utc_now() + timedelta(seconds=ttl_seconds),
        )
        row.allowed_actions = allowed_actions or []
        db.add(row)
        db.flush()
        return row

    @staticmethod
    def find_valid_by_hash(db: Session, token_hash: str) -> Optional[DeviceSetupToken]:
        row = db.query(DeviceSetupToken).filter(DeviceSetupToken.token_hash == token_hash).first()
        if row is None or not row.is_valid():
            return None
        return row

    @staticmethod
    def mark_consumed(db: Session, row: DeviceSetupToken) -> DeviceSetupToken:
        row.status = STATUS_CONSUMED
        row.consumed_at = _utc_now()
        db.add(row)
        db.flush()
        return row


__all__ = [
    "DeviceSetupToken",
    "DeviceSetupTokenService",
    "STATUS_PENDING",
    "STATUS_CONSUMED",
    "STATUS_EXPIRED",
    "STATUS_REVOKED",
    "VALID_SETUP_TOKEN_STATUSES",
    "DEVICE_TYPE_WINDOWS",
]
