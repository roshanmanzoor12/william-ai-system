"""
database/models/system_worker.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Real, honest presence tracking for a Windows/Mac device worker
(apps/worker_nodes/windows/windows_worker.py, apps/worker_nodes/mac/
mac_worker.py) -- mirrors database/models/voice.py's VoiceSettings.
voice_worker_connected/voice_worker_last_seen_at pattern exactly, since
that pattern already solves the same real problem (an idle-but-alive
worker must not look offline just because no task has run yet, and a
crashed worker must not look connected forever).

This table only tracks whether a worker has said "I'm here" recently. It
does NOT implement real remote task dispatch (poll/report) -- see
agents/system_agent/system_agent.py's open_app()/close_app() for why that
distinction matters: even a connected worker can't be sent a task yet, so
those actions honestly report external_dependency_required regardless of
worker_connected, and this table's job is limited to what it can honestly
answer.

SaaS isolation: every row is scoped by workspace_id.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    from sqlalchemy import Boolean, Column, DateTime, Index, String, Text
except Exception as exc:  # pragma: no cover
    raise ImportError(
        "SQLAlchemy is required for database/models/system_worker.py. "
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


logger = logging.getLogger("william.database.models.system_worker")
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


PLATFORM_WINDOWS = "windows"
PLATFORM_MAC = "mac"
VALID_PLATFORMS = {PLATFORM_WINDOWS, PLATFORM_MAC}


class SystemWorkerStatus(Base):
    """One row per workspace -- the most recently seen device worker's
    heartbeat. Multiple physical devices per workspace aren't distinguished
    yet (out of scope for this fix); this answers "is ANY device worker for
    this workspace alive right now", which is what System Agent's
    device-control gating needs."""

    __tablename__ = "system_worker_status"

    id = Column(String(80), primary_key=True, default=lambda: _new_id("sysworker"))

    workspace_id = Column(String(80), nullable=False, unique=True, index=True)

    platform = Column(String(20), nullable=False, default=PLATFORM_WINDOWS)
    worker_connected = Column(Boolean, nullable=False, default=False)
    worker_last_seen_at = Column(DateTime(timezone=True), nullable=True)

    # Added alongside the real worker task-dispatch protocol
    # (database/models/worker_task.py) -- purely additive, presence-record
    # columns for dashboard display; none of these change what
    # compute_worker_connected() considers "connected."
    device_name = Column(String(140), nullable=True)
    supported_actions_json = Column(Text, nullable=True)
    last_command = Column(Text, nullable=True)
    last_result = Column(Text, nullable=True)

    # Added alongside the device setup-token / device-token auth flow
    # (database/models/device_setup_token.py, apps/api/routes/
    # device_setup.py) -- an installed worker authenticates with an opaque
    # device_token instead of a full user JWT. Only its SHA-256 hash is
    # ever stored; the plaintext is returned exactly once, at
    # POST /system/device/register time.
    owner_user_id = Column(String(140), nullable=True)
    device_id = Column(String(80), nullable=True)
    device_token_hash = Column(String(128), nullable=True, index=True)
    device_token_status = Column(String(20), nullable=True)
    setup_completed_at = Column(DateTime(timezone=True), nullable=True)

    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now)

    __table_args__ = (
        Index("ix_system_worker_status_workspace", "workspace_id"),
    )

    @property
    def supported_actions(self) -> List[str]:
        return _json_loads(self.supported_actions_json, [])

    @supported_actions.setter
    def supported_actions(self, value: List[str]) -> None:
        self.supported_actions_json = _json_dumps(value)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "workspace_id": self.workspace_id,
            "platform": self.platform,
            "worker_connected": bool(self.worker_connected),
            "worker_last_seen_at": self.worker_last_seen_at.isoformat() if self.worker_last_seen_at else None,
            "device_name": self.device_name,
            "supported_actions": self.supported_actions,
            "last_command": self.last_command,
            "last_result": self.last_result,
            "owner_user_id": self.owner_user_id,
            "device_id": self.device_id,
            "device_token_status": self.device_token_status,
            "setup_completed_at": self.setup_completed_at.isoformat() if self.setup_completed_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


CONNECTION_STATE_NEEDS_SETUP = "needs_setup"
CONNECTION_STATE_DISABLED = "disabled"
CONNECTION_STATE_CONNECTED = "connected"
CONNECTION_STATE_OFFLINE = "offline"


def compute_connection_state(row_dict: Optional[Dict[str, Any]], worker_connected: bool) -> str:
    """The one place both apps/api/routes/system_worker.py's HTTP status
    endpoint and SystemAgent's in-process device gating derive a single
    display/decision state from -- never duplicated ad-hoc booleans.

    A row that only ever heartbeated via a plain user JWT (dev/manual
    mode, device_token_status still None) can only ever read connected/
    offline, never needs_setup/disabled -- this is what keeps existing
    dev-mode behavior and tests unchanged. needs_setup means no device has
    EVER registered for this workspace at all; disabled means one did,
    then was explicitly revoked from the dashboard."""
    if row_dict is None:
        return CONNECTION_STATE_NEEDS_SETUP
    if row_dict.get("device_token_status") == "revoked":
        return CONNECTION_STATE_DISABLED
    if worker_connected:
        return CONNECTION_STATE_CONNECTED
    return CONNECTION_STATE_OFFLINE


__all__ = [
    "SystemWorkerStatus",
    "PLATFORM_WINDOWS",
    "PLATFORM_MAC",
    "VALID_PLATFORMS",
    "compute_connection_state",
    "CONNECTION_STATE_NEEDS_SETUP",
    "CONNECTION_STATE_DISABLED",
    "CONNECTION_STATE_CONNECTED",
    "CONNECTION_STATE_OFFLINE",
]
