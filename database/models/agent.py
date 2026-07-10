"""
database/models/agent.py

Agent Models for William / Jarvis Multi-Agent SaaS System

Purpose:
- Agent execution sessions
- Health monitoring
- Error tracking

Note:
- Agent registry, per-agent task tracking, and event logging used to be
  duplicated here with their own `agent_registry` / `agent_tasks` /
  `agent_events` tables, which collided with the richer, canonical
  models in agent_registry.py / agent_task.py / agent_event.py (two
  SQLAlchemy classes mapped to the same table name raises
  InvalidRequestError as soon as both are imported). Those three
  duplicate classes were removed; use AgentModels.Registry / .Task /
  .Event below, which point at the real classes.

Critical Rule:
- All agent execution MUST be scoped by user_id + workspace_id
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, Optional

try:
    from sqlalchemy import Column, String, DateTime, Boolean, JSON, Integer, Text
    from sqlalchemy.orm import relationship
except Exception:
    Column = String = DateTime = Boolean = JSON = Integer = Text = object
    relationship = lambda *args, **kwargs: None

from database.db import Base
from database.models.agent_registry import AgentRegistry
from database.models.agent_task import AgentTask
from database.models.agent_event import AgentEvent


# ---------------------------------------------------------------------
# Agent Session Model
# ---------------------------------------------------------------------

class AgentSessionModel(Base):
    """
    Tracks runtime execution sessions of agents.
    """

    __tablename__ = "agent_sessions"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))

    agent_name = Column(String(100), index=True, nullable=False)

    user_id = Column(String, index=True, nullable=False)
    workspace_id = Column(String, index=True, nullable=False)

    status = Column(String(50), default="running")  # running, completed, failed

    input_data = Column(JSON, default=dict)
    output_data = Column(JSON, default=dict)

    started_at = Column(DateTime, default=datetime.utcnow)
    ended_at = Column(DateTime, nullable=True)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "agent_name": self.agent_name,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "status": self.status,
            "input_data": self.input_data or {},
            "output_data": self.output_data or {},
            "started_at": str(self.started_at),
            "ended_at": str(self.ended_at),
        }


# ---------------------------------------------------------------------
# Agent Health Model
# ---------------------------------------------------------------------

class AgentHealthModel(Base):
    """
    Tracks health status of agents.
    """

    __tablename__ = "agent_health"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))

    agent_name = Column(String(100), index=True)

    status = Column(String(50), default="healthy")
    latency_ms = Column(Integer, default=0)

    last_checked = Column(DateTime, default=datetime.utcnow)

    health_metadata = Column(JSON, default=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "agent_name": self.agent_name,
            "status": self.status,
            "latency_ms": self.latency_ms,
            "health_metadata": self.health_metadata or {},
        }


# ---------------------------------------------------------------------
# Agent Error Model
# ---------------------------------------------------------------------

class AgentErrorModel(Base):
    """
    Stores agent failures and exceptions.
    """

    __tablename__ = "agent_errors"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))

    agent_name = Column(String(100))

    user_id = Column(String, index=True)
    workspace_id = Column(String, index=True)

    error_message = Column(Text)
    stack_trace = Column(Text)

    context = Column(JSON, default=dict)

    created_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "agent_name": self.agent_name,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "error_message": self.error_message,
            "context": self.context or {},
        }


# ---------------------------------------------------------------------
# Unified Export Class (for compatibility layer)
# ---------------------------------------------------------------------

class AgentModels:
    """
    Compatibility wrapper for Master Agent / Registry system.
    """

    Registry = AgentRegistry
    Session = AgentSessionModel
    Task = AgentTask
    Event = AgentEvent
    Health = AgentHealthModel
    Error = AgentErrorModel