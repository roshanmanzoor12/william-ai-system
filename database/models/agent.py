"""
database/models/agent.py

Agent Models for William / Jarvis Multi-Agent SaaS System

Purpose:
- Agent registry (all AI agents)
- Agent execution sessions
- Task tracking per agent
- Event logging system
- Health monitoring
- Error tracking

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


# ---------------------------------------------------------------------
# Agent Registry Model
# ---------------------------------------------------------------------

class AgentRegistryModel(Base):
    """
    Stores all available AI agents in the system.
    """

    __tablename__ = "agent_registry"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(100), unique=True, nullable=False)  # Voice, Browser, etc.
    description = Column(Text, nullable=True)

    version = Column(String(50), default="1.0")
    is_active = Column(Boolean, default=True)

    capabilities = Column(JSON, default=dict)  # tools, permissions, features

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "is_active": self.is_active,
            "capabilities": self.capabilities or {},
        }


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
# Agent Task Model
# ---------------------------------------------------------------------

class AgentTaskModel(Base):
    """
    Stores individual tasks executed by agents.
    """

    __tablename__ = "agent_tasks"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))

    session_id = Column(String, index=True, nullable=False)

    user_id = Column(String, index=True, nullable=False)
    workspace_id = Column(String, index=True, nullable=False)

    task_type = Column(String(100))
    status = Column(String(50), default="pending")

    payload = Column(JSON, default=dict)
    result = Column(JSON, default=dict)

    created_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "session_id": self.session_id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "task_type": self.task_type,
            "status": self.status,
            "payload": self.payload or {},
            "result": self.result or {},
        }


# ---------------------------------------------------------------------
# Agent Event Model
# ---------------------------------------------------------------------

class AgentEventModel(Base):
    """
    Logs all agent events (actions, decisions, tool usage).
    """

    __tablename__ = "agent_events"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))

    agent_name = Column(String(100))
    event_type = Column(String(100))  # tool_call, decision, error, etc.

    user_id = Column(String, index=True)
    workspace_id = Column(String, index=True)

    data = Column(JSON, default=dict)

    created_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "agent_name": self.agent_name,
            "event_type": self.event_type,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "data": self.data or {},
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

    Registry = AgentRegistryModel
    Session = AgentSessionModel
    Task = AgentTaskModel
    Event = AgentEventModel
    Health = AgentHealthModel
    Error = AgentErrorModel