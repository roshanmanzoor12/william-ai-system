"""
database/models/security.py

William / Jarvis Multi-Agent AI SaaS System
Security, Audit, Approval, Risk Decision & Permission Event Models

Purpose:
- Audit logging system
- Security approval requests
- Risk decision tracking
- Permission enforcement events
- Security Agent compatibility layer
- SaaS-safe user_id/workspace_id isolation
- Structured responses
- Memory Agent compatible payloads
- Verification Agent confirmation payloads

Author: Digital Promotix
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

try:
    from sqlalchemy import (
        Boolean,
        Column,
        DateTime,
        Float,
        Index,
        Integer,
        String,
        Text,
    )
    from sqlalchemy.orm import Session
except Exception as exc:  # pragma: no cover
    raise ImportError(
        "SQLAlchemy is required for database/models/security.py. "
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

logger = logging.getLogger("william.database.models.security")

if not logger.handlers:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

logger.setLevel(os.getenv("SECURITY_MODEL_LOG_LEVEL", "INFO"))


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

UTC = timezone.utc

DEFAULT_SYSTEM_USER_ID = "system"
DEFAULT_SYSTEM_WORKSPACE_ID = "system"

AUDIT_STATUS_SUCCESS = "success"
AUDIT_STATUS_FAILED = "failed"
AUDIT_STATUS_DENIED = "denied"
AUDIT_STATUS_PENDING = "pending"

VALID_AUDIT_STATUSES = {
    AUDIT_STATUS_SUCCESS,
    AUDIT_STATUS_FAILED,
    AUDIT_STATUS_DENIED,
    AUDIT_STATUS_PENDING,
}

APPROVAL_STATUS_PENDING = "pending"
APPROVAL_STATUS_APPROVED = "approved"
APPROVAL_STATUS_REJECTED = "rejected"
APPROVAL_STATUS_EXPIRED = "expired"
APPROVAL_STATUS_CANCELLED = "cancelled"

VALID_APPROVAL_STATUSES = {
    APPROVAL_STATUS_PENDING,
    APPROVAL_STATUS_APPROVED,
    APPROVAL_STATUS_REJECTED,
    APPROVAL_STATUS_EXPIRED,
    APPROVAL_STATUS_CANCELLED,
}

RISK_LEVEL_LOW = "low"
RISK_LEVEL_MEDIUM = "medium"
RISK_LEVEL_HIGH = "high"
RISK_LEVEL_CRITICAL = "critical"

VALID_RISK_LEVELS = {
    RISK_LEVEL_LOW,
    RISK_LEVEL_MEDIUM,
    RISK_LEVEL_HIGH,
    RISK_LEVEL_CRITICAL,
}

PERMISSION_GRANTED = "granted"
PERMISSION_DENIED = "denied"
PERMISSION_REVOKED = "revoked"
PERMISSION_CHECKED = "checked"

VALID_PERMISSION_EVENTS = {
    PERMISSION_GRANTED,
    PERMISSION_DENIED,
    PERMISSION_REVOKED,
    PERMISSION_CHECKED,
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

SENSITIVE_ACTION_KEYWORDS = {
    "delete",
    "remove",
    "drop",
    "truncate",
    "payment",
    "billing",
    "subscription",
    "external_api",
    "send_email",
    "send_message",
    "file_write",
    "file_delete",
    "system_control",
    "browser_action",
    "database_query",
    "database_write",
    "agent_disable",
    "permission_change",
    "credential",
    "token",
    "secret",
}


# ---------------------------------------------------------------------
# Utility Helpers
# ---------------------------------------------------------------------

def _utc_now() -> datetime:
    return datetime.now(UTC)


def _iso_now() -> str:
    return _utc_now().isoformat()


def _new_id(prefix: str) -> str:
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


def _normalize_text(value: Optional[Any], max_length: Optional[int] = None) -> str:
    text = str(value or "").strip()
    if max_length and len(text) > max_length:
        return text[:max_length]
    return text


def _normalize_status(value: Optional[str], valid_values: Sequence[str], default: str) -> str:
    cleaned = _normalize_text(value or default).lower()
    return cleaned if cleaned in set(valid_values) else default


def _normalize_dict(value: Optional[Union[str, Dict[str, Any]]]) -> Dict[str, Any]:
    if value is None:
        return {}

    if isinstance(value, dict):
        return value

    if isinstance(value, str):
        loaded = _safe_json_loads(value, {})
        return loaded if isinstance(loaded, dict) else {}

    return {}


def _normalize_list(values: Optional[Union[str, Sequence[str]]]) -> List[str]:
    if values is None:
        return []

    if isinstance(values, str):
        raw_items = [item.strip() for item in values.split(",")]
    else:
        raw_items = [str(item).strip() for item in values]

    return sorted({item for item in raw_items if item})


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
        "authorization",
        "cookie",
        "session",
        "credential",
    }

    clean: Dict[str, Any] = {}

    for key, value in metadata.items():
        key_str = str(key)
        key_lower = key_str.lower()

        if any(secret_key in key_lower for secret_key in sensitive_keys):
            clean[key_str] = "***masked***"
        elif isinstance(value, dict):
            clean[key_str] = _mask_sensitive_metadata(value)
        elif isinstance(value, list):
            clean[key_str] = [
                _mask_sensitive_metadata(item) if isinstance(item, dict) else item
                for item in value
            ]
        else:
            clean[key_str] = value

    return clean


def _score_to_risk_level(score: Union[int, float]) -> str:
    numeric = float(score)

    if numeric >= 90:
        return RISK_LEVEL_CRITICAL

    if numeric >= 70:
        return RISK_LEVEL_HIGH

    if numeric >= 40:
        return RISK_LEVEL_MEDIUM

    return RISK_LEVEL_LOW


def _is_sensitive_action(action: str) -> bool:
    action_lower = _normalize_text(action).lower()
    return any(keyword in action_lower for keyword in SENSITIVE_ACTION_KEYWORDS)


# ---------------------------------------------------------------------
# Future Agent Safe Stubs
# ---------------------------------------------------------------------

class MemoryAgentStub:
    """
    Fallback Memory Agent adapter.
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
    """

    def prepare_confirmation(self, **kwargs: Any) -> Dict[str, Any]:
        return {
            "verification_ready": True,
            "payload": kwargs,
            "timestamp": _iso_now(),
        }


# ---------------------------------------------------------------------
# Audit Log Model
# ---------------------------------------------------------------------

class AuditLogModel(Base):
    """
    Stores all sensitive or important system actions for traceability.

    SaaS isolation:
    - Every record has user_id and workspace_id.
    """

    __tablename__ = "audit_logs"

    id = Column(String(90), primary_key=True, default=lambda: _new_id("audit"))

    user_id = Column(String(90), index=True, nullable=False)
    workspace_id = Column(String(90), index=True, nullable=False)

    action = Column(String(255), nullable=False, index=True)
    resource_type = Column(String(120), nullable=False, default="")
    resource_id = Column(String(255), nullable=False, default="")

    agent_key = Column(String(120), nullable=False, default="")
    task_id = Column(String(90), nullable=False, default="")
    actor = Column(String(255), nullable=False, default="system")

    status = Column(String(50), nullable=False, default=AUDIT_STATUS_SUCCESS)
    risk_level = Column(String(50), nullable=False, default=RISK_LEVEL_LOW)

    ip_address = Column(String(100), nullable=False, default="")
    user_agent = Column(Text, nullable=False, default="")

    metadata_json = Column(Text, nullable=False, default="{}")

    timestamp = Column(DateTime(timezone=True), nullable=False, default=_utc_now)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)

    __table_args__ = (
        Index("ix_audit_logs_tenant_time", "user_id", "workspace_id", "timestamp"),
        Index("ix_audit_logs_resource", "resource_type", "resource_id"),
        Index("ix_audit_logs_action_status", "action", "status"),
    )

    @property
    def extra_metadata(self) -> Dict[str, Any]:
        data = _safe_json_loads(self.metadata_json, {})
        return data if isinstance(data, dict) else {}

    @extra_metadata.setter
    def extra_metadata(self, value: Optional[Union[str, Dict[str, Any]]]) -> None:
        self.metadata_json = _safe_json_dumps(_mask_sensitive_metadata(_normalize_dict(value)))

    @property
    def metadata(self) -> Dict[str, Any]:
        return self.extra_metadata

    @metadata.setter
    def metadata(self, value: Optional[Union[str, Dict[str, Any]]]) -> None:
        self.extra_metadata = value

    def to_dict(self, include_internal: bool = True) -> Dict[str, Any]:
        data = {
            "id": self.id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "agent_key": self.agent_key,
            "task_id": self.task_id,
            "actor": self.actor,
            "status": self.status,
            "risk_level": self.risk_level,
            "metadata": self.extra_metadata,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

        if include_internal:
            data["ip_address"] = self.ip_address
            data["user_agent"] = self.user_agent

        return data


# ---------------------------------------------------------------------
# Security Approval Model
# ---------------------------------------------------------------------

class SecurityApprovalModel(Base):
    """
    Tracks approval requests for sensitive operations.
    """

    __tablename__ = "security_approvals"

    id = Column(String(90), primary_key=True, default=lambda: _new_id("approval"))

    user_id = Column(String(90), index=True, nullable=False)
    workspace_id = Column(String(90), index=True, nullable=False)

    request_type = Column(String(120), nullable=False, index=True)
    action = Column(String(255), nullable=False, default="")
    resource_type = Column(String(120), nullable=False, default="")
    resource_id = Column(String(255), nullable=False, default="")

    agent_key = Column(String(120), nullable=False, default="")
    task_id = Column(String(90), nullable=False, default="")

    status = Column(String(50), nullable=False, default=APPROVAL_STATUS_PENDING)
    risk_level = Column(String(50), nullable=False, default=RISK_LEVEL_MEDIUM)
    risk_score = Column(Float, nullable=False, default=0.0)

    reason = Column(Text, nullable=False, default="")
    decision_reason = Column(Text, nullable=False, default="")

    requested_by = Column(String(255), nullable=False, default="")
    decided_by = Column(String(255), nullable=False, default="")

    request_payload_json = Column(Text, nullable=False, default="{}")
    decision_payload_json = Column(Text, nullable=False, default="{}")

    requested_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)
    decided_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)

    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now)

    __table_args__ = (
        Index("ix_security_approvals_tenant_status", "user_id", "workspace_id", "status"),
        Index("ix_security_approvals_action_status", "action", "status"),
        Index("ix_security_approvals_task", "task_id"),
    )

    @property
    def request_payload(self) -> Dict[str, Any]:
        data = _safe_json_loads(self.request_payload_json, {})
        return data if isinstance(data, dict) else {}

    @request_payload.setter
    def request_payload(self, value: Optional[Union[str, Dict[str, Any]]]) -> None:
        self.request_payload_json = _safe_json_dumps(_mask_sensitive_metadata(_normalize_dict(value)))

    @property
    def decision_payload(self) -> Dict[str, Any]:
        data = _safe_json_loads(self.decision_payload_json, {})
        return data if isinstance(data, dict) else {}

    @decision_payload.setter
    def decision_payload(self, value: Optional[Union[str, Dict[str, Any]]]) -> None:
        self.decision_payload_json = _safe_json_dumps(_mask_sensitive_metadata(_normalize_dict(value)))

    def is_pending(self) -> bool:
        return self.status == APPROVAL_STATUS_PENDING

    def approve(self, decided_by: str, reason: Optional[str] = None, payload: Optional[Dict[str, Any]] = None) -> None:
        self.status = APPROVAL_STATUS_APPROVED
        self.decided_by = _normalize_text(decided_by, 255)
        self.decision_reason = _normalize_text(reason)
        self.decision_payload = payload or {}
        self.decided_at = _utc_now()
        self.updated_at = _utc_now()

    def reject(self, decided_by: str, reason: Optional[str] = None, payload: Optional[Dict[str, Any]] = None) -> None:
        self.status = APPROVAL_STATUS_REJECTED
        self.decided_by = _normalize_text(decided_by, 255)
        self.decision_reason = _normalize_text(reason)
        self.decision_payload = payload or {}
        self.decided_at = _utc_now()
        self.updated_at = _utc_now()

    def cancel(self, decided_by: str, reason: Optional[str] = None) -> None:
        self.status = APPROVAL_STATUS_CANCELLED
        self.decided_by = _normalize_text(decided_by, 255)
        self.decision_reason = _normalize_text(reason)
        self.decided_at = _utc_now()
        self.updated_at = _utc_now()

    def to_dict(self, include_internal: bool = True) -> Dict[str, Any]:
        data = {
            "id": self.id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "request_type": self.request_type,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "agent_key": self.agent_key,
            "task_id": self.task_id,
            "status": self.status,
            "risk_level": self.risk_level,
            "risk_score": self.risk_score,
            "reason": self.reason,
            "decision_reason": self.decision_reason,
            "requested_by": self.requested_by,
            "decided_by": self.decided_by,
            "requested_at": self.requested_at.isoformat() if self.requested_at else None,
            "decided_at": self.decided_at.isoformat() if self.decided_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

        if include_internal:
            data["request_payload"] = self.request_payload
            data["decision_payload"] = self.decision_payload

        return data


# ---------------------------------------------------------------------
# Risk Decision Model
# ---------------------------------------------------------------------

class RiskDecisionModel(Base):
    """
    Stores risk analysis results for sensitive actions.
    """

    __tablename__ = "risk_decisions"

    id = Column(String(90), primary_key=True, default=lambda: _new_id("risk"))

    user_id = Column(String(90), index=True, nullable=False)
    workspace_id = Column(String(90), index=True, nullable=False)

    action = Column(String(255), nullable=False, index=True)
    resource_type = Column(String(120), nullable=False, default="")
    resource_id = Column(String(255), nullable=False, default="")
    agent_key = Column(String(120), nullable=False, default="")
    task_id = Column(String(90), nullable=False, default="")

    risk_level = Column(String(50), nullable=False, default=RISK_LEVEL_LOW)
    score = Column(Float, nullable=False, default=0.0)
    decision = Column(String(50), nullable=False, default="allow")

    explanation = Column(Text, nullable=False, default="")
    signals_json = Column(Text, nullable=False, default="{}")

    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)

    __table_args__ = (
        Index("ix_risk_decisions_tenant_time", "user_id", "workspace_id", "created_at"),
        Index("ix_risk_decisions_action_level", "action", "risk_level"),
        Index("ix_risk_decisions_task", "task_id"),
    )

    @property
    def signals(self) -> Dict[str, Any]:
        data = _safe_json_loads(self.signals_json, {})
        return data if isinstance(data, dict) else {}

    @signals.setter
    def signals(self, value: Optional[Union[str, Dict[str, Any]]]) -> None:
        self.signals_json = _safe_json_dumps(_mask_sensitive_metadata(_normalize_dict(value)))

    def to_dict(self, include_internal: bool = True) -> Dict[str, Any]:
        data = {
            "id": self.id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "agent_key": self.agent_key,
            "task_id": self.task_id,
            "risk_level": self.risk_level,
            "score": self.score,
            "decision": self.decision,
            "explanation": self.explanation,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

        if include_internal:
            data["signals"] = self.signals

        return data


# ---------------------------------------------------------------------
# Permission Event Model
# ---------------------------------------------------------------------

class PermissionEventModel(Base):
    """
    Tracks permission changes and permission enforcement decisions.
    """

    __tablename__ = "permission_events"

    id = Column(String(90), primary_key=True, default=lambda: _new_id("permission_event"))

    user_id = Column(String(90), index=True, nullable=False)
    workspace_id = Column(String(90), index=True, nullable=False)

    permission_name = Column(String(255), nullable=False, index=True)
    event_type = Column(String(50), nullable=False, default=PERMISSION_CHECKED)

    actor = Column(String(255), nullable=False, default="system")
    target_user_id = Column(String(90), nullable=False, default="")
    target_role = Column(String(120), nullable=False, default="")

    allowed = Column(Boolean, nullable=False, default=False)
    reason = Column(Text, nullable=False, default="")
    metadata_json = Column(Text, nullable=False, default="{}")

    timestamp = Column(DateTime(timezone=True), nullable=False, default=_utc_now)

    __table_args__ = (
        Index("ix_permission_events_tenant_time", "user_id", "workspace_id", "timestamp"),
        Index("ix_permission_events_permission_type", "permission_name", "event_type"),
    )

    @property
    def metadata(self) -> Dict[str, Any]:
        data = _safe_json_loads(self.metadata_json, {})
        return data if isinstance(data, dict) else {}

    @metadata.setter
    def metadata(self, value: Optional[Union[str, Dict[str, Any]]]) -> None:
        self.metadata_json = _safe_json_dumps(_mask_sensitive_metadata(_normalize_dict(value)))

    def to_dict(self, include_internal: bool = True) -> Dict[str, Any]:
        data = {
            "id": self.id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "permission_name": self.permission_name,
            "event_type": self.event_type,
            "actor": self.actor,
            "target_user_id": self.target_user_id,
            "target_role": self.target_role,
            "allowed": self.allowed,
            "reason": self.reason,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }

        if include_internal:
            data["metadata"] = self.metadata

        return data


# ---------------------------------------------------------------------
# Main Security Service / Component
# ---------------------------------------------------------------------

class Security:
    """
    Main Security component for William/Jarvis.

    This class can be used by:
    - Security Agent
    - Master Agent
    - API routes
    - Worker nodes
    - Dashboard backend
    - Agent registry
    - Agent task service

    Core responsibilities:
    - authorize actions
    - record audit logs
    - create approval requests
    - decide approvals
    - record risk decisions
    - track permission events
    """

    def __init__(
        self,
        memory_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        plan_tiers: Optional[Dict[str, int]] = None,
    ) -> None:
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
    # Context / Access Helpers
    # -----------------------------------------------------------------

    def validate_context(self, user_id: Optional[str], workspace_id: Optional[str]) -> bool:
        return bool(_normalize_text(user_id)) and bool(_normalize_text(workspace_id))

    def _plan_rank(self, plan: Optional[str]) -> int:
        return self.plan_tiers.get(_normalize_text(plan or "free").lower(), 0)

    def _has_plan_access(self, user_plan: Optional[str], required_plan: Optional[str]) -> bool:
        return self._plan_rank(user_plan) >= self._plan_rank(required_plan or "free")

    def _has_role_access(
        self,
        user_roles: Optional[Sequence[str]],
        allowed_roles: Optional[Sequence[str]] = None,
    ) -> bool:
        roles = set(_normalize_list(user_roles))
        allowed = set(_normalize_list(allowed_roles or ["owner", "admin", "security", "manager"]))

        if not allowed:
            return True

        return bool(roles.intersection(allowed)) or "owner" in roles or "admin" in roles

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

    # -----------------------------------------------------------------
    # Payload Hooks
    # -----------------------------------------------------------------

    def _memory_payload(
        self,
        action: str,
        user_id: str,
        workspace_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        payload = {
            "source": "security",
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
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
        result: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        payload = {
            "source": "security",
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "result": result or {},
            "timestamp": _iso_now(),
        }

        try:
            return self.verification_agent.prepare_confirmation(**payload)
        except Exception:
            return payload

    # -----------------------------------------------------------------
    # Risk Evaluation
    # -----------------------------------------------------------------

    def calculate_risk_score(
        self,
        action: str,
        metadata: Optional[Dict[str, Any]] = None,
        user_plan: Optional[str] = "free",
        user_roles: Optional[Sequence[str]] = None,
        user_permissions: Optional[Sequence[str]] = None,
    ) -> Tuple[float, str, str]:
        """
        Lightweight deterministic risk scoring.

        Real Security Agent can replace this later.
        """
        score = 10.0
        signals: List[str] = []

        action_lower = _normalize_text(action).lower()
        clean_metadata = metadata or {}

        if _is_sensitive_action(action_lower):
            score += 35
            signals.append("Sensitive action keyword detected.")

        if any(word in action_lower for word in ["delete", "drop", "truncate", "remove"]):
            score += 25
            signals.append("Destructive operation detected.")

        if any(word in action_lower for word in ["billing", "payment", "subscription"]):
            score += 20
            signals.append("Billing or payment action detected.")

        if any(word in action_lower for word in ["system", "device", "app_launch", "file_write", "file_delete"]):
            score += 20
            signals.append("System/device/file action detected.")

        if clean_metadata.get("external_api") or "external_api" in action_lower:
            score += 15
            signals.append("External API action detected.")

        if clean_metadata.get("bulk_action"):
            score += 20
            signals.append("Bulk action detected.")

        if clean_metadata.get("contains_sensitive_data"):
            score += 20
            signals.append("Sensitive data flag detected.")

        roles = set(_normalize_list(user_roles))
        permissions = set(_normalize_list(user_permissions))

        if "owner" in roles or "admin" in roles:
            score -= 10
            signals.append("Privileged role reduces risk.")

        if "*" in permissions or "admin:*" in permissions:
            score -= 5
            signals.append("Admin permission reduces risk.")

        if not self._has_plan_access(user_plan, "free"):
            score += 15
            signals.append("Plan access is insufficient.")

        score = max(0.0, min(100.0, round(score, 2)))
        risk_level = _score_to_risk_level(score)
        explanation = " ".join(signals) if signals else "No elevated risk signals detected."

        return score, risk_level, explanation

    def record_risk_decision(
        self,
        db: Session,
        user_id: str,
        workspace_id: str,
        action: str,
        score: Union[int, float],
        risk_level: Optional[str] = None,
        decision: str = "allow",
        explanation: str = "",
        resource_type: str = "",
        resource_id: str = "",
        agent_key: str = "",
        task_id: str = "",
        signals: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if not self.validate_context(user_id, workspace_id):
            return self._error("Invalid SaaS context. user_id and workspace_id are required.")

        try:
            numeric_score = max(0.0, min(100.0, float(score)))
            final_risk_level = _normalize_status(
                risk_level or _score_to_risk_level(numeric_score),
                list(VALID_RISK_LEVELS),
                RISK_LEVEL_LOW,
            )

            risk = RiskDecisionModel(
                id=_new_id("risk"),
                user_id=user_id,
                workspace_id=workspace_id,
                action=_normalize_text(action, 255),
                resource_type=_normalize_text(resource_type, 120),
                resource_id=_normalize_text(resource_id, 255),
                agent_key=_normalize_text(agent_key, 120),
                task_id=_normalize_text(task_id, 90),
                risk_level=final_risk_level,
                score=numeric_score,
                decision=_normalize_text(decision, 50) or "allow",
                explanation=_normalize_text(explanation),
                created_at=_utc_now(),
            )
            risk.signals = signals or {}

            db.add(risk)
            db.commit()
            db.refresh(risk)

            result = {"risk_decision": risk.to_dict(include_internal=True)}

            return self._success(
                "Risk decision recorded successfully.",
                data=result,
                metadata={
                    "memory_payload": self._memory_payload(
                        action="security.record_risk_decision",
                        user_id=user_id,
                        workspace_id=workspace_id,
                        metadata=result,
                    ),
                    "verification_payload": self._verification_payload(
                        action="security.record_risk_decision",
                        user_id=user_id,
                        workspace_id=workspace_id,
                        result=result,
                    ),
                },
            )

        except Exception as exc:
            db.rollback()
            logger.exception("Failed to record risk decision.")
            return self._error("Failed to record risk decision.", exc)

    # -----------------------------------------------------------------
    # Audit Logging
    # -----------------------------------------------------------------

    def record_audit_log(
        self,
        db: Session,
        user_id: str,
        workspace_id: str,
        action: str,
        resource_type: str = "",
        resource_id: str = "",
        status: str = AUDIT_STATUS_SUCCESS,
        metadata: Optional[Dict[str, Any]] = None,
        agent_key: str = "",
        task_id: str = "",
        actor: str = "system",
        risk_level: str = RISK_LEVEL_LOW,
        ip_address: str = "",
        user_agent: str = "",
    ) -> Dict[str, Any]:
        if not self.validate_context(user_id, workspace_id):
            return self._error("Invalid SaaS context. user_id and workspace_id are required.")

        clean_action = _normalize_text(action, 255)

        if not clean_action:
            return self._error("Audit action is required.")

        try:
            audit = AuditLogModel(
                id=_new_id("audit"),
                user_id=user_id,
                workspace_id=workspace_id,
                action=clean_action,
                resource_type=_normalize_text(resource_type, 120),
                resource_id=_normalize_text(resource_id, 255),
                agent_key=_normalize_text(agent_key, 120),
                task_id=_normalize_text(task_id, 90),
                actor=_normalize_text(actor, 255) or "system",
                status=_normalize_status(status, list(VALID_AUDIT_STATUSES), AUDIT_STATUS_SUCCESS),
                risk_level=_normalize_status(risk_level, list(VALID_RISK_LEVELS), RISK_LEVEL_LOW),
                ip_address=_normalize_text(ip_address, 100),
                user_agent=_normalize_text(user_agent),
                timestamp=_utc_now(),
                created_at=_utc_now(),
            )
            audit.extra_metadata = metadata or {}

            db.add(audit)
            db.commit()
            db.refresh(audit)

            result = {"audit_log": audit.to_dict(include_internal=True)}

            return self._success(
                "Audit log recorded successfully.",
                data=result,
                metadata={
                    "memory_payload": self._memory_payload(
                        action="security.record_audit_log",
                        user_id=user_id,
                        workspace_id=workspace_id,
                        metadata=result,
                    )
                },
            )

        except Exception as exc:
            db.rollback()
            logger.exception("Failed to record audit log.")
            return self._error("Failed to record audit log.", exc)

    def list_audit_logs(
        self,
        db: Session,
        user_id: str,
        workspace_id: str,
        action: Optional[str] = None,
        status: Optional[str] = None,
        resource_type: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        user_plan: Optional[str] = "free",
        user_roles: Optional[Sequence[str]] = None,
        user_permissions: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        if not self.validate_context(user_id, workspace_id):
            return self._error("Invalid SaaS context. user_id and workspace_id are required.")

        if not self._has_plan_access(user_plan, "starter"):
            return self._error("Audit log access denied by subscription plan.")

        if not self._has_role_access(user_roles, ["owner", "admin", "security"]):
            return self._error("Audit log access denied by role.")

        if not self._has_permission_access(user_permissions, ["security:audit:read"]):
            return self._error("Audit log access denied by permission.")

        safe_limit = max(1, min(int(limit or 100), 500))
        safe_offset = max(0, int(offset or 0))

        try:
            query = db.query(AuditLogModel).filter(
                AuditLogModel.user_id == user_id,
                AuditLogModel.workspace_id == workspace_id,
            )

            if action:
                query = query.filter(AuditLogModel.action == _normalize_text(action, 255))

            if status:
                query = query.filter(AuditLogModel.status == _normalize_status(status, list(VALID_AUDIT_STATUSES), AUDIT_STATUS_SUCCESS))

            if resource_type:
                query = query.filter(AuditLogModel.resource_type == _normalize_text(resource_type, 120))

            total = query.count()

            rows = (
                query.order_by(AuditLogModel.timestamp.desc())
                .offset(safe_offset)
                .limit(safe_limit)
                .all()
            )

            result = {
                "audit_logs": [row.to_dict(include_internal=True) for row in rows],
                "count": len(rows),
                "total": total,
                "limit": safe_limit,
                "offset": safe_offset,
            }

            return self._success(
                "Audit logs listed successfully.",
                data=result,
                metadata={
                    "verification_payload": self._verification_payload(
                        action="security.list_audit_logs",
                        user_id=user_id,
                        workspace_id=workspace_id,
                        result={"count": len(rows), "total": total},
                    )
                },
            )

        except Exception as exc:
            logger.exception("Failed to list audit logs.")
            return self._error("Failed to list audit logs.", exc)

    # -----------------------------------------------------------------
    # Approval Requests
    # -----------------------------------------------------------------

    def create_approval_request(
        self,
        db: Session,
        user_id: str,
        workspace_id: str,
        request_type: str,
        action: str,
        reason: str = "",
        request_payload: Optional[Dict[str, Any]] = None,
        requested_by: str = "",
        resource_type: str = "",
        resource_id: str = "",
        agent_key: str = "",
        task_id: str = "",
        risk_score: Optional[Union[int, float]] = None,
        risk_level: Optional[str] = None,
        expires_at: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        if not self.validate_context(user_id, workspace_id):
            return self._error("Invalid SaaS context. user_id and workspace_id are required.")

        clean_action = _normalize_text(action, 255)
        clean_request_type = _normalize_text(request_type, 120)

        if not clean_action:
            return self._error("Approval action is required.")

        if not clean_request_type:
            return self._error("Approval request_type is required.")

        calculated_score, calculated_level, explanation = self.calculate_risk_score(
            action=clean_action,
            metadata=request_payload or {},
        )

        final_score = float(risk_score) if risk_score is not None else calculated_score
        final_level = risk_level or calculated_level

        try:
            approval = SecurityApprovalModel(
                id=_new_id("approval"),
                user_id=user_id,
                workspace_id=workspace_id,
                request_type=clean_request_type,
                action=clean_action,
                resource_type=_normalize_text(resource_type, 120),
                resource_id=_normalize_text(resource_id, 255),
                agent_key=_normalize_text(agent_key, 120),
                task_id=_normalize_text(task_id, 90),
                status=APPROVAL_STATUS_PENDING,
                risk_level=_normalize_status(final_level, list(VALID_RISK_LEVELS), RISK_LEVEL_MEDIUM),
                risk_score=max(0.0, min(100.0, float(final_score))),
                reason=_normalize_text(reason or explanation),
                requested_by=_normalize_text(requested_by or user_id, 255),
                requested_at=_utc_now(),
                expires_at=expires_at,
                created_at=_utc_now(),
                updated_at=_utc_now(),
            )
            approval.request_payload = request_payload or {}

            db.add(approval)
            db.commit()
            db.refresh(approval)

            audit_response = self.record_audit_log(
                db=db,
                user_id=user_id,
                workspace_id=workspace_id,
                action="security.approval_requested",
                resource_type="security_approval",
                resource_id=approval.id,
                status=AUDIT_STATUS_PENDING,
                metadata={
                    "request_type": approval.request_type,
                    "approval_action": approval.action,
                    "risk_score": approval.risk_score,
                    "risk_level": approval.risk_level,
                },
                agent_key=agent_key,
                task_id=task_id,
                actor=requested_by or user_id,
                risk_level=approval.risk_level,
            )

            result = {
                "approval": approval.to_dict(include_internal=True),
                "audit_recorded": audit_response.get("success", False),
            }

            return self._success(
                "Security approval request created successfully.",
                data=result,
                metadata={
                    "memory_payload": self._memory_payload(
                        action="security.create_approval_request",
                        user_id=user_id,
                        workspace_id=workspace_id,
                        metadata=result,
                    ),
                    "verification_payload": self._verification_payload(
                        action="security.create_approval_request",
                        user_id=user_id,
                        workspace_id=workspace_id,
                        result=result,
                    ),
                },
            )

        except Exception as exc:
            db.rollback()
            logger.exception("Failed to create approval request.")
            return self._error("Failed to create approval request.", exc)

    def decide_approval(
        self,
        db: Session,
        approval_id: str,
        user_id: str,
        workspace_id: str,
        approved: bool,
        decided_by: str,
        reason: Optional[str] = None,
        decision_payload: Optional[Dict[str, Any]] = None,
        user_plan: Optional[str] = "free",
        user_roles: Optional[Sequence[str]] = None,
        user_permissions: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        if not self.validate_context(user_id, workspace_id):
            return self._error("Invalid SaaS context. user_id and workspace_id are required.")

        if not self._has_plan_access(user_plan, "starter"):
            return self._error("Approval decision denied by subscription plan.")

        if not self._has_role_access(user_roles, ["owner", "admin", "security"]):
            return self._error("Approval decision denied by role.")

        if not self._has_permission_access(user_permissions, ["security:approval:decide"]):
            return self._error("Approval decision denied by permission.")

        try:
            approval = db.query(SecurityApprovalModel).filter(
                SecurityApprovalModel.id == _normalize_text(approval_id, 90),
                SecurityApprovalModel.user_id == user_id,
                SecurityApprovalModel.workspace_id == workspace_id,
            ).first()

            if not approval:
                return self._error("Approval request not found.")

            if not approval.is_pending():
                return self._error(
                    "Approval request is no longer pending.",
                    metadata={"approval_id": approval.id, "status": approval.status},
                )

            if approved:
                approval.approve(decided_by=decided_by, reason=reason, payload=decision_payload)
                audit_status = AUDIT_STATUS_SUCCESS
                action = "security.approval_approved"
                message = "Security approval approved successfully."
            else:
                approval.reject(decided_by=decided_by, reason=reason, payload=decision_payload)
                audit_status = AUDIT_STATUS_DENIED
                action = "security.approval_rejected"
                message = "Security approval rejected successfully."

            db.commit()
            db.refresh(approval)

            audit_response = self.record_audit_log(
                db=db,
                user_id=user_id,
                workspace_id=workspace_id,
                action=action,
                resource_type="security_approval",
                resource_id=approval.id,
                status=audit_status,
                metadata={
                    "approval_action": approval.action,
                    "approved": approved,
                    "decision_reason": reason,
                },
                agent_key=approval.agent_key,
                task_id=approval.task_id,
                actor=decided_by,
                risk_level=approval.risk_level,
            )

            result = {
                "approval": approval.to_dict(include_internal=True),
                "audit_recorded": audit_response.get("success", False),
            }

            return self._success(
                message,
                data=result,
                metadata={
                    "memory_payload": self._memory_payload(
                        action=action,
                        user_id=user_id,
                        workspace_id=workspace_id,
                        metadata=result,
                    ),
                    "verification_payload": self._verification_payload(
                        action=action,
                        user_id=user_id,
                        workspace_id=workspace_id,
                        result=result,
                    ),
                },
            )

        except Exception as exc:
            db.rollback()
            logger.exception("Failed to decide approval request.")
            return self._error("Failed to decide approval request.", exc)

    def list_approval_requests(
        self,
        db: Session,
        user_id: str,
        workspace_id: str,
        status: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        user_plan: Optional[str] = "free",
        user_roles: Optional[Sequence[str]] = None,
        user_permissions: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        if not self.validate_context(user_id, workspace_id):
            return self._error("Invalid SaaS context. user_id and workspace_id are required.")

        if not self._has_plan_access(user_plan, "starter"):
            return self._error("Approval list access denied by subscription plan.")

        if not self._has_role_access(user_roles, ["owner", "admin", "security", "manager"]):
            return self._error("Approval list access denied by role.")

        if not self._has_permission_access(user_permissions, ["security:approval:read"]):
            return self._error("Approval list access denied by permission.")

        safe_limit = max(1, min(int(limit or 100), 500))
        safe_offset = max(0, int(offset or 0))

        try:
            query = db.query(SecurityApprovalModel).filter(
                SecurityApprovalModel.user_id == user_id,
                SecurityApprovalModel.workspace_id == workspace_id,
            )

            if status:
                query = query.filter(
                    SecurityApprovalModel.status == _normalize_status(
                        status,
                        list(VALID_APPROVAL_STATUSES),
                        APPROVAL_STATUS_PENDING,
                    )
                )

            total = query.count()

            rows = (
                query.order_by(SecurityApprovalModel.requested_at.desc())
                .offset(safe_offset)
                .limit(safe_limit)
                .all()
            )

            result = {
                "approvals": [row.to_dict(include_internal=True) for row in rows],
                "count": len(rows),
                "total": total,
                "limit": safe_limit,
                "offset": safe_offset,
            }

            return self._success(
                "Security approval requests listed successfully.",
                data=result,
                metadata={
                    "verification_payload": self._verification_payload(
                        action="security.list_approval_requests",
                        user_id=user_id,
                        workspace_id=workspace_id,
                        result={"count": len(rows), "total": total},
                    )
                },
            )

        except Exception as exc:
            logger.exception("Failed to list approval requests.")
            return self._error("Failed to list approval requests.", exc)

    # -----------------------------------------------------------------
    # Permission Events
    # -----------------------------------------------------------------

    def record_permission_event(
        self,
        db: Session,
        user_id: str,
        workspace_id: str,
        permission_name: str,
        event_type: str,
        allowed: bool,
        actor: str = "system",
        target_user_id: str = "",
        target_role: str = "",
        reason: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if not self.validate_context(user_id, workspace_id):
            return self._error("Invalid SaaS context. user_id and workspace_id are required.")

        clean_permission = _normalize_text(permission_name, 255)

        if not clean_permission:
            return self._error("permission_name is required.")

        try:
            event = PermissionEventModel(
                id=_new_id("permission_event"),
                user_id=user_id,
                workspace_id=workspace_id,
                permission_name=clean_permission,
                event_type=_normalize_status(event_type, list(VALID_PERMISSION_EVENTS), PERMISSION_CHECKED),
                actor=_normalize_text(actor, 255) or "system",
                target_user_id=_normalize_text(target_user_id, 90),
                target_role=_normalize_text(target_role, 120),
                allowed=bool(allowed),
                reason=_normalize_text(reason),
                timestamp=_utc_now(),
            )
            event.metadata = metadata or {}

            db.add(event)
            db.commit()
            db.refresh(event)

            result = {"permission_event": event.to_dict(include_internal=True)}

            return self._success(
                "Permission event recorded successfully.",
                data=result,
                metadata={
                    "memory_payload": self._memory_payload(
                        action="security.record_permission_event",
                        user_id=user_id,
                        workspace_id=workspace_id,
                        metadata=result,
                    )
                },
            )

        except Exception as exc:
            db.rollback()
            logger.exception("Failed to record permission event.")
            return self._error("Failed to record permission event.", exc)

    # -----------------------------------------------------------------
    # Authorization Method for Security Agent Compatibility
    # -----------------------------------------------------------------

    def authorize(
        self,
        db: Optional[Session] = None,
        action: str = "",
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        user_plan: Optional[str] = "free",
        user_roles: Optional[Sequence[str]] = None,
        user_permissions: Optional[Sequence[str]] = None,
        required_permissions: Optional[Sequence[str]] = None,
        minimum_plan: Optional[str] = "free",
        metadata: Optional[Dict[str, Any]] = None,
        resource_type: str = "",
        resource_id: str = "",
        agent_key: str = "",
        task_id: str = "",
        actor: str = "system",
        auto_create_approval_for_high_risk: bool = False,
    ) -> bool:
        """
        Boolean authorization hook.

        This signature intentionally supports future calls like:
            security.authorize(action=..., user_id=..., workspace_id=...)

        If db is provided, the method records audit/risk/approval rows.
        If db is not provided, it still makes a deterministic allow/deny decision.
        """
        clean_user_id = _normalize_text(user_id)
        clean_workspace_id = _normalize_text(workspace_id)
        clean_action = _normalize_text(action, 255)

        if not self.validate_context(clean_user_id, clean_workspace_id):
            logger.warning("Security authorization denied: missing user_id/workspace_id.")
            return False

        if not clean_action:
            logger.warning("Security authorization denied: missing action.")
            return False

        has_plan = self._has_plan_access(user_plan, minimum_plan)
        has_permission = self._has_permission_access(user_permissions, required_permissions)

        score, risk_level, explanation = self.calculate_risk_score(
            action=clean_action,
            metadata=metadata or {},
            user_plan=user_plan,
            user_roles=user_roles,
            user_permissions=user_permissions,
        )

        allowed = bool(has_plan and has_permission)

        if risk_level == RISK_LEVEL_CRITICAL and not self._has_role_access(user_roles, ["owner", "admin", "security"]):
            allowed = False

        if db is not None:
            decision = "allow" if allowed else "deny"

            self.record_risk_decision(
                db=db,
                user_id=clean_user_id,
                workspace_id=clean_workspace_id,
                action=clean_action,
                score=score,
                risk_level=risk_level,
                decision=decision,
                explanation=explanation,
                resource_type=resource_type,
                resource_id=resource_id,
                agent_key=agent_key,
                task_id=task_id,
                signals={
                    "has_plan": has_plan,
                    "has_permission": has_permission,
                    "required_permissions": _normalize_list(required_permissions),
                    "user_permissions": _normalize_list(user_permissions),
                    "user_roles": _normalize_list(user_roles),
                    "sensitive_action": _is_sensitive_action(clean_action),
                },
            )

            self.record_audit_log(
                db=db,
                user_id=clean_user_id,
                workspace_id=clean_workspace_id,
                action=clean_action,
                resource_type=resource_type,
                resource_id=resource_id,
                status=AUDIT_STATUS_SUCCESS if allowed else AUDIT_STATUS_DENIED,
                metadata={
                    "authorization_result": allowed,
                    "risk_score": score,
                    "risk_level": risk_level,
                    "explanation": explanation,
                    "required_permissions": _normalize_list(required_permissions),
                },
                agent_key=agent_key,
                task_id=task_id,
                actor=actor,
                risk_level=risk_level,
            )

            if auto_create_approval_for_high_risk and allowed and risk_level in {RISK_LEVEL_HIGH, RISK_LEVEL_CRITICAL}:
                self.create_approval_request(
                    db=db,
                    user_id=clean_user_id,
                    workspace_id=clean_workspace_id,
                    request_type="high_risk_action",
                    action=clean_action,
                    reason=explanation,
                    request_payload=metadata or {},
                    requested_by=actor,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    agent_key=agent_key,
                    task_id=task_id,
                    risk_score=score,
                    risk_level=risk_level,
                )

        return allowed

    # -----------------------------------------------------------------
    # Dashboard Statistics
    # -----------------------------------------------------------------

    def security_statistics(
        self,
        db: Session,
        user_id: str,
        workspace_id: str,
        user_plan: Optional[str] = "free",
        user_roles: Optional[Sequence[str]] = None,
        user_permissions: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        if not self.validate_context(user_id, workspace_id):
            return self._error("Invalid SaaS context. user_id and workspace_id are required.")

        if not self._has_plan_access(user_plan, "starter"):
            return self._error("Security statistics access denied by subscription plan.")

        if not self._has_role_access(user_roles, ["owner", "admin", "security"]):
            return self._error("Security statistics access denied by role.")

        if not self._has_permission_access(user_permissions, ["security:read"]):
            return self._error("Security statistics access denied by permission.")

        try:
            audit_base = db.query(AuditLogModel).filter(
                AuditLogModel.user_id == user_id,
                AuditLogModel.workspace_id == workspace_id,
            )

            approval_base = db.query(SecurityApprovalModel).filter(
                SecurityApprovalModel.user_id == user_id,
                SecurityApprovalModel.workspace_id == workspace_id,
            )

            risk_base = db.query(RiskDecisionModel).filter(
                RiskDecisionModel.user_id == user_id,
                RiskDecisionModel.workspace_id == workspace_id,
            )

            permission_base = db.query(PermissionEventModel).filter(
                PermissionEventModel.user_id == user_id,
                PermissionEventModel.workspace_id == workspace_id,
            )

            approvals_by_status = {
                status: approval_base.filter(SecurityApprovalModel.status == status).count()
                for status in VALID_APPROVAL_STATUSES
            }

            audit_by_status = {
                status: audit_base.filter(AuditLogModel.status == status).count()
                for status in VALID_AUDIT_STATUSES
            }

            risks_by_level = {
                level: risk_base.filter(RiskDecisionModel.risk_level == level).count()
                for level in VALID_RISK_LEVELS
            }

            result = {
                "audit_logs_total": audit_base.count(),
                "approvals_total": approval_base.count(),
                "risk_decisions_total": risk_base.count(),
                "permission_events_total": permission_base.count(),
                "approvals_by_status": approvals_by_status,
                "audit_by_status": audit_by_status,
                "risks_by_level": risks_by_level,
                "pending_approvals": approvals_by_status.get(APPROVAL_STATUS_PENDING, 0),
                "critical_risks": risks_by_level.get(RISK_LEVEL_CRITICAL, 0),
                "high_risks": risks_by_level.get(RISK_LEVEL_HIGH, 0),
            }

            return self._success(
                "Security statistics generated successfully.",
                data=result,
                metadata={
                    "memory_payload": self._memory_payload(
                        action="security.statistics",
                        user_id=user_id,
                        workspace_id=workspace_id,
                        metadata=result,
                    ),
                    "verification_payload": self._verification_payload(
                        action="security.statistics",
                        user_id=user_id,
                        workspace_id=workspace_id,
                        result=result,
                    ),
                },
            )

        except Exception as exc:
            logger.exception("Failed to generate security statistics.")
            return self._error("Failed to generate security statistics.", exc)


# ---------------------------------------------------------------------
# Compatibility Wrapper
# ---------------------------------------------------------------------

class SecurityModels:
    """
    Compatibility wrapper for Master Agent / Security Agent routing.
    """

    Audit = AuditLogModel
    Approval = SecurityApprovalModel
    Risk = RiskDecisionModel
    Permission = PermissionEventModel
    Service = Security


# ---------------------------------------------------------------------
# Module-Level Singleton
# ---------------------------------------------------------------------

security_service = Security()


# ---------------------------------------------------------------------
# Convenience Functions
# ---------------------------------------------------------------------

def record_audit_log(
    db: Session,
    user_id: str,
    workspace_id: str,
    action: str,
    **kwargs: Any,
) -> Dict[str, Any]:
    return security_service.record_audit_log(
        db=db,
        user_id=user_id,
        workspace_id=workspace_id,
        action=action,
        **kwargs,
    )


def create_approval_request(
    db: Session,
    user_id: str,
    workspace_id: str,
    request_type: str,
    action: str,
    **kwargs: Any,
) -> Dict[str, Any]:
    return security_service.create_approval_request(
        db=db,
        user_id=user_id,
        workspace_id=workspace_id,
        request_type=request_type,
        action=action,
        **kwargs,
    )


def decide_approval(
    db: Session,
    approval_id: str,
    user_id: str,
    workspace_id: str,
    approved: bool,
    decided_by: str,
    **kwargs: Any,
) -> Dict[str, Any]:
    return security_service.decide_approval(
        db=db,
        approval_id=approval_id,
        user_id=user_id,
        workspace_id=workspace_id,
        approved=approved,
        decided_by=decided_by,
        **kwargs,
    )


def record_risk_decision(
    db: Session,
    user_id: str,
    workspace_id: str,
    action: str,
    score: Union[int, float],
    **kwargs: Any,
) -> Dict[str, Any]:
    return security_service.record_risk_decision(
        db=db,
        user_id=user_id,
        workspace_id=workspace_id,
        action=action,
        score=score,
        **kwargs,
    )


def record_permission_event(
    db: Session,
    user_id: str,
    workspace_id: str,
    permission_name: str,
    event_type: str,
    allowed: bool,
    **kwargs: Any,
) -> Dict[str, Any]:
    return security_service.record_permission_event(
        db=db,
        user_id=user_id,
        workspace_id=workspace_id,
        permission_name=permission_name,
        event_type=event_type,
        allowed=allowed,
        **kwargs,
    )


def authorize(
    action: str,
    user_id: str,
    workspace_id: str,
    db: Optional[Session] = None,
    **kwargs: Any,
) -> bool:
    return security_service.authorize(
        db=db,
        action=action,
        user_id=user_id,
        workspace_id=workspace_id,
        **kwargs,
    )


def security_statistics(
    db: Session,
    user_id: str,
    workspace_id: str,
    **kwargs: Any,
) -> Dict[str, Any]:
    return security_service.security_statistics(
        db=db,
        user_id=user_id,
        workspace_id=workspace_id,
        **kwargs,
    )


__all__ = [
    "Security",
    "SecurityModels",
    "AuditLogModel",
    "SecurityApprovalModel",
    "RiskDecisionModel",
    "PermissionEventModel",
    "security_service",
    "record_audit_log",
    "create_approval_request",
    "decide_approval",
    "record_risk_decision",
    "record_permission_event",
    "authorize",
    "security_statistics",
    "AUDIT_STATUS_SUCCESS",
    "AUDIT_STATUS_FAILED",
    "AUDIT_STATUS_DENIED",
    "AUDIT_STATUS_PENDING",
    "APPROVAL_STATUS_PENDING",
    "APPROVAL_STATUS_APPROVED",
    "APPROVAL_STATUS_REJECTED",
    "APPROVAL_STATUS_EXPIRED",
    "APPROVAL_STATUS_CANCELLED",
    "RISK_LEVEL_LOW",
    "RISK_LEVEL_MEDIUM",
    "RISK_LEVEL_HIGH",
    "RISK_LEVEL_CRITICAL",
    "PERMISSION_GRANTED",
    "PERMISSION_DENIED",
    "PERMISSION_REVOKED",
    "PERMISSION_CHECKED",
]