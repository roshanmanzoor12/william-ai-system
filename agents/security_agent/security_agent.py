"""
agents/security_agent/security_agent.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Central protection brain for:

    - SaaS user/workspace isolation
    - Role and permission checks
    - Sensitive action classification
    - Risk scoring
    - Security approvals
    - Biometric verification gates
    - Device and session trust
    - Fraud and anomaly detection
    - Emergency workspace locks
    - Audit logging
    - Verification Agent payload preparation
    - Memory Agent-compatible security context
    - Master Agent, Agent Registry, Agent Loader, and Agent Router integration

Design principles:
    1. Safety and permissions always take precedence.
    2. No user/workspace data may cross tenant boundaries.
    3. High-risk or destructive actions are denied by default.
    4. Real actions are never executed by this module.
    5. This module authorizes, denies, challenges, or queues actions only.
    6. The file remains import-safe before future Security Agent files exist.
    7. All public methods return structured JSON-style dictionaries.

Future modules designed to integrate with this file:
    - permission_checker.py
    - biometric_gate.py
    - risk_engine.py
    - audit_logger.py
    - action_classifier.py
    - approval_manager.py
    - fraud_detector.py
    - anomaly_detector.py
    - device_access.py
    - file_protection.py
    - payment_guard.py
    - app_lock.py
    - session_guard.py
    - privacy_guard.py
    - threat_monitor.py
    - policy_engine.py
    - emergency_lock.py
    - config.py
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import logging
import math
import re
import secrets
import threading
import time
import uuid
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Deque, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple, Union


# =============================================================================
# Safe optional BaseAgent import
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Import-safe fallback BaseAgent.

        The real William/Jarvis BaseAgent can replace this class automatically
        when agents.base_agent becomes available.
        """

        def __init__(
            self,
            agent_name: str = "security_agent",
            agent_type: str = "security",
            version: str = "1.0.0",
            **kwargs: Any,
        ) -> None:
            self.agent_name = agent_name
            self.agent_type = agent_type
            self.version = version
            self.base_config = kwargs

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            return None

        def log_audit(self, payload: Dict[str, Any]) -> None:
            return None


# =============================================================================
# Logging
# =============================================================================

logger = logging.getLogger("william.security_agent")

if not logger.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


# =============================================================================
# Enumerations
# =============================================================================

class SecurityDecision(str, Enum):
    """Final authorization decision."""

    ALLOW = "allow"
    DENY = "deny"
    CHALLENGE = "challenge"
    REQUIRE_APPROVAL = "require_approval"
    REQUIRE_BIOMETRIC = "require_biometric"
    REQUIRE_MFA = "require_mfa"
    LOCKED = "locked"


class RiskLevel(str, Enum):
    """Normalized risk level."""

    MINIMAL = "minimal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ActionSensitivity(str, Enum):
    """Security classification for an action."""

    PUBLIC = "public"
    NORMAL = "normal"
    SENSITIVE = "sensitive"
    HIGH_RISK = "high_risk"
    DESTRUCTIVE = "destructive"
    FINANCIAL = "financial"
    PRIVILEGED = "privileged"
    EXTERNAL_COMMUNICATION = "external_communication"


class ApprovalStatus(str, Enum):
    """Lifecycle state of a security approval."""

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class BiometricStatus(str, Enum):
    """Biometric challenge status."""

    NOT_REQUIRED = "not_required"
    REQUIRED = "required"
    VERIFIED = "verified"
    FAILED = "failed"
    EXPIRED = "expired"
    UNAVAILABLE = "unavailable"


class FraudSignalType(str, Enum):
    """Common fraud/anomaly signals."""

    IMPOSSIBLE_TRAVEL = "impossible_travel"
    NEW_DEVICE = "new_device"
    UNTRUSTED_DEVICE = "untrusted_device"
    VELOCITY_SPIKE = "velocity_spike"
    REPEATED_FAILURES = "repeated_failures"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    TENANT_BOUNDARY_ATTEMPT = "tenant_boundary_attempt"
    SESSION_MISMATCH = "session_mismatch"
    IP_REPUTATION = "ip_reputation"
    AUTOMATION_PATTERN = "automation_pattern"
    PAYMENT_ANOMALY = "payment_anomaly"
    DATA_EXFILTRATION = "data_exfiltration"
    SECRET_EXPOSURE = "secret_exposure"
    SUSPICIOUS_USER_AGENT = "suspicious_user_agent"
    EMERGENCY_LOCK_ACTIVE = "emergency_lock_active"


# =============================================================================
# Data models
# =============================================================================

@dataclass
class SecurityAgentConfig:
    """Configuration for SecurityAgent."""

    agent_version: str = "1.0.0"

    enable_permission_checks: bool = True
    enable_risk_scoring: bool = True
    enable_fraud_detection: bool = True
    enable_anomaly_detection: bool = True
    enable_biometric_gate: bool = True
    enable_device_trust: bool = True
    enable_session_guard: bool = True
    enable_audit_log: bool = True
    enable_agent_events: bool = True
    enable_memory_payloads: bool = True
    enable_verification_payloads: bool = True

    default_deny_unknown_actions: bool = True
    require_explicit_permission_for_sensitive_actions: bool = True
    require_approval_for_high_risk: bool = True
    require_biometric_for_destructive_actions: bool = True
    require_biometric_for_financial_actions: bool = True
    require_mfa_for_privileged_actions: bool = True

    low_risk_max: float = 29.99
    medium_risk_max: float = 59.99
    high_risk_max: float = 84.99
    critical_risk_min: float = 85.0

    approval_ttl_seconds: int = 900
    biometric_challenge_ttl_seconds: int = 300
    session_max_age_seconds: int = 43_200
    max_failed_attempts: int = 5
    failed_attempt_window_seconds: int = 900
    max_actions_per_minute: int = 120
    max_sensitive_actions_per_minute: int = 20

    audit_retention_max_records: int = 10_000
    max_event_history_per_tenant: int = 2_000
    max_string_length: int = 4_000

    trusted_roles: Tuple[str, ...] = (
        "owner",
        "workspace_owner",
        "admin",
        "security_admin",
    )

    elevated_roles: Tuple[str, ...] = (
        "admin",
        "security_admin",
        "finance_admin",
        "workspace_owner",
        "owner",
    )

    protected_roles: Tuple[str, ...] = (
        "owner",
        "workspace_owner",
        "security_admin",
        "admin",
    )

    allow_local_fallback_approval_for_low_risk: bool = True
    block_cross_tenant_requests: bool = True
    block_expired_sessions: bool = True
    block_disabled_users: bool = True
    block_suspended_workspaces: bool = True


@dataclass
class SecurityContext:
    """Normalized SaaS security context."""

    user_id: str
    workspace_id: str
    task_id: str
    source_agent: str
    role: str = "user"
    permissions: List[str] = field(default_factory=list)
    subscription_status: str = "active"
    user_status: str = "active"
    workspace_status: str = "active"
    session_id: Optional[str] = None
    session_created_at: Optional[str] = None
    device_id: Optional[str] = None
    device_trusted: bool = False
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    country_code: Optional[str] = None
    mfa_verified: bool = False
    biometric_verified: bool = False
    request_id: Optional[str] = None
    correlation_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RiskAssessment:
    """Detailed security risk result."""

    assessment_id: str
    score: float
    level: str
    signals: List[Dict[str, Any]]
    factors: Dict[str, float]
    recommended_decision: str
    created_at: str


@dataclass
class ApprovalRecord:
    """Security approval lifecycle record."""

    approval_id: str
    user_id: str
    workspace_id: str
    task_id: str
    action: str
    sensitivity: str
    status: str
    requested_by: str
    requested_at: str
    expires_at: str
    risk_score: float
    reason: str
    payload_hash: str
    required_approver_roles: List[str] = field(default_factory=list)
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    denied_by: Optional[str] = None
    denied_at: Optional[str] = None
    decision_reason: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BiometricChallenge:
    """Biometric challenge state."""

    challenge_id: str
    user_id: str
    workspace_id: str
    task_id: str
    action: str
    nonce_hash: str
    status: str
    created_at: str
    expires_at: str
    verified_at: Optional[str] = None
    device_id: Optional[str] = None
    attempt_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditRecord:
    """Tenant-isolated security audit record."""

    audit_id: str
    user_id: str
    workspace_id: str
    action: str
    event_type: str
    decision: Optional[str]
    success: Optional[bool]
    risk_level: Optional[str]
    risk_score: Optional[float]
    task_id: Optional[str]
    source_agent: Optional[str]
    timestamp: str
    payload_summary: Dict[str, Any]
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityPolicy:
    """Action-level security policy."""

    action_pattern: str
    sensitivity: str
    required_permissions: List[str] = field(default_factory=list)
    allowed_roles: List[str] = field(default_factory=list)
    denied_roles: List[str] = field(default_factory=list)
    require_approval: bool = False
    require_biometric: bool = False
    require_mfa: bool = False
    require_trusted_device: bool = False
    max_risk_score: float = 100.0
    enabled: bool = True
    priority: int = 100
    metadata: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# Security Agent
# =============================================================================

class SecurityAgent(BaseAgent):
    """
    William/Jarvis central security and authorization agent.

    Public responsibilities:
        - validate task context
        - authorize actions
        - check role and permission access
        - classify actions
        - calculate risk
        - detect fraud/anomalies
        - create and resolve approvals
        - create and verify biometric challenges
        - manage emergency locks
        - protect tenant boundaries
        - emit audit and agent events
        - prepare Verification Agent and Memory Agent payloads

    This class never performs real financial, system, browser, messaging,
    calling, deployment, file deletion, or destructive operations. It only
    produces security decisions for the calling agent.
    """

    def __init__(
        self,
        config: Optional[Union[SecurityAgentConfig, Dict[str, Any]]] = None,
        permission_checker: Optional[Any] = None,
        risk_engine: Optional[Any] = None,
        approval_manager: Optional[Any] = None,
        biometric_gate: Optional[Any] = None,
        fraud_detector: Optional[Any] = None,
        anomaly_detector: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        policy_engine: Optional[Any] = None,
        session_guard: Optional[Any] = None,
        device_access: Optional[Any] = None,
        threat_monitor: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            agent_name="security_agent",
            agent_type="security",
            version="1.0.0",
            **kwargs,
        )

        self.config = self._build_config(config)

        self.permission_checker = permission_checker
        self.risk_engine = risk_engine
        self.approval_manager = approval_manager
        self.biometric_gate = biometric_gate
        self.fraud_detector = fraud_detector
        self.anomaly_detector = anomaly_detector
        self.audit_logger = audit_logger
        self.event_bus = event_bus
        self.policy_engine = policy_engine
        self.session_guard = session_guard
        self.device_access = device_access
        self.threat_monitor = threat_monitor
        self.memory_agent = memory_agent
        self.verification_agent = verification_agent

        self._lock = threading.RLock()
        self._started_at = self._utc_now()

        self._approvals: Dict[str, ApprovalRecord] = {}
        self._biometric_challenges: Dict[str, BiometricChallenge] = {}
        self._audit_records: Deque[AuditRecord] = deque(
            maxlen=self.config.audit_retention_max_records
        )

        self._workspace_locks: Dict[str, Dict[str, Any]] = {}
        self._user_locks: Dict[str, Dict[str, Any]] = {}
        self._known_devices: Dict[str, Dict[str, Dict[str, Any]]] = defaultdict(dict)
        self._failed_attempts: Dict[str, Deque[float]] = defaultdict(deque)
        self._action_history: Dict[str, Deque[Dict[str, Any]]] = defaultdict(
            lambda: deque(maxlen=self.config.max_event_history_per_tenant)
        )

        self._policies: List[SecurityPolicy] = self._default_policies()

        self.registry_metadata = {
            "agent_name": "security_agent",
            "class_name": "SecurityAgent",
            "module": "agents.security_agent.security_agent",
            "version": self.config.agent_version,
            "safe_import": True,
            "requires_user_context": True,
            "requires_workspace_context": True,
            "capabilities": [
                "permission_checks",
                "risk_scoring",
                "security_approvals",
                "biometric_gates",
                "mfa_enforcement",
                "fraud_detection",
                "anomaly_detection",
                "device_trust",
                "session_guard",
                "tenant_isolation",
                "audit_logging",
                "policy_enforcement",
                "emergency_lock",
                "verification_payloads",
                "memory_payloads",
            ],
            "supported_actions": [
                "authorize",
                "approve",
                "deny",
                "risk_assessment",
                "permission_check",
                "create_biometric_challenge",
                "verify_biometric",
                "register_device",
                "lock_workspace",
                "unlock_workspace",
                "lock_user",
                "unlock_user",
                "audit_search",
                "security_status",
                "fraud_check",
            ],
        }

    # =========================================================================
    # Required compatibility hooks
    # =========================================================================

    def _validate_task_context(self, task_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate and normalize user/workspace security context.

        This is the primary tenant-isolation boundary. Every user-specific
        security decision must pass through this method.
        """

        if not isinstance(task_context, dict):
            return self._error_result(
                message="Invalid security task context.",
                error="task_context must be a dictionary.",
                metadata={"hook": "_validate_task_context"},
            )

        user_id = self._clean_identifier(task_context.get("user_id"))
        workspace_id = self._clean_identifier(task_context.get("workspace_id"))

        if not user_id:
            return self._error_result(
                message="Missing user security context.",
                error="user_id is required.",
                metadata={"hook": "_validate_task_context"},
            )

        if not workspace_id:
            return self._error_result(
                message="Missing workspace security context.",
                error="workspace_id is required.",
                metadata={"hook": "_validate_task_context"},
            )

        claimed_user_id = self._clean_identifier(
            task_context.get("target_user_id") or task_context.get("resource_user_id")
        )
        claimed_workspace_id = self._clean_identifier(
            task_context.get("target_workspace_id")
            or task_context.get("resource_workspace_id")
        )

        if self.config.block_cross_tenant_requests:
            if claimed_user_id and claimed_user_id != user_id:
                self._record_boundary_attempt(task_context, "user")
                return self._error_result(
                    message="Cross-user access denied.",
                    error="The requested resource belongs to another user.",
                    metadata={
                        "hook": "_validate_task_context",
                        "security_decision": SecurityDecision.DENY.value,
                        "reason": FraudSignalType.TENANT_BOUNDARY_ATTEMPT.value,
                    },
                )

            if claimed_workspace_id and claimed_workspace_id != workspace_id:
                self._record_boundary_attempt(task_context, "workspace")
                return self._error_result(
                    message="Cross-workspace access denied.",
                    error="The requested resource belongs to another workspace.",
                    metadata={
                        "hook": "_validate_task_context",
                        "security_decision": SecurityDecision.DENY.value,
                        "reason": FraudSignalType.TENANT_BOUNDARY_ATTEMPT.value,
                    },
                )

        context = SecurityContext(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=self._clean_identifier(task_context.get("task_id"))
            or str(uuid.uuid4()),
            source_agent=self._clean_identifier(task_context.get("source_agent"))
            or "unknown",
            role=self._normalize_role(task_context.get("role")),
            permissions=self._normalize_permissions(task_context.get("permissions", [])),
            subscription_status=str(
                task_context.get("subscription_status", "active")
            ).lower().strip(),
            user_status=str(task_context.get("user_status", "active")).lower().strip(),
            workspace_status=str(
                task_context.get("workspace_status", "active")
            ).lower().strip(),
            session_id=self._clean_optional_identifier(task_context.get("session_id")),
            session_created_at=self._normalize_datetime_string(
                task_context.get("session_created_at")
            ),
            device_id=self._clean_optional_identifier(task_context.get("device_id")),
            device_trusted=bool(task_context.get("device_trusted", False)),
            ip_address=self._clean_optional_string(task_context.get("ip_address"), 128),
            user_agent=self._clean_optional_string(task_context.get("user_agent"), 512),
            country_code=self._clean_optional_string(
                task_context.get("country_code"), 8
            ),
            mfa_verified=bool(task_context.get("mfa_verified", False)),
            biometric_verified=bool(
                task_context.get("biometric_verified", False)
            ),
            request_id=self._clean_optional_identifier(task_context.get("request_id")),
            correlation_id=self._clean_optional_identifier(
                task_context.get("correlation_id")
            ),
            metadata=self._safe_metadata(task_context.get("metadata", {})),
        )

        if self.config.block_disabled_users and context.user_status in {
            "disabled",
            "suspended",
            "blocked",
            "deleted",
        }:
            return self._error_result(
                message="User access is disabled.",
                error=f"user_status={context.user_status}",
                metadata={
                    "security_decision": SecurityDecision.DENY.value,
                    "hook": "_validate_task_context",
                },
            )

        if self.config.block_suspended_workspaces and context.workspace_status in {
            "disabled",
            "suspended",
            "blocked",
            "deleted",
        }:
            return self._error_result(
                message="Workspace access is disabled.",
                error=f"workspace_status={context.workspace_status}",
                metadata={
                    "security_decision": SecurityDecision.DENY.value,
                    "hook": "_validate_task_context",
                },
            )

        lock_result = self._check_emergency_lock(context)
        if not lock_result["success"]:
            return lock_result

        session_result = self._validate_session(context)
        if not session_result["success"]:
            return session_result

        return self._safe_result(
            message="Security context validated.",
            data=asdict(context),
            metadata={
                "hook": "_validate_task_context",
                "tenant_isolation_checked": True,
            },
        )

    def _requires_security_check(
        self,
        action: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Determine whether an action needs full Security Agent authorization.

        Security Agent itself always performs a lightweight check. This method
        indicates whether the complete permission/risk/approval pipeline is
        required.
        """

        payload = payload or {}
        normalized_action = self._normalize_action(action)
        classification = self.classify_action(normalized_action, payload)

        if not classification["success"]:
            return True

        sensitivity = classification["data"]["sensitivity"]

        if sensitivity != ActionSensitivity.PUBLIC.value:
            return True

        if payload.get("requires_security_check") is True:
            return True

        if payload.get("destructive") is True:
            return True

        if payload.get("external_effect") is True:
            return True

        if payload.get("contains_sensitive_data") is True:
            return True

        return False

    def _request_security_approval(
        self,
        action: str,
        task_context: Dict[str, Any],
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Compatibility approval hook.

        Other William agents may call this method directly. It runs the full
        authorization process and returns an allow, deny, challenge, or approval
        requirement decision.
        """

        return self.authorize_action(
            action=action,
            task_context=task_context,
            payload=payload or {},
        )

    def _prepare_verification_payload(
        self,
        action: str,
        task_context: Dict[str, Any],
        result: Dict[str, Any],
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Prepare a Verification Agent-compatible payload."""

        risk_data = result.get("data", {}).get("risk_assessment", {})

        return {
            "verification_id": str(uuid.uuid4()),
            "agent_name": "security_agent",
            "agent_type": "security",
            "action": action,
            "success": bool(result.get("success")),
            "security_decision": result.get("data", {}).get("decision"),
            "user_id": task_context.get("user_id"),
            "workspace_id": task_context.get("workspace_id"),
            "task_id": task_context.get("task_id"),
            "source_agent": task_context.get("source_agent"),
            "timestamp": self._utc_now(),
            "risk_score": risk_data.get("score"),
            "risk_level": risk_data.get("level"),
            "checks": {
                "tenant_isolation_checked": True,
                "permission_check_completed": True,
                "risk_assessment_completed": bool(risk_data),
                "fraud_signals_checked": self.config.enable_fraud_detection,
                "session_checked": self.config.enable_session_guard,
                "device_checked": self.config.enable_device_trust,
                "structured_result": True,
            },
            "result_hash": self._stable_hash(
                {
                    "success": result.get("success"),
                    "message": result.get("message"),
                    "data": result.get("data"),
                }
            ),
            "extra": self._safe_metadata(extra or {}),
        }

    def _prepare_memory_payload(
        self,
        content: str,
        task_context: Dict[str, Any],
        scope: str = "security",
        metadata: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
        sensitivity: str = "confidential",
    ) -> Dict[str, Any]:
        """Prepare a Memory Agent-compatible security event payload."""

        safe_content = self._redact_text(self._clean_string(content))

        return {
            "payload_id": str(uuid.uuid4()),
            "user_id": task_context.get("user_id"),
            "workspace_id": task_context.get("workspace_id"),
            "scope": scope,
            "content": safe_content,
            "summary": safe_content[:500],
            "tags": tags or ["security"],
            "metadata": self._safe_metadata(metadata or {}),
            "sensitivity": sensitivity,
            "source_agent": "security_agent",
            "source_task_id": task_context.get("task_id"),
            "created_at": self._utc_now(),
        }

    def _emit_agent_event(
        self,
        event_name: str,
        payload: Dict[str, Any],
    ) -> None:
        """Emit a safe event to the William event bus or BaseAgent."""

        if not self.config.enable_agent_events:
            return

        safe_payload = self._redact_payload(copy.deepcopy(payload))

        try:
            if self.event_bus and hasattr(self.event_bus, "emit"):
                self.event_bus.emit(event_name, safe_payload)
                return

            try:
                super().emit_event(event_name, safe_payload)  # type: ignore
                return
            except Exception:
                pass

            logger.info("Security event=%s payload=%s", event_name, safe_payload)
        except Exception as exc:
            logger.warning("Security event emission failed: %s", exc)

    def _log_audit_event(
        self,
        action: str,
        task_context: Dict[str, Any],
        payload: Optional[Dict[str, Any]] = None,
        result: Optional[Dict[str, Any]] = None,
        event_type: str = "security_action",
    ) -> None:
        """Create an isolated, redacted security audit record."""

        if not self.config.enable_audit_log:
            return

        user_id = self._clean_identifier(task_context.get("user_id"))
        workspace_id = self._clean_identifier(task_context.get("workspace_id"))

        if not user_id or not workspace_id:
            logger.warning("Skipped audit event without tenant identifiers.")
            return

        result_data = result.get("data", {}) if isinstance(result, dict) else {}
        risk_data = result_data.get("risk_assessment", {})

        audit_record = AuditRecord(
            audit_id=str(uuid.uuid4()),
            user_id=user_id,
            workspace_id=workspace_id,
            action=self._normalize_action(action),
            event_type=event_type,
            decision=result_data.get("decision"),
            success=None if result is None else bool(result.get("success")),
            risk_level=risk_data.get("level"),
            risk_score=risk_data.get("score"),
            task_id=self._clean_optional_identifier(task_context.get("task_id")),
            source_agent=self._clean_optional_identifier(
                task_context.get("source_agent")
            ),
            timestamp=self._utc_now(),
            payload_summary=self._audit_payload_summary(payload or {}),
            metadata={
                "request_id": task_context.get("request_id"),
                "correlation_id": task_context.get("correlation_id"),
            },
        )

        with self._lock:
            self._audit_records.append(audit_record)

        external_payload = asdict(audit_record)

        try:
            if self.audit_logger and hasattr(self.audit_logger, "log"):
                self.audit_logger.log(external_payload)
            else:
                try:
                    super().log_audit(external_payload)  # type: ignore
                except Exception:
                    logger.info("Security audit=%s", external_payload)
        except Exception as exc:
            logger.warning("Security audit logging failed: %s", exc)

    def _safe_result(
        self,
        message: str,
        data: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return a standard success result."""

        return {
            "success": True,
            "message": message,
            "data": data if data is not None else {},
            "error": None,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        message: str,
        error: Union[str, Exception],
        data: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return a standard failure result."""

        return {
            "success": False,
            "message": message,
            "data": data if data is not None else {},
            "error": str(error),
            "metadata": metadata or {},
        }

    # =========================================================================
    # Master Agent / Router entrypoint
    # =========================================================================

    def run_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main Master Agent and Agent Router entrypoint.

        Supported task actions:
            authorize
            permission_check
            risk_assessment
            fraud_check
            approve
            deny
            approval_status
            create_biometric_challenge
            verify_biometric
            register_device
            revoke_device
            lock_workspace
            unlock_workspace
            lock_user
            unlock_user
            audit_search
            security_status
            register_policy
            list_policies
        """

        if not isinstance(task, dict):
            return self._error_result(
                message="Invalid Security Agent task.",
                error="task must be a dictionary.",
            )

        command = self._normalize_action(task.get("command") or task.get("operation"))
        protected_action = self._normalize_action(
            task.get("protected_action")
            or task.get("target_action")
            or task.get("action")
        )

        if not command or command == protected_action:
            command = self._infer_command(task)

        context_result = self._validate_task_context(task)

        if not context_result["success"]:
            return context_result

        context = context_result["data"]
        self._log_audit_event(command, context, task, event_type="task_received")

        try:
            if command == "authorize":
                result = self.authorize_action(
                    action=protected_action,
                    task_context=context,
                    payload=task.get("payload", {}),
                )

            elif command == "permission_check":
                result = self.check_permission(
                    task_context=context,
                    action=protected_action,
                    required_permissions=task.get("required_permissions"),
                    allowed_roles=task.get("allowed_roles"),
                )

            elif command == "risk_assessment":
                result = self.assess_risk(
                    action=protected_action,
                    task_context=context,
                    payload=task.get("payload", {}),
                )

            elif command == "fraud_check":
                result = self.detect_fraud(
                    action=protected_action,
                    task_context=context,
                    payload=task.get("payload", {}),
                )

            elif command == "approve":
                result = self.resolve_approval(
                    task_context=context,
                    approval_id=str(task.get("approval_id", "")),
                    approve=True,
                    reason=str(task.get("reason", "")),
                )

            elif command == "deny":
                result = self.resolve_approval(
                    task_context=context,
                    approval_id=str(task.get("approval_id", "")),
                    approve=False,
                    reason=str(task.get("reason", "")),
                )

            elif command == "approval_status":
                result = self.get_approval_status(
                    task_context=context,
                    approval_id=str(task.get("approval_id", "")),
                )

            elif command == "create_biometric_challenge":
                result = self.create_biometric_challenge(
                    task_context=context,
                    action=protected_action,
                    device_id=task.get("device_id"),
                )

            elif command == "verify_biometric":
                result = self.verify_biometric_challenge(
                    task_context=context,
                    challenge_id=str(task.get("challenge_id", "")),
                    assertion=task.get("assertion", {}),
                )

            elif command == "register_device":
                result = self.register_device(
                    task_context=context,
                    device_id=str(task.get("device_id", "")),
                    device_metadata=task.get("device_metadata", {}),
                    trusted=bool(task.get("trusted", False)),
                )

            elif command == "revoke_device":
                result = self.revoke_device(
                    task_context=context,
                    device_id=str(task.get("device_id", "")),
                )

            elif command == "lock_workspace":
                result = self.lock_workspace(
                    task_context=context,
                    reason=str(task.get("reason", "Security lock requested.")),
                )

            elif command == "unlock_workspace":
                result = self.unlock_workspace(
                    task_context=context,
                    reason=str(task.get("reason", "Security unlock requested.")),
                )

            elif command == "lock_user":
                result = self.lock_user(
                    task_context=context,
                    target_user_id=str(task.get("target_user_id", context["user_id"])),
                    reason=str(task.get("reason", "Security lock requested.")),
                )

            elif command == "unlock_user":
                result = self.unlock_user(
                    task_context=context,
                    target_user_id=str(task.get("target_user_id", context["user_id"])),
                    reason=str(task.get("reason", "Security unlock requested.")),
                )

            elif command == "audit_search":
                result = self.search_audit_logs(
                    task_context=context,
                    query=task.get("query"),
                    action_filter=task.get("action_filter"),
                    limit=int(task.get("limit", 100)),
                )

            elif command == "security_status":
                result = self.get_security_status(context)

            elif command == "register_policy":
                result = self.register_policy(
                    task_context=context,
                    policy=task.get("policy", {}),
                )

            elif command == "list_policies":
                result = self.list_policies(context)

            else:
                result = self._error_result(
                    message="Unsupported Security Agent command.",
                    error=f"Unsupported command: {command}",
                    metadata={
                        "supported_commands": self.registry_metadata[
                            "supported_actions"
                        ]
                    },
                )

            result.setdefault("metadata", {})
            result["metadata"]["verification_payload"] = (
                self._prepare_verification_payload(
                    action=command,
                    task_context=context,
                    result=result,
                )
            )

            self._log_audit_event(
                action=command,
                task_context=context,
                payload=task,
                result=result,
                event_type="task_completed",
            )

            self._emit_agent_event(
                f"security_agent.{command}",
                {
                    "user_id": context["user_id"],
                    "workspace_id": context["workspace_id"],
                    "task_id": context["task_id"],
                    "success": result.get("success"),
                    "decision": result.get("data", {}).get("decision"),
                },
            )

            return result

        except Exception as exc:
            logger.exception("Security Agent task failed.")
            result = self._error_result(
                message="Security Agent task failed.",
                error=exc,
                metadata={"command": command},
            )

            self._log_audit_event(
                action=command,
                task_context=context,
                payload=task,
                result=result,
                event_type="task_failed",
            )
            return result

    # =========================================================================
    # Core authorization
    # =========================================================================

    def authorize_action(
        self,
        action: str,
        task_context: Dict[str, Any],
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Execute the full security decision pipeline.

        Pipeline:
            1. Validate tenant context
            2. Check emergency locks
            3. Classify action
            4. Match security policy
            5. Check role and permissions
            6. Validate subscription/session/device
            7. Detect fraud and anomalies
            8. Calculate risk
            9. Enforce MFA/biometric requirements
            10. Create approval request if needed
            11. Return structured decision
        """

        payload = payload or {}

        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        context = context_result["data"]
        normalized_action = self._normalize_action(action)

        if not normalized_action:
            return self._error_result(
                message="Security authorization failed.",
                error="action is required.",
                data={"decision": SecurityDecision.DENY.value},
            )

        self._record_action_history(context, normalized_action, payload)

        classification_result = self.classify_action(normalized_action, payload)
        if not classification_result["success"]:
            return classification_result

        classification = classification_result["data"]
        sensitivity = classification["sensitivity"]

        policy = self._match_policy(normalized_action)

        permission_result = self.check_permission(
            task_context=context,
            action=normalized_action,
            required_permissions=policy.required_permissions if policy else None,
            allowed_roles=policy.allowed_roles if policy else None,
        )

        if not permission_result["success"]:
            return self._authorization_response(
                decision=SecurityDecision.DENY,
                action=normalized_action,
                context=context,
                sensitivity=sensitivity,
                message="Permission denied.",
                reason=permission_result.get("error") or permission_result["message"],
                permission_result=permission_result,
            )

        fraud_result = self.detect_fraud(
            action=normalized_action,
            task_context=context,
            payload=payload,
        )

        risk_result = self.assess_risk(
            action=normalized_action,
            task_context=context,
            payload=payload,
            classification=classification,
            fraud_result=fraud_result,
        )

        if not risk_result["success"]:
            return risk_result

        risk_assessment = risk_result["data"]["risk_assessment"]
        risk_score = float(risk_assessment["score"])
        risk_level = risk_assessment["level"]

        if policy and risk_score > policy.max_risk_score:
            return self._authorization_response(
                decision=SecurityDecision.DENY,
                action=normalized_action,
                context=context,
                sensitivity=sensitivity,
                message="Action denied by security policy.",
                reason=(
                    f"Risk score {risk_score:.2f} exceeds policy maximum "
                    f"{policy.max_risk_score:.2f}."
                ),
                permission_result=permission_result,
                risk_assessment=risk_assessment,
                fraud_result=fraud_result,
                policy=policy,
            )

        if risk_level == RiskLevel.CRITICAL.value:
            return self._authorization_response(
                decision=SecurityDecision.DENY,
                action=normalized_action,
                context=context,
                sensitivity=sensitivity,
                message="Critical-risk action denied.",
                reason="Critical security risk detected.",
                permission_result=permission_result,
                risk_assessment=risk_assessment,
                fraud_result=fraud_result,
                policy=policy,
            )

        require_trusted_device = bool(
            policy.require_trusted_device if policy else False
        )

        if sensitivity in {
            ActionSensitivity.DESTRUCTIVE.value,
            ActionSensitivity.FINANCIAL.value,
            ActionSensitivity.PRIVILEGED.value,
        }:
            require_trusted_device = True

        device_result = self._evaluate_device_trust(context)

        if require_trusted_device and not device_result["data"]["trusted"]:
            return self._authorization_response(
                decision=SecurityDecision.CHALLENGE,
                action=normalized_action,
                context=context,
                sensitivity=sensitivity,
                message="Trusted device verification required.",
                reason="The current device is not trusted for this action.",
                permission_result=permission_result,
                risk_assessment=risk_assessment,
                fraud_result=fraud_result,
                policy=policy,
                extra={"device_check": device_result["data"]},
            )

        require_mfa = bool(policy.require_mfa if policy else False)

        if (
            sensitivity == ActionSensitivity.PRIVILEGED.value
            and self.config.require_mfa_for_privileged_actions
        ):
            require_mfa = True

        if require_mfa and not bool(context.get("mfa_verified")):
            return self._authorization_response(
                decision=SecurityDecision.REQUIRE_MFA,
                action=normalized_action,
                context=context,
                sensitivity=sensitivity,
                message="Multi-factor authentication required.",
                reason="MFA verification is required before this action.",
                permission_result=permission_result,
                risk_assessment=risk_assessment,
                fraud_result=fraud_result,
                policy=policy,
            )

        require_biometric = bool(policy.require_biometric if policy else False)

        if (
            sensitivity == ActionSensitivity.DESTRUCTIVE.value
            and self.config.require_biometric_for_destructive_actions
        ):
            require_biometric = True

        if (
            sensitivity == ActionSensitivity.FINANCIAL.value
            and self.config.require_biometric_for_financial_actions
        ):
            require_biometric = True

        if require_biometric and not bool(context.get("biometric_verified")):
            challenge_result = self.create_biometric_challenge(
                task_context=context,
                action=normalized_action,
                device_id=context.get("device_id"),
            )

            challenge_data = (
                challenge_result.get("data", {})
                if challenge_result.get("success")
                else {}
            )

            return self._authorization_response(
                decision=SecurityDecision.REQUIRE_BIOMETRIC,
                action=normalized_action,
                context=context,
                sensitivity=sensitivity,
                message="Biometric verification required.",
                reason="The action requires biometric confirmation.",
                permission_result=permission_result,
                risk_assessment=risk_assessment,
                fraud_result=fraud_result,
                policy=policy,
                extra={"biometric_challenge": challenge_data},
            )

        require_approval = bool(policy.require_approval if policy else False)

        if (
            sensitivity
            in {
                ActionSensitivity.HIGH_RISK.value,
                ActionSensitivity.DESTRUCTIVE.value,
                ActionSensitivity.FINANCIAL.value,
            }
            and self.config.require_approval_for_high_risk
        ):
            require_approval = True

        if risk_level == RiskLevel.HIGH.value:
            require_approval = True

        if require_approval:
            approval_result = self.create_approval_request(
                task_context=context,
                action=normalized_action,
                payload=payload,
                sensitivity=sensitivity,
                risk_assessment=risk_assessment,
                policy=policy,
            )

            if not approval_result["success"]:
                return approval_result

            return self._authorization_response(
                decision=SecurityDecision.REQUIRE_APPROVAL,
                action=normalized_action,
                context=context,
                sensitivity=sensitivity,
                message="Security approval required.",
                reason="The action is awaiting an authorized approver.",
                permission_result=permission_result,
                risk_assessment=risk_assessment,
                fraud_result=fraud_result,
                policy=policy,
                extra={"approval": approval_result["data"]},
            )

        return self._authorization_response(
            decision=SecurityDecision.ALLOW,
            action=normalized_action,
            context=context,
            sensitivity=sensitivity,
            message="Action authorized.",
            reason="All required security checks passed.",
            permission_result=permission_result,
            risk_assessment=risk_assessment,
            fraud_result=fraud_result,
            policy=policy,
        )

    def approve(
        self,
        action: str,
        task_context: Dict[str, Any],
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Compatibility alias used by other agents.

        This does not blindly approve an action. It runs authorize_action().
        """

        return self.authorize_action(action, task_context, payload or {})

    # =========================================================================
    # Permission checks
    # =========================================================================

    def check_permission(
        self,
        task_context: Dict[str, Any],
        action: str,
        required_permissions: Optional[Sequence[str]] = None,
        allowed_roles: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        """Check role and permission authorization for an action."""

        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        context = context_result["data"]
        normalized_action = self._normalize_action(action)

        if self.permission_checker and hasattr(
            self.permission_checker, "check_permission"
        ):
            try:
                external_result = self.permission_checker.check_permission(
                    task_context=context,
                    action=normalized_action,
                    required_permissions=list(required_permissions or []),
                    allowed_roles=list(allowed_roles or []),
                )
                if isinstance(external_result, dict):
                    return external_result
            except Exception as exc:
                logger.warning("External permission checker failed: %s", exc)

        role = self._normalize_role(context.get("role"))
        permissions = set(
            self._normalize_permissions(context.get("permissions", []))
        )
        requirements = set(
            self._normalize_permissions(required_permissions or [])
        )
        roles = {
            self._normalize_role(item)
            for item in (allowed_roles or [])
            if self._normalize_role(item)
        }

        if role in {"owner", "workspace_owner", "security_admin"}:
            return self._safe_result(
                message="Permission granted by trusted role.",
                data={
                    "granted": True,
                    "role": role,
                    "matched_permissions": sorted(requirements),
                    "missing_permissions": [],
                },
            )

        if roles and role not in roles:
            return self._error_result(
                message="Role is not authorized for this action.",
                error=f"role={role} is not in allowed_roles.",
                data={
                    "granted": False,
                    "role": role,
                    "allowed_roles": sorted(roles),
                },
            )

        wildcard_permissions = {
            "*",
            "security.*",
            f"{normalized_action}.*",
            normalized_action,
        }

        if permissions.intersection(wildcard_permissions):
            return self._safe_result(
                message="Permission granted.",
                data={
                    "granted": True,
                    "role": role,
                    "matched_permissions": sorted(
                        permissions.intersection(wildcard_permissions)
                    ),
                    "missing_permissions": [],
                },
            )

        missing = sorted(requirements.difference(permissions))

        if requirements and missing:
            return self._error_result(
                message="Required permission is missing.",
                error=f"Missing permissions: {', '.join(missing)}",
                data={
                    "granted": False,
                    "role": role,
                    "required_permissions": sorted(requirements),
                    "missing_permissions": missing,
                },
            )

        classification = self.classify_action(normalized_action, {})

        if classification["success"]:
            sensitivity = classification["data"]["sensitivity"]

            if (
                self.config.require_explicit_permission_for_sensitive_actions
                and sensitivity
                in {
                    ActionSensitivity.SENSITIVE.value,
                    ActionSensitivity.HIGH_RISK.value,
                    ActionSensitivity.DESTRUCTIVE.value,
                    ActionSensitivity.FINANCIAL.value,
                    ActionSensitivity.PRIVILEGED.value,
                    ActionSensitivity.EXTERNAL_COMMUNICATION.value,
                }
                and not permissions
            ):
                return self._error_result(
                    message="Explicit permission is required.",
                    error=(
                        "Sensitive actions require an assigned permission or "
                        "trusted administrative role."
                    ),
                    data={
                        "granted": False,
                        "role": role,
                        "action": normalized_action,
                        "sensitivity": sensitivity,
                    },
                )

        return self._safe_result(
            message="Permission granted.",
            data={
                "granted": True,
                "role": role,
                "matched_permissions": sorted(requirements),
                "missing_permissions": [],
            },
        )

    # =========================================================================
    # Action classification
    # =========================================================================

    def classify_action(
        self,
        action: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Classify an action by operational and security sensitivity."""

        payload = payload or {}
        normalized_action = self._normalize_action(action)

        if not normalized_action:
            return self._error_result(
                message="Action classification failed.",
                error="action is required.",
            )

        if self.policy_engine and hasattr(self.policy_engine, "classify_action"):
            try:
                external = self.policy_engine.classify_action(
                    normalized_action, payload
                )
                if isinstance(external, dict):
                    return external
            except Exception as exc:
                logger.warning("External action classifier failed: %s", exc)

        destructive_terms = {
            "delete",
            "destroy",
            "drop",
            "wipe",
            "erase",
            "terminate",
            "remove_account",
            "remove_workspace",
            "revoke_all",
            "factory_reset",
            "shutdown",
            "format",
            "purge",
        }

        financial_terms = {
            "payment",
            "pay",
            "charge",
            "refund",
            "withdraw",
            "transfer",
            "invoice",
            "payout",
            "bank",
            "purchase",
            "subscription_change",
            "billing",
        }

        privileged_terms = {
            "role",
            "permission",
            "admin",
            "security_policy",
            "api_key",
            "secret",
            "credential",
            "impersonate",
            "elevate",
            "grant_access",
            "revoke_access",
            "workspace_lock",
            "user_lock",
        }

        external_terms = {
            "send_email",
            "send_message",
            "place_call",
            "publish",
            "post",
            "deploy",
            "browser_submit",
            "external_request",
            "notify_customer",
        }

        sensitive_terms = {
            "read_memory",
            "export",
            "download",
            "customer_data",
            "personal_data",
            "health_data",
            "financial_data",
            "audit_log",
            "session",
            "device",
            "location",
            "biometric",
        }

        high_risk_terms = {
            "execute_command",
            "terminal",
            "shell",
            "system_change",
            "install",
            "uninstall",
            "git_push",
            "production",
            "database_write",
            "file_write",
            "file_move",
            "automation_run",
        }

        tokens = set(re.split(r"[^a-z0-9]+", normalized_action))
        combined = normalized_action.replace(".", "_").replace(":", "_")

        sensitivity = ActionSensitivity.NORMAL
        reasons: List[str] = []

        if payload.get("public_read_only") is True:
            sensitivity = ActionSensitivity.PUBLIC
            reasons.append("payload_public_read_only")

        if any(term in combined or term in tokens for term in destructive_terms):
            sensitivity = ActionSensitivity.DESTRUCTIVE
            reasons.append("destructive_action_pattern")

        elif any(term in combined or term in tokens for term in financial_terms):
            sensitivity = ActionSensitivity.FINANCIAL
            reasons.append("financial_action_pattern")

        elif any(term in combined or term in tokens for term in privileged_terms):
            sensitivity = ActionSensitivity.PRIVILEGED
            reasons.append("privileged_action_pattern")

        elif any(term in combined or term in tokens for term in external_terms):
            sensitivity = ActionSensitivity.EXTERNAL_COMMUNICATION
            reasons.append("external_effect_pattern")

        elif any(term in combined or term in tokens for term in high_risk_terms):
            sensitivity = ActionSensitivity.HIGH_RISK
            reasons.append("high_risk_action_pattern")

        elif any(term in combined or term in tokens for term in sensitive_terms):
            sensitivity = ActionSensitivity.SENSITIVE
            reasons.append("sensitive_data_pattern")

        if payload.get("destructive") is True:
            sensitivity = ActionSensitivity.DESTRUCTIVE
            reasons.append("payload_destructive")

        if payload.get("financial") is True:
            sensitivity = ActionSensitivity.FINANCIAL
            reasons.append("payload_financial")

        if payload.get("privileged") is True:
            sensitivity = ActionSensitivity.PRIVILEGED
            reasons.append("payload_privileged")

        if payload.get("external_effect") is True:
            sensitivity = ActionSensitivity.EXTERNAL_COMMUNICATION
            reasons.append("payload_external_effect")

        if payload.get("contains_sensitive_data") is True and sensitivity in {
            ActionSensitivity.PUBLIC,
            ActionSensitivity.NORMAL,
        }:
            sensitivity = ActionSensitivity.SENSITIVE
            reasons.append("payload_sensitive_data")

        return self._safe_result(
            message="Action classified.",
            data={
                "action": normalized_action,
                "sensitivity": sensitivity.value,
                "reasons": reasons or ["default_normal_classification"],
                "requires_full_security_check": (
                    sensitivity != ActionSensitivity.PUBLIC
                ),
            },
        )

    # =========================================================================
    # Risk scoring and fraud detection
    # =========================================================================

    def assess_risk(
        self,
        action: str,
        task_context: Dict[str, Any],
        payload: Optional[Dict[str, Any]] = None,
        classification: Optional[Dict[str, Any]] = None,
        fraud_result: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Calculate a deterministic risk score from 0 to 100."""

        payload = payload or {}

        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        context = context_result["data"]

        if self.risk_engine and hasattr(self.risk_engine, "assess"):
            try:
                external = self.risk_engine.assess(
                    action=action,
                    task_context=context,
                    payload=payload,
                )
                if isinstance(external, dict):
                    return external
            except Exception as exc:
                logger.warning("External risk engine failed: %s", exc)

        if classification is None:
            classification_result = self.classify_action(action, payload)
            if not classification_result["success"]:
                return classification_result
            classification = classification_result["data"]

        sensitivity = classification["sensitivity"]
        factors: Dict[str, float] = {}
        signals: List[Dict[str, Any]] = []

        base_scores = {
            ActionSensitivity.PUBLIC.value: 2.0,
            ActionSensitivity.NORMAL.value: 10.0,
            ActionSensitivity.SENSITIVE.value: 30.0,
            ActionSensitivity.EXTERNAL_COMMUNICATION.value: 38.0,
            ActionSensitivity.HIGH_RISK.value: 50.0,
            ActionSensitivity.PRIVILEGED.value: 55.0,
            ActionSensitivity.FINANCIAL.value: 60.0,
            ActionSensitivity.DESTRUCTIVE.value: 70.0,
        }

        factors["action_sensitivity"] = base_scores.get(sensitivity, 25.0)

        role = self._normalize_role(context.get("role"))

        if role in self.config.trusted_roles:
            factors["trusted_role_adjustment"] = -10.0
        elif role in {"viewer", "guest", "contractor"}:
            factors["limited_role"] = 12.0
        else:
            factors["standard_role"] = 0.0

        if not context.get("session_id"):
            factors["missing_session"] = 8.0
            signals.append(
                self._signal(
                    FraudSignalType.SESSION_MISMATCH,
                    "No session identifier was supplied.",
                    8.0,
                )
            )

        if self.config.enable_device_trust:
            device_result = self._evaluate_device_trust(context)
            if not device_result["data"]["trusted"]:
                factors["untrusted_device"] = 12.0
                signals.append(
                    self._signal(
                        FraudSignalType.UNTRUSTED_DEVICE,
                        "Action originated from an untrusted device.",
                        12.0,
                    )
                )
            else:
                factors["trusted_device_adjustment"] = -5.0

        if context.get("mfa_verified"):
            factors["mfa_adjustment"] = -8.0

        if context.get("biometric_verified"):
            factors["biometric_adjustment"] = -10.0

        velocity = self._calculate_velocity(context, action)

        if velocity["total_last_minute"] > self.config.max_actions_per_minute:
            excess = velocity["total_last_minute"] - self.config.max_actions_per_minute
            penalty = min(20.0, 5.0 + excess * 0.25)
            factors["action_velocity"] = penalty
            signals.append(
                self._signal(
                    FraudSignalType.VELOCITY_SPIKE,
                    "General action velocity exceeded the configured threshold.",
                    penalty,
                    velocity,
                )
            )

        if (
            sensitivity
            != ActionSensitivity.PUBLIC.value
            and velocity["sensitive_last_minute"]
            > self.config.max_sensitive_actions_per_minute
        ):
            factors["sensitive_velocity"] = 18.0
            signals.append(
                self._signal(
                    FraudSignalType.VELOCITY_SPIKE,
                    "Sensitive action velocity exceeded the configured threshold.",
                    18.0,
                    velocity,
                )
            )

        failed_attempt_count = self._recent_failed_attempt_count(context)

        if failed_attempt_count >= self.config.max_failed_attempts:
            factors["repeated_failures"] = 20.0
            signals.append(
                self._signal(
                    FraudSignalType.REPEATED_FAILURES,
                    "Repeated failed security attempts detected.",
                    20.0,
                    {"failed_attempts": failed_attempt_count},
                )
            )
        elif failed_attempt_count:
            factors["recent_failures"] = min(10.0, failed_attempt_count * 2.0)

        if self._payload_contains_secret(payload):
            factors["secret_exposure"] = 18.0
            signals.append(
                self._signal(
                    FraudSignalType.SECRET_EXPOSURE,
                    "Payload appears to contain secret or credential material.",
                    18.0,
                )
            )

        if self._payload_indicates_bulk_export(payload):
            factors["data_exfiltration"] = 20.0
            signals.append(
                self._signal(
                    FraudSignalType.DATA_EXFILTRATION,
                    "Large or bulk data export pattern detected.",
                    20.0,
                )
            )

        if fraud_result is None:
            fraud_result = self.detect_fraud(action, context, payload)

        if fraud_result.get("success"):
            fraud_signals = fraud_result.get("data", {}).get("signals", [])
            for signal in fraud_signals:
                severity = float(signal.get("risk_points", 0.0))
                factors[
                    f"fraud_{signal.get('type', 'unknown')}"
                ] = severity
                signals.append(signal)

        score = max(0.0, min(100.0, sum(factors.values())))
        level = self._risk_level(score)

        if level == RiskLevel.CRITICAL.value:
            recommended = SecurityDecision.DENY.value
        elif level == RiskLevel.HIGH.value:
            recommended = SecurityDecision.REQUIRE_APPROVAL.value
        elif level == RiskLevel.MEDIUM.value:
            recommended = SecurityDecision.CHALLENGE.value
        else:
            recommended = SecurityDecision.ALLOW.value

        assessment = RiskAssessment(
            assessment_id=str(uuid.uuid4()),
            score=round(score, 2),
            level=level,
            signals=signals,
            factors={key: round(value, 2) for key, value in factors.items()},
            recommended_decision=recommended,
            created_at=self._utc_now(),
        )

        return self._safe_result(
            message="Security risk assessed.",
            data={"risk_assessment": asdict(assessment)},
        )

    def detect_fraud(
        self,
        action: str,
        task_context: Dict[str, Any],
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Detect common fraud and anomaly patterns."""

        payload = payload or {}

        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        context = context_result["data"]
        signals: List[Dict[str, Any]] = []

        if self.fraud_detector and hasattr(self.fraud_detector, "detect"):
            try:
                external = self.fraud_detector.detect(
                    action=action,
                    task_context=context,
                    payload=payload,
                )
                if isinstance(external, dict):
                    return external
            except Exception as exc:
                logger.warning("External fraud detector failed: %s", exc)

        if context.get("target_workspace_id") and (
            context.get("target_workspace_id") != context.get("workspace_id")
        ):
            signals.append(
                self._signal(
                    FraudSignalType.TENANT_BOUNDARY_ATTEMPT,
                    "Cross-workspace access attempt detected.",
                    100.0,
                )
            )

        if context.get("target_user_id") and (
            context.get("target_user_id") != context.get("user_id")
        ):
            signals.append(
                self._signal(
                    FraudSignalType.TENANT_BOUNDARY_ATTEMPT,
                    "Cross-user access attempt detected.",
                    100.0,
                )
            )

        device_result = self._evaluate_device_trust(context)

        if (
            context.get("device_id")
            and not device_result["data"]["known"]
        ):
            signals.append(
                self._signal(
                    FraudSignalType.NEW_DEVICE,
                    "A previously unknown device is being used.",
                    8.0,
                    device_result["data"],
                )
            )

        if self._looks_like_automation_user_agent(context.get("user_agent")):
            signals.append(
                self._signal(
                    FraudSignalType.SUSPICIOUS_USER_AGENT,
                    "Potential automated or scripted client detected.",
                    8.0,
                )
            )

        if self._payload_requests_privilege_escalation(action, payload):
            current_role = self._normalize_role(context.get("role"))
            if current_role not in self.config.protected_roles:
                signals.append(
                    self._signal(
                        FraudSignalType.PRIVILEGE_ESCALATION,
                        "Privilege escalation attempted by a non-protected role.",
                        40.0,
                        {"current_role": current_role},
                    )
                )

        if self._payload_contains_secret(payload):
            signals.append(
                self._signal(
                    FraudSignalType.SECRET_EXPOSURE,
                    "Potential secret material detected in request payload.",
                    12.0,
                )
            )

        if self._payload_indicates_payment_anomaly(payload):
            signals.append(
                self._signal(
                    FraudSignalType.PAYMENT_ANOMALY,
                    "Potential payment anomaly detected.",
                    25.0,
                )
            )

        if self._payload_indicates_bulk_export(payload):
            signals.append(
                self._signal(
                    FraudSignalType.DATA_EXFILTRATION,
                    "Potential bulk data extraction pattern detected.",
                    25.0,
                )
            )

        high_confidence = any(
            float(item.get("risk_points", 0.0)) >= 40.0 for item in signals
        )

        total_risk_points = min(
            100.0,
            sum(float(item.get("risk_points", 0.0)) for item in signals),
        )

        return self._safe_result(
            message="Fraud detection completed.",
            data={
                "fraud_detected": bool(signals),
                "high_confidence": high_confidence,
                "signal_count": len(signals),
                "risk_points": round(total_risk_points, 2),
                "signals": signals,
            },
        )

    # =========================================================================
    # Approval management
    # =========================================================================

    def create_approval_request(
        self,
        task_context: Dict[str, Any],
        action: str,
        payload: Dict[str, Any],
        sensitivity: str,
        risk_assessment: Dict[str, Any],
        policy: Optional[SecurityPolicy] = None,
    ) -> Dict[str, Any]:
        """Create a tenant-isolated approval request."""

        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        context = context_result["data"]

        if self.approval_manager and hasattr(
            self.approval_manager, "create_request"
        ):
            try:
                external = self.approval_manager.create_request(
                    task_context=context,
                    action=action,
                    payload=payload,
                    sensitivity=sensitivity,
                    risk_assessment=risk_assessment,
                )
                if isinstance(external, dict):
                    return external
            except Exception as exc:
                logger.warning("External approval manager failed: %s", exc)

        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=self.config.approval_ttl_seconds)

        required_roles = (
            list(policy.allowed_roles)
            if policy and policy.allowed_roles
            else ["owner", "workspace_owner", "security_admin", "admin"]
        )

        approval = ApprovalRecord(
            approval_id=f"apr_{uuid.uuid4().hex}",
            user_id=context["user_id"],
            workspace_id=context["workspace_id"],
            task_id=context["task_id"],
            action=self._normalize_action(action),
            sensitivity=sensitivity,
            status=ApprovalStatus.PENDING.value,
            requested_by=context["user_id"],
            requested_at=now.isoformat(),
            expires_at=expires_at.isoformat(),
            risk_score=float(risk_assessment.get("score", 0.0)),
            reason="Security policy requires approval.",
            payload_hash=self._stable_hash(payload),
            required_approver_roles=required_roles,
            metadata={
                "source_agent": context.get("source_agent"),
                "request_id": context.get("request_id"),
            },
        )

        with self._lock:
            self._approvals[approval.approval_id] = approval

        self._emit_agent_event(
            "security_agent.approval_requested",
            {
                "approval_id": approval.approval_id,
                "user_id": context["user_id"],
                "workspace_id": context["workspace_id"],
                "action": action,
                "risk_score": approval.risk_score,
            },
        )

        return self._safe_result(
            message="Security approval request created.",
            data={
                "approval_id": approval.approval_id,
                "status": approval.status,
                "action": approval.action,
                "expires_at": approval.expires_at,
                "required_approver_roles": approval.required_approver_roles,
            },
        )

    def resolve_approval(
        self,
        task_context: Dict[str, Any],
        approval_id: str,
        approve: bool,
        reason: str = "",
    ) -> Dict[str, Any]:
        """Approve or deny a pending security approval."""

        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        context = context_result["data"]
        approval_id = self._clean_identifier(approval_id)

        if not approval_id:
            return self._error_result(
                message="Approval resolution failed.",
                error="approval_id is required.",
            )

        with self._lock:
            approval = self._approvals.get(approval_id)

            if not approval:
                return self._error_result(
                    message="Approval not found.",
                    error="No approval exists for the provided approval_id.",
                )

            if not self._same_tenant(context, approval):
                return self._error_result(
                    message="Approval access denied.",
                    error="Approval belongs to another user/workspace tenant.",
                )

            self._refresh_approval_status(approval)

            if approval.status != ApprovalStatus.PENDING.value:
                return self._error_result(
                    message="Approval is no longer pending.",
                    error=f"Current status: {approval.status}",
                    data={
                        "approval_id": approval.approval_id,
                        "status": approval.status,
                    },
                )

            approver_role = self._normalize_role(context.get("role"))

            if (
                approval.required_approver_roles
                and approver_role not in approval.required_approver_roles
            ):
                return self._error_result(
                    message="Approver role is not authorized.",
                    error=(
                        f"Role {approver_role} cannot resolve this approval."
                    ),
                )

            if (
                approval.requested_by == context["user_id"]
                and approver_role not in {"owner", "workspace_owner"}
                and approval.sensitivity
                in {
                    ActionSensitivity.DESTRUCTIVE.value,
                    ActionSensitivity.FINANCIAL.value,
                    ActionSensitivity.PRIVILEGED.value,
                }
            ):
                return self._error_result(
                    message="Self-approval is not permitted.",
                    error=(
                        "High-impact actions require a separate authorized "
                        "approver unless the user is a workspace owner."
                    ),
                )

            now = self._utc_now()

            if approve:
                approval.status = ApprovalStatus.APPROVED.value
                approval.approved_by = context["user_id"]
                approval.approved_at = now
            else:
                approval.status = ApprovalStatus.DENIED.value
                approval.denied_by = context["user_id"]
                approval.denied_at = now

            approval.decision_reason = self._clean_string(reason)[:1000]

        event_name = (
            "security_agent.approval_granted"
            if approve
            else "security_agent.approval_denied"
        )

        self._emit_agent_event(
            event_name,
            {
                "approval_id": approval.approval_id,
                "user_id": context["user_id"],
                "workspace_id": context["workspace_id"],
                "status": approval.status,
            },
        )

        return self._safe_result(
            message=(
                "Security approval granted."
                if approve
                else "Security approval denied."
            ),
            data=self._approval_public_dict(approval),
        )

    def get_approval_status(
        self,
        task_context: Dict[str, Any],
        approval_id: str,
    ) -> Dict[str, Any]:
        """Read a tenant-owned approval status."""

        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        context = context_result["data"]
        approval_id = self._clean_identifier(approval_id)

        with self._lock:
            approval = self._approvals.get(approval_id)

            if not approval:
                return self._error_result(
                    message="Approval not found.",
                    error="No approval exists for the provided approval_id.",
                )

            if not self._same_tenant(context, approval):
                return self._error_result(
                    message="Approval access denied.",
                    error="Approval belongs to another tenant.",
                )

            self._refresh_approval_status(approval)

            return self._safe_result(
                message="Approval status loaded.",
                data=self._approval_public_dict(approval),
            )

    # =========================================================================
    # Biometric gates
    # =========================================================================

    def create_biometric_challenge(
        self,
        task_context: Dict[str, Any],
        action: str,
        device_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Create a biometric challenge.

        Raw biometric data is never stored. Only a server-generated nonce hash
        and challenge status are retained.
        """

        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        context = context_result["data"]

        if not self.config.enable_biometric_gate:
            return self._error_result(
                message="Biometric verification is unavailable.",
                error="Biometric gate is disabled by configuration.",
            )

        if self.biometric_gate and hasattr(
            self.biometric_gate, "create_challenge"
        ):
            try:
                external = self.biometric_gate.create_challenge(
                    task_context=context,
                    action=action,
                    device_id=device_id,
                )
                if isinstance(external, dict):
                    return external
            except Exception as exc:
                logger.warning("External biometric gate failed: %s", exc)

        nonce = secrets.token_urlsafe(32)
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(
            seconds=self.config.biometric_challenge_ttl_seconds
        )

        challenge = BiometricChallenge(
            challenge_id=f"bio_{uuid.uuid4().hex}",
            user_id=context["user_id"],
            workspace_id=context["workspace_id"],
            task_id=context["task_id"],
            action=self._normalize_action(action),
            nonce_hash=self._stable_hash(nonce),
            status=BiometricStatus.REQUIRED.value,
            created_at=now.isoformat(),
            expires_at=expires_at.isoformat(),
            device_id=self._clean_optional_identifier(
                device_id or context.get("device_id")
            ),
        )

        with self._lock:
            self._biometric_challenges[challenge.challenge_id] = challenge

        return self._safe_result(
            message="Biometric challenge created.",
            data={
                "challenge_id": challenge.challenge_id,
                "challenge_nonce": nonce,
                "status": challenge.status,
                "expires_at": challenge.expires_at,
                "action": challenge.action,
                "device_id": challenge.device_id,
            },
            metadata={
                "security_notice": (
                    "Raw biometric templates must be verified by the device or "
                    "specialized biometric provider and must not be sent here."
                )
            },
        )

    def verify_biometric_challenge(
        self,
        task_context: Dict[str, Any],
        challenge_id: str,
        assertion: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Verify a biometric assertion.

        The fallback verifier accepts only an explicit verified assertion from a
        trusted device-side or external biometric verifier. It does not process
        fingerprints, face images, voiceprints, or raw biometric templates.
        """

        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        context = context_result["data"]
        challenge_id = self._clean_identifier(challenge_id)

        if not challenge_id:
            return self._error_result(
                message="Biometric verification failed.",
                error="challenge_id is required.",
            )

        if not isinstance(assertion, dict):
            return self._error_result(
                message="Biometric verification failed.",
                error="assertion must be a dictionary.",
            )

        with self._lock:
            challenge = self._biometric_challenges.get(challenge_id)

            if not challenge:
                return self._error_result(
                    message="Biometric challenge not found.",
                    error="No biometric challenge exists for the provided ID.",
                )

            if not self._same_tenant(context, challenge):
                return self._error_result(
                    message="Biometric challenge access denied.",
                    error="Challenge belongs to another tenant.",
                )

            if self._is_expired(challenge.expires_at):
                challenge.status = BiometricStatus.EXPIRED.value
                return self._error_result(
                    message="Biometric challenge expired.",
                    error="Create a new biometric challenge.",
                    data={"status": challenge.status},
                )

            challenge.attempt_count += 1

            if challenge.attempt_count > self.config.max_failed_attempts:
                challenge.status = BiometricStatus.FAILED.value
                self._record_failed_attempt(context)
                return self._error_result(
                    message="Biometric challenge blocked.",
                    error="Maximum biometric verification attempts exceeded.",
                )

            expected_device = challenge.device_id
            assertion_device = self._clean_optional_identifier(
                assertion.get("device_id")
            )

            if (
                expected_device
                and assertion_device
                and expected_device != assertion_device
            ):
                self._record_failed_attempt(context)
                challenge.status = BiometricStatus.FAILED.value
                return self._error_result(
                    message="Biometric device mismatch.",
                    error="Assertion was produced by a different device.",
                )

            if self.biometric_gate and hasattr(self.biometric_gate, "verify"):
                try:
                    external = self.biometric_gate.verify(
                        task_context=context,
                        challenge=asdict(challenge),
                        assertion=assertion,
                    )
                    if isinstance(external, dict):
                        verified = bool(
                            external.get("success")
                            and external.get("data", {}).get("verified", False)
                        )
                    else:
                        verified = False
                except Exception as exc:
                    logger.warning("External biometric verification failed: %s", exc)
                    verified = False
            else:
                verified = bool(
                    assertion.get("verified") is True
                    and assertion.get("provider_verified") is True
                    and assertion.get("raw_biometric_data") is None
                    and assertion.get("biometric_template") is None
                )

            if not verified:
                self._record_failed_attempt(context)
                challenge.status = BiometricStatus.FAILED.value
                return self._error_result(
                    message="Biometric verification failed.",
                    error="The trusted verifier did not confirm the assertion.",
                    data={
                        "challenge_id": challenge.challenge_id,
                        "status": challenge.status,
                        "attempt_count": challenge.attempt_count,
                    },
                )

            challenge.status = BiometricStatus.VERIFIED.value
            challenge.verified_at = self._utc_now()

        return self._safe_result(
            message="Biometric verification completed.",
            data={
                "challenge_id": challenge.challenge_id,
                "verified": True,
                "status": challenge.status,
                "verified_at": challenge.verified_at,
                "action": challenge.action,
            },
        )

    # =========================================================================
    # Device trust
    # =========================================================================

    def register_device(
        self,
        task_context: Dict[str, Any],
        device_id: str,
        device_metadata: Optional[Dict[str, Any]] = None,
        trusted: bool = False,
    ) -> Dict[str, Any]:
        """Register a device for the current user/workspace."""

        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        context = context_result["data"]
        device_id = self._clean_identifier(device_id)

        if not device_id:
            return self._error_result(
                message="Device registration failed.",
                error="device_id is required.",
            )

        if trusted and self._normalize_role(context.get("role")) not in {
            "owner",
            "workspace_owner",
            "security_admin",
            "admin",
        }:
            return self._error_result(
                message="Device trust assignment denied.",
                error="Only authorized administrative roles may trust a device.",
            )

        tenant_key = self._tenant_key(context)
        now = self._utc_now()

        with self._lock:
            existing = self._known_devices[tenant_key].get(device_id, {})

            self._known_devices[tenant_key][device_id] = {
                "device_id": device_id,
                "user_id": context["user_id"],
                "workspace_id": context["workspace_id"],
                "trusted": bool(trusted or existing.get("trusted", False)),
                "registered_at": existing.get("registered_at", now),
                "last_seen_at": now,
                "metadata": self._safe_metadata(device_metadata or {}),
                "revoked": False,
            }

        return self._safe_result(
            message="Device registered.",
            data=copy.deepcopy(self._known_devices[tenant_key][device_id]),
        )

    def revoke_device(
        self,
        task_context: Dict[str, Any],
        device_id: str,
    ) -> Dict[str, Any]:
        """Revoke a tenant-owned device."""

        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        context = context_result["data"]

        if self._normalize_role(context.get("role")) not in {
            "owner",
            "workspace_owner",
            "security_admin",
            "admin",
        }:
            return self._error_result(
                message="Device revocation denied.",
                error="Administrative role required.",
            )

        device_id = self._clean_identifier(device_id)
        tenant_key = self._tenant_key(context)

        with self._lock:
            device = self._known_devices[tenant_key].get(device_id)

            if not device:
                return self._error_result(
                    message="Device not found.",
                    error="No matching device exists in this tenant.",
                )

            device["trusted"] = False
            device["revoked"] = True
            device["revoked_at"] = self._utc_now()
            device["revoked_by"] = context["user_id"]

        return self._safe_result(
            message="Device revoked.",
            data=copy.deepcopy(device),
        )

    # =========================================================================
    # Emergency locks
    # =========================================================================

    def lock_workspace(
        self,
        task_context: Dict[str, Any],
        reason: str,
    ) -> Dict[str, Any]:
        """Activate an emergency lock for the current workspace."""

        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        context = context_result["data"]

        if self._normalize_role(context.get("role")) not in {
            "owner",
            "workspace_owner",
            "security_admin",
        }:
            return self._error_result(
                message="Workspace lock denied.",
                error="Owner or security administrator role required.",
            )

        key = context["workspace_id"]

        with self._lock:
            self._workspace_locks[key] = {
                "workspace_id": key,
                "locked": True,
                "reason": self._clean_string(reason)[:1000],
                "locked_by": context["user_id"],
                "locked_at": self._utc_now(),
            }

        return self._safe_result(
            message="Workspace emergency lock activated.",
            data=copy.deepcopy(self._workspace_locks[key]),
        )

    def unlock_workspace(
        self,
        task_context: Dict[str, Any],
        reason: str,
    ) -> Dict[str, Any]:
        """Remove a workspace emergency lock."""

        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        context = context_result["data"]

        if self._normalize_role(context.get("role")) not in {
            "owner",
            "workspace_owner",
            "security_admin",
        }:
            return self._error_result(
                message="Workspace unlock denied.",
                error="Owner or security administrator role required.",
            )

        key = context["workspace_id"]

        with self._lock:
            previous = self._workspace_locks.get(key, {})
            self._workspace_locks[key] = {
                "workspace_id": key,
                "locked": False,
                "reason": self._clean_string(reason)[:1000],
                "unlocked_by": context["user_id"],
                "unlocked_at": self._utc_now(),
                "previous_lock": previous,
            }

        return self._safe_result(
            message="Workspace emergency lock removed.",
            data=copy.deepcopy(self._workspace_locks[key]),
        )

    def lock_user(
        self,
        task_context: Dict[str, Any],
        target_user_id: str,
        reason: str,
    ) -> Dict[str, Any]:
        """Lock a user inside the current workspace."""

        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        context = context_result["data"]

        if self._normalize_role(context.get("role")) not in {
            "owner",
            "workspace_owner",
            "security_admin",
            "admin",
        }:
            return self._error_result(
                message="User lock denied.",
                error="Administrative role required.",
            )

        target_user_id = self._clean_identifier(target_user_id)

        if not target_user_id:
            return self._error_result(
                message="User lock failed.",
                error="target_user_id is required.",
            )

        key = f"{context['workspace_id']}:{target_user_id}"

        with self._lock:
            self._user_locks[key] = {
                "user_id": target_user_id,
                "workspace_id": context["workspace_id"],
                "locked": True,
                "reason": self._clean_string(reason)[:1000],
                "locked_by": context["user_id"],
                "locked_at": self._utc_now(),
            }

        return self._safe_result(
            message="User security lock activated.",
            data=copy.deepcopy(self._user_locks[key]),
        )

    def unlock_user(
        self,
        task_context: Dict[str, Any],
        target_user_id: str,
        reason: str,
    ) -> Dict[str, Any]:
        """Unlock a user inside the current workspace."""

        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        context = context_result["data"]

        if self._normalize_role(context.get("role")) not in {
            "owner",
            "workspace_owner",
            "security_admin",
            "admin",
        }:
            return self._error_result(
                message="User unlock denied.",
                error="Administrative role required.",
            )

        target_user_id = self._clean_identifier(target_user_id)
        key = f"{context['workspace_id']}:{target_user_id}"

        with self._lock:
            previous = self._user_locks.get(key, {})
            self._user_locks[key] = {
                "user_id": target_user_id,
                "workspace_id": context["workspace_id"],
                "locked": False,
                "reason": self._clean_string(reason)[:1000],
                "unlocked_by": context["user_id"],
                "unlocked_at": self._utc_now(),
                "previous_lock": previous,
            }

        return self._safe_result(
            message="User security lock removed.",
            data=copy.deepcopy(self._user_locks[key]),
        )

    # =========================================================================
    # Audit API
    # =========================================================================

    def search_audit_logs(
        self,
        task_context: Dict[str, Any],
        query: Optional[str] = None,
        action_filter: Optional[str] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """Search isolated audit records for the current user/workspace."""

        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        context = context_result["data"]
        role = self._normalize_role(context.get("role"))

        if role not in {
            "owner",
            "workspace_owner",
            "security_admin",
            "admin",
            "auditor",
        }:
            return self._error_result(
                message="Audit log access denied.",
                error="Authorized audit or administrative role required.",
            )

        limit = max(1, min(int(limit), 500))
        query_text = self._clean_string(query or "").lower()
        action_value = self._normalize_action(action_filter)

        matches: List[Dict[str, Any]] = []

        with self._lock:
            for record in reversed(self._audit_records):
                if record.user_id != context["user_id"]:
                    continue

                if record.workspace_id != context["workspace_id"]:
                    continue

                if action_value and record.action != action_value:
                    continue

                public_record = asdict(record)

                if query_text:
                    searchable = json.dumps(
                        public_record,
                        sort_keys=True,
                        default=str,
                    ).lower()

                    if query_text not in searchable:
                        continue

                matches.append(public_record)

                if len(matches) >= limit:
                    break

        return self._safe_result(
            message="Security audit records loaded.",
            data={
                "count": len(matches),
                "records": matches,
            },
        )

    # =========================================================================
    # Policy management
    # =========================================================================

    def register_policy(
        self,
        task_context: Dict[str, Any],
        policy: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Register an in-memory policy for future Policy Engine migration."""

        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        context = context_result["data"]

        if self._normalize_role(context.get("role")) not in {
            "owner",
            "workspace_owner",
            "security_admin",
        }:
            return self._error_result(
                message="Policy registration denied.",
                error="Security administrator role required.",
            )

        if not isinstance(policy, dict):
            return self._error_result(
                message="Invalid security policy.",
                error="policy must be a dictionary.",
            )

        action_pattern = self._normalize_action(policy.get("action_pattern"))

        if not action_pattern:
            return self._error_result(
                message="Invalid security policy.",
                error="action_pattern is required.",
            )

        sensitivity = str(
            policy.get("sensitivity", ActionSensitivity.NORMAL.value)
        ).lower().strip()

        valid_sensitivities = {item.value for item in ActionSensitivity}

        if sensitivity not in valid_sensitivities:
            return self._error_result(
                message="Invalid security policy.",
                error=f"Unsupported sensitivity: {sensitivity}",
            )

        new_policy = SecurityPolicy(
            action_pattern=action_pattern,
            sensitivity=sensitivity,
            required_permissions=self._normalize_permissions(
                policy.get("required_permissions", [])
            ),
            allowed_roles=[
                self._normalize_role(item)
                for item in policy.get("allowed_roles", [])
                if self._normalize_role(item)
            ],
            denied_roles=[
                self._normalize_role(item)
                for item in policy.get("denied_roles", [])
                if self._normalize_role(item)
            ],
            require_approval=bool(policy.get("require_approval", False)),
            require_biometric=bool(policy.get("require_biometric", False)),
            require_mfa=bool(policy.get("require_mfa", False)),
            require_trusted_device=bool(
                policy.get("require_trusted_device", False)
            ),
            max_risk_score=max(
                0.0,
                min(100.0, float(policy.get("max_risk_score", 100.0))),
            ),
            enabled=bool(policy.get("enabled", True)),
            priority=int(policy.get("priority", 100)),
            metadata=self._safe_metadata(policy.get("metadata", {})),
        )

        with self._lock:
            self._policies.append(new_policy)
            self._policies.sort(key=lambda item: item.priority)

        return self._safe_result(
            message="Security policy registered.",
            data={"policy": asdict(new_policy)},
        )

    def list_policies(self, task_context: Dict[str, Any]) -> Dict[str, Any]:
        """List active policies for administrative users."""

        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        context = context_result["data"]

        if self._normalize_role(context.get("role")) not in {
            "owner",
            "workspace_owner",
            "security_admin",
            "admin",
            "auditor",
        }:
            return self._error_result(
                message="Policy access denied.",
                error="Administrative or audit role required.",
            )

        with self._lock:
            policies = [asdict(policy) for policy in self._policies]

        return self._safe_result(
            message="Security policies loaded.",
            data={"count": len(policies), "policies": policies},
        )

    # =========================================================================
    # Status and registry
    # =========================================================================

    def get_security_status(
        self,
        task_context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Return tenant-scoped security status."""

        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        context = context_result["data"]
        tenant_key = self._tenant_key(context)
        workspace_lock = self._workspace_locks.get(context["workspace_id"], {})
        user_lock = self._user_locks.get(
            f"{context['workspace_id']}:{context['user_id']}",
            {},
        )

        with self._lock:
            pending_approvals = sum(
                1
                for approval in self._approvals.values()
                if approval.user_id == context["user_id"]
                and approval.workspace_id == context["workspace_id"]
                and approval.status == ApprovalStatus.PENDING.value
            )

            known_devices = list(
                self._known_devices.get(tenant_key, {}).values()
            )

            recent_audits = sum(
                1
                for record in self._audit_records
                if record.user_id == context["user_id"]
                and record.workspace_id == context["workspace_id"]
            )

        return self._safe_result(
            message="Security status loaded.",
            data={
                "agent_name": "security_agent",
                "version": self.config.agent_version,
                "started_at": self._started_at,
                "workspace_locked": bool(workspace_lock.get("locked", False)),
                "user_locked": bool(user_lock.get("locked", False)),
                "pending_approvals": pending_approvals,
                "known_devices": len(known_devices),
                "trusted_devices": sum(
                    1
                    for device in known_devices
                    if device.get("trusted") and not device.get("revoked")
                ),
                "audit_record_count": recent_audits,
                "features": {
                    "permission_checks": self.config.enable_permission_checks,
                    "risk_scoring": self.config.enable_risk_scoring,
                    "fraud_detection": self.config.enable_fraud_detection,
                    "anomaly_detection": self.config.enable_anomaly_detection,
                    "biometric_gate": self.config.enable_biometric_gate,
                    "device_trust": self.config.enable_device_trust,
                    "session_guard": self.config.enable_session_guard,
                },
            },
        )

    def health_check(self) -> Dict[str, Any]:
        """Return import-safe agent health information."""

        with self._lock:
            approval_count = len(self._approvals)
            biometric_count = len(self._biometric_challenges)
            audit_count = len(self._audit_records)

        return self._safe_result(
            message="Security Agent is healthy.",
            data={
                "agent_name": "security_agent",
                "version": self.config.agent_version,
                "started_at": self._started_at,
                "approval_records": approval_count,
                "biometric_challenges": biometric_count,
                "audit_records": audit_count,
                "policy_count": len(self._policies),
                "external_components": {
                    "permission_checker": bool(self.permission_checker),
                    "risk_engine": bool(self.risk_engine),
                    "approval_manager": bool(self.approval_manager),
                    "biometric_gate": bool(self.biometric_gate),
                    "fraud_detector": bool(self.fraud_detector),
                    "anomaly_detector": bool(self.anomaly_detector),
                    "audit_logger": bool(self.audit_logger),
                    "policy_engine": bool(self.policy_engine),
                    "session_guard": bool(self.session_guard),
                    "device_access": bool(self.device_access),
                    "threat_monitor": bool(self.threat_monitor),
                },
            },
        )

    def get_registry_metadata(self) -> Dict[str, Any]:
        """Return Agent Registry-compatible metadata."""

        return copy.deepcopy(self.registry_metadata)

    # =========================================================================
    # Authorization response helper
    # =========================================================================

    def _authorization_response(
        self,
        decision: SecurityDecision,
        action: str,
        context: Dict[str, Any],
        sensitivity: str,
        message: str,
        reason: str,
        permission_result: Optional[Dict[str, Any]] = None,
        risk_assessment: Optional[Dict[str, Any]] = None,
        fraud_result: Optional[Dict[str, Any]] = None,
        policy: Optional[SecurityPolicy] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Build a standard security authorization result."""

        allowed = decision == SecurityDecision.ALLOW

        data: Dict[str, Any] = {
            "authorized": allowed,
            "decision": decision.value,
            "action": action,
            "sensitivity": sensitivity,
            "reason": reason,
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "task_id": context.get("task_id"),
            "permission_check": (
                permission_result.get("data", {})
                if permission_result
                else {}
            ),
            "risk_assessment": risk_assessment or {},
            "fraud_detection": (
                fraud_result.get("data", {})
                if fraud_result
                else {}
            ),
            "policy": asdict(policy) if policy else None,
        }

        if extra:
            data.update(self._safe_metadata(extra))

        result = (
            self._safe_result(message=message, data=data)
            if allowed
            else self._error_result(
                message=message,
                error=reason,
                data=data,
            )
        )

        memory_payload = self._prepare_memory_payload(
            content=(
                f"Security decision {decision.value} for action {action}. "
                f"Reason: {reason}"
            ),
            task_context=context,
            metadata={
                "decision": decision.value,
                "action": action,
                "sensitivity": sensitivity,
                "risk_score": (
                    risk_assessment.get("score")
                    if risk_assessment
                    else None
                ),
                "risk_level": (
                    risk_assessment.get("level")
                    if risk_assessment
                    else None
                ),
            },
            tags=[
                "security",
                "authorization",
                decision.value,
                sensitivity,
            ],
        )

        result.setdefault("metadata", {})
        result["metadata"]["memory_payload"] = memory_payload

        self._log_audit_event(
            action=action,
            task_context=context,
            payload={"sensitivity": sensitivity},
            result=result,
            event_type="authorization_decision",
        )

        return result

    # =========================================================================
    # Session and lock helpers
    # =========================================================================

    def _validate_session(self, context: SecurityContext) -> Dict[str, Any]:
        """Validate session age and optional external Session Guard."""

        if not self.config.enable_session_guard:
            return self._safe_result(message="Session guard disabled.")

        if self.session_guard and hasattr(self.session_guard, "validate"):
            try:
                external = self.session_guard.validate(asdict(context))
                if isinstance(external, dict):
                    return external
            except Exception as exc:
                logger.warning("External session guard failed: %s", exc)

        if not context.session_created_at:
            return self._safe_result(
                message="No session timestamp supplied.",
                data={"session_checked": False},
            )

        created_at = self._parse_datetime(context.session_created_at)

        if created_at is None:
            return self._error_result(
                message="Invalid session timestamp.",
                error="session_created_at must be an ISO-8601 datetime.",
            )

        age_seconds = (
            datetime.now(timezone.utc) - created_at
        ).total_seconds()

        if (
            self.config.block_expired_sessions
            and age_seconds > self.config.session_max_age_seconds
        ):
            return self._error_result(
                message="Session expired.",
                error="The current session exceeds the configured maximum age.",
                metadata={
                    "security_decision": SecurityDecision.DENY.value,
                    "session_age_seconds": round(age_seconds, 2),
                },
            )

        return self._safe_result(
            message="Session validated.",
            data={"session_age_seconds": round(max(age_seconds, 0.0), 2)},
        )

    def _check_emergency_lock(
        self,
        context: SecurityContext,
    ) -> Dict[str, Any]:
        """Enforce workspace and user emergency locks."""

        workspace_lock = self._workspace_locks.get(context.workspace_id)

        if workspace_lock and workspace_lock.get("locked"):
            lock_bypass_actions = {
                "security_status",
                "unlock_workspace",
                "audit_search",
            }

            requested_action = self._normalize_action(
                context.metadata.get("requested_action")
            )

            if requested_action not in lock_bypass_actions:
                return self._error_result(
                    message="Workspace is security locked.",
                    error=workspace_lock.get(
                        "reason",
                        "Emergency workspace lock is active.",
                    ),
                    metadata={
                        "security_decision": SecurityDecision.LOCKED.value,
                        "signal": FraudSignalType.EMERGENCY_LOCK_ACTIVE.value,
                    },
                )

        user_lock = self._user_locks.get(
            f"{context.workspace_id}:{context.user_id}"
        )

        if user_lock and user_lock.get("locked"):
            return self._error_result(
                message="User account is security locked.",
                error=user_lock.get(
                    "reason",
                    "Emergency user lock is active.",
                ),
                metadata={
                    "security_decision": SecurityDecision.LOCKED.value,
                    "signal": FraudSignalType.EMERGENCY_LOCK_ACTIVE.value,
                },
            )

        return self._safe_result(message="No emergency lock is active.")

    # =========================================================================
    # Internal security helpers
    # =========================================================================

    def _evaluate_device_trust(
        self,
        context: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Evaluate device trust without crossing tenant boundaries."""

        device_id = self._clean_optional_identifier(context.get("device_id"))

        if not device_id:
            return self._safe_result(
                message="No device identifier supplied.",
                data={
                    "known": False,
                    "trusted": False,
                    "revoked": False,
                    "device_id": None,
                },
            )

        tenant_key = self._tenant_key(context)
        device = self._known_devices.get(tenant_key, {}).get(device_id)

        if not device:
            return self._safe_result(
                message="Device is unknown.",
                data={
                    "known": False,
                    "trusted": bool(context.get("device_trusted", False)),
                    "revoked": False,
                    "device_id": device_id,
                },
            )

        trusted = bool(device.get("trusted")) and not bool(device.get("revoked"))

        return self._safe_result(
            message="Device trust evaluated.",
            data={
                "known": True,
                "trusted": trusted,
                "revoked": bool(device.get("revoked")),
                "device_id": device_id,
                "registered_at": device.get("registered_at"),
                "last_seen_at": device.get("last_seen_at"),
            },
        )

    def _record_action_history(
        self,
        context: Dict[str, Any],
        action: str,
        payload: Dict[str, Any],
    ) -> None:
        """Record action metadata for velocity detection."""

        key = self._tenant_key(context)
        classification = self.classify_action(action, payload)

        sensitivity = (
            classification.get("data", {}).get(
                "sensitivity",
                ActionSensitivity.NORMAL.value,
            )
        )

        with self._lock:
            self._action_history[key].append(
                {
                    "timestamp": time.time(),
                    "action": action,
                    "sensitivity": sensitivity,
                    "task_id": context.get("task_id"),
                }
            )

    def _calculate_velocity(
        self,
        context: Dict[str, Any],
        action: str,
    ) -> Dict[str, int]:
        """Calculate recent action velocity."""

        key = self._tenant_key(context)
        now = time.time()
        cutoff = now - 60.0

        total = 0
        sensitive = 0
        same_action = 0

        with self._lock:
            history = self._action_history.get(key, deque())

            for record in history:
                if float(record.get("timestamp", 0.0)) < cutoff:
                    continue

                total += 1

                if record.get("action") == action:
                    same_action += 1

                if record.get("sensitivity") != ActionSensitivity.PUBLIC.value:
                    sensitive += 1

        return {
            "total_last_minute": total,
            "sensitive_last_minute": sensitive,
            "same_action_last_minute": same_action,
        }

    def _record_failed_attempt(
        self,
        context: Mapping[str, Any],
    ) -> None:
        """Record a failed security attempt."""

        key = self._tenant_key(context)
        now = time.time()

        with self._lock:
            queue = self._failed_attempts[key]
            queue.append(now)
            self._prune_failed_attempts(queue, now)

    def _recent_failed_attempt_count(
        self,
        context: Mapping[str, Any],
    ) -> int:
        """Return failed attempts inside configured window."""

        key = self._tenant_key(context)
        now = time.time()

        with self._lock:
            queue = self._failed_attempts[key]
            self._prune_failed_attempts(queue, now)
            return len(queue)

    def _prune_failed_attempts(
        self,
        queue: Deque[float],
        now: float,
    ) -> None:
        """Remove expired failure entries."""

        cutoff = now - self.config.failed_attempt_window_seconds

        while queue and queue[0] < cutoff:
            queue.popleft()

    def _record_boundary_attempt(
        self,
        context: Dict[str, Any],
        boundary_type: str,
    ) -> None:
        """Record cross-tenant boundary attempts without exposing target IDs."""

        user_id = self._clean_identifier(context.get("user_id")) or "unknown"
        workspace_id = (
            self._clean_identifier(context.get("workspace_id")) or "unknown"
        )

        self._log_audit_event(
            action="tenant_boundary_check",
            task_context={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "task_id": context.get("task_id"),
                "source_agent": context.get("source_agent"),
            },
            payload={"boundary_type": boundary_type},
            result=self._error_result(
                message="Tenant boundary attempt blocked.",
                error="Cross-tenant access attempt.",
                data={"decision": SecurityDecision.DENY.value},
            ),
            event_type="security_violation",
        )

    # =========================================================================
    # Policy helpers
    # =========================================================================

    def _default_policies(self) -> List[SecurityPolicy]:
        """Create safe built-in policies."""

        return sorted(
            [
                SecurityPolicy(
                    action_pattern="delete*",
                    sensitivity=ActionSensitivity.DESTRUCTIVE.value,
                    required_permissions=["resource.delete"],
                    allowed_roles=[
                        "owner",
                        "workspace_owner",
                        "security_admin",
                        "admin",
                    ],
                    require_approval=True,
                    require_biometric=True,
                    require_mfa=True,
                    require_trusted_device=True,
                    max_risk_score=75.0,
                    priority=10,
                ),
                SecurityPolicy(
                    action_pattern="payment*",
                    sensitivity=ActionSensitivity.FINANCIAL.value,
                    required_permissions=["finance.execute"],
                    allowed_roles=[
                        "owner",
                        "workspace_owner",
                        "finance_admin",
                    ],
                    require_approval=True,
                    require_biometric=True,
                    require_mfa=True,
                    require_trusted_device=True,
                    max_risk_score=75.0,
                    priority=20,
                ),
                SecurityPolicy(
                    action_pattern="permission*",
                    sensitivity=ActionSensitivity.PRIVILEGED.value,
                    required_permissions=["security.permissions.manage"],
                    allowed_roles=[
                        "owner",
                        "workspace_owner",
                        "security_admin",
                    ],
                    require_approval=True,
                    require_mfa=True,
                    require_trusted_device=True,
                    max_risk_score=70.0,
                    priority=30,
                ),
                SecurityPolicy(
                    action_pattern="role*",
                    sensitivity=ActionSensitivity.PRIVILEGED.value,
                    required_permissions=["security.roles.manage"],
                    allowed_roles=[
                        "owner",
                        "workspace_owner",
                        "security_admin",
                    ],
                    require_approval=True,
                    require_mfa=True,
                    require_trusted_device=True,
                    max_risk_score=70.0,
                    priority=31,
                ),
                SecurityPolicy(
                    action_pattern="export*",
                    sensitivity=ActionSensitivity.SENSITIVE.value,
                    required_permissions=["data.export"],
                    allowed_roles=[
                        "owner",
                        "workspace_owner",
                        "admin",
                        "auditor",
                    ],
                    require_approval=True,
                    require_mfa=True,
                    require_trusted_device=True,
                    max_risk_score=65.0,
                    priority=40,
                ),
                SecurityPolicy(
                    action_pattern="send_*",
                    sensitivity=ActionSensitivity.EXTERNAL_COMMUNICATION.value,
                    required_permissions=["communications.send"],
                    require_approval=False,
                    require_mfa=False,
                    require_trusted_device=False,
                    max_risk_score=70.0,
                    priority=50,
                ),
                SecurityPolicy(
                    action_pattern="deploy*",
                    sensitivity=ActionSensitivity.HIGH_RISK.value,
                    required_permissions=["deployment.execute"],
                    allowed_roles=[
                        "owner",
                        "workspace_owner",
                        "admin",
                        "developer",
                    ],
                    require_approval=True,
                    require_mfa=True,
                    require_trusted_device=True,
                    max_risk_score=70.0,
                    priority=60,
                ),
                SecurityPolicy(
                    action_pattern="*",
                    sensitivity=ActionSensitivity.NORMAL.value,
                    required_permissions=[],
                    allowed_roles=[],
                    require_approval=False,
                    require_biometric=False,
                    require_mfa=False,
                    require_trusted_device=False,
                    max_risk_score=85.0,
                    priority=999,
                ),
            ],
            key=lambda item: item.priority,
        )

    def _match_policy(self, action: str) -> Optional[SecurityPolicy]:
        """Match the highest-priority enabled policy."""

        normalized_action = self._normalize_action(action)

        with self._lock:
            policies = list(self._policies)

        for policy in policies:
            if not policy.enabled:
                continue

            if self._pattern_matches(policy.action_pattern, normalized_action):
                return policy

        return None

    def _pattern_matches(self, pattern: str, value: str) -> bool:
        """Match a simple wildcard policy pattern."""

        escaped = re.escape(pattern).replace(r"\*", ".*")
        return bool(re.fullmatch(escaped, value))

    # =========================================================================
    # Fraud pattern helpers
    # =========================================================================

    def _payload_contains_secret(self, payload: Dict[str, Any]) -> bool:
        """Detect likely secret material in payload values."""

        serialized = json.dumps(payload, default=str)[:50_000]

        patterns = [
            r"(?i)\bpassword\b\s*[:=]",
            r"(?i)\bapi[_-]?key\b\s*[:=]",
            r"(?i)\bsecret\b\s*[:=]",
            r"(?i)\baccess[_-]?token\b\s*[:=]",
            r"(?i)\brefresh[_-]?token\b\s*[:=]",
            r"-----BEGIN\s+(RSA|OPENSSH|PRIVATE)\s+KEY-----",
            r"\bAKIA[0-9A-Z]{16}\b",
            r"(?i)\bbearer\s+[a-z0-9._\-]{20,}",
        ]

        return any(re.search(pattern, serialized) for pattern in patterns)

    def _payload_indicates_bulk_export(self, payload: Dict[str, Any]) -> bool:
        """Detect potential bulk extraction or exfiltration."""

        record_count = self._safe_float(
            payload.get("record_count")
            or payload.get("limit")
            or payload.get("rows")
            or 0
        )

        include_all = bool(
            payload.get("include_all")
            or payload.get("export_all")
            or payload.get("all_workspaces")
            or payload.get("all_users")
        )

        return include_all or record_count >= 10_000

    def _payload_indicates_payment_anomaly(
        self,
        payload: Dict[str, Any],
    ) -> bool:
        """Detect obvious unusual payment request attributes."""

        amount = self._safe_float(payload.get("amount", 0.0))
        repeated = self._safe_float(payload.get("repeat_count", 0.0))
        destination_changed = bool(payload.get("new_destination", False))
        unusual_currency = bool(payload.get("unusual_currency", False))

        return (
            amount >= 50_000
            or repeated >= 10
            or (destination_changed and amount >= 5_000)
            or unusual_currency
        )

    def _payload_requests_privilege_escalation(
        self,
        action: str,
        payload: Dict[str, Any],
    ) -> bool:
        """Detect privilege escalation intent."""

        combined = f"{action} {json.dumps(payload, default=str)}".lower()

        patterns = [
            "grant admin",
            "set role admin",
            "security_admin",
            "workspace_owner",
            "elevate privilege",
            "bypass permission",
            "disable security",
            "impersonate user",
        ]

        return any(pattern in combined for pattern in patterns)

    def _looks_like_automation_user_agent(
        self,
        user_agent: Optional[str],
    ) -> bool:
        """Detect obvious scripted clients."""

        if not user_agent:
            return False

        value = user_agent.lower()

        indicators = [
            "selenium",
            "playwright",
            "phantomjs",
            "headlesschrome",
            "python-requests",
            "curl/",
            "wget/",
            "scrapy",
            "httpclient",
        ]

        return any(indicator in value for indicator in indicators)

    # =========================================================================
    # Utility helpers
    # =========================================================================

    def _build_config(
        self,
        config: Optional[Union[SecurityAgentConfig, Dict[str, Any]]],
    ) -> SecurityAgentConfig:
        """Build validated config from dataclass or dictionary."""

        if isinstance(config, SecurityAgentConfig):
            return config

        if isinstance(config, dict):
            defaults = asdict(SecurityAgentConfig())
            allowed_keys = set(defaults)
            supplied = {
                key: value
                for key, value in config.items()
                if key in allowed_keys
            }
            defaults.update(supplied)
            return SecurityAgentConfig(**defaults)

        return SecurityAgentConfig()

    def _infer_command(self, task: Dict[str, Any]) -> str:
        """Infer router command from task fields."""

        explicit = self._normalize_action(
            task.get("command") or task.get("operation")
        )

        if explicit:
            return explicit

        action = self._normalize_action(task.get("action"))

        known_commands = {
            "authorize",
            "permission_check",
            "risk_assessment",
            "fraud_check",
            "approve",
            "deny",
            "approval_status",
            "create_biometric_challenge",
            "verify_biometric",
            "register_device",
            "revoke_device",
            "lock_workspace",
            "unlock_workspace",
            "lock_user",
            "unlock_user",
            "audit_search",
            "security_status",
            "register_policy",
            "list_policies",
        }

        if action in known_commands:
            return action

        return "authorize"

    def _risk_level(self, score: float) -> str:
        """Convert numerical risk score to level."""

        if score >= self.config.critical_risk_min:
            return RiskLevel.CRITICAL.value

        if score > self.config.medium_risk_max:
            return RiskLevel.HIGH.value

        if score > self.config.low_risk_max:
            return RiskLevel.MEDIUM.value

        if score > 10.0:
            return RiskLevel.LOW.value

        return RiskLevel.MINIMAL.value

    def _signal(
        self,
        signal_type: FraudSignalType,
        description: str,
        risk_points: float,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create a normalized fraud signal."""

        return {
            "signal_id": str(uuid.uuid4()),
            "type": signal_type.value,
            "description": description,
            "risk_points": round(float(risk_points), 2),
            "metadata": self._safe_metadata(metadata or {}),
            "detected_at": self._utc_now(),
        }

    def _same_tenant(
        self,
        context: Mapping[str, Any],
        record: Any,
    ) -> bool:
        """Check strict user/workspace ownership."""

        return (
            str(context.get("user_id")) == str(getattr(record, "user_id", ""))
            and str(context.get("workspace_id"))
            == str(getattr(record, "workspace_id", ""))
        )

    def _tenant_key(self, context: Mapping[str, Any]) -> str:
        """Build a non-reversible tenant storage key."""

        raw = (
            f"{context.get('workspace_id', '')}:"
            f"{context.get('user_id', '')}"
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def _approval_public_dict(
        self,
        approval: ApprovalRecord,
    ) -> Dict[str, Any]:
        """Return safe approval fields."""

        data = asdict(approval)
        data.pop("payload_hash", None)
        return data

    def _refresh_approval_status(
        self,
        approval: ApprovalRecord,
    ) -> None:
        """Expire stale pending approvals."""

        if (
            approval.status == ApprovalStatus.PENDING.value
            and self._is_expired(approval.expires_at)
        ):
            approval.status = ApprovalStatus.EXPIRED.value

    def _is_expired(self, iso_timestamp: str) -> bool:
        """Check whether ISO timestamp is expired."""

        parsed = self._parse_datetime(iso_timestamp)

        if parsed is None:
            return True

        return parsed <= datetime.now(timezone.utc)

    def _parse_datetime(
        self,
        value: Any,
    ) -> Optional[datetime]:
        """Parse ISO-8601 datetime safely."""

        if value is None:
            return None

        try:
            parsed = datetime.fromisoformat(
                str(value).replace("Z", "+00:00")
            )

            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)

            return parsed.astimezone(timezone.utc)
        except (TypeError, ValueError):
            return None

    def _normalize_datetime_string(
        self,
        value: Any,
    ) -> Optional[str]:
        """Normalize datetime value to ISO-8601."""

        parsed = self._parse_datetime(value)
        return parsed.isoformat() if parsed else None

    def _utc_now(self) -> str:
        """Return current UTC datetime."""

        return datetime.now(timezone.utc).isoformat()

    def _normalize_action(self, value: Any) -> str:
        """Normalize action name."""

        if value is None:
            return ""

        text = str(value).strip().lower()
        text = re.sub(r"[\s:/.-]+", "_", text)
        text = re.sub(r"[^a-z0-9_*]", "", text)
        text = re.sub(r"_+", "_", text)
        return text[:200].strip("_")

    def _normalize_role(self, value: Any) -> str:
        """Normalize role name."""

        role = self._normalize_action(value or "user")
        return role or "user"

    def _normalize_permissions(
        self,
        values: Any,
    ) -> List[str]:
        """Normalize a permission collection."""

        if values is None:
            return []

        if isinstance(values, str):
            values = [
                item.strip()
                for item in re.split(r"[,;\n]", values)
                if item.strip()
            ]

        if not isinstance(values, Iterable):
            return []

        normalized: List[str] = []

        for item in values:
            value = str(item).strip().lower()
            value = re.sub(r"[^a-z0-9_.*:-]", "", value)

            if value and value not in normalized:
                normalized.append(value)

        return normalized[:500]

    def _clean_identifier(self, value: Any) -> str:
        """Clean an identifier."""

        if value is None:
            return ""

        text = str(value).strip()
        text = re.sub(r"[^a-zA-Z0-9_\-:.@]", "", text)
        return text[:200]

    def _clean_optional_identifier(
        self,
        value: Any,
    ) -> Optional[str]:
        """Clean an optional identifier."""

        cleaned = self._clean_identifier(value)
        return cleaned or None

    def _clean_string(self, value: Any) -> str:
        """Normalize arbitrary text."""

        if value is None:
            return ""

        text = str(value).replace("\x00", "").strip()
        text = re.sub(r"\s+", " ", text)
        return text[: self.config.max_string_length]

    def _clean_optional_string(
        self,
        value: Any,
        max_length: int,
    ) -> Optional[str]:
        """Clean optional text."""

        if value is None:
            return None

        cleaned = str(value).replace("\x00", "").strip()
        return cleaned[:max_length] or None

    def _safe_metadata(
        self,
        metadata: Any,
    ) -> Dict[str, Any]:
        """Convert metadata into a redacted JSON-safe dictionary."""

        if not isinstance(metadata, dict):
            return {}

        try:
            serialized = json.loads(json.dumps(metadata, default=str))
            return self._redact_payload(serialized)
        except Exception:
            return {"metadata_error": "Metadata was not JSON serializable."}

    def _stable_hash(self, value: Any) -> str:
        """Create deterministic SHA-256 hash."""

        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")

        return hashlib.sha256(encoded).hexdigest()

    def _safe_float(self, value: Any) -> float:
        """Convert a value to finite float."""

        try:
            number = float(value)

            if not math.isfinite(number):
                return 0.0

            return number
        except (TypeError, ValueError):
            return 0.0

    def _redact_payload(
        self,
        payload: Any,
    ) -> Any:
        """Recursively redact secrets and sensitive authentication fields."""

        sensitive_keys = {
            "password",
            "passcode",
            "pin",
            "secret",
            "api_key",
            "apikey",
            "access_token",
            "refresh_token",
            "authorization",
            "private_key",
            "biometric_template",
            "raw_biometric_data",
            "fingerprint",
            "face_embedding",
            "voiceprint",
            "challenge_nonce",
        }

        if isinstance(payload, dict):
            result: Dict[str, Any] = {}

            for key, value in payload.items():
                if str(key).lower() in sensitive_keys:
                    result[key] = "[REDACTED]"
                else:
                    result[key] = self._redact_payload(value)

            return result

        if isinstance(payload, list):
            return [self._redact_payload(item) for item in payload]

        if isinstance(payload, tuple):
            return [self._redact_payload(item) for item in payload]

        if isinstance(payload, str):
            return self._redact_text(payload)

        return payload

    def _redact_text(self, text: str) -> str:
        """Redact common secret patterns from text."""

        patterns = [
            (
                r"(?i)(password|passcode|secret|api[_-]?key|access[_-]?token|"
                r"refresh[_-]?token)\s*[:=]\s*[^\s,;]+",
                r"\1=[REDACTED]",
            ),
            (
                r"(?i)bearer\s+[a-z0-9._\-]+",
                "Bearer [REDACTED]",
            ),
            (
                r"-----BEGIN\s+(RSA|OPENSSH|PRIVATE)\s+KEY-----.*?"
                r"-----END\s+(RSA|OPENSSH|PRIVATE)\s+KEY-----",
                "[PRIVATE KEY REDACTED]",
            ),
        ]

        redacted = text

        for pattern, replacement in patterns:
            redacted = re.sub(
                pattern,
                replacement,
                redacted,
                flags=re.DOTALL,
            )

        return redacted

    def _audit_payload_summary(
        self,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Create a non-sensitive summary for audit records."""

        return {
            "keys": sorted(str(key) for key in payload.keys())[:200],
            "payload_hash": self._stable_hash(
                self._redact_payload(payload)
            ),
            "contains_secret_like_data": self._payload_contains_secret(payload),
            "contains_bulk_export_pattern": self._payload_indicates_bulk_export(
                payload
            ),
            "approximate_size_bytes": len(
                json.dumps(payload, default=str).encode("utf-8")
            ),
        }


# =============================================================================
# Agent Loader / Registry factory functions
# =============================================================================

def create_agent(**kwargs: Any) -> SecurityAgent:
    """
    Create SecurityAgent for Agent Loader.

    Example:
        security_agent = create_agent()
    """

    return SecurityAgent(**kwargs)


def get_agent_metadata() -> Dict[str, Any]:
    """Return static Agent Registry metadata without starting the agent."""

    return {
        "agent_name": "security_agent",
        "class_name": "SecurityAgent",
        "module": "agents.security_agent.security_agent",
        "version": "1.0.0",
        "safe_import": True,
        "requires_user_context": True,
        "requires_workspace_context": True,
        "capabilities": [
            "permission_checks",
            "risk_scoring",
            "security_approvals",
            "biometric_gates",
            "fraud_detection",
            "anomaly_detection",
            "device_trust",
            "session_guard",
            "tenant_isolation",
            "audit_logging",
            "policy_enforcement",
            "emergency_lock",
        ],
    }


__all__ = [
    "SecurityAgent",
    "SecurityAgentConfig",
    "SecurityContext",
    "SecurityPolicy",
    "SecurityDecision",
    "RiskLevel",
    "ActionSensitivity",
    "ApprovalStatus",
    "BiometricStatus",
    "FraudSignalType",
    "RiskAssessment",
    "ApprovalRecord",
    "BiometricChallenge",
    "AuditRecord",
    "create_agent",
    "get_agent_metadata",
]