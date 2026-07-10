"""
agents/security_agent/audit_logger.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Securely log sensitive requests, approvals, denials, blocks, biometric
    attempts, reports, policy decisions, security events, and audit activity.

Architecture connections:
    - Security Agent:
        Records security-sensitive actions and policy decisions.
    - Master Agent:
        Provides structured audit references for routed tasks.
    - Verification Agent:
        Produces verification payloads for completed audit operations.
    - Memory Agent:
        Produces privacy-safe memory payloads without exposing secrets.
    - Agent Registry / Loader / Router:
        Exposes a stable capability manifest and structured public methods.
    - Dashboard / FastAPI:
        Supports filtered audit queries, statistics, reports, and exports.
    - SaaS isolation:
        Stores and retrieves records using mandatory user_id and workspace_id
        boundaries. Cross-workspace access requires explicit authorization.

Security properties:
    - Tenant-isolated storage paths.
    - Recursive sensitive-field redaction.
    - Optional HMAC record signatures.
    - SHA-256 hash chaining for tamper detection.
    - No raw biometric samples are stored.
    - No secrets are hardcoded.
    - Append-only JSONL storage by default.
    - Thread-safe writes and reads.
    - Structured success/error responses.
    - Import-safe fallback classes and optional integrations.

This module uses Python's standard library only.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import logging
import os
import re
import threading
import time
import traceback
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    Iterator,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
)


# =============================================================================
# Safe optional imports
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Import-safe BaseAgent fallback.

        The real William BaseAgent can replace this class automatically when
        available. The fallback intentionally performs no external actions.
        """

        agent_name = "BaseAgent"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get(
                "agent_name",
                getattr(self, "agent_name", self.__class__.__name__),
            )

        def emit_event(self, *args: Any, **kwargs: Any) -> None:
            return None


try:
    from agents.security_agent.config import SecurityConfig  # type: ignore
except Exception:  # pragma: no cover
    SecurityConfig = None  # type: ignore


# =============================================================================
# Logging
# =============================================================================

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# =============================================================================
# Constants
# =============================================================================

AUDIT_SCHEMA_VERSION = "1.0"
AUDIT_LOGGER_VERSION = "1.0.0"

DEFAULT_STORAGE_DIRECTORY = "data/security_audit"
DEFAULT_RETENTION_DAYS = 365
DEFAULT_MAX_QUERY_RESULTS = 500
MAX_QUERY_RESULTS_HARD_LIMIT = 5000
MAX_EVENT_MESSAGE_LENGTH = 4000
MAX_METADATA_DEPTH = 12
MAX_COLLECTION_ITEMS = 500
MAX_STRING_VALUE_LENGTH = 20_000

GENESIS_HASH = "0" * 64

SAFE_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9_.:@+\-]{1,255}$")

DEFAULT_SENSITIVE_KEYS: Set[str] = {
    "access_token",
    "api_key",
    "apikey",
    "authorization",
    "auth_token",
    "biometric_data",
    "biometric_sample",
    "card_number",
    "client_secret",
    "cookie",
    "cookies",
    "credit_card",
    "cvv",
    "encryption_key",
    "face_embedding",
    "face_image",
    "fingerprint",
    "fingerprint_data",
    "hmac_key",
    "id_token",
    "jwt",
    "password",
    "passcode",
    "pin",
    "private_key",
    "raw_biometric",
    "recovery_code",
    "refresh_token",
    "secret",
    "secret_key",
    "security_answer",
    "session_cookie",
    "session_token",
    "signature_key",
    "ssn",
    "token",
    "totp_secret",
}

DEFAULT_HASH_ONLY_KEYS: Set[str] = {
    "device_fingerprint",
    "email",
    "ip_address",
    "phone",
    "phone_number",
    "remote_ip",
    "user_agent",
}

ALLOWED_EVENT_TYPES: Set[str] = {
    "sensitive_request",
    "approval",
    "denial",
    "block",
    "biometric_attempt",
    "security_report",
    "permission_check",
    "policy_decision",
    "risk_assessment",
    "fraud_alert",
    "anomaly_detected",
    "device_access",
    "file_protection",
    "payment_guard",
    "app_lock",
    "session_guard",
    "privacy_event",
    "threat_event",
    "emergency_lock",
    "audit_access",
    "audit_export",
    "audit_retention",
    "security_event",
    "custom",
}


# =============================================================================
# Enums
# =============================================================================

class AuditEventType(str, Enum):
    """Supported audit event categories."""

    SENSITIVE_REQUEST = "sensitive_request"
    APPROVAL = "approval"
    DENIAL = "denial"
    BLOCK = "block"
    BIOMETRIC_ATTEMPT = "biometric_attempt"
    SECURITY_REPORT = "security_report"
    PERMISSION_CHECK = "permission_check"
    POLICY_DECISION = "policy_decision"
    RISK_ASSESSMENT = "risk_assessment"
    FRAUD_ALERT = "fraud_alert"
    ANOMALY_DETECTED = "anomaly_detected"
    DEVICE_ACCESS = "device_access"
    FILE_PROTECTION = "file_protection"
    PAYMENT_GUARD = "payment_guard"
    APP_LOCK = "app_lock"
    SESSION_GUARD = "session_guard"
    PRIVACY_EVENT = "privacy_event"
    THREAT_EVENT = "threat_event"
    EMERGENCY_LOCK = "emergency_lock"
    AUDIT_ACCESS = "audit_access"
    AUDIT_EXPORT = "audit_export"
    AUDIT_RETENTION = "audit_retention"
    SECURITY_EVENT = "security_event"
    CUSTOM = "custom"


class AuditOutcome(str, Enum):
    """Outcome attached to an audit event."""

    REQUESTED = "requested"
    APPROVED = "approved"
    DENIED = "denied"
    BLOCKED = "blocked"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CHALLENGED = "challenged"
    CANCELLED = "cancelled"
    EXPIRED = "expired"
    DETECTED = "detected"
    REPORTED = "reported"
    UNKNOWN = "unknown"


class AuditSeverity(str, Enum):
    """Audit event severity."""

    DEBUG = "debug"
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AuditRiskLevel(str, Enum):
    """Normalized risk classification."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class BiometricMethod(str, Enum):
    """
    Biometric methods.

    Only method names and outcomes are logged. Raw biometric material must
    never be placed into audit metadata.
    """

    FACE = "face"
    FINGERPRINT = "fingerprint"
    VOICE = "voice"
    IRIS = "iris"
    DEVICE_BIOMETRIC = "device_biometric"
    UNKNOWN = "unknown"


class BiometricOutcome(str, Enum):
    """Biometric verification outcomes."""

    SUCCESS = "success"
    FAILED = "failed"
    CANCELLED = "cancelled"
    LOCKED_OUT = "locked_out"
    UNAVAILABLE = "unavailable"
    ERROR = "error"
    UNKNOWN = "unknown"


# =============================================================================
# Data models
# =============================================================================

@dataclass
class AuditContext:
    """
    Tenant and execution context required for audit operations.
    """

    user_id: Union[str, int]
    workspace_id: Union[str, int]

    actor_id: Optional[Union[str, int]] = None
    actor_type: str = "user"
    role: Optional[str] = None

    session_id: Optional[Union[str, int]] = None
    task_id: Optional[Union[str, int]] = None
    request_id: Optional[str] = None
    correlation_id: Optional[str] = None

    source_agent: Optional[str] = None
    target_agent: Optional[str] = None

    project_id: Optional[Union[str, int]] = None
    client_id: Optional[Union[str, int]] = None
    device_id: Optional[Union[str, int]] = None

    ip_address: Optional[str] = None
    user_agent: Optional[str] = None

    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditRecord:
    """
    Canonical append-only audit record.

    record_hash and signature are calculated after all other fields have been
    normalized and redacted.
    """

    schema_version: str
    event_id: str
    sequence: int
    timestamp: str

    event_type: str
    action: str
    outcome: str
    severity: str
    risk_level: str

    message: str

    user_id: str
    workspace_id: str
    actor_id: Optional[str]
    actor_type: str
    role: Optional[str]

    session_id: Optional[str]
    task_id: Optional[str]
    request_id: str
    correlation_id: str

    source_agent: Optional[str]
    target_agent: Optional[str]

    project_id: Optional[str]
    client_id: Optional[str]
    device_id: Optional[str]

    resource_type: Optional[str]
    resource_id: Optional[str]

    policy_id: Optional[str]
    approval_id: Optional[str]
    report_id: Optional[str]

    reason_code: Optional[str]
    tags: List[str]

    metadata: Dict[str, Any]

    previous_hash: str
    record_hash: str
    signature: Optional[str] = None


@dataclass
class AuditQuery:
    """
    Filters used by Dashboard/API or internal agents.
    """

    user_id: Union[str, int]
    workspace_id: Union[str, int]

    event_types: List[str] = field(default_factory=list)
    outcomes: List[str] = field(default_factory=list)
    severities: List[str] = field(default_factory=list)
    risk_levels: List[str] = field(default_factory=list)

    actor_id: Optional[Union[str, int]] = None
    action: Optional[str] = None
    source_agent: Optional[str] = None
    target_agent: Optional[str] = None

    task_id: Optional[Union[str, int]] = None
    request_id: Optional[str] = None
    correlation_id: Optional[str] = None
    project_id: Optional[Union[str, int]] = None
    client_id: Optional[Union[str, int]] = None
    device_id: Optional[Union[str, int]] = None

    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    policy_id: Optional[str] = None
    approval_id: Optional[str] = None
    report_id: Optional[str] = None

    tags: List[str] = field(default_factory=list)
    search_text: Optional[str] = None

    start_time: Optional[Union[str, datetime]] = None
    end_time: Optional[Union[str, datetime]] = None

    limit: int = DEFAULT_MAX_QUERY_RESULTS
    offset: int = 0
    newest_first: bool = True

    include_metadata: bool = True
    include_integrity_fields: bool = False

    strict_isolation: bool = True
    allow_cross_workspace: bool = False


# =============================================================================
# Utility functions
# =============================================================================

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso_now() -> str:
    return _utc_now().isoformat()


def _safe_str(value: Any, max_length: Optional[int] = None) -> str:
    if value is None:
        return ""

    text = str(value).strip()

    if max_length is not None:
        return text[:max_length]

    return text


def _optional_str(value: Any, max_length: Optional[int] = None) -> Optional[str]:
    text = _safe_str(value, max_length=max_length)
    return text if text else None


def _normalize_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", _safe_str(value).lower()).strip("_")


def _normalize_tag(value: Any) -> str:
    return re.sub(
        r"[^a-zA-Z0-9_.:@+\-]+",
        "-",
        _safe_str(value).lower(),
    ).strip("-")[:100]


def _coerce_tags(value: Any) -> List[str]:
    if value is None:
        return []

    if isinstance(value, str):
        raw_values = re.split(r"[,;|]", value)
    elif isinstance(value, (list, tuple, set)):
        raw_values = list(value)
    else:
        raw_values = [value]

    result: List[str] = []
    seen: Set[str] = set()

    for raw_value in raw_values:
        normalized = _normalize_tag(raw_value)
        if normalized and normalized not in seen:
            seen.add(normalized)
            result.append(normalized)

    return result[:100]


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _parse_datetime(
    value: Optional[Union[str, datetime]],
) -> Optional[datetime]:
    if value is None:
        return None

    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    text = _safe_str(value)
    if not text:
        return None

    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"

        parsed = datetime.fromisoformat(text)

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc)
    except ValueError:
        pass

    for date_format in (
        "%Y-%m-%d",
        "%Y/%m/%d",
        "%d-%m-%Y",
        "%d/%m/%Y",
    ):
        try:
            parsed = datetime.strptime(text, date_format)
            return parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            continue

    return None


def _canonical_json(data: Mapping[str, Any]) -> str:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _stable_identifier_hash(value: Any) -> str:
    """
    Hash a potentially sensitive identifier before storage.
    """

    text = _safe_str(value)
    if not text:
        return ""

    return f"sha256:{_sha256_text(text)}"


def _safe_enum_value(
    enum_class: Any,
    value: Any,
    default: Any,
) -> str:
    if isinstance(value, enum_class):
        return value.value

    text = _safe_str(value).lower()

    try:
        return enum_class(text).value
    except (TypeError, ValueError):
        if isinstance(default, enum_class):
            return default.value
        return _safe_str(default).lower()


# =============================================================================
# AuditLogger
# =============================================================================

class AuditLogger(BaseAgent):
    """
    Security Agent audit logging service.

    Public responsibilities:
        - Log sensitive requests.
        - Log approvals.
        - Log denials.
        - Log blocked actions.
        - Log privacy-safe biometric attempts.
        - Log security reports.
        - Search tenant-isolated audit records.
        - Produce dashboard statistics and reports.
        - Export tenant-scoped audit data.
        - Verify hash-chain and HMAC integrity.
        - Apply retention cleanup.

    Storage:
        Records are stored as append-only JSON Lines files. Each workspace/user
        pair has an isolated directory based on hashes of its identifiers.

    Production extension:
        A future database or event-stream backend can be injected through
        storage_provider without changing public methods.
    """

    agent_name = "AuditLogger"
    agent_type = "security_helper"
    version = AUDIT_LOGGER_VERSION

    def __init__(
        self,
        storage_directory: Optional[Union[str, Path]] = None,
        storage_provider: Optional[Any] = None,
        security_provider: Optional[Any] = None,
        event_emitter: Optional[Callable[[Dict[str, Any]], None]] = None,
        memory_sink: Optional[Callable[[Dict[str, Any]], Any]] = None,
        verification_sink: Optional[Callable[[Dict[str, Any]], Any]] = None,
        signing_key: Optional[Union[str, bytes]] = None,
        config: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        try:
            super().__init__(agent_name=self.agent_name, **kwargs)
        except TypeError:
            super().__init__()

        self.config = self._build_config(config or {})

        configured_directory = (
            storage_directory
            or self.config.get("storage_directory")
            or os.getenv("WILLIAM_AUDIT_STORAGE_DIR")
            or DEFAULT_STORAGE_DIRECTORY
        )

        self.storage_directory = Path(configured_directory).expanduser()
        self.storage_provider = storage_provider
        self.security_provider = security_provider
        self.event_emitter = event_emitter
        self.memory_sink = memory_sink
        self.verification_sink = verification_sink

        configured_signing_key = (
            signing_key
            or self.config.get("signing_key")
            or os.getenv("WILLIAM_AUDIT_SIGNING_KEY")
        )

        if isinstance(configured_signing_key, str):
            self._signing_key: Optional[bytes] = configured_signing_key.encode(
                "utf-8"
            )
        elif isinstance(configured_signing_key, bytes):
            self._signing_key = configured_signing_key
        else:
            self._signing_key = None

        self._lock = threading.RLock()
        self._sequence_cache: Dict[str, int] = {}
        self._last_hash_cache: Dict[str, str] = {}

        self._sensitive_keys = {
            _normalize_key(key)
            for key in self.config.get(
                "sensitive_keys",
                DEFAULT_SENSITIVE_KEYS,
            )
        }

        self._hash_only_keys = {
            _normalize_key(key)
            for key in self.config.get(
                "hash_only_keys",
                DEFAULT_HASH_ONLY_KEYS,
            )
        }

        self._initialize_storage()

    # =========================================================================
    # Configuration and initialization
    # =========================================================================

    def _build_config(self, supplied_config: Dict[str, Any]) -> Dict[str, Any]:
        defaults: Dict[str, Any] = {
            "storage_directory": DEFAULT_STORAGE_DIRECTORY,
            "retention_days": DEFAULT_RETENTION_DAYS,
            "max_query_results": DEFAULT_MAX_QUERY_RESULTS,
            "hard_max_query_results": MAX_QUERY_RESULTS_HARD_LIMIT,
            "enable_file_storage": True,
            "enable_hash_chain": True,
            "enable_hmac_signatures": True,
            "enable_event_emission": True,
            "enable_memory_payloads": True,
            "enable_verification_payloads": True,
            "enable_access_auditing": True,
            "fsync_writes": False,
            "strict_isolation": True,
            "allow_cross_workspace": False,
            "redaction_text": "[REDACTED]",
            "hash_sensitive_identifiers": True,
            "store_ip_hash_only": True,
            "store_user_agent_hash_only": True,
            "safe_debug_errors": False,
            "sensitive_keys": sorted(DEFAULT_SENSITIVE_KEYS),
            "hash_only_keys": sorted(DEFAULT_HASH_ONLY_KEYS),
        }

        merged = dict(defaults)
        merged.update(supplied_config or {})
        return merged

    def _initialize_storage(self) -> None:
        """
        Create the base storage directory safely.

        Failure does not prevent import or construction when a custom storage
        provider is available.
        """

        if not self.config.get("enable_file_storage", True):
            return

        try:
            self.storage_directory.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            if self.storage_provider is None:
                logger.warning(
                    "Audit storage directory could not be initialized: %s",
                    exc,
                )

    # =========================================================================
    # Primary public API
    # =========================================================================

    def log_event(
        self,
        event_type: Union[str, AuditEventType],
        action: str,
        context: Union[AuditContext, Dict[str, Any]],
        *,
        outcome: Union[str, AuditOutcome] = AuditOutcome.UNKNOWN,
        severity: Union[str, AuditSeverity] = AuditSeverity.INFO,
        risk_level: Union[str, AuditRiskLevel] = AuditRiskLevel.UNKNOWN,
        message: str = "",
        resource_type: Optional[str] = None,
        resource_id: Optional[Union[str, int]] = None,
        policy_id: Optional[Union[str, int]] = None,
        approval_id: Optional[Union[str, int]] = None,
        report_id: Optional[Union[str, int]] = None,
        reason_code: Optional[str] = None,
        tags: Optional[Sequence[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Append a generic security audit event.

        All specialized methods eventually call this method.
        """

        started_at = time.perf_counter()

        try:
            audit_context = self._coerce_context(context)

            validation = self._validate_task_context(audit_context)
            if not validation["success"]:
                return validation

            normalized_event_type = self._normalize_event_type(event_type)
            normalized_action = _safe_str(action, 255)

            if not normalized_action:
                return self._error_result(
                    message="action is required for an audit event.",
                    error_code="MISSING_ACTION",
                )

            combined_metadata = dict(audit_context.metadata or {})
            combined_metadata.update(metadata or {})

            record = self._build_record(
                event_type=normalized_event_type,
                action=normalized_action,
                context=audit_context,
                outcome=outcome,
                severity=severity,
                risk_level=risk_level,
                message=message,
                resource_type=resource_type,
                resource_id=resource_id,
                policy_id=policy_id,
                approval_id=approval_id,
                report_id=report_id,
                reason_code=reason_code,
                tags=tags,
                metadata=combined_metadata,
            )

            persistence_result = self._persist_record(record)
            if not persistence_result["success"]:
                return persistence_result

            verification_payload = self._prepare_verification_payload(
                operation="audit_event_created",
                context=audit_context,
                records=[asdict(record)],
                additional_data={
                    "event_id": record.event_id,
                    "record_hash": record.record_hash,
                },
            )

            memory_payload = self._prepare_memory_payload(
                operation="audit_event_created",
                context=audit_context,
                records=[asdict(record)],
                additional_data={
                    "event_type": record.event_type,
                    "action": record.action,
                    "outcome": record.outcome,
                },
            )

            self._dispatch_optional_payloads(
                verification_payload=verification_payload,
                memory_payload=memory_payload,
            )

            duration_ms = round(
                (time.perf_counter() - started_at) * 1000,
                3,
            )

            self._emit_agent_event(
                event_type="security.audit.recorded",
                payload={
                    "event_id": record.event_id,
                    "event_type": record.event_type,
                    "action": record.action,
                    "outcome": record.outcome,
                    "severity": record.severity,
                    "risk_level": record.risk_level,
                    "user_id": record.user_id,
                    "workspace_id": record.workspace_id,
                    "request_id": record.request_id,
                },
            )

            return self._safe_result(
                message="Audit event recorded successfully.",
                data={
                    "event_id": record.event_id,
                    "sequence": record.sequence,
                    "timestamp": record.timestamp,
                    "event_type": record.event_type,
                    "action": record.action,
                    "outcome": record.outcome,
                    "severity": record.severity,
                    "risk_level": record.risk_level,
                    "record_hash": record.record_hash,
                    "signed": record.signature is not None,
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                metadata={
                    "agent": self.agent_name,
                    "version": self.version,
                    "duration_ms": duration_ms,
                    "request_id": record.request_id,
                    "correlation_id": record.correlation_id,
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to record audit event.",
                error_code="AUDIT_WRITE_FAILED",
                exception=exc,
            )

    def log_sensitive_request(
        self,
        context: Union[AuditContext, Dict[str, Any]],
        action: str,
        *,
        resource_type: Optional[str] = None,
        resource_id: Optional[Union[str, int]] = None,
        reason: Optional[str] = None,
        risk_level: Union[str, AuditRiskLevel] = AuditRiskLevel.MEDIUM,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Log a request to execute or access a sensitive action."""

        event_metadata = dict(metadata or {})

        if reason:
            event_metadata["request_reason"] = reason

        return self.log_event(
            event_type=AuditEventType.SENSITIVE_REQUEST,
            action=action,
            context=context,
            outcome=AuditOutcome.REQUESTED,
            severity=self._severity_for_risk(risk_level),
            risk_level=risk_level,
            message="Sensitive action requested.",
            resource_type=resource_type,
            resource_id=resource_id,
            tags=["security", "sensitive-request"],
            metadata=event_metadata,
        )

    def log_approval(
        self,
        context: Union[AuditContext, Dict[str, Any]],
        action: str,
        *,
        approval_id: Optional[Union[str, int]] = None,
        approved_by: Optional[Union[str, int]] = None,
        approval_method: Optional[str] = None,
        policy_id: Optional[Union[str, int]] = None,
        reason: Optional[str] = None,
        risk_level: Union[str, AuditRiskLevel] = AuditRiskLevel.MEDIUM,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Log an approval for a sensitive request or action."""

        event_metadata = dict(metadata or {})

        if approved_by is not None:
            event_metadata["approved_by"] = _safe_str(approved_by, 255)

        if approval_method:
            event_metadata["approval_method"] = _safe_str(
                approval_method,
                100,
            )

        if reason:
            event_metadata["approval_reason"] = _safe_str(
                reason,
                MAX_EVENT_MESSAGE_LENGTH,
            )

        return self.log_event(
            event_type=AuditEventType.APPROVAL,
            action=action,
            context=context,
            outcome=AuditOutcome.APPROVED,
            severity=AuditSeverity.INFO,
            risk_level=risk_level,
            message="Sensitive action approved.",
            approval_id=approval_id,
            policy_id=policy_id,
            tags=["security", "approval"],
            metadata=event_metadata,
        )

    def log_denial(
        self,
        context: Union[AuditContext, Dict[str, Any]],
        action: str,
        *,
        reason_code: Optional[str] = None,
        denied_by: Optional[Union[str, int]] = None,
        policy_id: Optional[Union[str, int]] = None,
        reason: Optional[str] = None,
        risk_level: Union[str, AuditRiskLevel] = AuditRiskLevel.HIGH,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Log a denied request or permission decision."""

        event_metadata = dict(metadata or {})

        if denied_by is not None:
            event_metadata["denied_by"] = _safe_str(denied_by, 255)

        if reason:
            event_metadata["denial_reason"] = _safe_str(
                reason,
                MAX_EVENT_MESSAGE_LENGTH,
            )

        return self.log_event(
            event_type=AuditEventType.DENIAL,
            action=action,
            context=context,
            outcome=AuditOutcome.DENIED,
            severity=self._severity_for_risk(risk_level),
            risk_level=risk_level,
            message="Sensitive action denied.",
            policy_id=policy_id,
            reason_code=reason_code,
            tags=["security", "denial"],
            metadata=event_metadata,
        )

    def log_block(
        self,
        context: Union[AuditContext, Dict[str, Any]],
        action: str,
        *,
        reason_code: Optional[str] = None,
        policy_id: Optional[Union[str, int]] = None,
        blocked_resource_type: Optional[str] = None,
        blocked_resource_id: Optional[Union[str, int]] = None,
        reason: Optional[str] = None,
        risk_level: Union[str, AuditRiskLevel] = AuditRiskLevel.HIGH,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Log an action blocked by Security Agent or a policy."""

        event_metadata = dict(metadata or {})

        if reason:
            event_metadata["block_reason"] = _safe_str(
                reason,
                MAX_EVENT_MESSAGE_LENGTH,
            )

        return self.log_event(
            event_type=AuditEventType.BLOCK,
            action=action,
            context=context,
            outcome=AuditOutcome.BLOCKED,
            severity=self._severity_for_risk(risk_level),
            risk_level=risk_level,
            message="Sensitive action blocked.",
            resource_type=blocked_resource_type,
            resource_id=blocked_resource_id,
            policy_id=policy_id,
            reason_code=reason_code,
            tags=["security", "block"],
            metadata=event_metadata,
        )

    def log_biometric_attempt(
        self,
        context: Union[AuditContext, Dict[str, Any]],
        *,
        method: Union[str, BiometricMethod],
        biometric_outcome: Union[str, BiometricOutcome],
        action: str = "biometric_verification",
        challenge_id: Optional[Union[str, int]] = None,
        attempt_number: Optional[int] = None,
        liveness_checked: Optional[bool] = None,
        device_trusted: Optional[bool] = None,
        reason_code: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Log a biometric attempt without storing biometric material.

        Raw images, embeddings, fingerprints, voiceprints, or samples are
        recursively redacted if accidentally supplied in metadata.
        """

        normalized_method = _safe_enum_value(
            BiometricMethod,
            method,
            BiometricMethod.UNKNOWN,
        )

        normalized_biometric_outcome = _safe_enum_value(
            BiometricOutcome,
            biometric_outcome,
            BiometricOutcome.UNKNOWN,
        )

        if normalized_biometric_outcome == BiometricOutcome.SUCCESS.value:
            audit_outcome = AuditOutcome.SUCCEEDED
            severity = AuditSeverity.INFO
            risk_level = AuditRiskLevel.LOW
        elif normalized_biometric_outcome in {
            BiometricOutcome.FAILED.value,
            BiometricOutcome.LOCKED_OUT.value,
            BiometricOutcome.ERROR.value,
        }:
            audit_outcome = AuditOutcome.FAILED
            severity = AuditSeverity.HIGH
            risk_level = AuditRiskLevel.HIGH
        elif normalized_biometric_outcome == BiometricOutcome.CANCELLED.value:
            audit_outcome = AuditOutcome.CANCELLED
            severity = AuditSeverity.LOW
            risk_level = AuditRiskLevel.LOW
        else:
            audit_outcome = AuditOutcome.UNKNOWN
            severity = AuditSeverity.MEDIUM
            risk_level = AuditRiskLevel.MEDIUM

        event_metadata = dict(metadata or {})
        event_metadata.update(
            {
                "biometric_method": normalized_method,
                "biometric_outcome": normalized_biometric_outcome,
                "challenge_id": _optional_str(challenge_id, 255),
                "attempt_number": (
                    max(1, _safe_int(attempt_number, 1))
                    if attempt_number is not None
                    else None
                ),
                "liveness_checked": liveness_checked,
                "device_trusted": device_trusted,
                "raw_biometric_stored": False,
            }
        )

        return self.log_event(
            event_type=AuditEventType.BIOMETRIC_ATTEMPT,
            action=action,
            context=context,
            outcome=audit_outcome,
            severity=severity,
            risk_level=risk_level,
            message="Biometric verification attempt recorded.",
            reason_code=reason_code,
            tags=["security", "biometric", normalized_method],
            metadata=event_metadata,
        )

    def log_report(
        self,
        context: Union[AuditContext, Dict[str, Any]],
        *,
        report_type: str,
        report_id: Optional[Union[str, int]] = None,
        title: Optional[str] = None,
        summary: Optional[str] = None,
        finding_count: int = 0,
        severity: Union[str, AuditSeverity] = AuditSeverity.INFO,
        risk_level: Union[str, AuditRiskLevel] = AuditRiskLevel.UNKNOWN,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Log creation or delivery of a security report."""

        event_metadata = dict(metadata or {})
        event_metadata.update(
            {
                "report_type": _safe_str(report_type, 150),
                "report_title": _optional_str(title, 500),
                "report_summary": _optional_str(
                    summary,
                    MAX_EVENT_MESSAGE_LENGTH,
                ),
                "finding_count": max(0, _safe_int(finding_count, 0)),
            }
        )

        return self.log_event(
            event_type=AuditEventType.SECURITY_REPORT,
            action="security_report_generated",
            context=context,
            outcome=AuditOutcome.REPORTED,
            severity=severity,
            risk_level=risk_level,
            message="Security report recorded.",
            report_id=report_id,
            tags=["security", "report", _normalize_tag(report_type)],
            metadata=event_metadata,
        )

    # =========================================================================
    # Query, retrieval, statistics, reports, and exports
    # =========================================================================

    def query_events(
        self,
        query: Union[AuditQuery, Dict[str, Any]],
        *,
        requester_context: Optional[
            Union[AuditContext, Dict[str, Any]]
        ] = None,
    ) -> Dict[str, Any]:
        """
        Query audit events under strict user/workspace isolation.
        """

        started_at = time.perf_counter()

        try:
            audit_query = self._coerce_query(query)

            validation = self._validate_query_context(audit_query)
            if not validation["success"]:
                return validation

            if self._requires_security_check(
                operation="query_events",
                allow_cross_workspace=audit_query.allow_cross_workspace,
                strict_isolation=audit_query.strict_isolation,
            ):
                approval = self._request_security_approval(
                    operation="query_events",
                    context={
                        "user_id": audit_query.user_id,
                        "workspace_id": audit_query.workspace_id,
                    },
                    details={
                        "allow_cross_workspace": (
                            audit_query.allow_cross_workspace
                        ),
                        "strict_isolation": audit_query.strict_isolation,
                    },
                )

                if not approval["success"]:
                    return approval

            records = list(
                self._read_tenant_records(
                    user_id=audit_query.user_id,
                    workspace_id=audit_query.workspace_id,
                )
            )

            filtered_records = [
                record
                for record in records
                if self._record_matches_query(record, audit_query)
            ]

            filtered_records.sort(
                key=lambda record: (
                    _safe_str(record.get("timestamp")),
                    _safe_int(record.get("sequence"), 0),
                ),
                reverse=audit_query.newest_first,
            )

            total_matching = len(filtered_records)
            start_index = max(0, audit_query.offset)
            end_index = start_index + audit_query.limit
            selected_records = filtered_records[start_index:end_index]

            serialized_records = [
                self._serialize_record_for_query(record, audit_query)
                for record in selected_records
            ]

            duration_ms = round(
                (time.perf_counter() - started_at) * 1000,
                3,
            )

            if (
                requester_context is not None
                and self.config.get("enable_access_auditing", True)
            ):
                self._record_internal_access_event(
                    requester_context=requester_context,
                    target_user_id=audit_query.user_id,
                    target_workspace_id=audit_query.workspace_id,
                    operation="query_events",
                    record_count=len(serialized_records),
                )

            return self._safe_result(
                message="Audit events retrieved successfully.",
                data={
                    "events": serialized_records,
                    "count": len(serialized_records),
                    "total_matching": total_matching,
                    "offset": start_index,
                    "limit": audit_query.limit,
                    "has_more": end_index < total_matching,
                    "filters": self._query_to_dict(audit_query),
                },
                metadata={
                    "agent": self.agent_name,
                    "duration_ms": duration_ms,
                    "strict_isolation": audit_query.strict_isolation,
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to query audit events.",
                error_code="AUDIT_QUERY_FAILED",
                exception=exc,
            )

    def get_event(
        self,
        event_id: str,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        include_metadata: bool = True,
        include_integrity_fields: bool = True,
    ) -> Dict[str, Any]:
        """Retrieve one audit event within the specified tenant boundary."""

        query_result = self.query_events(
            AuditQuery(
                user_id=user_id,
                workspace_id=workspace_id,
                limit=MAX_QUERY_RESULTS_HARD_LIMIT,
                include_metadata=include_metadata,
                include_integrity_fields=include_integrity_fields,
            )
        )

        if not query_result["success"]:
            return query_result

        normalized_event_id = _safe_str(event_id)

        for record in query_result["data"]["events"]:
            if _safe_str(record.get("event_id")) == normalized_event_id:
                return self._safe_result(
                    message="Audit event retrieved successfully.",
                    data={"event": record},
                )

        return self._error_result(
            message="Audit event was not found in the requested tenant.",
            error_code="AUDIT_EVENT_NOT_FOUND",
        )

    def get_statistics(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        start_time: Optional[Union[str, datetime]] = None,
        end_time: Optional[Union[str, datetime]] = None,
    ) -> Dict[str, Any]:
        """
        Return Dashboard/API-ready audit statistics.
        """

        query_result = self.query_events(
            AuditQuery(
                user_id=user_id,
                workspace_id=workspace_id,
                start_time=start_time,
                end_time=end_time,
                limit=MAX_QUERY_RESULTS_HARD_LIMIT,
                include_metadata=False,
                include_integrity_fields=False,
                newest_first=True,
            )
        )

        if not query_result["success"]:
            return query_result

        events = query_result["data"]["events"]

        event_type_counts: Dict[str, int] = {}
        outcome_counts: Dict[str, int] = {}
        severity_counts: Dict[str, int] = {}
        risk_counts: Dict[str, int] = {}
        action_counts: Dict[str, int] = {}

        critical_events = 0
        denied_or_blocked = 0
        biometric_failures = 0

        for event in events:
            event_type = _safe_str(event.get("event_type"), 100)
            outcome = _safe_str(event.get("outcome"), 100)
            severity = _safe_str(event.get("severity"), 100)
            risk_level = _safe_str(event.get("risk_level"), 100)
            action = _safe_str(event.get("action"), 255)

            event_type_counts[event_type] = (
                event_type_counts.get(event_type, 0) + 1
            )
            outcome_counts[outcome] = outcome_counts.get(outcome, 0) + 1
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1
            action_counts[action] = action_counts.get(action, 0) + 1

            if severity == AuditSeverity.CRITICAL.value:
                critical_events += 1

            if outcome in {
                AuditOutcome.DENIED.value,
                AuditOutcome.BLOCKED.value,
            }:
                denied_or_blocked += 1

            if (
                event_type == AuditEventType.BIOMETRIC_ATTEMPT.value
                and outcome == AuditOutcome.FAILED.value
            ):
                biometric_failures += 1

        top_actions = sorted(
            action_counts.items(),
            key=lambda item: item[1],
            reverse=True,
        )[:20]

        return self._safe_result(
            message="Audit statistics generated successfully.",
            data={
                "total_events": len(events),
                "critical_events": critical_events,
                "denied_or_blocked_events": denied_or_blocked,
                "biometric_failures": biometric_failures,
                "event_types": event_type_counts,
                "outcomes": outcome_counts,
                "severities": severity_counts,
                "risk_levels": risk_counts,
                "top_actions": [
                    {"action": action, "count": count}
                    for action, count in top_actions
                ],
                "time_range": {
                    "start_time": (
                        _parse_datetime(start_time).isoformat()
                        if _parse_datetime(start_time)
                        else None
                    ),
                    "end_time": (
                        _parse_datetime(end_time).isoformat()
                        if _parse_datetime(end_time)
                        else None
                    ),
                },
            },
        )

    def generate_report(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        start_time: Optional[Union[str, datetime]] = None,
        end_time: Optional[Union[str, datetime]] = None,
        report_type: str = "security_audit_summary",
        include_events: bool = False,
        event_limit: int = 100,
    ) -> Dict[str, Any]:
        """
        Generate a structured security audit report.
        """

        statistics_result = self.get_statistics(
            user_id=user_id,
            workspace_id=workspace_id,
            start_time=start_time,
            end_time=end_time,
        )

        if not statistics_result["success"]:
            return statistics_result

        statistics = statistics_result["data"]
        findings = self._build_report_findings(statistics)

        report_id = str(uuid.uuid4())
        report: Dict[str, Any] = {
            "report_id": report_id,
            "report_type": _safe_str(report_type, 150),
            "generated_at": _iso_now(),
            "user_id": _safe_str(user_id),
            "workspace_id": _safe_str(workspace_id),
            "time_range": {
                "start_time": (
                    _parse_datetime(start_time).isoformat()
                    if _parse_datetime(start_time)
                    else None
                ),
                "end_time": (
                    _parse_datetime(end_time).isoformat()
                    if _parse_datetime(end_time)
                    else None
                ),
            },
            "statistics": statistics,
            "findings": findings,
            "finding_count": len(findings),
        }

        if include_events:
            events_result = self.query_events(
                AuditQuery(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    start_time=start_time,
                    end_time=end_time,
                    limit=min(
                        max(1, _safe_int(event_limit, 100)),
                        MAX_QUERY_RESULTS_HARD_LIMIT,
                    ),
                    include_metadata=True,
                    include_integrity_fields=False,
                    newest_first=True,
                )
            )

            if events_result["success"]:
                report["events"] = events_result["data"]["events"]

        report["report_hash"] = _sha256_text(_canonical_json(report))

        return self._safe_result(
            message="Security audit report generated successfully.",
            data={"report": report},
            metadata={
                "agent": self.agent_name,
                "version": self.version,
            },
        )

    def export_events(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        export_format: str = "json",
        start_time: Optional[Union[str, datetime]] = None,
        end_time: Optional[Union[str, datetime]] = None,
        include_metadata: bool = True,
        include_integrity_fields: bool = True,
        requester_context: Optional[
            Union[AuditContext, Dict[str, Any]]
        ] = None,
    ) -> Dict[str, Any]:
        """
        Export tenant-scoped audit events as JSON or JSONL text.

        This method returns export content. It does not transmit data or write
        arbitrary user-controlled files.
        """

        normalized_format = _safe_str(export_format).lower()

        if normalized_format not in {"json", "jsonl"}:
            return self._error_result(
                message="Unsupported audit export format.",
                error_code="UNSUPPORTED_EXPORT_FORMAT",
                details={"supported_formats": ["json", "jsonl"]},
            )

        security_approval = self._request_security_approval(
            operation="export_events",
            context={
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
            details={
                "export_format": normalized_format,
                "include_metadata": include_metadata,
                "include_integrity_fields": include_integrity_fields,
            },
        )

        if not security_approval["success"]:
            return security_approval

        query_result = self.query_events(
            AuditQuery(
                user_id=user_id,
                workspace_id=workspace_id,
                start_time=start_time,
                end_time=end_time,
                limit=MAX_QUERY_RESULTS_HARD_LIMIT,
                include_metadata=include_metadata,
                include_integrity_fields=include_integrity_fields,
                newest_first=False,
            ),
            requester_context=requester_context,
        )

        if not query_result["success"]:
            return query_result

        events = query_result["data"]["events"]

        if normalized_format == "json":
            content = json.dumps(
                events,
                ensure_ascii=False,
                indent=2,
                default=str,
            )
            content_type = "application/json"
            extension = "json"
        else:
            content = "\n".join(
                _canonical_json(event)
                for event in events
            )
            content_type = "application/x-ndjson"
            extension = "jsonl"

        export_hash = _sha256_text(content)

        return self._safe_result(
            message="Audit export prepared successfully.",
            data={
                "format": normalized_format,
                "content_type": content_type,
                "suggested_filename": (
                    f"security-audit-{_utc_now().strftime('%Y%m%d-%H%M%S')}"
                    f".{extension}"
                ),
                "record_count": len(events),
                "content": content,
                "content_hash": export_hash,
            },
        )

    # =========================================================================
    # Integrity and retention
    # =========================================================================

    def verify_integrity(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
    ) -> Dict[str, Any]:
        """
        Verify sequence order, hash chain, record hashes, and HMAC signatures.
        """

        try:
            records = list(
                self._read_tenant_records(
                    user_id=user_id,
                    workspace_id=workspace_id,
                )
            )

            expected_previous_hash = GENESIS_HASH
            expected_sequence = 1
            failures: List[Dict[str, Any]] = []

            for record in records:
                event_id = _safe_str(record.get("event_id"))
                sequence = _safe_int(record.get("sequence"), 0)
                stored_previous_hash = _safe_str(
                    record.get("previous_hash")
                )
                stored_record_hash = _safe_str(record.get("record_hash"))
                stored_signature = _optional_str(record.get("signature"))

                if sequence != expected_sequence:
                    failures.append(
                        {
                            "event_id": event_id,
                            "check": "sequence",
                            "expected": expected_sequence,
                            "actual": sequence,
                        }
                    )

                if stored_previous_hash != expected_previous_hash:
                    failures.append(
                        {
                            "event_id": event_id,
                            "check": "previous_hash",
                            "expected": expected_previous_hash,
                            "actual": stored_previous_hash,
                        }
                    )

                calculated_record_hash = self._calculate_record_hash(record)

                if not hmac.compare_digest(
                    calculated_record_hash,
                    stored_record_hash,
                ):
                    failures.append(
                        {
                            "event_id": event_id,
                            "check": "record_hash",
                            "expected": calculated_record_hash,
                            "actual": stored_record_hash,
                        }
                    )

                if stored_signature is not None:
                    if self._signing_key is None:
                        failures.append(
                            {
                                "event_id": event_id,
                                "check": "signature",
                                "error": (
                                    "A signature exists but no verification "
                                    "key is configured."
                                ),
                            }
                        )
                    else:
                        expected_signature = self._sign_hash(
                            stored_record_hash
                        )

                        if not hmac.compare_digest(
                            expected_signature or "",
                            stored_signature,
                        ):
                            failures.append(
                                {
                                    "event_id": event_id,
                                    "check": "signature",
                                    "expected": expected_signature,
                                    "actual": stored_signature,
                                }
                            )

                expected_previous_hash = stored_record_hash
                expected_sequence = sequence + 1

            integrity_valid = len(failures) == 0

            verification_payload = self._prepare_verification_payload(
                operation="audit_integrity_verification",
                context=AuditContext(
                    user_id=user_id,
                    workspace_id=workspace_id,
                ),
                records=[],
                additional_data={
                    "integrity_valid": integrity_valid,
                    "record_count": len(records),
                    "failure_count": len(failures),
                },
            )

            return self._safe_result(
                message=(
                    "Audit integrity verification passed."
                    if integrity_valid
                    else "Audit integrity verification found failures."
                ),
                data={
                    "integrity_valid": integrity_valid,
                    "record_count": len(records),
                    "failure_count": len(failures),
                    "failures": failures,
                    "last_record_hash": (
                        expected_previous_hash
                        if records
                        else GENESIS_HASH
                    ),
                    "verification_payload": verification_payload,
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Audit integrity verification failed.",
                error_code="AUDIT_INTEGRITY_CHECK_FAILED",
                exception=exc,
            )

    def purge_expired_records(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        retention_days: Optional[int] = None,
        requester_context: Optional[
            Union[AuditContext, Dict[str, Any]]
        ] = None,
    ) -> Dict[str, Any]:
        """
        Remove records older than the configured retention period.

        This is a destructive operation and requires Security Agent approval.
        The remaining records are re-chained to preserve integrity.
        """

        days = max(
            1,
            _safe_int(
                retention_days,
                _safe_int(
                    self.config.get("retention_days"),
                    DEFAULT_RETENTION_DAYS,
                ),
            ),
        )

        approval = self._request_security_approval(
            operation="purge_expired_records",
            context={
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
            details={"retention_days": days},
        )

        if not approval["success"]:
            return approval

        cutoff = _utc_now() - timedelta(days=days)

        with self._lock:
            records = list(
                self._read_tenant_records(
                    user_id=user_id,
                    workspace_id=workspace_id,
                )
            )

            kept_records: List[Dict[str, Any]] = []
            removed_records: List[Dict[str, Any]] = []

            for record in records:
                timestamp = _parse_datetime(record.get("timestamp"))

                if timestamp is not None and timestamp < cutoff:
                    removed_records.append(record)
                else:
                    kept_records.append(record)

            rechained_records = self._rechain_records(kept_records)

            replacement_result = self._replace_tenant_records(
                user_id=user_id,
                workspace_id=workspace_id,
                records=rechained_records,
            )

            if not replacement_result["success"]:
                return replacement_result

            tenant_key = self._tenant_key(user_id, workspace_id)
            self._sequence_cache[tenant_key] = len(rechained_records)
            self._last_hash_cache[tenant_key] = (
                _safe_str(rechained_records[-1].get("record_hash"))
                if rechained_records
                else GENESIS_HASH
            )

        if requester_context is not None:
            self._record_internal_access_event(
                requester_context=requester_context,
                target_user_id=user_id,
                target_workspace_id=workspace_id,
                operation="purge_expired_records",
                record_count=len(removed_records),
            )

        return self._safe_result(
            message="Expired audit records purged successfully.",
            data={
                "retention_days": days,
                "cutoff": cutoff.isoformat(),
                "removed_count": len(removed_records),
                "remaining_count": len(rechained_records),
                "audit_chain_rebuilt": True,
            },
        )

    # =========================================================================
    # Record construction
    # =========================================================================

    def _build_record(
        self,
        *,
        event_type: str,
        action: str,
        context: AuditContext,
        outcome: Union[str, AuditOutcome],
        severity: Union[str, AuditSeverity],
        risk_level: Union[str, AuditRiskLevel],
        message: str,
        resource_type: Optional[str],
        resource_id: Optional[Union[str, int]],
        policy_id: Optional[Union[str, int]],
        approval_id: Optional[Union[str, int]],
        report_id: Optional[Union[str, int]],
        reason_code: Optional[str],
        tags: Optional[Sequence[str]],
        metadata: Optional[Dict[str, Any]],
    ) -> AuditRecord:
        tenant_key = self._tenant_key(
            context.user_id,
            context.workspace_id,
        )

        with self._lock:
            sequence, previous_hash = self._next_chain_state(
                tenant_key=tenant_key,
                user_id=context.user_id,
                workspace_id=context.workspace_id,
            )

            request_id = (
                _optional_str(context.request_id, 255)
                or str(uuid.uuid4())
            )

            correlation_id = (
                _optional_str(context.correlation_id, 255)
                or request_id
            )

            safe_metadata = self._sanitize_value(
                metadata or {},
                current_key="metadata",
                depth=0,
            )

            if not isinstance(safe_metadata, dict):
                safe_metadata = {"value": safe_metadata}

            safe_metadata["network"] = self._build_safe_network_metadata(
                ip_address=context.ip_address,
                user_agent=context.user_agent,
            )

            record = AuditRecord(
                schema_version=AUDIT_SCHEMA_VERSION,
                event_id=str(uuid.uuid4()),
                sequence=sequence,
                timestamp=_iso_now(),
                event_type=event_type,
                action=action,
                outcome=_safe_enum_value(
                    AuditOutcome,
                    outcome,
                    AuditOutcome.UNKNOWN,
                ),
                severity=_safe_enum_value(
                    AuditSeverity,
                    severity,
                    AuditSeverity.INFO,
                ),
                risk_level=_safe_enum_value(
                    AuditRiskLevel,
                    risk_level,
                    AuditRiskLevel.UNKNOWN,
                ),
                message=_safe_str(
                    message,
                    MAX_EVENT_MESSAGE_LENGTH,
                ),
                user_id=_safe_str(context.user_id, 255),
                workspace_id=_safe_str(context.workspace_id, 255),
                actor_id=_optional_str(context.actor_id, 255),
                actor_type=(
                    _safe_str(context.actor_type, 100) or "user"
                ),
                role=_optional_str(context.role, 255),
                session_id=_optional_str(context.session_id, 255),
                task_id=_optional_str(context.task_id, 255),
                request_id=request_id,
                correlation_id=correlation_id,
                source_agent=_optional_str(
                    context.source_agent,
                    255,
                ),
                target_agent=_optional_str(
                    context.target_agent,
                    255,
                ),
                project_id=_optional_str(context.project_id, 255),
                client_id=_optional_str(context.client_id, 255),
                device_id=(
                    _stable_identifier_hash(context.device_id)
                    if context.device_id is not None
                    else None
                ),
                resource_type=_optional_str(resource_type, 255),
                resource_id=_optional_str(resource_id, 255),
                policy_id=_optional_str(policy_id, 255),
                approval_id=_optional_str(approval_id, 255),
                report_id=_optional_str(report_id, 255),
                reason_code=_optional_str(reason_code, 255),
                tags=_coerce_tags(tags),
                metadata=safe_metadata,
                previous_hash=previous_hash,
                record_hash="",
                signature=None,
            )

            raw_record = asdict(record)
            record.record_hash = self._calculate_record_hash(raw_record)

            if (
                self.config.get("enable_hmac_signatures", True)
                and self._signing_key is not None
            ):
                record.signature = self._sign_hash(record.record_hash)

            return record

    def _calculate_record_hash(self, record: Mapping[str, Any]) -> str:
        """
        Calculate a record hash without record_hash or signature fields.
        """

        hashable_record = copy.deepcopy(dict(record))
        hashable_record.pop("record_hash", None)
        hashable_record.pop("signature", None)

        return _sha256_text(_canonical_json(hashable_record))

    def _sign_hash(self, record_hash: str) -> Optional[str]:
        if self._signing_key is None:
            return None

        return hmac.new(
            self._signing_key,
            record_hash.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def _next_chain_state(
        self,
        *,
        tenant_key: str,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
    ) -> Tuple[int, str]:
        if tenant_key in self._sequence_cache:
            sequence = self._sequence_cache[tenant_key] + 1
            previous_hash = self._last_hash_cache.get(
                tenant_key,
                GENESIS_HASH,
            )
            return sequence, previous_hash

        last_record = self._get_last_tenant_record(
            user_id=user_id,
            workspace_id=workspace_id,
        )

        if last_record is None:
            return 1, GENESIS_HASH

        last_sequence = _safe_int(last_record.get("sequence"), 0)
        last_hash = (
            _safe_str(last_record.get("record_hash"))
            or GENESIS_HASH
        )

        self._sequence_cache[tenant_key] = last_sequence
        self._last_hash_cache[tenant_key] = last_hash

        return last_sequence + 1, last_hash

    # =========================================================================
    # Persistence
    # =========================================================================

    def _persist_record(self, record: AuditRecord) -> Dict[str, Any]:
        record_dict = asdict(record)

        with self._lock:
            try:
                if self.storage_provider is not None:
                    provider_result = self._persist_with_provider(
                        record_dict
                    )

                    if not provider_result["success"]:
                        return provider_result

                if self.config.get("enable_file_storage", True):
                    file_result = self._persist_to_file(record_dict)

                    if not file_result["success"]:
                        return file_result

                if (
                    self.storage_provider is None
                    and not self.config.get("enable_file_storage", True)
                ):
                    return self._error_result(
                        message="No audit storage backend is enabled.",
                        error_code="NO_AUDIT_STORAGE_BACKEND",
                    )

                tenant_key = self._tenant_key(
                    record.user_id,
                    record.workspace_id,
                )
                self._sequence_cache[tenant_key] = record.sequence
                self._last_hash_cache[tenant_key] = record.record_hash

                return self._safe_result(
                    message="Audit record persisted.",
                    data={
                        "event_id": record.event_id,
                        "sequence": record.sequence,
                    },
                )

            except Exception as exc:
                return self._error_result(
                    message="Audit record persistence failed.",
                    error_code="AUDIT_PERSISTENCE_FAILED",
                    exception=exc,
                )

    def _persist_with_provider(
        self,
        record: Dict[str, Any],
    ) -> Dict[str, Any]:
        try:
            if hasattr(self.storage_provider, "append"):
                result = self.storage_provider.append(record)
            elif hasattr(self.storage_provider, "write"):
                result = self.storage_provider.write(record)
            elif hasattr(self.storage_provider, "save"):
                result = self.storage_provider.save(record)
            elif callable(self.storage_provider):
                result = self.storage_provider(record)
            else:
                return self._error_result(
                    message="Invalid audit storage provider.",
                    error_code="INVALID_AUDIT_STORAGE_PROVIDER",
                )

            if isinstance(result, dict) and result.get("success") is False:
                return result

            return self._safe_result(
                message="Audit record persisted by provider.",
                data={"provider_result": result},
            )

        except Exception as exc:
            return self._error_result(
                message="Audit storage provider failed.",
                error_code="AUDIT_STORAGE_PROVIDER_FAILED",
                exception=exc,
            )

    def _persist_to_file(
        self,
        record: Dict[str, Any],
    ) -> Dict[str, Any]:
        user_id = record["user_id"]
        workspace_id = record["workspace_id"]

        log_file = self._tenant_log_file(
            user_id=user_id,
            workspace_id=workspace_id,
        )
        log_file.parent.mkdir(parents=True, exist_ok=True)

        serialized = _canonical_json(record)

        with log_file.open(
            mode="a",
            encoding="utf-8",
            newline="\n",
        ) as file_handle:
            file_handle.write(serialized)
            file_handle.write("\n")
            file_handle.flush()

            if self.config.get("fsync_writes", False):
                os.fsync(file_handle.fileno())

        return self._safe_result(
            message="Audit record persisted to file.",
            data={"storage_file": str(log_file)},
        )

    def _read_tenant_records(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
    ) -> Iterator[Dict[str, Any]]:
        if self.storage_provider is not None:
            provider_records = self._read_with_provider(
                user_id=user_id,
                workspace_id=workspace_id,
            )

            if provider_records is not None:
                for record in provider_records:
                    if self._record_belongs_to_tenant(
                        record,
                        user_id=user_id,
                        workspace_id=workspace_id,
                    ):
                        yield record

                if not self.config.get("enable_file_storage", True):
                    return

        if not self.config.get("enable_file_storage", True):
            return

        log_file = self._tenant_log_file(
            user_id=user_id,
            workspace_id=workspace_id,
        )

        if not log_file.exists():
            return

        with self._lock:
            with log_file.open(
                mode="r",
                encoding="utf-8",
            ) as file_handle:
                for line_number, line in enumerate(
                    file_handle,
                    start=1,
                ):
                    stripped_line = line.strip()

                    if not stripped_line:
                        continue

                    try:
                        record = json.loads(stripped_line)
                    except json.JSONDecodeError:
                        logger.warning(
                            "Skipping malformed audit record at %s:%s",
                            log_file,
                            line_number,
                        )
                        continue

                    if not isinstance(record, dict):
                        continue

                    if not self._record_belongs_to_tenant(
                        record,
                        user_id=user_id,
                        workspace_id=workspace_id,
                    ):
                        logger.error(
                            "Tenant boundary violation detected in audit file."
                        )
                        continue

                    yield record

    def _read_with_provider(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
    ) -> Optional[List[Dict[str, Any]]]:
        try:
            if hasattr(self.storage_provider, "query"):
                result = self.storage_provider.query(
                    {
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                    }
                )
            elif hasattr(self.storage_provider, "read"):
                result = self.storage_provider.read(
                    user_id=user_id,
                    workspace_id=workspace_id,
                )
            elif hasattr(self.storage_provider, "list_records"):
                result = self.storage_provider.list_records(
                    user_id=user_id,
                    workspace_id=workspace_id,
                )
            else:
                return None

            if isinstance(result, list):
                return [
                    record
                    for record in result
                    if isinstance(record, dict)
                ]

            if isinstance(result, dict):
                data = result.get("data", result)

                for key in ("records", "events", "items", "results"):
                    records = data.get(key) if isinstance(data, dict) else None

                    if isinstance(records, list):
                        return [
                            record
                            for record in records
                            if isinstance(record, dict)
                        ]

            return []

        except Exception as exc:
            logger.warning(
                "Failed reading from audit storage provider: %s",
                exc,
            )
            return None

    def _replace_tenant_records(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        records: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Atomically replace the file-backed tenant audit stream.

        Custom storage providers may implement replace_records().
        """

        try:
            if self.storage_provider is not None:
                if hasattr(self.storage_provider, "replace_records"):
                    provider_result = (
                        self.storage_provider.replace_records(
                            user_id=user_id,
                            workspace_id=workspace_id,
                            records=records,
                        )
                    )

                    if (
                        isinstance(provider_result, dict)
                        and provider_result.get("success") is False
                    ):
                        return provider_result
                elif not self.config.get("enable_file_storage", True):
                    return self._error_result(
                        message=(
                            "Storage provider does not support record "
                            "replacement."
                        ),
                        error_code=(
                            "STORAGE_PROVIDER_REPLACE_UNSUPPORTED"
                        ),
                    )

            if self.config.get("enable_file_storage", True):
                log_file = self._tenant_log_file(
                    user_id=user_id,
                    workspace_id=workspace_id,
                )
                log_file.parent.mkdir(parents=True, exist_ok=True)

                temporary_file = log_file.with_suffix(
                    f".{uuid.uuid4().hex}.tmp"
                )

                with temporary_file.open(
                    mode="w",
                    encoding="utf-8",
                    newline="\n",
                ) as file_handle:
                    for record in records:
                        file_handle.write(_canonical_json(record))
                        file_handle.write("\n")

                    file_handle.flush()

                    if self.config.get("fsync_writes", False):
                        os.fsync(file_handle.fileno())

                os.replace(temporary_file, log_file)

            return self._safe_result(
                message="Tenant audit records replaced successfully.",
                data={"record_count": len(records)},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to replace tenant audit records.",
                error_code="AUDIT_RECORD_REPLACEMENT_FAILED",
                exception=exc,
            )

    def _get_last_tenant_record(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
    ) -> Optional[Dict[str, Any]]:
        last_record: Optional[Dict[str, Any]] = None

        for record in self._read_tenant_records(
            user_id=user_id,
            workspace_id=workspace_id,
        ):
            if last_record is None:
                last_record = record
                continue

            if _safe_int(record.get("sequence"), 0) >= _safe_int(
                last_record.get("sequence"),
                0,
            ):
                last_record = record

        return last_record

    def _rechain_records(
        self,
        records: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        rechained: List[Dict[str, Any]] = []
        previous_hash = GENESIS_HASH

        records_sorted = sorted(
            records,
            key=lambda record: (
                _safe_str(record.get("timestamp")),
                _safe_int(record.get("sequence"), 0),
            ),
        )

        for index, original_record in enumerate(
            records_sorted,
            start=1,
        ):
            record = copy.deepcopy(original_record)
            record["sequence"] = index
            record["previous_hash"] = previous_hash
            record["record_hash"] = ""
            record["signature"] = None

            record_hash = self._calculate_record_hash(record)
            record["record_hash"] = record_hash

            if (
                self.config.get("enable_hmac_signatures", True)
                and self._signing_key is not None
            ):
                record["signature"] = self._sign_hash(record_hash)

            previous_hash = record_hash
            rechained.append(record)

        return rechained

    # =========================================================================
    # Query helpers
    # =========================================================================

    def _record_matches_query(
        self,
        record: Dict[str, Any],
        query: AuditQuery,
    ) -> bool:
        if not self._record_belongs_to_tenant(
            record,
            user_id=query.user_id,
            workspace_id=query.workspace_id,
        ):
            return False

        list_filters = (
            ("event_type", query.event_types),
            ("outcome", query.outcomes),
            ("severity", query.severities),
            ("risk_level", query.risk_levels),
        )

        for record_key, query_values in list_filters:
            normalized_values = {
                _safe_str(value).lower()
                for value in query_values
                if _safe_str(value)
            }

            if (
                normalized_values
                and _safe_str(record.get(record_key)).lower()
                not in normalized_values
            ):
                return False

        exact_filters = (
            ("actor_id", query.actor_id),
            ("action", query.action),
            ("source_agent", query.source_agent),
            ("target_agent", query.target_agent),
            ("task_id", query.task_id),
            ("request_id", query.request_id),
            ("correlation_id", query.correlation_id),
            ("project_id", query.project_id),
            ("client_id", query.client_id),
            ("resource_type", query.resource_type),
            ("resource_id", query.resource_id),
            ("policy_id", query.policy_id),
            ("approval_id", query.approval_id),
            ("report_id", query.report_id),
        )

        for record_key, query_value in exact_filters:
            if query_value is None:
                continue

            if _safe_str(record.get(record_key)) != _safe_str(query_value):
                return False

        if query.device_id is not None:
            expected_device_hash = _stable_identifier_hash(query.device_id)

            if _safe_str(record.get("device_id")) != expected_device_hash:
                return False

        requested_tags = set(_coerce_tags(query.tags))

        if requested_tags:
            record_tags = set(_coerce_tags(record.get("tags", [])))

            if not requested_tags.intersection(record_tags):
                return False

        start_time = _parse_datetime(query.start_time)
        end_time = _parse_datetime(query.end_time)
        record_time = _parse_datetime(record.get("timestamp"))

        if start_time is not None:
            if record_time is None or record_time < start_time:
                return False

        if end_time is not None:
            if record_time is None or record_time > end_time:
                return False

        if query.search_text:
            searchable_record = copy.deepcopy(record)
            searchable_record.pop("signature", None)

            searchable_text = _canonical_json(
                searchable_record
            ).lower()

            if _safe_str(query.search_text).lower() not in searchable_text:
                return False

        return True

    def _serialize_record_for_query(
        self,
        record: Dict[str, Any],
        query: AuditQuery,
    ) -> Dict[str, Any]:
        serialized = copy.deepcopy(record)

        if not query.include_metadata:
            serialized.pop("metadata", None)

        if not query.include_integrity_fields:
            serialized.pop("previous_hash", None)
            serialized.pop("record_hash", None)
            serialized.pop("signature", None)

        return serialized

    def _record_belongs_to_tenant(
        self,
        record: Mapping[str, Any],
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
    ) -> bool:
        return (
            _safe_str(record.get("user_id")) == _safe_str(user_id)
            and _safe_str(record.get("workspace_id"))
            == _safe_str(workspace_id)
        )

    # =========================================================================
    # Sanitization and privacy
    # =========================================================================

    def _sanitize_value(
        self,
        value: Any,
        *,
        current_key: str,
        depth: int,
    ) -> Any:
        """
        Recursively redact secret fields and bound metadata size.
        """

        if depth > MAX_METADATA_DEPTH:
            return "[MAX_DEPTH_REACHED]"

        normalized_key = _normalize_key(current_key)

        if normalized_key in self._sensitive_keys:
            return self.config.get("redaction_text", "[REDACTED]")

        if (
            normalized_key in self._hash_only_keys
            and self.config.get("hash_sensitive_identifiers", True)
        ):
            return _stable_identifier_hash(value)

        if isinstance(value, Mapping):
            output: Dict[str, Any] = {}

            for index, (key, nested_value) in enumerate(value.items()):
                if index >= MAX_COLLECTION_ITEMS:
                    output["_truncated"] = True
                    break

                safe_key = _safe_str(key, 255)

                output[safe_key] = self._sanitize_value(
                    nested_value,
                    current_key=safe_key,
                    depth=depth + 1,
                )

            return output

        if isinstance(value, (list, tuple, set)):
            output_list: List[Any] = []

            for index, nested_value in enumerate(value):
                if index >= MAX_COLLECTION_ITEMS:
                    output_list.append("[TRUNCATED]")
                    break

                output_list.append(
                    self._sanitize_value(
                        nested_value,
                        current_key=current_key,
                        depth=depth + 1,
                    )
                )

            return output_list

        if isinstance(value, bytes):
            return {
                "type": "bytes",
                "length": len(value),
                "sha256": hashlib.sha256(value).hexdigest(),
            }

        if isinstance(value, str):
            if self._looks_like_secret(value):
                return self.config.get(
                    "redaction_text",
                    "[REDACTED]",
                )

            return value[:MAX_STRING_VALUE_LENGTH]

        if isinstance(value, (int, float, bool)) or value is None:
            return value

        return _safe_str(value, MAX_STRING_VALUE_LENGTH)

    def _looks_like_secret(self, value: str) -> bool:
        """
        Conservative detection for obvious bearer tokens and private keys.

        This intentionally avoids redacting every long string because audit
        messages may legitimately contain hashes or identifiers.
        """

        stripped = value.strip()

        if re.match(r"(?i)^bearer\s+[A-Za-z0-9._~+/=-]{12,}$", stripped):
            return True

        if "-----BEGIN PRIVATE KEY-----" in stripped:
            return True

        if "-----BEGIN RSA PRIVATE KEY-----" in stripped:
            return True

        if re.match(r"^sk-[A-Za-z0-9_\-]{20,}$", stripped):
            return True

        return False

    def _build_safe_network_metadata(
        self,
        *,
        ip_address: Optional[str],
        user_agent: Optional[str],
    ) -> Dict[str, Any]:
        network_metadata: Dict[str, Any] = {
            "ip_address": None,
            "user_agent": None,
        }

        if ip_address:
            if self.config.get("store_ip_hash_only", True):
                network_metadata["ip_address"] = (
                    _stable_identifier_hash(ip_address)
                )
            else:
                network_metadata["ip_address"] = _safe_str(
                    ip_address,
                    255,
                )

        if user_agent:
            if self.config.get("store_user_agent_hash_only", True):
                network_metadata["user_agent"] = (
                    _stable_identifier_hash(user_agent)
                )
            else:
                network_metadata["user_agent"] = _safe_str(
                    user_agent,
                    1000,
                )

        return network_metadata

    # =========================================================================
    # Context and query coercion
    # =========================================================================

    def _coerce_context(
        self,
        context: Union[AuditContext, Dict[str, Any]],
    ) -> AuditContext:
        if isinstance(context, AuditContext):
            return context

        if not isinstance(context, dict):
            raise TypeError(
                "context must be AuditContext or a dictionary."
            )

        return AuditContext(
            user_id=context.get("user_id"),
            workspace_id=context.get("workspace_id"),
            actor_id=context.get("actor_id"),
            actor_type=context.get("actor_type", "user"),
            role=context.get("role"),
            session_id=context.get("session_id"),
            task_id=context.get("task_id"),
            request_id=context.get("request_id"),
            correlation_id=context.get("correlation_id"),
            source_agent=context.get("source_agent"),
            target_agent=context.get("target_agent"),
            project_id=context.get("project_id"),
            client_id=context.get("client_id"),
            device_id=context.get("device_id"),
            ip_address=context.get("ip_address"),
            user_agent=context.get("user_agent"),
            metadata=dict(context.get("metadata", {}) or {}),
        )

    def _coerce_query(
        self,
        query: Union[AuditQuery, Dict[str, Any]],
    ) -> AuditQuery:
        if isinstance(query, AuditQuery):
            query.limit = min(
                max(1, _safe_int(query.limit, DEFAULT_MAX_QUERY_RESULTS)),
                _safe_int(
                    self.config.get("hard_max_query_results"),
                    MAX_QUERY_RESULTS_HARD_LIMIT,
                ),
            )
            query.offset = max(0, _safe_int(query.offset, 0))
            return query

        if not isinstance(query, dict):
            raise TypeError(
                "query must be AuditQuery or a dictionary."
            )

        return AuditQuery(
            user_id=query.get("user_id"),
            workspace_id=query.get("workspace_id"),
            event_types=self._coerce_string_list(
                query.get("event_types", query.get("event_type", []))
            ),
            outcomes=self._coerce_string_list(
                query.get("outcomes", query.get("outcome", []))
            ),
            severities=self._coerce_string_list(
                query.get("severities", query.get("severity", []))
            ),
            risk_levels=self._coerce_string_list(
                query.get("risk_levels", query.get("risk_level", []))
            ),
            actor_id=query.get("actor_id"),
            action=query.get("action"),
            source_agent=query.get("source_agent"),
            target_agent=query.get("target_agent"),
            task_id=query.get("task_id"),
            request_id=query.get("request_id"),
            correlation_id=query.get("correlation_id"),
            project_id=query.get("project_id"),
            client_id=query.get("client_id"),
            device_id=query.get("device_id"),
            resource_type=query.get("resource_type"),
            resource_id=query.get("resource_id"),
            policy_id=query.get("policy_id"),
            approval_id=query.get("approval_id"),
            report_id=query.get("report_id"),
            tags=_coerce_tags(query.get("tags", [])),
            search_text=query.get("search_text"),
            start_time=query.get("start_time"),
            end_time=query.get("end_time"),
            limit=min(
                max(
                    1,
                    _safe_int(
                        query.get("limit"),
                        _safe_int(
                            self.config.get("max_query_results"),
                            DEFAULT_MAX_QUERY_RESULTS,
                        ),
                    ),
                ),
                _safe_int(
                    self.config.get("hard_max_query_results"),
                    MAX_QUERY_RESULTS_HARD_LIMIT,
                ),
            ),
            offset=max(0, _safe_int(query.get("offset"), 0)),
            newest_first=bool(query.get("newest_first", True)),
            include_metadata=bool(
                query.get("include_metadata", True)
            ),
            include_integrity_fields=bool(
                query.get("include_integrity_fields", False)
            ),
            strict_isolation=bool(
                query.get(
                    "strict_isolation",
                    self.config.get("strict_isolation", True),
                )
            ),
            allow_cross_workspace=bool(
                query.get(
                    "allow_cross_workspace",
                    self.config.get("allow_cross_workspace", False),
                )
            ),
        )

    def _coerce_string_list(self, value: Any) -> List[str]:
        if value is None:
            return []

        if isinstance(value, str):
            values = re.split(r"[,;|]", value)
        elif isinstance(value, (list, tuple, set)):
            values = list(value)
        else:
            values = [value]

        result: List[str] = []
        seen: Set[str] = set()

        for item in values:
            normalized = _safe_str(item).lower()

            if normalized and normalized not in seen:
                seen.add(normalized)
                result.append(normalized)

        return result

    def _query_to_dict(self, query: AuditQuery) -> Dict[str, Any]:
        data = asdict(query)

        if isinstance(query.start_time, datetime):
            data["start_time"] = query.start_time.isoformat()

        if isinstance(query.end_time, datetime):
            data["end_time"] = query.end_time.isoformat()

        return data

    # =========================================================================
    # Tenant storage paths
    # =========================================================================

    def _tenant_key(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
    ) -> str:
        raw_value = (
            f"workspace:{_safe_str(workspace_id)}|"
            f"user:{_safe_str(user_id)}"
        )
        return _sha256_text(raw_value)

    def _tenant_log_file(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
    ) -> Path:
        workspace_hash = _sha256_text(
            f"workspace:{_safe_str(workspace_id)}"
        )[:24]
        user_hash = _sha256_text(
            f"user:{_safe_str(user_id)}"
        )[:24]

        return (
            self.storage_directory
            / f"workspace_{workspace_hash}"
            / f"user_{user_hash}"
            / "security_audit.jsonl"
        )

    # =========================================================================
    # Validation and Security Agent compatibility hooks
    # =========================================================================

    def _validate_task_context(
        self,
        context: AuditContext,
    ) -> Dict[str, Any]:
        """
        Required William compatibility hook.

        Audit events must always have both user_id and workspace_id.
        """

        user_id = _safe_str(context.user_id)
        workspace_id = _safe_str(context.workspace_id)

        if not user_id:
            return self._error_result(
                message="user_id is required for audit logging.",
                error_code="MISSING_USER_ID",
            )

        if not workspace_id:
            return self._error_result(
                message="workspace_id is required for audit logging.",
                error_code="MISSING_WORKSPACE_ID",
            )

        if len(user_id) > 255:
            return self._error_result(
                message="user_id exceeds the supported length.",
                error_code="INVALID_USER_ID",
            )

        if len(workspace_id) > 255:
            return self._error_result(
                message="workspace_id exceeds the supported length.",
                error_code="INVALID_WORKSPACE_ID",
            )

        return self._safe_result(
            message="Audit context validated.",
            data={
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )

    def _validate_query_context(
        self,
        query: AuditQuery,
    ) -> Dict[str, Any]:
        context_validation = self._validate_task_context(
            AuditContext(
                user_id=query.user_id,
                workspace_id=query.workspace_id,
            )
        )

        if not context_validation["success"]:
            return context_validation

        if query.strict_isolation and query.allow_cross_workspace:
            return self._error_result(
                message=(
                    "Cross-workspace audit access is blocked while strict "
                    "isolation is enabled."
                ),
                error_code="CROSS_WORKSPACE_AUDIT_ACCESS_BLOCKED",
            )

        start_time = _parse_datetime(query.start_time)
        end_time = _parse_datetime(query.end_time)

        if query.start_time is not None and start_time is None:
            return self._error_result(
                message="start_time is invalid.",
                error_code="INVALID_START_TIME",
            )

        if query.end_time is not None and end_time is None:
            return self._error_result(
                message="end_time is invalid.",
                error_code="INVALID_END_TIME",
            )

        if (
            start_time is not None
            and end_time is not None
            and start_time > end_time
        ):
            return self._error_result(
                message="start_time cannot be after end_time.",
                error_code="INVALID_TIME_RANGE",
            )

        return self._safe_result(
            message="Audit query context validated.",
            data={
                "user_id": _safe_str(query.user_id),
                "workspace_id": _safe_str(query.workspace_id),
            },
        )

    def _requires_security_check(
        self,
        *,
        operation: str,
        allow_cross_workspace: bool = False,
        strict_isolation: bool = True,
    ) -> bool:
        """
        Required William compatibility hook.

        Writing an audit event does not recursively require approval. Reading,
        exporting, retention cleanup, and cross-workspace operations may.
        """

        protected_operations = {
            "export_events",
            "purge_expired_records",
            "cross_workspace_query",
            "delete_audit_records",
            "modify_audit_records",
        }

        if operation in protected_operations:
            return True

        if allow_cross_workspace or not strict_isolation:
            return True

        return False

    def _request_security_approval(
        self,
        *,
        operation: str,
        context: Dict[str, Any],
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Required William compatibility hook.

        When Security Agent is unavailable, safe read-only tenant-scoped
        operations may proceed. Protected operations fail closed.
        """

        protected = self._requires_security_check(
            operation=operation,
            allow_cross_workspace=bool(
                (details or {}).get("allow_cross_workspace", False)
            ),
            strict_isolation=bool(
                (details or {}).get("strict_isolation", True)
            ),
        )

        if not protected:
            return self._safe_result(
                message="Security approval is not required.",
                data={"approved": True},
            )

        if self.security_provider is None:
            return self._error_result(
                message=(
                    "Security Agent approval is required for this audit "
                    "operation."
                ),
                error_code="SECURITY_APPROVAL_REQUIRED",
                details={"operation": operation},
            )

        approval_request = {
            "action": operation,
            "category": "security_audit",
            "risk_level": "high",
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "details": self._sanitize_value(
                details or {},
                current_key="details",
                depth=0,
            ),
            "requested_at": _iso_now(),
        }

        try:
            if hasattr(self.security_provider, "request_approval"):
                result = self.security_provider.request_approval(
                    approval_request
                )
            elif hasattr(self.security_provider, "approve"):
                result = self.security_provider.approve(
                    approval_request
                )
            elif hasattr(self.security_provider, "check_permission"):
                result = self.security_provider.check_permission(
                    approval_request
                )
            elif callable(self.security_provider):
                result = self.security_provider(approval_request)
            else:
                return self._error_result(
                    message="Invalid Security Agent provider.",
                    error_code="INVALID_SECURITY_PROVIDER",
                )

            if isinstance(result, bool):
                approved = result
            elif isinstance(result, dict):
                approved = bool(
                    result.get("approved")
                    or (
                        result.get("success")
                        and result.get("data", {}).get(
                            "approved",
                            True,
                        )
                    )
                )
            else:
                approved = False

            if not approved:
                return self._error_result(
                    message="Security Agent denied the audit operation.",
                    error_code="SECURITY_APPROVAL_DENIED",
                    details={
                        "operation": operation,
                        "provider_result": result,
                    },
                )

            return self._safe_result(
                message="Security Agent approved the audit operation.",
                data={
                    "approved": True,
                    "provider_result": result,
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Security approval request failed.",
                error_code="SECURITY_APPROVAL_FAILED",
                exception=exc,
            )

    # =========================================================================
    # Verification, Memory, event, and audit compatibility hooks
    # =========================================================================

    def _prepare_verification_payload(
        self,
        *,
        operation: str,
        context: Union[AuditContext, Dict[str, Any]],
        records: Sequence[Dict[str, Any]],
        additional_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Required William compatibility hook.

        Produces a payload the Verification Agent can inspect.
        """

        audit_context = (
            context
            if isinstance(context, AuditContext)
            else self._coerce_context(context)
        )

        event_ids = [
            _safe_str(record.get("event_id"))
            for record in records
            if _safe_str(record.get("event_id"))
        ]

        record_hashes = [
            _safe_str(record.get("record_hash"))
            for record in records
            if _safe_str(record.get("record_hash"))
        ]

        return {
            "type": "security_audit_verification",
            "operation": operation,
            "agent": self.agent_name,
            "agent_version": self.version,
            "user_id": _safe_str(audit_context.user_id),
            "workspace_id": _safe_str(
                audit_context.workspace_id
            ),
            "request_id": _optional_str(
                audit_context.request_id
            ),
            "correlation_id": _optional_str(
                audit_context.correlation_id
            ),
            "record_count": len(records),
            "event_ids": event_ids,
            "record_hashes": record_hashes,
            "checks": {
                "tenant_context_present": bool(
                    _safe_str(audit_context.user_id)
                    and _safe_str(audit_context.workspace_id)
                ),
                "sensitive_fields_redacted": True,
                "raw_biometrics_stored": False,
                "hash_chain_enabled": bool(
                    self.config.get("enable_hash_chain", True)
                ),
                "hmac_signatures_enabled": bool(
                    self.config.get(
                        "enable_hmac_signatures",
                        True,
                    )
                    and self._signing_key is not None
                ),
            },
            "additional_data": additional_data or {},
            "created_at": _iso_now(),
        }

    def _prepare_memory_payload(
        self,
        *,
        operation: str,
        context: Union[AuditContext, Dict[str, Any]],
        records: Sequence[Dict[str, Any]],
        additional_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Required William compatibility hook.

        Produces privacy-safe context for Memory Agent. Full audit metadata,
        network identifiers, secrets, and biometric material are excluded.
        """

        audit_context = (
            context
            if isinstance(context, AuditContext)
            else self._coerce_context(context)
        )

        summaries = []

        for record in records[:20]:
            summaries.append(
                {
                    "event_id": record.get("event_id"),
                    "event_type": record.get("event_type"),
                    "action": record.get("action"),
                    "outcome": record.get("outcome"),
                    "severity": record.get("severity"),
                    "risk_level": record.get("risk_level"),
                    "timestamp": record.get("timestamp"),
                }
            )

        return {
            "type": "security_audit_memory",
            "operation": operation,
            "user_id": _safe_str(audit_context.user_id),
            "workspace_id": _safe_str(
                audit_context.workspace_id
            ),
            "content": (
                f"Security audit operation completed: {operation}"
            ),
            "records": summaries,
            "metadata": {
                "record_count": len(records),
                "source_agent": self.agent_name,
                "privacy_safe": True,
                "raw_secrets_included": False,
                "raw_biometrics_included": False,
                "additional_data": additional_data or {},
                "created_at": _iso_now(),
            },
        }

    def _dispatch_optional_payloads(
        self,
        *,
        verification_payload: Dict[str, Any],
        memory_payload: Dict[str, Any],
    ) -> None:
        if (
            self.config.get("enable_verification_payloads", True)
            and self.verification_sink is not None
        ):
            try:
                self.verification_sink(verification_payload)
            except Exception:
                logger.debug(
                    "Verification payload dispatch failed.",
                    exc_info=True,
                )

        if (
            self.config.get("enable_memory_payloads", True)
            and self.memory_sink is not None
        ):
            try:
                self.memory_sink(memory_payload)
            except Exception:
                logger.debug(
                    "Memory payload dispatch failed.",
                    exc_info=True,
                )

    def _emit_agent_event(
        self,
        *,
        event_type: str,
        payload: Dict[str, Any],
    ) -> None:
        """
        Required William compatibility hook.
        """

        if not self.config.get("enable_event_emission", True):
            return

        event = {
            "event_type": event_type,
            "agent": self.agent_name,
            "timestamp": _iso_now(),
            "payload": self._sanitize_value(
                payload,
                current_key="payload",
                depth=0,
            ),
        }

        try:
            if self.event_emitter is not None:
                self.event_emitter(event)
                return

            if hasattr(self, "emit_event"):
                try:
                    self.emit_event(event_type, event)
                except TypeError:
                    self.emit_event(event)
        except Exception:
            logger.debug(
                "Audit agent event emission failed.",
                exc_info=True,
            )

    def _log_audit_event(
        self,
        *,
        action: str,
        context: Union[AuditContext, Dict[str, Any]],
        status: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Required William compatibility hook.

        This wrapper avoids agents needing to know AuditLogger internals.
        """

        normalized_status = _safe_str(status).lower()

        status_to_outcome = {
            "success": AuditOutcome.SUCCEEDED,
            "succeeded": AuditOutcome.SUCCEEDED,
            "approved": AuditOutcome.APPROVED,
            "denied": AuditOutcome.DENIED,
            "blocked": AuditOutcome.BLOCKED,
            "failed": AuditOutcome.FAILED,
            "requested": AuditOutcome.REQUESTED,
        }

        outcome = status_to_outcome.get(
            normalized_status,
            AuditOutcome.UNKNOWN,
        )

        return self.log_event(
            event_type=AuditEventType.SECURITY_EVENT,
            action=action,
            context=context,
            outcome=outcome,
            severity=(
                AuditSeverity.HIGH
                if outcome
                in {
                    AuditOutcome.DENIED,
                    AuditOutcome.BLOCKED,
                    AuditOutcome.FAILED,
                }
                else AuditSeverity.INFO
            ),
            risk_level=(
                AuditRiskLevel.HIGH
                if outcome
                in {
                    AuditOutcome.DENIED,
                    AuditOutcome.BLOCKED,
                    AuditOutcome.FAILED,
                }
                else AuditRiskLevel.LOW
            ),
            message=f"Security audit hook recorded status: {status}",
            tags=["security", "audit-hook"],
            metadata=metadata,
        )

    # =========================================================================
    # Internal access logging
    # =========================================================================

    def _record_internal_access_event(
        self,
        *,
        requester_context: Union[AuditContext, Dict[str, Any]],
        target_user_id: Union[str, int],
        target_workspace_id: Union[str, int],
        operation: str,
        record_count: int,
    ) -> None:
        """
        Best-effort audit of audit-log access.

        Failures are intentionally swallowed to prevent infinite logging loops.
        """

        try:
            context = self._coerce_context(requester_context)

            if (
                _safe_str(context.user_id) != _safe_str(target_user_id)
                or _safe_str(context.workspace_id)
                != _safe_str(target_workspace_id)
            ):
                return

            self.log_event(
                event_type=AuditEventType.AUDIT_ACCESS,
                action=operation,
                context=context,
                outcome=AuditOutcome.SUCCEEDED,
                severity=AuditSeverity.INFO,
                risk_level=AuditRiskLevel.LOW,
                message="Security audit records accessed.",
                tags=["security", "audit-access"],
                metadata={
                    "record_count": max(
                        0,
                        _safe_int(record_count, 0),
                    ),
                },
            )
        except Exception:
            logger.debug(
                "Audit access event could not be recorded.",
                exc_info=True,
            )

    # =========================================================================
    # Report helpers
    # =========================================================================

    def _build_report_findings(
        self,
        statistics: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        critical_events = _safe_int(
            statistics.get("critical_events"),
            0,
        )
        denied_or_blocked = _safe_int(
            statistics.get("denied_or_blocked_events"),
            0,
        )
        biometric_failures = _safe_int(
            statistics.get("biometric_failures"),
            0,
        )

        if critical_events > 0:
            findings.append(
                {
                    "code": "CRITICAL_SECURITY_EVENTS",
                    "severity": AuditSeverity.CRITICAL.value,
                    "title": "Critical security events detected",
                    "count": critical_events,
                    "recommendation": (
                        "Review critical events and their associated tasks, "
                        "devices, policies, and actors immediately."
                    ),
                }
            )

        if denied_or_blocked > 0:
            findings.append(
                {
                    "code": "DENIED_OR_BLOCKED_ACTIONS",
                    "severity": AuditSeverity.HIGH.value,
                    "title": "Denied or blocked actions detected",
                    "count": denied_or_blocked,
                    "recommendation": (
                        "Review recurring denial and blocking patterns for "
                        "misconfiguration, misuse, or attack indicators."
                    ),
                }
            )

        if biometric_failures > 0:
            findings.append(
                {
                    "code": "BIOMETRIC_FAILURES",
                    "severity": AuditSeverity.HIGH.value,
                    "title": "Biometric verification failures detected",
                    "count": biometric_failures,
                    "recommendation": (
                        "Review device trust, liveness checks, lockout rules, "
                        "and suspicious authentication patterns."
                    ),
                }
            )

        if not findings:
            findings.append(
                {
                    "code": "NO_HIGH_PRIORITY_FINDINGS",
                    "severity": AuditSeverity.INFO.value,
                    "title": "No high-priority findings detected",
                    "count": 0,
                    "recommendation": (
                        "Continue monitoring and retain audit records "
                        "according to the configured security policy."
                    ),
                }
            )

        return findings

    # =========================================================================
    # Miscellaneous helpers
    # =========================================================================

    def _normalize_event_type(
        self,
        event_type: Union[str, AuditEventType],
    ) -> str:
        if isinstance(event_type, AuditEventType):
            return event_type.value

        normalized = _normalize_key(event_type)

        if normalized in ALLOWED_EVENT_TYPES:
            return normalized

        return AuditEventType.CUSTOM.value

    def _severity_for_risk(
        self,
        risk_level: Union[str, AuditRiskLevel],
    ) -> AuditSeverity:
        normalized_risk = _safe_enum_value(
            AuditRiskLevel,
            risk_level,
            AuditRiskLevel.UNKNOWN,
        )

        mapping = {
            AuditRiskLevel.NONE.value: AuditSeverity.INFO,
            AuditRiskLevel.LOW.value: AuditSeverity.LOW,
            AuditRiskLevel.MEDIUM.value: AuditSeverity.MEDIUM,
            AuditRiskLevel.HIGH.value: AuditSeverity.HIGH,
            AuditRiskLevel.CRITICAL.value: AuditSeverity.CRITICAL,
            AuditRiskLevel.UNKNOWN.value: AuditSeverity.INFO,
        }

        return mapping.get(normalized_risk, AuditSeverity.INFO)

    # =========================================================================
    # Structured results
    # =========================================================================

    def _safe_result(
        self,
        *,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Required William compatibility hook.
        """

        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        *,
        message: str,
        error_code: str = "AUDIT_LOGGER_ERROR",
        exception: Optional[BaseException] = None,
        details: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Required William compatibility hook.
        """

        error: Dict[str, Any] = {
            "code": error_code,
            "message": message,
            "details": details or {},
        }

        if exception is not None:
            error["exception_type"] = exception.__class__.__name__
            error["exception_message"] = _safe_str(
                exception,
                2000,
            )

            if self.config.get("safe_debug_errors", False):
                error["traceback"] = traceback.format_exc()

        return {
            "success": False,
            "message": message,
            "data": {},
            "error": error,
            "metadata": metadata or {},
        }

    # =========================================================================
    # Registry, health, and Dashboard compatibility
    # =========================================================================

    def health_check(self) -> Dict[str, Any]:
        """
        Return AuditLogger health and backend status.
        """

        storage_writable = False
        storage_error: Optional[str] = None

        if self.config.get("enable_file_storage", True):
            try:
                self.storage_directory.mkdir(
                    parents=True,
                    exist_ok=True,
                )
                storage_writable = os.access(
                    self.storage_directory,
                    os.W_OK,
                )
            except OSError as exc:
                storage_error = str(exc)
        else:
            storage_writable = self.storage_provider is not None

        healthy = (
            storage_writable
            or self.storage_provider is not None
        )

        result_factory = (
            self._safe_result if healthy else self._error_result
        )

        if healthy:
            return result_factory(
                message="AuditLogger is healthy.",
                data={
                    "agent": self.agent_name,
                    "agent_type": self.agent_type,
                    "version": self.version,
                    "schema_version": AUDIT_SCHEMA_VERSION,
                    "file_storage_enabled": bool(
                        self.config.get(
                            "enable_file_storage",
                            True,
                        )
                    ),
                    "storage_provider_available": (
                        self.storage_provider is not None
                    ),
                    "storage_writable": storage_writable,
                    "hash_chain_enabled": bool(
                        self.config.get(
                            "enable_hash_chain",
                            True,
                        )
                    ),
                    "signatures_enabled": bool(
                        self.config.get(
                            "enable_hmac_signatures",
                            True,
                        )
                        and self._signing_key is not None
                    ),
                    "security_provider_available": (
                        self.security_provider is not None
                    ),
                },
            )

        return result_factory(
            message="AuditLogger storage is unavailable.",
            error_code="AUDIT_STORAGE_UNAVAILABLE",
            details={"storage_error": storage_error},
        )

    def get_capabilities(self) -> Dict[str, Any]:
        """
        Capability manifest for Agent Registry, Loader, Router, and Master Agent.
        """

        return self._safe_result(
            message="AuditLogger capabilities loaded.",
            data={
                "name": self.agent_name,
                "type": self.agent_type,
                "version": self.version,
                "schema_version": AUDIT_SCHEMA_VERSION,
                "public_methods": [
                    "log_event",
                    "log_sensitive_request",
                    "log_approval",
                    "log_denial",
                    "log_block",
                    "log_biometric_attempt",
                    "log_report",
                    "query_events",
                    "get_event",
                    "get_statistics",
                    "generate_report",
                    "export_events",
                    "verify_integrity",
                    "purge_expired_records",
                    "health_check",
                    "get_capabilities",
                ],
                "event_types": sorted(ALLOWED_EVENT_TYPES),
                "features": {
                    "saas_isolation": True,
                    "append_only_storage": True,
                    "recursive_redaction": True,
                    "biometric_privacy": True,
                    "hash_chain": True,
                    "optional_hmac_signatures": True,
                    "dashboard_statistics": True,
                    "structured_reports": True,
                    "tenant_scoped_export": True,
                    "retention_cleanup": True,
                    "integrity_verification": True,
                },
                "required_context": [
                    "user_id",
                    "workspace_id",
                ],
                "protected_operations": [
                    "export_events",
                    "purge_expired_records",
                    "cross_workspace_query",
                    "delete_audit_records",
                    "modify_audit_records",
                ],
                "result_format": {
                    "success": "bool",
                    "message": "str",
                    "data": "dict",
                    "error": "dict|null",
                    "metadata": "dict",
                },
            },
        )


# =============================================================================
# Factory
# =============================================================================

def create_audit_logger(
    storage_directory: Optional[Union[str, Path]] = None,
    storage_provider: Optional[Any] = None,
    security_provider: Optional[Any] = None,
    event_emitter: Optional[Callable[[Dict[str, Any]], None]] = None,
    memory_sink: Optional[Callable[[Dict[str, Any]], Any]] = None,
    verification_sink: Optional[
        Callable[[Dict[str, Any]], Any]
    ] = None,
    signing_key: Optional[Union[str, bytes]] = None,
    config: Optional[Dict[str, Any]] = None,
) -> AuditLogger:
    """
    Factory for Agent Loader, Registry, FastAPI dependency injection, or tests.
    """

    return AuditLogger(
        storage_directory=storage_directory,
        storage_provider=storage_provider,
        security_provider=security_provider,
        event_emitter=event_emitter,
        memory_sink=memory_sink,
        verification_sink=verification_sink,
        signing_key=signing_key,
        config=config,
    )


__all__ = [
    "AuditLogger",
    "AuditContext",
    "AuditRecord",
    "AuditQuery",
    "AuditEventType",
    "AuditOutcome",
    "AuditSeverity",
    "AuditRiskLevel",
    "BiometricMethod",
    "BiometricOutcome",
    "create_audit_logger",
]