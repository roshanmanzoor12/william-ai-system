"""
agents/security_agent/anomaly_detector.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Detect unusual devices, voice patterns, command behavior, failed attempts,
    and mass export activity across SaaS users and workspaces.

Security priorities:
    1. Safety and permission enforcement.
    2. Strict SaaS user/workspace isolation.
    3. BaseAgent compatibility.
    4. Master Agent, Agent Registry, Agent Loader, and Agent Router support.
    5. Detection accuracy and explainable anomaly scoring.
    6. Future integrations and upgrades.

This module is intentionally import-safe. It provides fallback implementations
when other William/Jarvis modules have not yet been created.

The detector does not directly block users, devices, sessions, exports, calls,
payments, files, browsers, or system actions. It produces structured risk and
recommendation results that the Security Agent, Policy Engine, Session Guard,
Device Access module, Approval Manager, Emergency Lock, or Master Agent can use.

Main detections:
    - Unknown or unusual devices.
    - Device fingerprint changes.
    - Impossible or unusual location movement.
    - Voice identity mismatch.
    - Voice replay/spoof indicators.
    - Abnormal command frequency.
    - New privileged or destructive commands.
    - Repeated command sequences.
    - Repeated authentication or authorization failures.
    - Distributed failed attempts.
    - Mass file, memory, client, project, or data exports.
    - Sudden behavioral deviations from established user/workspace baselines.

Storage:
    The default implementation uses a local JSON file with atomic writes and
    thread locking. It can later be replaced by PostgreSQL, Redis, Elasticsearch,
    ClickHouse, or another persistence layer while preserving the public API.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import math
import os
import re
import statistics
import threading
import uuid
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import (
    Any,
    Callable,
    DefaultDict,
    Dict,
    Iterable,
    List,
    Literal,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
)


# =============================================================================
# Safe optional William/Jarvis imports
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Import-safe fallback BaseAgent.

        The production BaseAgent may later provide lifecycle management,
        permissions, metrics, routing, events, health checks, and registry hooks.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get(
                "agent_id",
                self.__class__.__name__.lower(),
            )


try:
    from agents.security_agent.security_agent import SecurityAgent  # type: ignore
except Exception:  # pragma: no cover
    SecurityAgent = None  # type: ignore


try:
    from agents.verification_agent.verification_agent import (  # type: ignore
        VerificationAgent,
    )
except Exception:  # pragma: no cover
    VerificationAgent = None  # type: ignore


try:
    from agents.security_agent.audit_logger import AuditLogger  # type: ignore
except Exception:  # pragma: no cover
    AuditLogger = None  # type: ignore


try:
    from agents.security_agent.risk_engine import RiskEngine  # type: ignore
except Exception:  # pragma: no cover
    RiskEngine = None  # type: ignore


# =============================================================================
# Logging
# =============================================================================

LOGGER = logging.getLogger("william.security_agent.anomaly_detector")

if not LOGGER.handlers:
    logging.basicConfig(
        level=os.getenv("WILLIAM_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


# =============================================================================
# Type aliases
# =============================================================================

AnomalyType = Literal[
    "unusual_device",
    "device_fingerprint_change",
    "unusual_location",
    "impossible_travel",
    "voice_identity_mismatch",
    "voice_spoof_suspected",
    "unusual_voice_pattern",
    "unusual_command",
    "command_frequency_spike",
    "privileged_command_change",
    "repeated_command_pattern",
    "failed_attempt_spike",
    "distributed_failed_attempts",
    "mass_export",
    "export_frequency_spike",
    "behavioral_deviation",
]

Severity = Literal["info", "low", "medium", "high", "critical"]
RiskDecision = Literal[
    "allow",
    "allow_with_monitoring",
    "challenge",
    "require_approval",
    "deny",
    "emergency_lock_recommended",
]
EventType = Literal[
    "device",
    "voice",
    "command",
    "failed_attempt",
    "export",
    "generic",
]
AnomalyStatus = Literal[
    "open",
    "acknowledged",
    "investigating",
    "resolved",
    "false_positive",
]
BaselineStatus = Literal["learning", "established"]


# =============================================================================
# Constants and defaults
# =============================================================================

DEFAULT_STORAGE_DIRECTORY = Path(
    os.getenv(
        "WILLIAM_SECURITY_STORAGE_DIR",
        str(Path.cwd() / ".william_security"),
    )
)

DEFAULT_STORAGE_FILE = DEFAULT_STORAGE_DIRECTORY / "anomaly_detector.json"

SAFE_IDENTIFIER_PATTERN = re.compile(r"^[a-zA-Z0-9_.:@\-]+$")

SENSITIVE_FIELDS: Set[str] = {
    "password",
    "passcode",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "authorization",
    "api_key",
    "apikey",
    "private_key",
    "session_cookie",
    "cookie",
    "voice_audio",
    "raw_audio",
    "biometric_template",
    "credit_card",
    "card_number",
    "cvv",
    "cnic",
    "ssn",
    "passport",
}

PRIVILEGED_COMMAND_KEYWORDS: Tuple[str, ...] = (
    "delete",
    "drop",
    "destroy",
    "remove all",
    "wipe",
    "shutdown",
    "restart",
    "sudo",
    "root",
    "admin",
    "grant permission",
    "change role",
    "disable security",
    "bypass",
    "export all",
    "download all",
    "send payment",
    "transfer money",
    "deploy production",
    "force push",
    "rotate secret",
    "revoke access",
    "unlock",
)

DESTRUCTIVE_COMMAND_KEYWORDS: Tuple[str, ...] = (
    "delete",
    "destroy",
    "wipe",
    "drop database",
    "truncate",
    "format disk",
    "remove all",
    "kill process",
    "shutdown",
    "factory reset",
    "force push",
)

EXPORT_OBJECT_KEYWORDS: Tuple[str, ...] = (
    "export",
    "download",
    "backup",
    "archive",
    "dump",
    "extract",
)

DEFAULT_THRESHOLDS: Dict[str, Any] = {
    "baseline_minimum_events": 5,
    "history_retention_days": 30,
    "max_events_per_tenant": 10000,
    "max_anomalies_per_tenant": 5000,

    # Device detection
    "new_device_base_score": 45.0,
    "device_fingerprint_change_score": 55.0,
    "unusual_location_score": 35.0,
    "impossible_travel_score": 80.0,
    "impossible_travel_speed_kmh": 1000.0,
    "trusted_device_learning_count": 3,
    "trusted_location_learning_count": 3,

    # Voice detection
    "voice_similarity_warning_threshold": 0.78,
    "voice_similarity_critical_threshold": 0.55,
    "voice_mismatch_base_score": 65.0,
    "voice_spoof_base_score": 80.0,
    "voice_liveness_minimum": 0.65,
    "voice_replay_score_threshold": 0.70,
    "voice_baseline_deviation_zscore": 3.0,

    # Command detection
    "command_window_minutes": 5,
    "command_frequency_warning": 20,
    "command_frequency_critical": 50,
    "command_frequency_spike_score": 55.0,
    "new_privileged_command_score": 65.0,
    "destructive_command_score": 75.0,
    "repeated_command_count": 8,
    "repeated_command_score": 40.0,
    "command_length_maximum": 10000,

    # Failed attempt detection
    "failed_attempt_window_minutes": 10,
    "failed_attempt_warning": 5,
    "failed_attempt_high": 10,
    "failed_attempt_critical": 20,
    "distributed_source_threshold": 4,
    "failed_attempt_base_score": 45.0,
    "distributed_failed_attempt_score": 70.0,

    # Export detection
    "export_window_minutes": 15,
    "export_record_warning": 1000,
    "export_record_high": 10000,
    "export_record_critical": 100000,
    "export_byte_warning": 100 * 1024 * 1024,
    "export_byte_high": 1024 * 1024 * 1024,
    "export_byte_critical": 10 * 1024 * 1024 * 1024,
    "export_operation_warning": 5,
    "export_operation_high": 15,
    "mass_export_base_score": 65.0,

    # Decisions
    "monitoring_score": 20.0,
    "challenge_score": 45.0,
    "approval_score": 65.0,
    "deny_score": 85.0,
    "emergency_lock_score": 95.0,
}

SEVERITY_ORDER: Dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


# =============================================================================
# Utility functions
# =============================================================================

def utc_now() -> datetime:
    """Return the current timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    """Return the current UTC timestamp in ISO 8601 format."""
    return utc_now().isoformat()


def parse_datetime(value: Any, default: Optional[datetime] = None) -> datetime:
    """
    Safely parse datetime values.

    Accepted inputs:
        - timezone-aware or naive datetime
        - ISO 8601 string
        - Unix timestamp in seconds
        - None
    """
    fallback = default or utc_now()

    if value is None:
        return fallback

    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, (int, float)):
        parsed = datetime.fromtimestamp(float(value), tz=timezone.utc)
    elif isinstance(value, str):
        cleaned = value.strip()
        if not cleaned:
            return fallback

        if cleaned.endswith("Z"):
            cleaned = cleaned[:-1] + "+00:00"

        try:
            parsed = datetime.fromisoformat(cleaned)
        except ValueError:
            try:
                parsed = datetime.fromtimestamp(float(cleaned), tz=timezone.utc)
            except (TypeError, ValueError, OverflowError):
                return fallback
    else:
        return fallback

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def clamp(value: float, minimum: float = 0.0, maximum: float = 100.0) -> float:
    """Clamp a numeric value to an inclusive range."""
    return max(minimum, min(maximum, float(value)))


def safe_float(value: Any, default: float = 0.0) -> float:
    """Convert a value to float safely."""
    try:
        converted = float(value)
        if math.isnan(converted) or math.isinf(converted):
            return default
        return converted
    except (TypeError, ValueError, OverflowError):
        return default


def safe_int(value: Any, default: int = 0) -> int:
    """Convert a value to int safely."""
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default


def safe_json_dumps(value: Any) -> str:
    """Serialize a value for logging without crashing."""
    try:
        return json.dumps(value, ensure_ascii=False, default=str)
    except Exception:
        return str(value)


def normalize_text(value: Any, maximum_length: int = 10000) -> str:
    """Normalize text for command and identity comparisons."""
    text = str(value or "").strip().lower()
    text = re.sub(r"\s+", " ", text)
    return text[:maximum_length]


def hash_value(value: Any) -> str:
    """
    Create a deterministic SHA-256 digest.

    Used for privacy-preserving device, source, and command identifiers.
    """
    normalized = safe_json_dumps(value)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def create_id(prefix: str) -> str:
    """Create a prefixed unique identifier."""
    return f"{prefix}_{uuid.uuid4().hex}"


def is_safe_identifier(value: Any) -> bool:
    """Validate SaaS identifiers used for isolation."""
    if not isinstance(value, str):
        return False

    cleaned = value.strip()
    if not cleaned or len(cleaned) > 255:
        return False

    return bool(SAFE_IDENTIFIER_PATTERN.fullmatch(cleaned))


def deep_merge(
    base: Mapping[str, Any],
    override: Mapping[str, Any],
) -> Dict[str, Any]:
    """Recursively merge mappings without mutating either input."""
    result = copy.deepcopy(dict(base))

    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(result.get(key), Mapping):
            result[key] = deep_merge(
                dict(result[key]),
                dict(value),
            )
        else:
            result[key] = copy.deepcopy(value)

    return result


def redact_sensitive_data(value: Any) -> Any:
    """
    Recursively redact sensitive fields before logging or returning evidence.
    """
    if isinstance(value, Mapping):
        redacted: Dict[str, Any] = {}

        for key, item in value.items():
            normalized_key = str(key).strip().lower()

            if normalized_key in SENSITIVE_FIELDS or any(
                sensitive in normalized_key
                for sensitive in SENSITIVE_FIELDS
            ):
                redacted[str(key)] = "***REDACTED***"
            else:
                redacted[str(key)] = redact_sensitive_data(item)

        return redacted

    if isinstance(value, list):
        return [redact_sensitive_data(item) for item in value]

    if isinstance(value, tuple):
        return tuple(redact_sensitive_data(item) for item in value)

    return value


def severity_from_score(score: float) -> Severity:
    """Map a numeric risk score to an anomaly severity."""
    score = clamp(score)

    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "info"


def maximum_severity(severities: Iterable[Severity]) -> Severity:
    """Return the highest severity from an iterable."""
    values = list(severities)

    if not values:
        return "info"

    return max(values, key=lambda item: SEVERITY_ORDER[item])


def haversine_distance_km(
    latitude_one: float,
    longitude_one: float,
    latitude_two: float,
    longitude_two: float,
) -> float:
    """Calculate approximate great-circle distance in kilometers."""
    radius_km = 6371.0088

    lat1 = math.radians(latitude_one)
    lon1 = math.radians(longitude_one)
    lat2 = math.radians(latitude_two)
    lon2 = math.radians(longitude_two)

    delta_lat = lat2 - lat1
    delta_lon = lon2 - lon1

    a = (
        math.sin(delta_lat / 2) ** 2
        + math.cos(lat1)
        * math.cos(lat2)
        * math.sin(delta_lon / 2) ** 2
    )

    c = 2 * math.atan2(math.sqrt(a), math.sqrt(max(0.0, 1 - a)))
    return radius_km * c


def calculate_z_score(
    value: float,
    samples: Sequence[float],
) -> float:
    """
    Calculate an absolute z-score.

    Returns 0 when there is insufficient variance or insufficient history.
    """
    valid_samples = [
        safe_float(sample)
        for sample in samples
        if isinstance(sample, (int, float))
    ]

    if len(valid_samples) < 2:
        return 0.0

    mean = statistics.fmean(valid_samples)
    deviation = statistics.pstdev(valid_samples)

    if deviation <= 0:
        return 0.0 if value == mean else 10.0

    return abs((value - mean) / deviation)


def fingerprint_device(device: Mapping[str, Any]) -> str:
    """
    Build a privacy-aware stable device fingerprint.

    Raw secrets, cookies, tokens, and full IP addresses are not required.
    """
    explicit_fingerprint = str(
        device.get("fingerprint")
        or device.get("device_fingerprint")
        or ""
    ).strip()

    if explicit_fingerprint:
        return hash_value(explicit_fingerprint)

    source = {
        "device_id": device.get("device_id"),
        "platform": device.get("platform"),
        "os": device.get("os"),
        "os_version": device.get("os_version"),
        "browser": device.get("browser"),
        "browser_version": device.get("browser_version"),
        "app_version": device.get("app_version"),
        "model": device.get("model"),
        "manufacturer": device.get("manufacturer"),
        "screen_resolution": device.get("screen_resolution"),
        "timezone": device.get("timezone"),
        "language": device.get("language"),
    }

    return hash_value(source)


def normalize_command(command: Any) -> str:
    """Normalize command text for behavioral comparisons."""
    text = normalize_text(command)

    # Replace long identifiers and numeric values so repeated commands are
    # detected without storing exact potentially sensitive arguments.
    text = re.sub(r"\b[0-9a-f]{16,}\b", "<identifier>", text)
    text = re.sub(r"\b\d{4,}\b", "<number>", text)
    text = re.sub(
        r"[\w.\-+]+@[\w.\-]+\.[a-zA-Z]{2,}",
        "<email>",
        text,
    )

    return text


def command_signature(command: Any) -> str:
    """Generate a privacy-preserving command signature."""
    return hash_value(normalize_command(command))


def source_signature(source: Any) -> str:
    """Generate a privacy-preserving source identifier."""
    if source is None:
        return "unknown"
    return hash_value(str(source).strip().lower())


# =============================================================================
# Dataclasses
# =============================================================================

@dataclass
class TaskContext:
    """
    Tenant-isolated execution context.

    user_id and workspace_id are mandatory for every user-specific operation.
    """

    user_id: str
    workspace_id: str
    request_id: str = field(default_factory=lambda: create_id("request"))
    session_id: Optional[str] = None
    device_id: Optional[str] = None
    role: Optional[str] = None
    subscription_tier: Optional[str] = None
    source_agent: Optional[str] = None
    source: str = "anomaly_detector"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityEvent:
    """Normalized security event accepted by the detector."""

    event_id: str
    event_type: EventType
    user_id: str
    workspace_id: str
    timestamp: str
    action: Optional[str] = None
    success: Optional[bool] = None
    source_agent: Optional[str] = None
    session_id: Optional[str] = None
    device_id: Optional[str] = None
    request_id: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AnomalyEvidence:
    """Explainable evidence supporting one detected anomaly."""

    code: str
    description: str
    observed: Any = None
    expected: Any = None
    weight: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AnomalyRecord:
    """Persistent anomaly result."""

    anomaly_id: str
    anomaly_type: AnomalyType
    user_id: str
    workspace_id: str
    event_id: str
    score: float
    severity: Severity
    decision: RiskDecision
    title: str
    description: str
    evidence: List[Dict[str, Any]]
    status: AnomalyStatus = "open"
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)
    acknowledged_at: Optional[str] = None
    acknowledged_by: Optional[str] = None
    resolution_note: Optional[str] = None
    false_positive: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BehaviorBaseline:
    """
    User/workspace-specific rolling behavior baseline.

    Baselines remain isolated by tenant and user. They never combine data from
    unrelated users or workspaces.
    """

    user_id: str
    workspace_id: str
    status: BaselineStatus = "learning"
    event_count: int = 0

    trusted_devices: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    known_locations: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    voice_similarity_samples: List[float] = field(default_factory=list)
    voice_liveness_samples: List[float] = field(default_factory=list)
    voice_feature_samples: Dict[str, List[float]] = field(default_factory=dict)

    command_signatures: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    command_rate_samples: List[float] = field(default_factory=list)
    command_hour_histogram: Dict[str, int] = field(default_factory=dict)

    failed_attempt_rate_samples: List[float] = field(default_factory=list)

    export_record_samples: List[float] = field(default_factory=list)
    export_byte_samples: List[float] = field(default_factory=list)
    export_operation_samples: List[float] = field(default_factory=list)

    last_device_location: Optional[Dict[str, Any]] = None
    last_seen_at: Optional[str] = None
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DetectionResult:
    """Internal result returned by a specialized detector."""

    anomaly_type: AnomalyType
    detected: bool
    score: float
    severity: Severity
    title: str
    description: str
    evidence: List[AnomalyEvidence] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# JSON persistence layer
# =============================================================================

class AnomalyStorage:
    """
    Thread-safe JSON persistence for events, anomalies, baselines, and config.

    Writes are atomic through a temporary file replacement. Corrupted storage
    is backed up and replaced with a clean structure.
    """

    SCHEMA_VERSION = 1

    def __init__(
        self,
        storage_file: Union[str, Path] = DEFAULT_STORAGE_FILE,
    ) -> None:
        self.storage_file = Path(storage_file)
        self.storage_file.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._ensure_storage()

    def _default_data(self) -> Dict[str, Any]:
        now = utc_now_iso()

        return {
            "schema_version": self.SCHEMA_VERSION,
            "created_at": now,
            "updated_at": now,
            "tenant_data": {},
            "configuration": {
                "thresholds": copy.deepcopy(DEFAULT_THRESHOLDS),
            },
        }

    def _ensure_storage(self) -> None:
        """Create storage safely when it does not exist."""
        with self._lock:
            if self.storage_file.exists():
                return

            self._atomic_write(self._default_data())

    def _atomic_write(self, data: Mapping[str, Any]) -> None:
        """Write JSON atomically."""
        temporary_file = self.storage_file.with_suffix(
            self.storage_file.suffix + ".tmp"
        )

        temporary_file.write_text(
            json.dumps(
                data,
                ensure_ascii=False,
                indent=2,
                default=str,
            ),
            encoding="utf-8",
        )

        temporary_file.replace(self.storage_file)

    def load(self) -> Dict[str, Any]:
        """Load and validate storage."""
        with self._lock:
            self._ensure_storage()

            try:
                raw = self.storage_file.read_text(encoding="utf-8")
                data = json.loads(raw or "{}")

                if not isinstance(data, dict):
                    raise ValueError("Storage root must be a JSON object.")

                data.setdefault("schema_version", self.SCHEMA_VERSION)
                data.setdefault("created_at", utc_now_iso())
                data.setdefault("updated_at", utc_now_iso())
                data.setdefault("tenant_data", {})
                data.setdefault(
                    "configuration",
                    {"thresholds": copy.deepcopy(DEFAULT_THRESHOLDS)},
                )

                if not isinstance(data["tenant_data"], dict):
                    data["tenant_data"] = {}

                if not isinstance(data["configuration"], dict):
                    data["configuration"] = {
                        "thresholds": copy.deepcopy(DEFAULT_THRESHOLDS)
                    }

                stored_thresholds = data["configuration"].get(
                    "thresholds",
                    {},
                )

                data["configuration"]["thresholds"] = deep_merge(
                    DEFAULT_THRESHOLDS,
                    stored_thresholds
                    if isinstance(stored_thresholds, Mapping)
                    else {},
                )

                return data

            except Exception as exc:
                corrupted_file = self.storage_file.with_suffix(
                    f".corrupt.{int(utc_now().timestamp())}.json"
                )

                try:
                    self.storage_file.replace(corrupted_file)
                except Exception:
                    LOGGER.exception(
                        "Could not preserve corrupted anomaly storage."
                    )

                LOGGER.exception(
                    "Anomaly storage was invalid and has been recreated: %s",
                    exc,
                )

                clean_data = self._default_data()
                clean_data["recovered_from_corruption"] = True
                clean_data["corruption_error"] = str(exc)
                self._atomic_write(clean_data)
                return clean_data

    def save(self, data: MutableMapping[str, Any]) -> None:
        """Persist complete storage data."""
        with self._lock:
            data["updated_at"] = utc_now_iso()
            self._atomic_write(data)

    @staticmethod
    def tenant_key(user_id: str, workspace_id: str) -> str:
        """Create a tenant-isolated storage key."""
        return hash_value(
            {
                "user_id": user_id,
                "workspace_id": workspace_id,
            }
        )

    def get_tenant_data(
        self,
        user_id: str,
        workspace_id: str,
        create: bool = True,
    ) -> Dict[str, Any]:
        """Return isolated storage for one user/workspace."""
        with self._lock:
            data = self.load()
            key = self.tenant_key(user_id, workspace_id)
            tenant_data = data["tenant_data"].get(key)

            if tenant_data is None and create:
                tenant_data = {
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "events": [],
                    "anomalies": {},
                    "baseline": None,
                    "created_at": utc_now_iso(),
                    "updated_at": utc_now_iso(),
                }
                data["tenant_data"][key] = tenant_data
                self.save(data)

            return copy.deepcopy(tenant_data or {})

    def replace_tenant_data(
        self,
        user_id: str,
        workspace_id: str,
        tenant_data: Mapping[str, Any],
    ) -> None:
        """Replace one tenant's isolated data."""
        with self._lock:
            data = self.load()
            key = self.tenant_key(user_id, workspace_id)

            safe_tenant_data = copy.deepcopy(dict(tenant_data))
            safe_tenant_data["user_id"] = user_id
            safe_tenant_data["workspace_id"] = workspace_id
            safe_tenant_data["updated_at"] = utc_now_iso()

            data["tenant_data"][key] = safe_tenant_data
            self.save(data)

    def get_thresholds(self) -> Dict[str, Any]:
        """Return merged detection thresholds."""
        data = self.load()
        return deep_merge(
            DEFAULT_THRESHOLDS,
            data.get("configuration", {}).get("thresholds", {}),
        )

    def update_thresholds(
        self,
        updates: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Update global detector thresholds."""
        with self._lock:
            data = self.load()
            current = data["configuration"].get(
                "thresholds",
                copy.deepcopy(DEFAULT_THRESHOLDS),
            )
            merged = deep_merge(current, updates)
            data["configuration"]["thresholds"] = merged
            self.save(data)
            return copy.deepcopy(merged)


# =============================================================================
# Anomaly Detector
# =============================================================================

class AnomalyDetector(BaseAgent):
    """
    William/Jarvis behavior and security anomaly detector.

    Integration points:
        Master Agent:
            Calls analyze_event() or analyze_activity() before or after routing
            sensitive tasks.

        Security Agent:
            Consumes score, severity, decision, and recommendations to approve,
            challenge, deny, or escalate actions.

        Device Access:
            Uses unusual-device and impossible-travel detections.

        Biometric Gate / Voice Agent:
            Uses voice mismatch, spoof, liveness, and feature deviations.

        Permission Checker / Policy Engine:
            Uses command and failed-attempt anomalies.

        File Protection / Memory Agent:
            Uses mass-export and export-frequency anomalies.

        Verification Agent:
            Receives verification payloads describing each detection.

        Memory Agent:
            Receives privacy-safe behavioral memory payloads.

        Dashboard/API:
            Uses structured results, anomaly lists, statistics, and status
            management methods.

        Agent Registry / Loader / Router:
            Uses get_agent_manifest() and handle_task().
    """

    agent_name = "AnomalyDetector"
    agent_type = "security_agent_helper"
    version = "1.0.0"

    def __init__(
        self,
        storage_file: Union[str, Path] = DEFAULT_STORAGE_FILE,
        thresholds: Optional[Mapping[str, Any]] = None,
        security_agent: Any = None,
        verification_agent: Any = None,
        audit_logger: Any = None,
        risk_engine: Any = None,
        event_handler: Optional[
            Callable[[str, Dict[str, Any]], None]
        ] = None,
        strict_identifier_validation: bool = True,
        enable_audit_logs: bool = True,
        enable_agent_events: bool = True,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            agent_name=self.agent_name,
            agent_id="security_agent.anomaly_detector",
            *args,
            **kwargs,
        )

        self.storage = AnomalyStorage(storage_file)
        self.security_agent = (
            security_agent
            if security_agent is not None
            else self._build_optional_agent(SecurityAgent)
        )
        self.verification_agent = (
            verification_agent
            if verification_agent is not None
            else self._build_optional_agent(VerificationAgent)
        )
        self.audit_logger = (
            audit_logger
            if audit_logger is not None
            else self._build_optional_agent(AuditLogger)
        )
        self.risk_engine = (
            risk_engine
            if risk_engine is not None
            else self._build_optional_agent(RiskEngine)
        )

        self.event_handler = event_handler
        self.strict_identifier_validation = strict_identifier_validation
        self.enable_audit_logs = enable_audit_logs
        self.enable_agent_events = enable_agent_events
        self.logger = LOGGER
        self._operation_lock = threading.RLock()

        stored_thresholds = self.storage.get_thresholds()
        self.thresholds = deep_merge(
            stored_thresholds,
            thresholds or {},
        )

    # -------------------------------------------------------------------------
    # Optional imports and agents
    # -------------------------------------------------------------------------

    @staticmethod
    def _build_optional_agent(agent_class: Any) -> Any:
        """Instantiate an optional William agent safely."""
        if agent_class is None:
            return None

        try:
            return agent_class()
        except Exception:
            return None

    # -------------------------------------------------------------------------
    # Required compatibility hooks
    # -------------------------------------------------------------------------

    def _safe_result(
        self,
        success: bool = True,
        message: str = "",
        data: Optional[Dict[str, Any]] = None,
        error: Optional[Union[str, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create a standard William/Jarvis structured result."""
        return {
            "success": bool(success),
            "message": message or (
                "Operation completed successfully."
                if success
                else "Operation failed."
            ),
            "data": data or {},
            "error": error,
            "metadata": {
                "agent": self.agent_name,
                "agent_type": self.agent_type,
                "version": self.version,
                "timestamp": utc_now_iso(),
                **(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str,
        error: Optional[
            Union[str, Dict[str, Any], Exception]
        ] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create a standard William/Jarvis error result."""
        if isinstance(error, Exception):
            error_payload: Union[str, Dict[str, Any]] = {
                "type": error.__class__.__name__,
                "detail": str(error),
            }
        elif error is None:
            error_payload = message
        else:
            error_payload = error

        return self._safe_result(
            success=False,
            message=message,
            data={},
            error=error_payload,
            metadata=metadata,
        )

    def _validate_task_context(
        self,
        user_id: Optional[str],
        workspace_id: Optional[str],
        context: Optional[
            Union[TaskContext, Mapping[str, Any]]
        ] = None,
    ) -> Tuple[bool, Optional[TaskContext], Optional[str]]:
        """
        Validate and normalize strict SaaS execution context.
        """
        try:
            if isinstance(context, TaskContext):
                normalized_context = copy.deepcopy(context)
            elif isinstance(context, Mapping):
                normalized_context = TaskContext(
                    user_id=str(
                        context.get("user_id")
                        or user_id
                        or ""
                    ).strip(),
                    workspace_id=str(
                        context.get("workspace_id")
                        or workspace_id
                        or ""
                    ).strip(),
                    request_id=str(
                        context.get("request_id")
                        or create_id("request")
                    ),
                    session_id=(
                        str(context["session_id"])
                        if context.get("session_id") is not None
                        else None
                    ),
                    device_id=(
                        str(context["device_id"])
                        if context.get("device_id") is not None
                        else None
                    ),
                    role=(
                        str(context["role"])
                        if context.get("role") is not None
                        else None
                    ),
                    subscription_tier=(
                        str(context["subscription_tier"])
                        if context.get("subscription_tier") is not None
                        else None
                    ),
                    source_agent=(
                        str(context["source_agent"])
                        if context.get("source_agent") is not None
                        else None
                    ),
                    source=str(
                        context.get("source")
                        or "anomaly_detector"
                    ),
                    metadata=copy.deepcopy(
                        dict(context.get("metadata") or {})
                    ),
                )
            else:
                normalized_context = TaskContext(
                    user_id=str(user_id or "").strip(),
                    workspace_id=str(workspace_id or "").strip(),
                )

            if not normalized_context.user_id:
                return False, None, "user_id is required."

            if not normalized_context.workspace_id:
                return False, None, "workspace_id is required."

            if self.strict_identifier_validation:
                if not is_safe_identifier(normalized_context.user_id):
                    return False, None, "Invalid user_id format."

                if not is_safe_identifier(normalized_context.workspace_id):
                    return False, None, "Invalid workspace_id format."

                optional_identifiers = {
                    "request_id": normalized_context.request_id,
                    "session_id": normalized_context.session_id,
                    "device_id": normalized_context.device_id,
                }

                for field_name, value in optional_identifiers.items():
                    if value and not is_safe_identifier(value):
                        return (
                            False,
                            None,
                            f"Invalid {field_name} format.",
                        )

            return True, normalized_context, None

        except Exception as exc:
            return (
                False,
                None,
                f"Task context validation failed: {exc}",
            )

    def _requires_security_check(
        self,
        action: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Determine whether a detector management action requires approval.

        Normal anomaly analysis does not require recursive Security Agent
        approval because this class is already part of the Security Agent.
        Destructive state changes and threshold weakening do require approval.
        """
        normalized_action = normalize_text(action, 255)

        protected_actions = {
            "clear_tenant_history",
            "clear_all_history",
            "delete_anomaly",
            "reset_baseline",
            "disable_detection",
            "update_thresholds",
            "mark_false_positive",
        }

        if normalized_action in protected_actions:
            return True

        if payload and payload.get("destructive"):
            return True

        return False

    def _request_security_approval(
        self,
        action: str,
        context: TaskContext,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval for protected detector operations.

        The fallback policy permits safe tenant-local administrative changes
        while denying global destructive changes without a real Security Agent.
        """
        safe_payload = redact_sensitive_data(dict(payload or {}))

        security_methods = (
            "approve_action",
            "request_approval",
            "check_permission",
            "authorize",
        )

        if self.security_agent is not None:
            for method_name in security_methods:
                method = getattr(
                    self.security_agent,
                    method_name,
                    None,
                )

                if not callable(method):
                    continue

                try:
                    result = method(
                        action=action,
                        user_id=context.user_id,
                        workspace_id=context.workspace_id,
                        payload=safe_payload,
                        context=asdict(context),
                    )

                    if isinstance(result, Mapping):
                        approved = bool(
                            result.get(
                                "approved",
                                result.get("success", False),
                            )
                        )

                        return {
                            "approved": approved,
                            "message": str(
                                result.get("message")
                                or "Security approval processed."
                            ),
                            "data": copy.deepcopy(dict(result)),
                            "source": "security_agent",
                        }

                    return {
                        "approved": bool(result),
                        "message": "Security approval processed.",
                        "data": {},
                        "source": "security_agent",
                    }

                except TypeError:
                    try:
                        result = method(
                            action,
                            context.user_id,
                            context.workspace_id,
                            safe_payload,
                        )

                        return {
                            "approved": bool(
                                result.get("approved", result.get("success"))
                                if isinstance(result, Mapping)
                                else result
                            ),
                            "message": "Security approval processed.",
                            "data": (
                                copy.deepcopy(dict(result))
                                if isinstance(result, Mapping)
                                else {}
                            ),
                            "source": "security_agent",
                        }
                    except Exception:
                        continue
                except Exception:
                    continue

        if action in {"clear_all_history", "disable_detection"}:
            return {
                "approved": False,
                "message": (
                    "A connected Security Agent is required for global or "
                    "detection-disabling operations."
                ),
                "data": {},
                "source": "local_safe_policy",
            }

        return {
            "approved": True,
            "message": (
                "Approved by the local tenant-isolated detector policy."
            ),
            "data": {},
            "source": "local_safe_policy",
        }

    def _prepare_verification_payload(
        self,
        action: str,
        context: TaskContext,
        result_data: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare a Verification Agent-compatible payload.
        """
        safe_data = redact_sensitive_data(dict(result_data or {}))

        return {
            "verification_id": create_id("verification"),
            "verification_type": "security_anomaly_detection",
            "agent": self.agent_name,
            "agent_version": self.version,
            "action": action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "session_id": context.session_id,
            "result": safe_data,
            "required_checks": {
                "tenant_isolation": True,
                "risk_score_in_range": True,
                "explainable_evidence": True,
                "structured_result": True,
                "sensitive_data_redacted": True,
                "no_direct_destructive_action": True,
            },
            "created_at": utc_now_iso(),
        }

    def _prepare_memory_payload(
        self,
        action: str,
        context: TaskContext,
        anomaly_data: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare a privacy-safe Memory Agent payload.

        Raw voice audio, passwords, secrets, and sensitive authentication
        material are never included.
        """
        safe_anomaly_data = redact_sensitive_data(
            dict(anomaly_data or {})
        )

        return {
            "memory_id": create_id("memory"),
            "memory_type": "security_behavior",
            "memory_layer": "long_term",
            "agent": self.agent_name,
            "action": action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "content": safe_anomaly_data,
            "importance": (
                "high"
                if safe_anomaly_data.get("severity") in {
                    "high",
                    "critical",
                }
                else "medium"
            ),
            "privacy": "user_workspace_isolated",
            "retention_hint": "security_policy_controlled",
            "created_at": utc_now_iso(),
            "metadata": {
                "request_id": context.request_id,
                "session_id": context.session_id,
                "source_agent": context.source_agent,
            },
        }

    def _emit_agent_event(
        self,
        event_name: str,
        context: TaskContext,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Emit a privacy-safe event for dashboards, analytics, or event buses.
        """
        if not self.enable_agent_events:
            return

        event_payload = {
            "event_name": event_name,
            "agent": self.agent_name,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "timestamp": utc_now_iso(),
            "payload": redact_sensitive_data(dict(payload or {})),
        }

        if callable(self.event_handler):
            try:
                self.event_handler(event_name, event_payload)
                return
            except Exception:
                self.logger.exception(
                    "External anomaly event handler failed."
                )

        self.logger.info(
            "Agent event: %s",
            safe_json_dumps(event_payload),
        )

    def _log_audit_event(
        self,
        action: str,
        context: TaskContext,
        payload: Optional[Mapping[str, Any]] = None,
        success: bool = True,
        error: Optional[str] = None,
    ) -> None:
        """
        Write an audit event through AuditLogger when available.

        Falls back to structured application logging.
        """
        if not self.enable_audit_logs:
            return

        audit_payload = {
            "audit_id": create_id("audit"),
            "action": action,
            "agent": self.agent_name,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "session_id": context.session_id,
            "success": bool(success),
            "error": error,
            "payload": redact_sensitive_data(dict(payload or {})),
            "timestamp": utc_now_iso(),
        }

        if self.audit_logger is not None:
            for method_name in (
                "log_event",
                "write",
                "record",
                "log",
            ):
                method = getattr(self.audit_logger, method_name, None)

                if not callable(method):
                    continue

                try:
                    method(audit_payload)
                    return
                except TypeError:
                    try:
                        method(
                            action=action,
                            user_id=context.user_id,
                            workspace_id=context.workspace_id,
                            data=audit_payload,
                        )
                        return
                    except Exception:
                        continue
                except Exception:
                    continue

        self.logger.info(
            "Security audit: %s",
            safe_json_dumps(audit_payload),
        )

    # -------------------------------------------------------------------------
    # Context and event normalization
    # -------------------------------------------------------------------------

    def _normalize_event(
        self,
        event: Mapping[str, Any],
        context: TaskContext,
        expected_type: Optional[EventType] = None,
    ) -> SecurityEvent:
        """Normalize and validate an incoming security event."""
        if not isinstance(event, Mapping):
            raise TypeError("event must be a mapping.")

        supplied_user_id = event.get("user_id")
        supplied_workspace_id = event.get("workspace_id")

        if (
            supplied_user_id is not None
            and str(supplied_user_id) != context.user_id
        ):
            raise ValueError(
                "Event user_id does not match the validated task context."
            )

        if (
            supplied_workspace_id is not None
            and str(supplied_workspace_id) != context.workspace_id
        ):
            raise ValueError(
                "Event workspace_id does not match the validated task context."
            )

        raw_type = normalize_text(
            event.get("event_type")
            or event.get("type")
            or expected_type
            or "generic",
            100,
        )

        allowed_types: Set[str] = {
            "device",
            "voice",
            "command",
            "failed_attempt",
            "export",
            "generic",
        }

        if raw_type not in allowed_types:
            raise ValueError(f"Unsupported event_type: {raw_type}")

        if expected_type and raw_type != expected_type:
            raise ValueError(
                f"Expected event_type '{expected_type}', received '{raw_type}'."
            )

        timestamp = parse_datetime(
            event.get("timestamp"),
            default=utc_now(),
        ).isoformat()

        raw_data = event.get("data")
        if raw_data is None:
            reserved_fields = {
                "event_id",
                "event_type",
                "type",
                "user_id",
                "workspace_id",
                "timestamp",
                "action",
                "success",
                "source_agent",
                "session_id",
                "device_id",
                "request_id",
                "metadata",
            }
            raw_data = {
                str(key): copy.deepcopy(value)
                for key, value in event.items()
                if key not in reserved_fields
            }

        if not isinstance(raw_data, Mapping):
            raise ValueError("event.data must be a mapping.")

        metadata = event.get("metadata") or {}

        if not isinstance(metadata, Mapping):
            raise ValueError("event.metadata must be a mapping.")

        return SecurityEvent(
            event_id=str(
                event.get("event_id")
                or create_id("event")
            ),
            event_type=raw_type,  # type: ignore[arg-type]
            user_id=context.user_id,
            workspace_id=context.workspace_id,
            timestamp=timestamp,
            action=(
                str(event["action"])
                if event.get("action") is not None
                else None
            ),
            success=(
                bool(event["success"])
                if event.get("success") is not None
                else None
            ),
            source_agent=(
                str(event.get("source_agent"))
                if event.get("source_agent") is not None
                else context.source_agent
            ),
            session_id=(
                str(event.get("session_id"))
                if event.get("session_id") is not None
                else context.session_id
            ),
            device_id=(
                str(event.get("device_id"))
                if event.get("device_id") is not None
                else context.device_id
            ),
            request_id=(
                str(event.get("request_id"))
                if event.get("request_id") is not None
                else context.request_id
            ),
            data=copy.deepcopy(dict(raw_data)),
            metadata=copy.deepcopy(dict(metadata)),
        )

    # -------------------------------------------------------------------------
    # Baseline persistence
    # -------------------------------------------------------------------------

    def _baseline_from_dict(
        self,
        user_id: str,
        workspace_id: str,
        data: Optional[Mapping[str, Any]],
    ) -> BehaviorBaseline:
        """Create a baseline object from storage."""
        if not data:
            return BehaviorBaseline(
                user_id=user_id,
                workspace_id=workspace_id,
            )

        return BehaviorBaseline(
            user_id=user_id,
            workspace_id=workspace_id,
            status=str(
                data.get("status")
                or "learning"
            ),  # type: ignore[arg-type]
            event_count=safe_int(data.get("event_count"), 0),
            trusted_devices=copy.deepcopy(
                dict(data.get("trusted_devices") or {})
            ),
            known_locations=copy.deepcopy(
                dict(data.get("known_locations") or {})
            ),
            voice_similarity_samples=[
                safe_float(value)
                for value in data.get("voice_similarity_samples", [])
            ],
            voice_liveness_samples=[
                safe_float(value)
                for value in data.get("voice_liveness_samples", [])
            ],
            voice_feature_samples={
                str(key): [
                    safe_float(value)
                    for value in values
                ]
                for key, values in dict(
                    data.get("voice_feature_samples") or {}
                ).items()
                if isinstance(values, list)
            },
            command_signatures=copy.deepcopy(
                dict(data.get("command_signatures") or {})
            ),
            command_rate_samples=[
                safe_float(value)
                for value in data.get("command_rate_samples", [])
            ],
            command_hour_histogram={
                str(key): safe_int(value)
                for key, value in dict(
                    data.get("command_hour_histogram") or {}
                ).items()
            },
            failed_attempt_rate_samples=[
                safe_float(value)
                for value in data.get(
                    "failed_attempt_rate_samples",
                    [],
                )
            ],
            export_record_samples=[
                safe_float(value)
                for value in data.get("export_record_samples", [])
            ],
            export_byte_samples=[
                safe_float(value)
                for value in data.get("export_byte_samples", [])
            ],
            export_operation_samples=[
                safe_float(value)
                for value in data.get(
                    "export_operation_samples",
                    [],
                )
            ],
            last_device_location=copy.deepcopy(
                data.get("last_device_location")
            ),
            last_seen_at=data.get("last_seen_at"),
            created_at=str(
                data.get("created_at")
                or utc_now_iso()
            ),
            updated_at=str(
                data.get("updated_at")
                or utc_now_iso()
            ),
            metadata=copy.deepcopy(
                dict(data.get("metadata") or {})
            ),
        )

    def _load_baseline(
        self,
        context: TaskContext,
    ) -> BehaviorBaseline:
        """Load one isolated baseline."""
        tenant_data = self.storage.get_tenant_data(
            context.user_id,
            context.workspace_id,
            create=True,
        )

        return self._baseline_from_dict(
            context.user_id,
            context.workspace_id,
            tenant_data.get("baseline"),
        )

    def _save_baseline(
        self,
        context: TaskContext,
        baseline: BehaviorBaseline,
    ) -> None:
        """Persist one isolated baseline."""
        tenant_data = self.storage.get_tenant_data(
            context.user_id,
            context.workspace_id,
            create=True,
        )

        baseline.updated_at = utc_now_iso()
        tenant_data["baseline"] = asdict(baseline)

        self.storage.replace_tenant_data(
            context.user_id,
            context.workspace_id,
            tenant_data,
        )

    # -------------------------------------------------------------------------
    # Event and anomaly persistence
    # -------------------------------------------------------------------------

    def _store_event(
        self,
        context: TaskContext,
        event: SecurityEvent,
    ) -> None:
        """Persist a sanitized tenant-isolated event."""
        tenant_data = self.storage.get_tenant_data(
            context.user_id,
            context.workspace_id,
            create=True,
        )

        events = list(tenant_data.get("events") or [])
        event_payload = asdict(event)
        event_payload["data"] = redact_sensitive_data(event_payload["data"])
        event_payload["metadata"] = redact_sensitive_data(
            event_payload["metadata"]
        )

        events.append(event_payload)

        maximum = safe_int(
            self.thresholds.get("max_events_per_tenant"),
            10000,
        )

        if maximum > 0 and len(events) > maximum:
            events = events[-maximum:]

        tenant_data["events"] = events

        self.storage.replace_tenant_data(
            context.user_id,
            context.workspace_id,
            tenant_data,
        )

    def _store_anomaly(
        self,
        context: TaskContext,
        anomaly: AnomalyRecord,
    ) -> None:
        """Persist one tenant-isolated anomaly record."""
        tenant_data = self.storage.get_tenant_data(
            context.user_id,
            context.workspace_id,
            create=True,
        )

        anomalies = dict(tenant_data.get("anomalies") or {})
        anomalies[anomaly.anomaly_id] = redact_sensitive_data(
            asdict(anomaly)
        )

        maximum = safe_int(
            self.thresholds.get("max_anomalies_per_tenant"),
            5000,
        )

        if maximum > 0 and len(anomalies) > maximum:
            ordered = sorted(
                anomalies.items(),
                key=lambda item: parse_datetime(
                    item[1].get("created_at")
                ),
            )

            overflow = len(ordered) - maximum

            for anomaly_id, _ in ordered[:overflow]:
                anomalies.pop(anomaly_id, None)

        tenant_data["anomalies"] = anomalies

        self.storage.replace_tenant_data(
            context.user_id,
            context.workspace_id,
            tenant_data,
        )

    def _recent_events(
        self,
        context: TaskContext,
        event_type: Optional[EventType] = None,
        since: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """Read recent events within one isolated tenant."""
        tenant_data = self.storage.get_tenant_data(
            context.user_id,
            context.workspace_id,
            create=True,
        )

        events = list(tenant_data.get("events") or [])
        filtered: List[Dict[str, Any]] = []

        for event in events:
            if event_type and event.get("event_type") != event_type:
                continue

            timestamp = parse_datetime(event.get("timestamp"))

            if since and timestamp < since:
                continue

            filtered.append(copy.deepcopy(event))

        return filtered

    # -------------------------------------------------------------------------
    # Risk decision helpers
    # -------------------------------------------------------------------------

    def _decision_from_score(
        self,
        score: float,
    ) -> RiskDecision:
        """Map score to a recommended Security Agent decision."""
        score = clamp(score)

        emergency_threshold = safe_float(
            self.thresholds.get("emergency_lock_score"),
            95.0,
        )
        deny_threshold = safe_float(
            self.thresholds.get("deny_score"),
            85.0,
        )
        approval_threshold = safe_float(
            self.thresholds.get("approval_score"),
            65.0,
        )
        challenge_threshold = safe_float(
            self.thresholds.get("challenge_score"),
            45.0,
        )
        monitoring_threshold = safe_float(
            self.thresholds.get("monitoring_score"),
            20.0,
        )

        if score >= emergency_threshold:
            return "emergency_lock_recommended"
        if score >= deny_threshold:
            return "deny"
        if score >= approval_threshold:
            return "require_approval"
        if score >= challenge_threshold:
            return "challenge"
        if score >= monitoring_threshold:
            return "allow_with_monitoring"
        return "allow"

    def _calculate_combined_score(
        self,
        detections: Sequence[DetectionResult],
    ) -> float:
        """
        Combine overlapping risk signals without simple unbounded addition.

        Formula:
            combined = 100 * (1 - product(1 - score_i / 100))

        This preserves stronger signals while allowing multiple independent
        anomalies to increase total confidence.
        """
        active_scores = [
            clamp(item.score) / 100.0
            for item in detections
            if item.detected and item.score > 0
        ]

        if not active_scores:
            return 0.0

        remaining_probability = 1.0

        for score in active_scores:
            remaining_probability *= 1.0 - score

        return round(
            clamp(100.0 * (1.0 - remaining_probability)),
            2,
        )

    # -------------------------------------------------------------------------
    # Device anomaly detection
    # -------------------------------------------------------------------------

    def _extract_location(
        self,
        data: Mapping[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Extract normalized coarse location information."""
        location = data.get("location")

        if isinstance(location, Mapping):
            latitude = location.get("latitude", location.get("lat"))
            longitude = location.get(
                "longitude",
                location.get("lon", location.get("lng")),
            )
            country = location.get("country")
            region = location.get("region")
            city = location.get("city")
        else:
            latitude = data.get("latitude", data.get("lat"))
            longitude = data.get(
                "longitude",
                data.get("lon", data.get("lng")),
            )
            country = data.get("country")
            region = data.get("region")
            city = data.get("city")

        if (
            latitude is None
            and longitude is None
            and country is None
            and region is None
            and city is None
        ):
            return None

        normalized: Dict[str, Any] = {
            "country": str(country).strip().upper() if country else None,
            "region": str(region).strip().lower() if region else None,
            "city": str(city).strip().lower() if city else None,
        }

        if latitude is not None and longitude is not None:
            normalized["latitude"] = safe_float(latitude)
            normalized["longitude"] = safe_float(longitude)

        location_key_source = {
            "country": normalized.get("country"),
            "region": normalized.get("region"),
            "city": normalized.get("city"),
        }

        normalized["location_key"] = hash_value(location_key_source)
        return normalized

    def _detect_unusual_device_internal(
        self,
        event: SecurityEvent,
        baseline: BehaviorBaseline,
    ) -> List[DetectionResult]:
        """Run unusual-device, fingerprint, location, and travel checks."""
        data = event.data
        device_data = data.get("device")

        if not isinstance(device_data, Mapping):
            device_data = data

        fingerprint = fingerprint_device(device_data)
        device_id = str(
            event.device_id
            or device_data.get("device_id")
            or fingerprint[:20]
        )

        trusted = baseline.trusted_devices.get(fingerprint)
        results: List[DetectionResult] = []

        new_device_score = safe_float(
            self.thresholds.get("new_device_base_score"),
            45.0,
        )

        if trusted is None:
            evidence = [
                AnomalyEvidence(
                    code="device_not_in_baseline",
                    description=(
                        "The current device fingerprint has not previously "
                        "been established for this user and workspace."
                    ),
                    observed=fingerprint[:16],
                    expected="Previously trusted device fingerprint",
                    weight=new_device_score,
                )
            ]

            results.append(
                DetectionResult(
                    anomaly_type="unusual_device",
                    detected=True,
                    score=new_device_score,
                    severity=severity_from_score(new_device_score),
                    title="Unusual device detected",
                    description=(
                        "A device outside the established user/workspace "
                        "baseline attempted an action."
                    ),
                    evidence=evidence,
                    recommendations=[
                        "Require step-up authentication for sensitive actions.",
                        "Confirm the device through Device Access.",
                        "Monitor the current session for related anomalies.",
                    ],
                    metadata={
                        "device_id": device_id,
                        "device_fingerprint": fingerprint[:16],
                        "baseline_status": baseline.status,
                    },
                )
            )

        supplied_previous_fingerprint = str(
            data.get("previous_device_fingerprint")
            or ""
        ).strip()

        if supplied_previous_fingerprint:
            supplied_previous_hash = hash_value(
                supplied_previous_fingerprint
            )

            if supplied_previous_hash != fingerprint:
                score = safe_float(
                    self.thresholds.get(
                        "device_fingerprint_change_score"
                    ),
                    55.0,
                )

                results.append(
                    DetectionResult(
                        anomaly_type="device_fingerprint_change",
                        detected=True,
                        score=score,
                        severity=severity_from_score(score),
                        title="Device fingerprint changed",
                        description=(
                            "The device fingerprint differs from the "
                            "previously supplied session fingerprint."
                        ),
                        evidence=[
                            AnomalyEvidence(
                                code="fingerprint_changed",
                                description=(
                                    "Current and previous device "
                                    "fingerprints do not match."
                                ),
                                observed=fingerprint[:16],
                                expected=supplied_previous_hash[:16],
                                weight=score,
                            )
                        ],
                        recommendations=[
                            "Revalidate the session.",
                            "Require device or biometric confirmation.",
                        ],
                        metadata={
                            "device_id": device_id,
                        },
                    )
                )

        location = self._extract_location(data)

        if location:
            location_key = location["location_key"]
            known_location = baseline.known_locations.get(location_key)

            if known_location is None:
                score = safe_float(
                    self.thresholds.get("unusual_location_score"),
                    35.0,
                )

                results.append(
                    DetectionResult(
                        anomaly_type="unusual_location",
                        detected=True,
                        score=score,
                        severity=severity_from_score(score),
                        title="Unusual location detected",
                        description=(
                            "The current coarse location is not established "
                            "in this user's workspace baseline."
                        ),
                        evidence=[
                            AnomalyEvidence(
                                code="location_not_in_baseline",
                                description=(
                                    "Country, region, or city differs from "
                                    "known activity."
                                ),
                                observed={
                                    "country": location.get("country"),
                                    "region": location.get("region"),
                                    "city": location.get("city"),
                                },
                                expected="Known user/workspace location",
                                weight=score,
                            )
                        ],
                        recommendations=[
                            "Apply additional authentication when combined with other risk.",
                            "Review the device and session history.",
                        ],
                        metadata={
                            "location_key": location_key[:16],
                        },
                    )
                )

            previous_location = baseline.last_device_location

            if (
                previous_location
                and location.get("latitude") is not None
                and location.get("longitude") is not None
                and previous_location.get("latitude") is not None
                and previous_location.get("longitude") is not None
                and previous_location.get("timestamp")
            ):
                previous_time = parse_datetime(
                    previous_location.get("timestamp")
                )
                current_time = parse_datetime(event.timestamp)
                elapsed_hours = (
                    current_time - previous_time
                ).total_seconds() / 3600.0

                if elapsed_hours > 0:
                    distance = haversine_distance_km(
                        safe_float(previous_location["latitude"]),
                        safe_float(previous_location["longitude"]),
                        safe_float(location["latitude"]),
                        safe_float(location["longitude"]),
                    )

                    speed = distance / elapsed_hours
                    maximum_speed = safe_float(
                        self.thresholds.get(
                            "impossible_travel_speed_kmh"
                        ),
                        1000.0,
                    )

                    if speed > maximum_speed:
                        score = safe_float(
                            self.thresholds.get(
                                "impossible_travel_score"
                            ),
                            80.0,
                        )

                        speed_factor = min(
                            20.0,
                            max(
                                0.0,
                                (speed - maximum_speed)
                                / max(maximum_speed, 1.0)
                                * 20.0,
                            ),
                        )
                        score = clamp(score + speed_factor)

                        results.append(
                            DetectionResult(
                                anomaly_type="impossible_travel",
                                detected=True,
                                score=score,
                                severity=severity_from_score(score),
                                title="Impossible travel suspected",
                                description=(
                                    "The geographic movement between recent "
                                    "events exceeds the configured plausible "
                                    "travel speed."
                                ),
                                evidence=[
                                    AnomalyEvidence(
                                        code="travel_speed_exceeded",
                                        description=(
                                            "Calculated movement speed exceeds "
                                            "the plausible threshold."
                                        ),
                                        observed={
                                            "distance_km": round(distance, 2),
                                            "elapsed_hours": round(
                                                elapsed_hours,
                                                4,
                                            ),
                                            "speed_kmh": round(speed, 2),
                                        },
                                        expected={
                                            "maximum_speed_kmh": maximum_speed
                                        },
                                        weight=score,
                                    )
                                ],
                                recommendations=[
                                    "Challenge or deny sensitive actions.",
                                    "Revoke suspicious sessions if identity cannot be confirmed.",
                                    "Review recent device and authentication events.",
                                ],
                                metadata={
                                    "distance_km": round(distance, 2),
                                    "speed_kmh": round(speed, 2),
                                },
                            )
                        )

        return results

    # -------------------------------------------------------------------------
    # Voice anomaly detection
    # -------------------------------------------------------------------------

    def _detect_voice_internal(
        self,
        event: SecurityEvent,
        baseline: BehaviorBaseline,
    ) -> List[DetectionResult]:
        """Detect voice identity mismatch, spoofing, and feature deviation."""
        data = event.data
        results: List[DetectionResult] = []

        similarity = data.get(
            "speaker_similarity",
            data.get(
                "voice_similarity",
                data.get("identity_confidence"),
            ),
        )
        liveness = data.get(
            "liveness_score",
            data.get("voice_liveness"),
        )
        replay_score = data.get(
            "replay_score",
            data.get("spoof_score"),
        )
        verified = data.get("verified")

        warning_threshold = safe_float(
            self.thresholds.get(
                "voice_similarity_warning_threshold"
            ),
            0.78,
        )
        critical_threshold = safe_float(
            self.thresholds.get(
                "voice_similarity_critical_threshold"
            ),
            0.55,
        )

        if similarity is not None:
            similarity_value = clamp(
                safe_float(similarity),
                0.0,
                1.0,
            )

            if similarity_value < warning_threshold:
                base_score = safe_float(
                    self.thresholds.get(
                        "voice_mismatch_base_score"
                    ),
                    65.0,
                )

                mismatch_ratio = (
                    warning_threshold - similarity_value
                ) / max(warning_threshold, 0.01)

                score = clamp(
                    base_score + mismatch_ratio * 30.0
                )

                if similarity_value <= critical_threshold:
                    score = max(score, 85.0)

                results.append(
                    DetectionResult(
                        anomaly_type="voice_identity_mismatch",
                        detected=True,
                        score=score,
                        severity=severity_from_score(score),
                        title="Voice identity mismatch",
                        description=(
                            "The supplied voice sample has lower similarity "
                            "than the configured identity threshold."
                        ),
                        evidence=[
                            AnomalyEvidence(
                                code="voice_similarity_below_threshold",
                                description=(
                                    "Speaker similarity did not meet the "
                                    "accepted baseline threshold."
                                ),
                                observed=round(similarity_value, 4),
                                expected={
                                    "warning_minimum": warning_threshold,
                                    "critical_minimum": critical_threshold,
                                },
                                weight=score,
                            )
                        ],
                        recommendations=[
                            "Require another biometric or authentication factor.",
                            "Do not authorize sensitive voice commands from this sample.",
                            "Review voice replay and session risk signals.",
                        ],
                        metadata={
                            "voice_similarity": round(
                                similarity_value,
                                4,
                            ),
                        },
                    )
                )

        if verified is False:
            score = max(
                safe_float(
                    self.thresholds.get(
                        "voice_mismatch_base_score"
                    ),
                    65.0,
                ),
                70.0,
            )

            results.append(
                DetectionResult(
                    anomaly_type="voice_identity_mismatch",
                    detected=True,
                    score=score,
                    severity=severity_from_score(score),
                    title="Voice verification failed",
                    description=(
                        "The upstream voice or biometric verification "
                        "reported an identity failure."
                    ),
                    evidence=[
                        AnomalyEvidence(
                            code="upstream_voice_verification_failed",
                            description=(
                                "The voice verification result was false."
                            ),
                            observed=False,
                            expected=True,
                            weight=score,
                        )
                    ],
                    recommendations=[
                        "Reject sensitive voice authorization.",
                        "Request another approved authentication method.",
                    ],
                )
            )

        liveness_minimum = safe_float(
            self.thresholds.get("voice_liveness_minimum"),
            0.65,
        )
        replay_threshold = safe_float(
            self.thresholds.get(
                "voice_replay_score_threshold"
            ),
            0.70,
        )

        spoof_signals: List[AnomalyEvidence] = []

        if liveness is not None:
            liveness_value = clamp(
                safe_float(liveness),
                0.0,
                1.0,
            )

            if liveness_value < liveness_minimum:
                spoof_signals.append(
                    AnomalyEvidence(
                        code="low_voice_liveness",
                        description=(
                            "Voice liveness score is below the configured "
                            "minimum."
                        ),
                        observed=round(liveness_value, 4),
                        expected=liveness_minimum,
                        weight=45.0,
                    )
                )

        if replay_score is not None:
            replay_value = clamp(
                safe_float(replay_score),
                0.0,
                1.0,
            )

            if replay_value >= replay_threshold:
                spoof_signals.append(
                    AnomalyEvidence(
                        code="voice_replay_signal",
                        description=(
                            "Replay or spoof confidence exceeds the "
                            "configured threshold."
                        ),
                        observed=round(replay_value, 4),
                        expected={
                            "maximum_allowed": replay_threshold
                        },
                        weight=55.0,
                    )
                )

        if bool(data.get("synthetic_voice_suspected")):
            spoof_signals.append(
                AnomalyEvidence(
                    code="synthetic_voice_suspected",
                    description=(
                        "The upstream voice system marked the sample as "
                        "potentially synthetic."
                    ),
                    observed=True,
                    expected=False,
                    weight=65.0,
                )
            )

        if spoof_signals:
            base_score = safe_float(
                self.thresholds.get(
                    "voice_spoof_base_score"
                ),
                80.0,
            )

            score = clamp(
                base_score
                + max(
                    0,
                    len(spoof_signals) - 1,
                )
                * 7.5
            )

            results.append(
                DetectionResult(
                    anomaly_type="voice_spoof_suspected",
                    detected=True,
                    score=score,
                    severity=severity_from_score(score),
                    title="Voice spoofing suspected",
                    description=(
                        "One or more liveness, replay, or synthetic voice "
                        "signals indicate possible spoofing."
                    ),
                    evidence=spoof_signals,
                    recommendations=[
                        "Deny voice-only authorization.",
                        "Require a strong secondary authentication factor.",
                        "Flag the session for Security Agent review.",
                    ],
                )
            )

        features = data.get("voice_features")

        if isinstance(features, Mapping):
            feature_evidence: List[AnomalyEvidence] = []
            threshold = safe_float(
                self.thresholds.get(
                    "voice_baseline_deviation_zscore"
                ),
                3.0,
            )

            for feature_name, feature_value in features.items():
                if not isinstance(feature_value, (int, float)):
                    continue

                samples = baseline.voice_feature_samples.get(
                    str(feature_name),
                    [],
                )

                z_score = calculate_z_score(
                    safe_float(feature_value),
                    samples,
                )

                if z_score >= threshold:
                    feature_evidence.append(
                        AnomalyEvidence(
                            code="voice_feature_deviation",
                            description=(
                                f"Voice feature '{feature_name}' differs "
                                "from the established baseline."
                            ),
                            observed={
                                "value": safe_float(feature_value),
                                "z_score": round(z_score, 4),
                            },
                            expected={
                                "maximum_z_score": threshold,
                                "sample_count": len(samples),
                            },
                            weight=min(35.0, z_score * 8.0),
                            metadata={
                                "feature": str(feature_name),
                            },
                        )
                    )

            if feature_evidence:
                score = clamp(
                    35.0
                    + sum(
                        evidence.weight
                        for evidence in feature_evidence
                    )
                    / max(len(feature_evidence), 1)
                )

                results.append(
                    DetectionResult(
                        anomaly_type="unusual_voice_pattern",
                        detected=True,
                        score=score,
                        severity=severity_from_score(score),
                        title="Unusual voice pattern",
                        description=(
                            "Acoustic voice features deviate from the "
                            "user/workspace behavior baseline."
                        ),
                        evidence=feature_evidence,
                        recommendations=[
                            "Request another voice sample.",
                            "Combine the result with liveness and device checks.",
                        ],
                    )
                )

        return results

    # -------------------------------------------------------------------------
    # Command anomaly detection
    # -------------------------------------------------------------------------

    def _detect_command_internal(
        self,
        event: SecurityEvent,
        baseline: BehaviorBaseline,
        context: TaskContext,
    ) -> List[DetectionResult]:
        """Detect abnormal command usage and command-frequency spikes."""
        data = event.data
        raw_command = (
            data.get("command")
            or data.get("command_text")
            or event.action
            or ""
        )

        command = normalize_command(raw_command)

        if not command:
            return []

        maximum_length = safe_int(
            self.thresholds.get("command_length_maximum"),
            10000,
        )

        command = command[:maximum_length]
        signature = command_signature(command)
        known_command = baseline.command_signatures.get(signature)
        results: List[DetectionResult] = []

        privileged = bool(data.get("privileged")) or any(
            keyword in command
            for keyword in PRIVILEGED_COMMAND_KEYWORDS
        )
        destructive = bool(data.get("destructive")) or any(
            keyword in command
            for keyword in DESTRUCTIVE_COMMAND_KEYWORDS
        )

        if privileged and known_command is None:
            score = safe_float(
                self.thresholds.get(
                    "new_privileged_command_score"
                ),
                65.0,
            )

            if destructive:
                score = max(
                    score,
                    safe_float(
                        self.thresholds.get(
                            "destructive_command_score"
                        ),
                        75.0,
                    ),
                )

            results.append(
                DetectionResult(
                    anomaly_type="privileged_command_change",
                    detected=True,
                    score=score,
                    severity=severity_from_score(score),
                    title="New privileged command pattern",
                    description=(
                        "A privileged or destructive command is not present "
                        "in the established behavior baseline."
                    ),
                    evidence=[
                        AnomalyEvidence(
                            code="new_privileged_command",
                            description=(
                                "The normalized command signature is new for "
                                "this user and workspace."
                            ),
                            observed={
                                "signature": signature[:16],
                                "privileged": privileged,
                                "destructive": destructive,
                            },
                            expected=(
                                "Previously established privileged command"
                            ),
                            weight=score,
                        )
                    ],
                    recommendations=[
                        "Require Security Agent approval.",
                        "Verify the user's role and current session.",
                        "Require confirmation before executing destructive actions.",
                    ],
                    metadata={
                        "command_signature": signature[:16],
                        "privileged": privileged,
                        "destructive": destructive,
                    },
                )
            )

        event_time = parse_datetime(event.timestamp)
        window_minutes = safe_int(
            self.thresholds.get("command_window_minutes"),
            5,
        )
        since = event_time - timedelta(minutes=window_minutes)

        recent_commands = self._recent_events(
            context,
            event_type="command",
            since=since,
        )

        command_count = len(recent_commands) + 1
        warning_count = safe_int(
            self.thresholds.get(
                "command_frequency_warning"
            ),
            20,
        )
        critical_count = safe_int(
            self.thresholds.get(
                "command_frequency_critical"
            ),
            50,
        )

        if command_count >= warning_count:
            base_score = safe_float(
                self.thresholds.get(
                    "command_frequency_spike_score"
                ),
                55.0,
            )

            range_size = max(
                critical_count - warning_count,
                1,
            )
            progress = (
                command_count - warning_count
            ) / range_size

            score = clamp(
                base_score + min(35.0, max(0.0, progress * 35.0))
            )

            if command_count >= critical_count:
                score = max(score, 85.0)

            results.append(
                DetectionResult(
                    anomaly_type="command_frequency_spike",
                    detected=True,
                    score=score,
                    severity=severity_from_score(score),
                    title="Command frequency spike",
                    description=(
                        "Command activity exceeds the configured rate "
                        "threshold for the current time window."
                    ),
                    evidence=[
                        AnomalyEvidence(
                            code="command_rate_exceeded",
                            description=(
                                "The command count is above the configured "
                                "warning level."
                            ),
                            observed={
                                "command_count": command_count,
                                "window_minutes": window_minutes,
                            },
                            expected={
                                "warning_count": warning_count,
                                "critical_count": critical_count,
                            },
                            weight=score,
                        )
                    ],
                    recommendations=[
                        "Rate-limit additional commands.",
                        "Require confirmation for sensitive actions.",
                        "Inspect the session for automation or account takeover.",
                    ],
                    metadata={
                        "command_count": command_count,
                        "window_minutes": window_minutes,
                    },
                )
            )

        repeated_threshold = safe_int(
            self.thresholds.get("repeated_command_count"),
            8,
        )

        matching_count = 1

        for recent_event in recent_commands:
            recent_data = recent_event.get("data") or {}
            recent_command = normalize_command(
                recent_data.get("command")
                or recent_data.get("command_text")
                or recent_event.get("action")
                or ""
            )

            if command_signature(recent_command) == signature:
                matching_count += 1

        if matching_count >= repeated_threshold:
            score = safe_float(
                self.thresholds.get(
                    "repeated_command_score"
                ),
                40.0,
            )

            score = clamp(
                score + min(
                    30.0,
                    max(
                        0,
                        matching_count - repeated_threshold,
                    )
                    * 3.0,
                )
            )

            results.append(
                DetectionResult(
                    anomaly_type="repeated_command_pattern",
                    detected=True,
                    score=score,
                    severity=severity_from_score(score),
                    title="Repeated command pattern",
                    description=(
                        "The same normalized command was issued repeatedly "
                        "within a short period."
                    ),
                    evidence=[
                        AnomalyEvidence(
                            code="repeated_command_threshold",
                            description=(
                                "Repeated command execution exceeded the "
                                "configured threshold."
                            ),
                            observed={
                                "matching_count": matching_count,
                                "window_minutes": window_minutes,
                            },
                            expected={
                                "maximum_before_alert": (
                                    repeated_threshold - 1
                                )
                            },
                            weight=score,
                        )
                    ],
                    recommendations=[
                        "Check whether the activity is an approved workflow.",
                        "Apply rate limiting when the sequence is unexpected.",
                    ],
                    metadata={
                        "command_signature": signature[:16],
                        "matching_count": matching_count,
                    },
                )
            )

        command_hour = str(event_time.hour)
        historic_hour_count = safe_int(
            baseline.command_hour_histogram.get(command_hour),
            0,
        )
        total_hour_events = sum(
            baseline.command_hour_histogram.values()
        )

        if (
            baseline.status == "established"
            and total_hour_events >= safe_int(
                self.thresholds.get("baseline_minimum_events"),
                5,
            )
            and historic_hour_count == 0
        ):
            score = 25.0

            results.append(
                DetectionResult(
                    anomaly_type="unusual_command",
                    detected=True,
                    score=score,
                    severity=severity_from_score(score),
                    title="Command issued at an unusual time",
                    description=(
                        "The command occurred during an hour not present in "
                        "the established command baseline."
                    ),
                    evidence=[
                        AnomalyEvidence(
                            code="unusual_command_hour",
                            description=(
                                "No prior command activity is recorded for "
                                "the current UTC hour."
                            ),
                            observed={
                                "utc_hour": event_time.hour
                            },
                            expected={
                                "known_utc_hours": sorted(
                                    int(key)
                                    for key, count
                                    in baseline.command_hour_histogram.items()
                                    if count > 0
                                )
                            },
                            weight=score,
                        )
                    ],
                    recommendations=[
                        "Monitor the session when combined with other anomalies.",
                    ],
                )
            )

        return results

    # -------------------------------------------------------------------------
    # Failed attempt anomaly detection
    # -------------------------------------------------------------------------

    def _detect_failed_attempt_internal(
        self,
        event: SecurityEvent,
        baseline: BehaviorBaseline,
        context: TaskContext,
    ) -> List[DetectionResult]:
        """Detect brute force, repeated failure, and distributed attacks."""
        data = event.data
        event_time = parse_datetime(event.timestamp)
        window_minutes = safe_int(
            self.thresholds.get(
                "failed_attempt_window_minutes"
            ),
            10,
        )
        since = event_time - timedelta(minutes=window_minutes)

        recent_failures = self._recent_events(
            context,
            event_type="failed_attempt",
            since=since,
        )

        count = len(recent_failures) + 1
        warning = safe_int(
            self.thresholds.get("failed_attempt_warning"),
            5,
        )
        high = safe_int(
            self.thresholds.get("failed_attempt_high"),
            10,
        )
        critical = safe_int(
            self.thresholds.get("failed_attempt_critical"),
            20,
        )

        results: List[DetectionResult] = []

        if count >= warning:
            base_score = safe_float(
                self.thresholds.get(
                    "failed_attempt_base_score"
                ),
                45.0,
            )

            if count >= critical:
                score = max(base_score, 90.0)
            elif count >= high:
                score = max(base_score, 70.0)
            else:
                score = base_score

            score = clamp(
                score + min(
                    10.0,
                    max(0, count - warning) * 1.5,
                )
            )

            results.append(
                DetectionResult(
                    anomaly_type="failed_attempt_spike",
                    detected=True,
                    score=score,
                    severity=severity_from_score(score),
                    title="Failed attempt spike",
                    description=(
                        "Authentication, authorization, biometric, or action "
                        "failures exceed the configured time-window threshold."
                    ),
                    evidence=[
                        AnomalyEvidence(
                            code="failed_attempt_threshold",
                            description=(
                                "The number of recent failed attempts exceeds "
                                "the permitted baseline."
                            ),
                            observed={
                                "failed_attempts": count,
                                "window_minutes": window_minutes,
                                "failure_type": data.get(
                                    "failure_type",
                                    event.action,
                                ),
                            },
                            expected={
                                "warning": warning,
                                "high": high,
                                "critical": critical,
                            },
                            weight=score,
                        )
                    ],
                    recommendations=[
                        "Apply temporary rate limiting or session challenge.",
                        "Require stronger authentication after repeated failures.",
                        "Review related devices, sources, and sessions.",
                    ],
                    metadata={
                        "failed_attempts": count,
                        "window_minutes": window_minutes,
                    },
                )
            )

        source = (
            data.get("source_ip")
            or data.get("ip_address")
            or data.get("source")
            or event.device_id
            or event.session_id
            or "unknown"
        )

        sources = {
            source_signature(source)
        }

        for recent_event in recent_failures:
            recent_data = recent_event.get("data") or {}
            recent_source = (
                recent_data.get("source_ip")
                or recent_data.get("ip_address")
                or recent_data.get("source")
                or recent_event.get("device_id")
                or recent_event.get("session_id")
                or "unknown"
            )
            sources.add(source_signature(recent_source))

        source_threshold = safe_int(
            self.thresholds.get(
                "distributed_source_threshold"
            ),
            4,
        )

        if len(sources) >= source_threshold and count >= warning:
            score = safe_float(
                self.thresholds.get(
                    "distributed_failed_attempt_score"
                ),
                70.0,
            )

            score = clamp(
                score
                + min(
                    20.0,
                    max(
                        0,
                        len(sources) - source_threshold,
                    )
                    * 5.0,
                )
            )

            results.append(
                DetectionResult(
                    anomaly_type="distributed_failed_attempts",
                    detected=True,
                    score=score,
                    severity=severity_from_score(score),
                    title="Distributed failed attempts",
                    description=(
                        "Failed attempts originated from multiple distinct "
                        "sources within the configured window."
                    ),
                    evidence=[
                        AnomalyEvidence(
                            code="multiple_failure_sources",
                            description=(
                                "The number of unique source signatures "
                                "exceeds the distributed-attempt threshold."
                            ),
                            observed={
                                "unique_sources": len(sources),
                                "failed_attempts": count,
                            },
                            expected={
                                "source_threshold": source_threshold,
                            },
                            weight=score,
                        )
                    ],
                    recommendations=[
                        "Challenge or temporarily lock the targeted session or identity.",
                        "Notify the Security Agent and Threat Monitor.",
                        "Review whether credentials or tokens may be compromised.",
                    ],
                    metadata={
                        "unique_source_count": len(sources),
                    },
                )
            )

        return results

    # -------------------------------------------------------------------------
    # Export anomaly detection
    # -------------------------------------------------------------------------

    def _detect_export_internal(
        self,
        event: SecurityEvent,
        baseline: BehaviorBaseline,
        context: TaskContext,
    ) -> List[DetectionResult]:
        """Detect mass exports and export-frequency spikes."""
        data = event.data
        event_time = parse_datetime(event.timestamp)

        record_count = max(
            0,
            safe_int(
                data.get(
                    "record_count",
                    data.get(
                        "items_count",
                        data.get("rows", 0),
                    ),
                ),
                0,
            ),
        )
        byte_count = max(
            0,
            safe_int(
                data.get(
                    "byte_count",
                    data.get(
                        "size_bytes",
                        data.get("export_size", 0),
                    ),
                ),
                0,
            ),
        )

        operation_count = max(
            1,
            safe_int(data.get("operation_count"), 1),
        )

        window_minutes = safe_int(
            self.thresholds.get("export_window_minutes"),
            15,
        )
        since = event_time - timedelta(minutes=window_minutes)

        recent_exports = self._recent_events(
            context,
            event_type="export",
            since=since,
        )

        total_records = record_count
        total_bytes = byte_count
        total_operations = operation_count

        for recent_event in recent_exports:
            recent_data = recent_event.get("data") or {}

            total_records += max(
                0,
                safe_int(
                    recent_data.get(
                        "record_count",
                        recent_data.get(
                            "items_count",
                            recent_data.get("rows", 0),
                        ),
                    )
                ),
            )
            total_bytes += max(
                0,
                safe_int(
                    recent_data.get(
                        "byte_count",
                        recent_data.get(
                            "size_bytes",
                            recent_data.get("export_size", 0),
                        ),
                    )
                ),
            )
            total_operations += max(
                1,
                safe_int(
                    recent_data.get("operation_count"),
                    1,
                ),
            )

        record_warning = safe_int(
            self.thresholds.get("export_record_warning"),
            1000,
        )
        record_high = safe_int(
            self.thresholds.get("export_record_high"),
            10000,
        )
        record_critical = safe_int(
            self.thresholds.get("export_record_critical"),
            100000,
        )

        byte_warning = safe_int(
            self.thresholds.get("export_byte_warning"),
            100 * 1024 * 1024,
        )
        byte_high = safe_int(
            self.thresholds.get("export_byte_high"),
            1024 * 1024 * 1024,
        )
        byte_critical = safe_int(
            self.thresholds.get("export_byte_critical"),
            10 * 1024 * 1024 * 1024,
        )

        operation_warning = safe_int(
            self.thresholds.get(
                "export_operation_warning"
            ),
            5,
        )
        operation_high = safe_int(
            self.thresholds.get(
                "export_operation_high"
            ),
            15,
        )

        evidence: List[AnomalyEvidence] = []
        severity_points: List[float] = []

        if total_records >= record_warning:
            if total_records >= record_critical:
                points = 95.0
            elif total_records >= record_high:
                points = 80.0
            else:
                points = 60.0

            severity_points.append(points)
            evidence.append(
                AnomalyEvidence(
                    code="export_record_volume",
                    description=(
                        "Exported record volume exceeds the configured "
                        "threshold."
                    ),
                    observed={
                        "records": total_records,
                        "window_minutes": window_minutes,
                    },
                    expected={
                        "warning": record_warning,
                        "high": record_high,
                        "critical": record_critical,
                    },
                    weight=points,
                )
            )

        if total_bytes >= byte_warning:
            if total_bytes >= byte_critical:
                points = 95.0
            elif total_bytes >= byte_high:
                points = 80.0
            else:
                points = 60.0

            severity_points.append(points)
            evidence.append(
                AnomalyEvidence(
                    code="export_byte_volume",
                    description=(
                        "Exported byte volume exceeds the configured "
                        "threshold."
                    ),
                    observed={
                        "bytes": total_bytes,
                        "window_minutes": window_minutes,
                    },
                    expected={
                        "warning": byte_warning,
                        "high": byte_high,
                        "critical": byte_critical,
                    },
                    weight=points,
                )
            )

        if total_operations >= operation_warning:
            points = (
                80.0
                if total_operations >= operation_high
                else 55.0
            )

            severity_points.append(points)
            evidence.append(
                AnomalyEvidence(
                    code="export_operation_frequency",
                    description=(
                        "Export operation count exceeds the configured "
                        "frequency threshold."
                    ),
                    observed={
                        "operations": total_operations,
                        "window_minutes": window_minutes,
                    },
                    expected={
                        "warning": operation_warning,
                        "high": operation_high,
                    },
                    weight=points,
                )
            )

        baseline_record_z = calculate_z_score(
            float(total_records),
            baseline.export_record_samples,
        )
        baseline_byte_z = calculate_z_score(
            float(total_bytes),
            baseline.export_byte_samples,
        )
        baseline_operation_z = calculate_z_score(
            float(total_operations),
            baseline.export_operation_samples,
        )

        maximum_z = max(
            baseline_record_z,
            baseline_byte_z,
            baseline_operation_z,
        )

        if baseline.status == "established" and maximum_z >= 3.0:
            points = clamp(40.0 + maximum_z * 8.0)
            severity_points.append(points)

            evidence.append(
                AnomalyEvidence(
                    code="export_baseline_deviation",
                    description=(
                        "Current export activity deviates materially from "
                        "the user's established export behavior."
                    ),
                    observed={
                        "record_z_score": round(
                            baseline_record_z,
                            4,
                        ),
                        "byte_z_score": round(
                            baseline_byte_z,
                            4,
                        ),
                        "operation_z_score": round(
                            baseline_operation_z,
                            4,
                        ),
                    },
                    expected={
                        "maximum_normal_z_score": 3.0,
                    },
                    weight=points,
                )
            )

        if not evidence:
            return []

        base_score = safe_float(
            self.thresholds.get("mass_export_base_score"),
            65.0,
        )

        score = max(
            base_score,
            max(severity_points),
        )

        if len(evidence) > 1:
            score = clamp(
                score + min(15.0, (len(evidence) - 1) * 5.0)
            )

        mass_export = (
            total_records >= record_warning
            or total_bytes >= byte_warning
        )

        anomaly_type: AnomalyType = (
            "mass_export"
            if mass_export
            else "export_frequency_spike"
        )

        return [
            DetectionResult(
                anomaly_type=anomaly_type,
                detected=True,
                score=score,
                severity=severity_from_score(score),
                title=(
                    "Mass export detected"
                    if mass_export
                    else "Export frequency spike"
                ),
                description=(
                    "Export behavior exceeds configured volume, frequency, "
                    "or historical baseline limits."
                ),
                evidence=evidence,
                recommendations=[
                    "Require Security Agent approval before completing the export.",
                    "Confirm the user's role and export permission.",
                    "Apply download limits or staged export processing.",
                    "Review the destination and requested data scope.",
                ],
                metadata={
                    "total_records": total_records,
                    "total_bytes": total_bytes,
                    "total_operations": total_operations,
                    "window_minutes": window_minutes,
                    "export_scope": data.get("scope"),
                    "export_type": data.get("export_type"),
                },
            )
        ]

    # -------------------------------------------------------------------------
    # Baseline learning
    # -------------------------------------------------------------------------

    @staticmethod
    def _bounded_append(
        values: List[float],
        value: float,
        maximum: int = 500,
    ) -> None:
        """Append a sample while limiting memory growth."""
        values.append(float(value))

        if len(values) > maximum:
            del values[:-maximum]

    def _learn_from_event(
        self,
        event: SecurityEvent,
        baseline: BehaviorBaseline,
        detections: Sequence[DetectionResult],
    ) -> BehaviorBaseline:
        """
        Update a baseline using trusted or low-risk observations.

        High and critical anomalous signals are not promoted into trusted
        baselines automatically.
        """
        updated = copy.deepcopy(baseline)
        combined_score = self._calculate_combined_score(detections)
        safe_to_learn = combined_score < safe_float(
            self.thresholds.get("approval_score"),
            65.0,
        )

        updated.event_count += 1
        updated.last_seen_at = event.timestamp
        updated.updated_at = utc_now_iso()

        if event.event_type == "device":
            device_data = event.data.get("device")

            if not isinstance(device_data, Mapping):
                device_data = event.data

            fingerprint = fingerprint_device(device_data)
            current = updated.trusted_devices.get(
                fingerprint,
                {
                    "first_seen_at": event.timestamp,
                    "seen_count": 0,
                    "trusted": False,
                    "device_id": (
                        event.device_id
                        or device_data.get("device_id")
                    ),
                },
            )

            current["seen_count"] = safe_int(
                current.get("seen_count"),
                0,
            ) + 1
            current["last_seen_at"] = event.timestamp

            trust_count = safe_int(
                self.thresholds.get(
                    "trusted_device_learning_count"
                ),
                3,
            )

            if safe_to_learn and current["seen_count"] >= trust_count:
                current["trusted"] = True

            updated.trusted_devices[fingerprint] = current

            location = self._extract_location(event.data)

            if location:
                key = location["location_key"]
                location_record = updated.known_locations.get(
                    key,
                    {
                        "first_seen_at": event.timestamp,
                        "seen_count": 0,
                        "trusted": False,
                        "country": location.get("country"),
                        "region": location.get("region"),
                        "city": location.get("city"),
                    },
                )

                location_record["seen_count"] = safe_int(
                    location_record.get("seen_count"),
                    0,
                ) + 1
                location_record["last_seen_at"] = event.timestamp

                trust_location_count = safe_int(
                    self.thresholds.get(
                        "trusted_location_learning_count"
                    ),
                    3,
                )

                if (
                    safe_to_learn
                    and location_record["seen_count"]
                    >= trust_location_count
                ):
                    location_record["trusted"] = True

                updated.known_locations[key] = location_record

                if (
                    location.get("latitude") is not None
                    and location.get("longitude") is not None
                ):
                    updated.last_device_location = {
                        "latitude": location["latitude"],
                        "longitude": location["longitude"],
                        "timestamp": event.timestamp,
                        "location_key": key,
                    }

        elif event.event_type == "voice" and safe_to_learn:
            similarity = event.data.get(
                "speaker_similarity",
                event.data.get(
                    "voice_similarity",
                    event.data.get("identity_confidence"),
                ),
            )
            liveness = event.data.get(
                "liveness_score",
                event.data.get("voice_liveness"),
            )

            if similarity is not None:
                self._bounded_append(
                    updated.voice_similarity_samples,
                    clamp(
                        safe_float(similarity),
                        0.0,
                        1.0,
                    ),
                )

            if liveness is not None:
                self._bounded_append(
                    updated.voice_liveness_samples,
                    clamp(
                        safe_float(liveness),
                        0.0,
                        1.0,
                    ),
                )

            features = event.data.get("voice_features")

            if isinstance(features, Mapping):
                for name, value in features.items():
                    if not isinstance(value, (int, float)):
                        continue

                    sample_list = updated.voice_feature_samples.setdefault(
                        str(name),
                        [],
                    )
                    self._bounded_append(
                        sample_list,
                        safe_float(value),
                    )

        elif event.event_type == "command":
            command = normalize_command(
                event.data.get("command")
                or event.data.get("command_text")
                or event.action
                or ""
            )

            if command:
                signature = command_signature(command)
                command_record = updated.command_signatures.get(
                    signature,
                    {
                        "first_seen_at": event.timestamp,
                        "count": 0,
                    },
                )

                command_record["count"] = safe_int(
                    command_record.get("count"),
                    0,
                ) + 1
                command_record["last_seen_at"] = event.timestamp

                if safe_to_learn:
                    command_record["established"] = True

                updated.command_signatures[signature] = command_record

            hour_key = str(parse_datetime(event.timestamp).hour)
            updated.command_hour_histogram[hour_key] = (
                safe_int(
                    updated.command_hour_histogram.get(hour_key),
                    0,
                )
                + 1
            )

        elif event.event_type == "failed_attempt":
            window_minutes = safe_int(
                self.thresholds.get(
                    "failed_attempt_window_minutes"
                ),
                10,
            )
            count = len(
                self._recent_events(
                    TaskContext(
                        user_id=event.user_id,
                        workspace_id=event.workspace_id,
                    ),
                    event_type="failed_attempt",
                    since=parse_datetime(event.timestamp)
                    - timedelta(minutes=window_minutes),
                )
            ) + 1

            self._bounded_append(
                updated.failed_attempt_rate_samples,
                float(count),
            )

        elif event.event_type == "export" and safe_to_learn:
            records = max(
                0,
                safe_int(
                    event.data.get(
                        "record_count",
                        event.data.get(
                            "items_count",
                            event.data.get("rows", 0),
                        ),
                    )
                ),
            )
            bytes_count = max(
                0,
                safe_int(
                    event.data.get(
                        "byte_count",
                        event.data.get(
                            "size_bytes",
                            event.data.get("export_size", 0),
                        ),
                    )
                ),
            )
            operations = max(
                1,
                safe_int(
                    event.data.get("operation_count"),
                    1,
                ),
            )

            self._bounded_append(
                updated.export_record_samples,
                float(records),
            )
            self._bounded_append(
                updated.export_byte_samples,
                float(bytes_count),
            )
            self._bounded_append(
                updated.export_operation_samples,
                float(operations),
            )

        minimum_events = safe_int(
            self.thresholds.get("baseline_minimum_events"),
            5,
        )

        if updated.event_count >= minimum_events:
            updated.status = "established"
        else:
            updated.status = "learning"

        return updated

    # -------------------------------------------------------------------------
    # Internal analysis orchestration
    # -------------------------------------------------------------------------

    def _run_detectors(
        self,
        event: SecurityEvent,
        baseline: BehaviorBaseline,
        context: TaskContext,
    ) -> List[DetectionResult]:
        """Route a normalized event to specialized detectors."""
        if event.event_type == "device":
            return self._detect_unusual_device_internal(
                event,
                baseline,
            )

        if event.event_type == "voice":
            return self._detect_voice_internal(
                event,
                baseline,
            )

        if event.event_type == "command":
            return self._detect_command_internal(
                event,
                baseline,
                context,
            )

        if event.event_type == "failed_attempt":
            return self._detect_failed_attempt_internal(
                event,
                baseline,
                context,
            )

        if event.event_type == "export":
            return self._detect_export_internal(
                event,
                baseline,
                context,
            )

        return []

    def _create_anomaly_record(
        self,
        detection: DetectionResult,
        event: SecurityEvent,
        context: TaskContext,
    ) -> AnomalyRecord:
        """Convert one detector result to a persistent anomaly record."""
        decision = self._decision_from_score(detection.score)

        return AnomalyRecord(
            anomaly_id=create_id("anomaly"),
            anomaly_type=detection.anomaly_type,
            user_id=context.user_id,
            workspace_id=context.workspace_id,
            event_id=event.event_id,
            score=round(clamp(detection.score), 2),
            severity=detection.severity,
            decision=decision,
            title=detection.title,
            description=detection.description,
            evidence=[
                redact_sensitive_data(asdict(item))
                for item in detection.evidence
            ],
            metadata={
                **redact_sensitive_data(detection.metadata),
                "recommendations": list(
                    detection.recommendations
                ),
                "request_id": context.request_id,
                "session_id": context.session_id,
                "source_agent": context.source_agent,
            },
        )

    # -------------------------------------------------------------------------
    # Main public analysis methods
    # -------------------------------------------------------------------------

    def analyze_event(
        self,
        user_id: str,
        workspace_id: str,
        event: Mapping[str, Any],
        context: Optional[
            Union[TaskContext, Mapping[str, Any]]
        ] = None,
        store_event: bool = True,
        update_baseline: bool = True,
    ) -> Dict[str, Any]:
        """
        Analyze one normalized or raw security event.

        Returns:
            {
                "success": true,
                "data": {
                    "event": {...},
                    "anomaly_detected": true,
                    "risk_score": 82.5,
                    "severity": "high",
                    "decision": "require_approval",
                    "anomalies": [...],
                    "recommendations": [...],
                    "verification_payload": {...},
                    "memory_payloads": [...]
                }
            }
        """
        valid, task_context, context_error = (
            self._validate_task_context(
                user_id,
                workspace_id,
                context,
            )
        )

        if not valid or task_context is None:
            return self._error_result(
                "Invalid task context.",
                context_error,
            )

        try:
            with self._operation_lock:
                normalized_event = self._normalize_event(
                    event,
                    task_context,
                )
                baseline = self._load_baseline(task_context)

                detections = self._run_detectors(
                    normalized_event,
                    baseline,
                    task_context,
                )

                active_detections = [
                    detection
                    for detection in detections
                    if detection.detected
                ]

                anomaly_records: List[AnomalyRecord] = []

                for detection in active_detections:
                    anomaly = self._create_anomaly_record(
                        detection,
                        normalized_event,
                        task_context,
                    )
                    self._store_anomaly(
                        task_context,
                        anomaly,
                    )
                    anomaly_records.append(anomaly)

                risk_score = self._calculate_combined_score(
                    active_detections
                )
                severity = severity_from_score(risk_score)
                decision = self._decision_from_score(risk_score)

                recommendations: List[str] = []

                for detection in active_detections:
                    for recommendation in detection.recommendations:
                        if recommendation not in recommendations:
                            recommendations.append(recommendation)

                if store_event:
                    self._store_event(
                        task_context,
                        normalized_event,
                    )

                if update_baseline:
                    updated_baseline = self._learn_from_event(
                        normalized_event,
                        baseline,
                        active_detections,
                    )
                    self._save_baseline(
                        task_context,
                        updated_baseline,
                    )
                else:
                    updated_baseline = baseline

                public_event = asdict(normalized_event)
                public_event["data"] = redact_sensitive_data(
                    public_event["data"]
                )
                public_event["metadata"] = redact_sensitive_data(
                    public_event["metadata"]
                )

                public_anomalies = [
                    redact_sensitive_data(asdict(anomaly))
                    for anomaly in anomaly_records
                ]

                verification_payload = (
                    self._prepare_verification_payload(
                        "analyze_event",
                        task_context,
                        {
                            "event_id": normalized_event.event_id,
                            "event_type": normalized_event.event_type,
                            "anomaly_count": len(anomaly_records),
                            "risk_score": risk_score,
                            "severity": severity,
                            "decision": decision,
                        },
                    )
                )

                memory_payloads = [
                    self._prepare_memory_payload(
                        "anomaly_detected",
                        task_context,
                        anomaly,
                    )
                    for anomaly in public_anomalies
                ]

                response_data = {
                    "event": public_event,
                    "anomaly_detected": bool(anomaly_records),
                    "anomaly_count": len(anomaly_records),
                    "risk_score": risk_score,
                    "severity": severity,
                    "decision": decision,
                    "anomalies": public_anomalies,
                    "recommendations": recommendations,
                    "baseline": {
                        "status": updated_baseline.status,
                        "event_count": updated_baseline.event_count,
                        "updated_at": updated_baseline.updated_at,
                    },
                    "verification_payload": verification_payload,
                    "memory_payloads": memory_payloads,
                }

                self._emit_agent_event(
                    (
                        "security.anomaly_detected"
                        if anomaly_records
                        else "security.event_analyzed"
                    ),
                    task_context,
                    {
                        "event_id": normalized_event.event_id,
                        "event_type": normalized_event.event_type,
                        "anomaly_count": len(anomaly_records),
                        "risk_score": risk_score,
                        "severity": severity,
                        "decision": decision,
                    },
                )

                self._log_audit_event(
                    "analyze_event",
                    task_context,
                    {
                        "event_id": normalized_event.event_id,
                        "event_type": normalized_event.event_type,
                        "anomaly_count": len(anomaly_records),
                        "risk_score": risk_score,
                        "severity": severity,
                        "decision": decision,
                    },
                    success=True,
                )

                return self._safe_result(
                    success=True,
                    message=(
                        f"Detected {len(anomaly_records)} anomaly signal(s)."
                        if anomaly_records
                        else "No anomaly detected."
                    ),
                    data=response_data,
                    metadata={
                        "request_id": task_context.request_id,
                        "user_id": task_context.user_id,
                        "workspace_id": task_context.workspace_id,
                    },
                )

        except Exception as exc:
            self.logger.exception("Anomaly event analysis failed.")

            self._log_audit_event(
                "analyze_event",
                task_context,
                {
                    "event_type": event.get("event_type")
                    if isinstance(event, Mapping)
                    else None,
                },
                success=False,
                error=str(exc),
            )

            return self._error_result(
                "Failed to analyze security event.",
                exc,
                metadata={
                    "request_id": task_context.request_id,
                },
            )

    def analyze_activity(
        self,
        user_id: str,
        workspace_id: str,
        events: Sequence[Mapping[str, Any]],
        context: Optional[
            Union[TaskContext, Mapping[str, Any]]
        ] = None,
        stop_on_critical: bool = False,
    ) -> Dict[str, Any]:
        """
        Analyze multiple events sequentially while preserving baseline order.
        """
        valid, task_context, context_error = (
            self._validate_task_context(
                user_id,
                workspace_id,
                context,
            )
        )

        if not valid or task_context is None:
            return self._error_result(
                "Invalid task context.",
                context_error,
            )

        if not isinstance(events, Sequence) or isinstance(
            events,
            (str, bytes),
        ):
            return self._error_result(
                "events must be a sequence of event mappings."
            )

        results: List[Dict[str, Any]] = []
        total_anomalies = 0
        combined_event_scores: List[float] = []
        highest_severity: Severity = "info"
        final_decision: RiskDecision = "allow"

        for event in events:
            if not isinstance(event, Mapping):
                results.append(
                    self._error_result(
                        "Skipped invalid event because it was not a mapping."
                    )
                )
                continue

            result = self.analyze_event(
                user_id=task_context.user_id,
                workspace_id=task_context.workspace_id,
                event=event,
                context=task_context,
            )
            results.append(result)

            if not result.get("success"):
                continue

            result_data = result.get("data") or {}
            total_anomalies += safe_int(
                result_data.get("anomaly_count"),
                0,
            )

            event_score = safe_float(
                result_data.get("risk_score"),
                0.0,
            )
            combined_event_scores.append(event_score)

            event_severity = result_data.get("severity", "info")
            highest_severity = maximum_severity(
                [
                    highest_severity,
                    event_severity,
                ]
            )

            event_decision = result_data.get("decision", "allow")

            decision_order = {
                "allow": 0,
                "allow_with_monitoring": 1,
                "challenge": 2,
                "require_approval": 3,
                "deny": 4,
                "emergency_lock_recommended": 5,
            }

            if (
                decision_order.get(event_decision, 0)
                > decision_order.get(final_decision, 0)
            ):
                final_decision = event_decision

            if (
                stop_on_critical
                and event_severity == "critical"
            ):
                break

        overall_score = self._combine_numeric_scores(
            combined_event_scores
        )

        return self._safe_result(
            success=True,
            message=(
                f"Analyzed {len(results)} event(s) and detected "
                f"{total_anomalies} anomaly signal(s)."
            ),
            data={
                "results": results,
                "events_processed": len(results),
                "anomaly_count": total_anomalies,
                "overall_risk_score": overall_score,
                "highest_severity": highest_severity,
                "decision": final_decision,
                "verification_payload": (
                    self._prepare_verification_payload(
                        "analyze_activity",
                        task_context,
                        {
                            "events_processed": len(results),
                            "anomaly_count": total_anomalies,
                            "overall_risk_score": overall_score,
                            "highest_severity": highest_severity,
                            "decision": final_decision,
                        },
                    )
                ),
            },
            metadata={
                "request_id": task_context.request_id,
            },
        )

    @staticmethod
    def _combine_numeric_scores(
        scores: Sequence[float],
    ) -> float:
        """Combine arbitrary risk scores using probability accumulation."""
        normalized = [
            clamp(score) / 100.0
            for score in scores
            if score > 0
        ]

        if not normalized:
            return 0.0

        remaining = 1.0

        for score in normalized:
            remaining *= 1.0 - score

        return round(
            clamp(100.0 * (1.0 - remaining)),
            2,
        )

    # -------------------------------------------------------------------------
    # Specialized public detection methods
    # -------------------------------------------------------------------------

    def detect_unusual_device(
        self,
        user_id: str,
        workspace_id: str,
        device: Mapping[str, Any],
        context: Optional[
            Union[TaskContext, Mapping[str, Any]]
        ] = None,
        timestamp: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Analyze a device and optional location signal."""
        event = {
            "event_type": "device",
            "timestamp": timestamp or utc_now_iso(),
            "device_id": device.get("device_id"),
            "data": copy.deepcopy(dict(device)),
        }

        return self.analyze_event(
            user_id=user_id,
            workspace_id=workspace_id,
            event=event,
            context=context,
        )

    def detect_voice_anomaly(
        self,
        user_id: str,
        workspace_id: str,
        voice_metrics: Mapping[str, Any],
        context: Optional[
            Union[TaskContext, Mapping[str, Any]]
        ] = None,
        timestamp: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Analyze voice identity, liveness, replay, and feature metrics."""
        event = {
            "event_type": "voice",
            "timestamp": timestamp or utc_now_iso(),
            "data": copy.deepcopy(dict(voice_metrics)),
        }

        return self.analyze_event(
            user_id=user_id,
            workspace_id=workspace_id,
            event=event,
            context=context,
        )

    def detect_command_anomaly(
        self,
        user_id: str,
        workspace_id: str,
        command: str,
        context: Optional[
            Union[TaskContext, Mapping[str, Any]]
        ] = None,
        privileged: bool = False,
        destructive: bool = False,
        metadata: Optional[Mapping[str, Any]] = None,
        timestamp: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Analyze a command and its current usage pattern."""
        event = {
            "event_type": "command",
            "timestamp": timestamp or utc_now_iso(),
            "action": command,
            "data": {
                "command": command,
                "privileged": privileged,
                "destructive": destructive,
            },
            "metadata": copy.deepcopy(dict(metadata or {})),
        }

        return self.analyze_event(
            user_id=user_id,
            workspace_id=workspace_id,
            event=event,
            context=context,
        )

    def detect_failed_attempts(
        self,
        user_id: str,
        workspace_id: str,
        failure_type: str,
        context: Optional[
            Union[TaskContext, Mapping[str, Any]]
        ] = None,
        source: Optional[str] = None,
        reason: Optional[str] = None,
        timestamp: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Register and analyze one failed attempt."""
        event = {
            "event_type": "failed_attempt",
            "timestamp": timestamp or utc_now_iso(),
            "action": failure_type,
            "success": False,
            "data": {
                "failure_type": failure_type,
                "source": source,
                "reason": reason,
            },
            "metadata": copy.deepcopy(dict(metadata or {})),
        }

        return self.analyze_event(
            user_id=user_id,
            workspace_id=workspace_id,
            event=event,
            context=context,
        )

    def detect_mass_export(
        self,
        user_id: str,
        workspace_id: str,
        record_count: int = 0,
        byte_count: int = 0,
        export_type: Optional[str] = None,
        export_scope: Optional[str] = None,
        destination: Optional[str] = None,
        operation_count: int = 1,
        context: Optional[
            Union[TaskContext, Mapping[str, Any]]
        ] = None,
        timestamp: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Analyze file, memory, project, client, or data export behavior."""
        event = {
            "event_type": "export",
            "timestamp": timestamp or utc_now_iso(),
            "action": "export",
            "data": {
                "record_count": max(0, safe_int(record_count)),
                "byte_count": max(0, safe_int(byte_count)),
                "operation_count": max(
                    1,
                    safe_int(operation_count, 1),
                ),
                "export_type": export_type,
                "scope": export_scope,
                "destination_hash": (
                    hash_value(destination)
                    if destination
                    else None
                ),
            },
            "metadata": copy.deepcopy(dict(metadata or {})),
        }

        return self.analyze_event(
            user_id=user_id,
            workspace_id=workspace_id,
            event=event,
            context=context,
        )

    # -------------------------------------------------------------------------
    # Anomaly management and dashboard methods
    # -------------------------------------------------------------------------

    def list_anomalies(
        self,
        user_id: str,
        workspace_id: str,
        context: Optional[
            Union[TaskContext, Mapping[str, Any]]
        ] = None,
        status: Optional[AnomalyStatus] = None,
        severity: Optional[Severity] = None,
        anomaly_type: Optional[AnomalyType] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """List tenant-isolated anomalies for dashboard or API use."""
        valid, task_context, context_error = (
            self._validate_task_context(
                user_id,
                workspace_id,
                context,
            )
        )

        if not valid or task_context is None:
            return self._error_result(
                "Invalid task context.",
                context_error,
            )

        limit = min(max(safe_int(limit, 100), 1), 1000)
        offset = max(safe_int(offset, 0), 0)

        tenant_data = self.storage.get_tenant_data(
            task_context.user_id,
            task_context.workspace_id,
            create=True,
        )

        anomalies = list(
            dict(tenant_data.get("anomalies") or {}).values()
        )

        filtered: List[Dict[str, Any]] = []

        for anomaly in anomalies:
            if status and anomaly.get("status") != status:
                continue

            if severity and anomaly.get("severity") != severity:
                continue

            if (
                anomaly_type
                and anomaly.get("anomaly_type") != anomaly_type
            ):
                continue

            filtered.append(
                redact_sensitive_data(copy.deepcopy(anomaly))
            )

        filtered.sort(
            key=lambda item: parse_datetime(
                item.get("created_at")
            ),
            reverse=True,
        )

        page = filtered[offset:offset + limit]

        return self._safe_result(
            success=True,
            message="Anomalies retrieved successfully.",
            data={
                "anomalies": page,
                "total": len(filtered),
                "limit": limit,
                "offset": offset,
                "has_more": offset + limit < len(filtered),
            },
            metadata={
                "request_id": task_context.request_id,
            },
        )

    def get_anomaly(
        self,
        user_id: str,
        workspace_id: str,
        anomaly_id: str,
        context: Optional[
            Union[TaskContext, Mapping[str, Any]]
        ] = None,
    ) -> Dict[str, Any]:
        """Get one anomaly without crossing tenant boundaries."""
        valid, task_context, context_error = (
            self._validate_task_context(
                user_id,
                workspace_id,
                context,
            )
        )

        if not valid or task_context is None:
            return self._error_result(
                "Invalid task context.",
                context_error,
            )

        tenant_data = self.storage.get_tenant_data(
            task_context.user_id,
            task_context.workspace_id,
            create=True,
        )

        anomaly = dict(
            tenant_data.get("anomalies") or {}
        ).get(anomaly_id)

        if not anomaly:
            return self._error_result(
                "Anomaly was not found in this user/workspace."
            )

        return self._safe_result(
            success=True,
            message="Anomaly retrieved successfully.",
            data={
                "anomaly": redact_sensitive_data(
                    copy.deepcopy(anomaly)
                )
            },
            metadata={
                "request_id": task_context.request_id,
            },
        )

    def update_anomaly_status(
        self,
        user_id: str,
        workspace_id: str,
        anomaly_id: str,
        status: AnomalyStatus,
        context: Optional[
            Union[TaskContext, Mapping[str, Any]]
        ] = None,
        note: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Acknowledge, investigate, resolve, or mark a false positive."""
        valid, task_context, context_error = (
            self._validate_task_context(
                user_id,
                workspace_id,
                context,
            )
        )

        if not valid or task_context is None:
            return self._error_result(
                "Invalid task context.",
                context_error,
            )

        allowed_statuses: Set[str] = {
            "open",
            "acknowledged",
            "investigating",
            "resolved",
            "false_positive",
        }

        if status not in allowed_statuses:
            return self._error_result(
                f"Unsupported anomaly status: {status}"
            )

        action = (
            "mark_false_positive"
            if status == "false_positive"
            else "update_anomaly_status"
        )

        if self._requires_security_check(action):
            approval = self._request_security_approval(
                action,
                task_context,
                {
                    "anomaly_id": anomaly_id,
                    "status": status,
                    "note": note,
                },
            )

            if not approval.get("approved"):
                return self._error_result(
                    "Security approval denied.",
                    approval,
                )

        with self._operation_lock:
            tenant_data = self.storage.get_tenant_data(
                task_context.user_id,
                task_context.workspace_id,
                create=True,
            )

            anomalies = dict(
                tenant_data.get("anomalies") or {}
            )
            anomaly = anomalies.get(anomaly_id)

            if not anomaly:
                return self._error_result(
                    "Anomaly was not found in this user/workspace."
                )

            anomaly["status"] = status
            anomaly["updated_at"] = utc_now_iso()

            if status in {
                "acknowledged",
                "investigating",
                "resolved",
                "false_positive",
            }:
                anomaly["acknowledged_at"] = utc_now_iso()
                anomaly["acknowledged_by"] = (
                    task_context.user_id
                )

            if note is not None:
                anomaly["resolution_note"] = str(note)[:5000]

            anomaly["false_positive"] = (
                status == "false_positive"
            )
            anomalies[anomaly_id] = anomaly
            tenant_data["anomalies"] = anomalies

            self.storage.replace_tenant_data(
                task_context.user_id,
                task_context.workspace_id,
                tenant_data,
            )

        self._log_audit_event(
            action,
            task_context,
            {
                "anomaly_id": anomaly_id,
                "status": status,
            },
            success=True,
        )

        self._emit_agent_event(
            "security.anomaly_status_updated",
            task_context,
            {
                "anomaly_id": anomaly_id,
                "status": status,
            },
        )

        return self._safe_result(
            success=True,
            message="Anomaly status updated successfully.",
            data={
                "anomaly": redact_sensitive_data(anomaly),
                "verification_payload": (
                    self._prepare_verification_payload(
                        action,
                        task_context,
                        {
                            "anomaly_id": anomaly_id,
                            "status": status,
                        },
                    )
                ),
            },
            metadata={
                "request_id": task_context.request_id,
            },
        )

    def get_dashboard_summary(
        self,
        user_id: str,
        workspace_id: str,
        context: Optional[
            Union[TaskContext, Mapping[str, Any]]
        ] = None,
        days: int = 7,
    ) -> Dict[str, Any]:
        """Return dashboard-ready anomaly statistics."""
        valid, task_context, context_error = (
            self._validate_task_context(
                user_id,
                workspace_id,
                context,
            )
        )

        if not valid or task_context is None:
            return self._error_result(
                "Invalid task context.",
                context_error,
            )

        days = min(max(safe_int(days, 7), 1), 365)
        cutoff = utc_now() - timedelta(days=days)

        tenant_data = self.storage.get_tenant_data(
            task_context.user_id,
            task_context.workspace_id,
            create=True,
        )

        anomalies = [
            anomaly
            for anomaly in dict(
                tenant_data.get("anomalies") or {}
            ).values()
            if parse_datetime(anomaly.get("created_at")) >= cutoff
        ]

        severity_counts: Counter[str] = Counter()
        type_counts: Counter[str] = Counter()
        status_counts: Counter[str] = Counter()
        decision_counts: Counter[str] = Counter()
        daily_counts: Counter[str] = Counter()
        scores: List[float] = []

        for anomaly in anomalies:
            severity_counts[str(anomaly.get("severity", "info"))] += 1
            type_counts[str(anomaly.get("anomaly_type", "unknown"))] += 1
            status_counts[str(anomaly.get("status", "open"))] += 1
            decision_counts[str(anomaly.get("decision", "allow"))] += 1
            day = parse_datetime(
                anomaly.get("created_at")
            ).date().isoformat()
            daily_counts[day] += 1
            scores.append(
                safe_float(anomaly.get("score"), 0.0)
            )

        baseline = self._baseline_from_dict(
            task_context.user_id,
            task_context.workspace_id,
            tenant_data.get("baseline"),
        )

        highest_score = max(scores) if scores else 0.0
        average_score = (
            round(statistics.fmean(scores), 2)
            if scores
            else 0.0
        )

        return self._safe_result(
            success=True,
            message="Anomaly dashboard summary generated.",
            data={
                "period_days": days,
                "total_anomalies": len(anomalies),
                "open_anomalies": status_counts.get("open", 0),
                "critical_anomalies": severity_counts.get(
                    "critical",
                    0,
                ),
                "high_anomalies": severity_counts.get("high", 0),
                "highest_score": round(highest_score, 2),
                "average_score": average_score,
                "severity_counts": dict(severity_counts),
                "type_counts": dict(type_counts),
                "status_counts": dict(status_counts),
                "decision_counts": dict(decision_counts),
                "daily_counts": dict(
                    sorted(daily_counts.items())
                ),
                "baseline": {
                    "status": baseline.status,
                    "event_count": baseline.event_count,
                    "trusted_device_count": sum(
                        1
                        for value
                        in baseline.trusted_devices.values()
                        if value.get("trusted")
                    ),
                    "known_location_count": len(
                        baseline.known_locations
                    ),
                    "known_command_count": len(
                        baseline.command_signatures
                    ),
                    "last_seen_at": baseline.last_seen_at,
                    "updated_at": baseline.updated_at,
                },
            },
            metadata={
                "request_id": task_context.request_id,
            },
        )

    # -------------------------------------------------------------------------
    # Baseline and retention management
    # -------------------------------------------------------------------------

    def get_baseline(
        self,
        user_id: str,
        workspace_id: str,
        context: Optional[
            Union[TaskContext, Mapping[str, Any]]
        ] = None,
    ) -> Dict[str, Any]:
        """Return a privacy-safe summary of the behavior baseline."""
        valid, task_context, context_error = (
            self._validate_task_context(
                user_id,
                workspace_id,
                context,
            )
        )

        if not valid or task_context is None:
            return self._error_result(
                "Invalid task context.",
                context_error,
            )

        baseline = self._load_baseline(task_context)

        summary = {
            "user_id": baseline.user_id,
            "workspace_id": baseline.workspace_id,
            "status": baseline.status,
            "event_count": baseline.event_count,
            "trusted_devices": [
                {
                    "fingerprint": fingerprint[:16],
                    "trusted": bool(record.get("trusted")),
                    "seen_count": safe_int(
                        record.get("seen_count")
                    ),
                    "first_seen_at": record.get(
                        "first_seen_at"
                    ),
                    "last_seen_at": record.get(
                        "last_seen_at"
                    ),
                }
                for fingerprint, record
                in baseline.trusted_devices.items()
            ],
            "known_location_count": len(
                baseline.known_locations
            ),
            "voice_similarity_sample_count": len(
                baseline.voice_similarity_samples
            ),
            "voice_liveness_sample_count": len(
                baseline.voice_liveness_samples
            ),
            "voice_feature_names": sorted(
                baseline.voice_feature_samples.keys()
            ),
            "known_command_count": len(
                baseline.command_signatures
            ),
            "command_hour_histogram": copy.deepcopy(
                baseline.command_hour_histogram
            ),
            "failed_attempt_sample_count": len(
                baseline.failed_attempt_rate_samples
            ),
            "export_sample_count": len(
                baseline.export_record_samples
            ),
            "last_seen_at": baseline.last_seen_at,
            "created_at": baseline.created_at,
            "updated_at": baseline.updated_at,
        }

        return self._safe_result(
            success=True,
            message="Behavior baseline retrieved successfully.",
            data={"baseline": summary},
            metadata={
                "request_id": task_context.request_id,
            },
        )

    def reset_baseline(
        self,
        user_id: str,
        workspace_id: str,
        context: Optional[
            Union[TaskContext, Mapping[str, Any]]
        ] = None,
        preserve_events: bool = True,
        preserve_anomalies: bool = True,
    ) -> Dict[str, Any]:
        """Reset only the current user/workspace behavior baseline."""
        valid, task_context, context_error = (
            self._validate_task_context(
                user_id,
                workspace_id,
                context,
            )
        )

        if not valid or task_context is None:
            return self._error_result(
                "Invalid task context.",
                context_error,
            )

        approval = self._request_security_approval(
            "reset_baseline",
            task_context,
            {
                "preserve_events": preserve_events,
                "preserve_anomalies": preserve_anomalies,
            },
        )

        if not approval.get("approved"):
            return self._error_result(
                "Security approval denied for baseline reset.",
                approval,
            )

        with self._operation_lock:
            tenant_data = self.storage.get_tenant_data(
                task_context.user_id,
                task_context.workspace_id,
                create=True,
            )

            tenant_data["baseline"] = asdict(
                BehaviorBaseline(
                    user_id=task_context.user_id,
                    workspace_id=task_context.workspace_id,
                )
            )

            if not preserve_events:
                tenant_data["events"] = []

            if not preserve_anomalies:
                tenant_data["anomalies"] = {}

            self.storage.replace_tenant_data(
                task_context.user_id,
                task_context.workspace_id,
                tenant_data,
            )

        self._log_audit_event(
            "reset_baseline",
            task_context,
            {
                "preserve_events": preserve_events,
                "preserve_anomalies": preserve_anomalies,
            },
            success=True,
        )

        return self._safe_result(
            success=True,
            message="Behavior baseline reset successfully.",
            data={
                "baseline_reset": True,
                "events_preserved": preserve_events,
                "anomalies_preserved": preserve_anomalies,
                "verification_payload": (
                    self._prepare_verification_payload(
                        "reset_baseline",
                        task_context,
                        {
                            "baseline_reset": True,
                            "events_preserved": preserve_events,
                            "anomalies_preserved": preserve_anomalies,
                        },
                    )
                ),
            },
            metadata={
                "request_id": task_context.request_id,
            },
        )

    def clear_tenant_history(
        self,
        user_id: str,
        workspace_id: str,
        context: Optional[
            Union[TaskContext, Mapping[str, Any]]
        ] = None,
    ) -> Dict[str, Any]:
        """
        Clear event, anomaly, and baseline history for one tenant context.

        This never affects another user or workspace.
        """
        valid, task_context, context_error = (
            self._validate_task_context(
                user_id,
                workspace_id,
                context,
            )
        )

        if not valid or task_context is None:
            return self._error_result(
                "Invalid task context.",
                context_error,
            )

        approval = self._request_security_approval(
            "clear_tenant_history",
            task_context,
            {
                "destructive": True,
                "scope": "current_user_workspace",
            },
        )

        if not approval.get("approved"):
            return self._error_result(
                "Security approval denied for tenant history deletion.",
                approval,
            )

        empty_data = {
            "user_id": task_context.user_id,
            "workspace_id": task_context.workspace_id,
            "events": [],
            "anomalies": {},
            "baseline": asdict(
                BehaviorBaseline(
                    user_id=task_context.user_id,
                    workspace_id=task_context.workspace_id,
                )
            ),
            "created_at": utc_now_iso(),
            "updated_at": utc_now_iso(),
        }

        self.storage.replace_tenant_data(
            task_context.user_id,
            task_context.workspace_id,
            empty_data,
        )

        self._log_audit_event(
            "clear_tenant_history",
            task_context,
            {
                "scope": "current_user_workspace",
            },
            success=True,
        )

        return self._safe_result(
            success=True,
            message=(
                "Anomaly history was cleared for the current "
                "user/workspace only."
            ),
            data={
                "cleared": True,
                "verification_payload": (
                    self._prepare_verification_payload(
                        "clear_tenant_history",
                        task_context,
                        {"cleared": True},
                    )
                ),
            },
            metadata={
                "request_id": task_context.request_id,
            },
        )

    def prune_history(
        self,
        user_id: str,
        workspace_id: str,
        context: Optional[
            Union[TaskContext, Mapping[str, Any]]
        ] = None,
        retention_days: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Remove expired tenant-local events and resolved anomalies."""
        valid, task_context, context_error = (
            self._validate_task_context(
                user_id,
                workspace_id,
                context,
            )
        )

        if not valid or task_context is None:
            return self._error_result(
                "Invalid task context.",
                context_error,
            )

        days = (
            safe_int(retention_days)
            if retention_days is not None
            else safe_int(
                self.thresholds.get(
                    "history_retention_days"
                ),
                30,
            )
        )

        days = min(max(days, 1), 3650)
        cutoff = utc_now() - timedelta(days=days)

        with self._operation_lock:
            tenant_data = self.storage.get_tenant_data(
                task_context.user_id,
                task_context.workspace_id,
                create=True,
            )

            old_events = list(
                tenant_data.get("events") or []
            )
            kept_events = [
                event
                for event in old_events
                if parse_datetime(event.get("timestamp")) >= cutoff
            ]

            old_anomalies = dict(
                tenant_data.get("anomalies") or {}
            )
            kept_anomalies: Dict[str, Any] = {}

            for anomaly_id, anomaly in old_anomalies.items():
                created_at = parse_datetime(
                    anomaly.get("created_at")
                )
                status = anomaly.get("status", "open")

                if (
                    created_at >= cutoff
                    or status in {
                        "open",
                        "acknowledged",
                        "investigating",
                    }
                ):
                    kept_anomalies[anomaly_id] = anomaly

            tenant_data["events"] = kept_events
            tenant_data["anomalies"] = kept_anomalies

            self.storage.replace_tenant_data(
                task_context.user_id,
                task_context.workspace_id,
                tenant_data,
            )

        deleted_events = len(old_events) - len(kept_events)
        deleted_anomalies = (
            len(old_anomalies) - len(kept_anomalies)
        )

        return self._safe_result(
            success=True,
            message="Expired anomaly history pruned successfully.",
            data={
                "retention_days": days,
                "deleted_events": deleted_events,
                "deleted_anomalies": deleted_anomalies,
                "remaining_events": len(kept_events),
                "remaining_anomalies": len(kept_anomalies),
            },
            metadata={
                "request_id": task_context.request_id,
            },
        )

    # -------------------------------------------------------------------------
    # Configuration
    # -------------------------------------------------------------------------

    def get_thresholds(self) -> Dict[str, Any]:
        """Return active anomaly detection thresholds."""
        return self._safe_result(
            success=True,
            message="Anomaly detection thresholds retrieved.",
            data={
                "thresholds": copy.deepcopy(self.thresholds)
            },
        )

    def update_thresholds(
        self,
        user_id: str,
        workspace_id: str,
        updates: Mapping[str, Any],
        context: Optional[
            Union[TaskContext, Mapping[str, Any]]
        ] = None,
    ) -> Dict[str, Any]:
        """
        Update anomaly thresholds after Security Agent approval.

        Unknown keys are rejected to avoid accidental configuration mistakes.
        """
        valid, task_context, context_error = (
            self._validate_task_context(
                user_id,
                workspace_id,
                context,
            )
        )

        if not valid or task_context is None:
            return self._error_result(
                "Invalid task context.",
                context_error,
            )

        if not isinstance(updates, Mapping) or not updates:
            return self._error_result(
                "updates must be a non-empty mapping."
            )

        unknown_keys = [
            key
            for key in updates
            if key not in DEFAULT_THRESHOLDS
        ]

        if unknown_keys:
            return self._error_result(
                "One or more threshold keys are unsupported.",
                {
                    "unknown_keys": unknown_keys,
                    "supported_keys": sorted(
                        DEFAULT_THRESHOLDS.keys()
                    ),
                },
            )

        validated_updates: Dict[str, Any] = {}

        for key, value in updates.items():
            default_value = DEFAULT_THRESHOLDS[key]

            if isinstance(default_value, bool):
                validated_updates[key] = bool(value)
            elif isinstance(default_value, int):
                converted = safe_int(value, default_value)

                if converted < 0:
                    return self._error_result(
                        f"Threshold '{key}' cannot be negative."
                    )

                validated_updates[key] = converted
            elif isinstance(default_value, float):
                converted = safe_float(value, default_value)

                if converted < 0:
                    return self._error_result(
                        f"Threshold '{key}' cannot be negative."
                    )

                validated_updates[key] = converted
            else:
                validated_updates[key] = copy.deepcopy(value)

        approval = self._request_security_approval(
            "update_thresholds",
            task_context,
            {
                "updates": validated_updates,
            },
        )

        if not approval.get("approved"):
            return self._error_result(
                "Security approval denied for threshold update.",
                approval,
            )

        updated = self.storage.update_thresholds(
            validated_updates
        )
        self.thresholds = deep_merge(
            DEFAULT_THRESHOLDS,
            updated,
        )

        self._log_audit_event(
            "update_thresholds",
            task_context,
            {
                "updated_keys": sorted(
                    validated_updates.keys()
                )
            },
            success=True,
        )

        return self._safe_result(
            success=True,
            message="Anomaly detection thresholds updated.",
            data={
                "thresholds": copy.deepcopy(self.thresholds),
                "updated_keys": sorted(
                    validated_updates.keys()
                ),
                "verification_payload": (
                    self._prepare_verification_payload(
                        "update_thresholds",
                        task_context,
                        {
                            "updated_keys": sorted(
                                validated_updates.keys()
                            )
                        },
                    )
                ),
            },
            metadata={
                "request_id": task_context.request_id,
            },
        )

    # -------------------------------------------------------------------------
    # Master Agent and router compatibility
    # -------------------------------------------------------------------------

    def handle_task(
        self,
        task: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Generic Agent Router and Master Agent entry point.

        Supported actions:
            - analyze_event
            - analyze_activity
            - detect_unusual_device
            - detect_voice_anomaly
            - detect_command_anomaly
            - detect_failed_attempts
            - detect_mass_export
            - list_anomalies
            - get_anomaly
            - update_anomaly_status
            - get_dashboard_summary
            - get_baseline
            - reset_baseline
            - prune_history
            - get_thresholds
            - update_thresholds
            - health_check
        """
        if not isinstance(task, Mapping):
            return self._error_result(
                "task must be a mapping."
            )

        action = normalize_text(
            task.get("action")
            or task.get("task_type")
            or "",
            255,
        )

        user_id = str(task.get("user_id") or "").strip()
        workspace_id = str(
            task.get("workspace_id") or ""
        ).strip()
        context = task.get("context")
        payload = task.get("payload") or {}

        if not isinstance(payload, Mapping):
            return self._error_result(
                "task.payload must be a mapping."
            )

        routes: Dict[str, Callable[..., Dict[str, Any]]] = {
            "analyze_event": self.analyze_event,
            "analyze_activity": self.analyze_activity,
            "detect_unusual_device": self.detect_unusual_device,
            "detect_voice_anomaly": self.detect_voice_anomaly,
            "detect_command_anomaly": self.detect_command_anomaly,
            "detect_failed_attempts": self.detect_failed_attempts,
            "detect_mass_export": self.detect_mass_export,
            "list_anomalies": self.list_anomalies,
            "get_anomaly": self.get_anomaly,
            "update_anomaly_status": self.update_anomaly_status,
            "get_dashboard_summary": self.get_dashboard_summary,
            "get_baseline": self.get_baseline,
            "reset_baseline": self.reset_baseline,
            "prune_history": self.prune_history,
            "get_thresholds": self.get_thresholds,
            "update_thresholds": self.update_thresholds,
            "health_check": self.health_check,
        }

        handler = routes.get(action)

        if handler is None:
            return self._error_result(
                f"Unsupported anomaly detector action: {action}",
                {
                    "supported_actions": sorted(routes.keys())
                },
            )

        if action in {"health_check", "get_thresholds"}:
            return handler()

        try:
            return handler(
                user_id=user_id,
                workspace_id=workspace_id,
                context=context,
                **copy.deepcopy(dict(payload)),
            )
        except TypeError as exc:
            return self._error_result(
                "Invalid task payload for the selected action.",
                exc,
                metadata={"action": action},
            )
        except Exception as exc:
            self.logger.exception(
                "AnomalyDetector task routing failed."
            )

            return self._error_result(
                "AnomalyDetector task execution failed.",
                exc,
                metadata={"action": action},
            )

    def get_agent_manifest(self) -> Dict[str, Any]:
        """Return Agent Registry and Loader-compatible metadata."""
        return {
            "agent_name": self.agent_name,
            "agent_type": self.agent_type,
            "agent_id": "security_agent.anomaly_detector",
            "version": self.version,
            "module": "agents.security_agent.anomaly_detector",
            "class_name": "AnomalyDetector",
            "description": (
                "Detects unusual devices, voice changes, command patterns, "
                "failed attempts, and mass export activity."
            ),
            "capabilities": [
                "device_anomaly_detection",
                "impossible_travel_detection",
                "voice_identity_anomaly_detection",
                "voice_spoof_detection",
                "command_pattern_detection",
                "failed_attempt_detection",
                "distributed_attack_detection",
                "mass_export_detection",
                "behavior_baseline_learning",
                "risk_scoring",
                "dashboard_statistics",
            ],
            "public_methods": [
                "analyze_event",
                "analyze_activity",
                "detect_unusual_device",
                "detect_voice_anomaly",
                "detect_command_anomaly",
                "detect_failed_attempts",
                "detect_mass_export",
                "list_anomalies",
                "get_anomaly",
                "update_anomaly_status",
                "get_dashboard_summary",
                "get_baseline",
                "reset_baseline",
                "clear_tenant_history",
                "prune_history",
                "get_thresholds",
                "update_thresholds",
                "handle_task",
                "health_check",
            ],
            "routing_actions": [
                "analyze_event",
                "analyze_activity",
                "detect_unusual_device",
                "detect_voice_anomaly",
                "detect_command_anomaly",
                "detect_failed_attempts",
                "detect_mass_export",
                "list_anomalies",
                "get_dashboard_summary",
            ],
            "context_requirements": {
                "user_id": True,
                "workspace_id": True,
                "request_id": "recommended",
                "session_id": "recommended",
                "device_id": "optional",
            },
            "integration": {
                "master_agent": True,
                "security_agent": True,
                "memory_agent": "payload_compatible",
                "verification_agent": "payload_compatible",
                "agent_registry": True,
                "agent_loader": True,
                "agent_router": True,
                "dashboard_api": True,
            },
            "safety": {
                "tenant_isolation": True,
                "sensitive_data_redaction": True,
                "no_direct_blocking_actions": True,
                "security_approval_for_destructive_management": True,
                "atomic_storage_writes": True,
            },
            "storage": {
                "default_backend": "json",
                "storage_file": str(self.storage.storage_file),
                "replaceable": True,
            },
        }

    # -------------------------------------------------------------------------
    # Health check
    # -------------------------------------------------------------------------

    def health_check(self) -> Dict[str, Any]:
        """Return operational health for API and dashboard monitoring."""
        try:
            storage_data = self.storage.load()
            tenant_count = len(
                storage_data.get("tenant_data", {})
            )

            return self._safe_result(
                success=True,
                message="AnomalyDetector is healthy.",
                data={
                    "status": "healthy",
                    "storage_accessible": True,
                    "storage_file": str(
                        self.storage.storage_file
                    ),
                    "tenant_count": tenant_count,
                    "threshold_count": len(self.thresholds),
                    "security_agent_available": (
                        self.security_agent is not None
                    ),
                    "verification_agent_available": (
                        self.verification_agent is not None
                    ),
                    "audit_logger_available": (
                        self.audit_logger is not None
                    ),
                    "risk_engine_available": (
                        self.risk_engine is not None
                    ),
                    "supported_event_types": [
                        "device",
                        "voice",
                        "command",
                        "failed_attempt",
                        "export",
                        "generic",
                    ],
                },
                metadata={
                    "manifest": self.get_agent_manifest(),
                },
            )

        except Exception as exc:
            return self._error_result(
                "AnomalyDetector health check failed.",
                exc,
            )


# =============================================================================
# Standalone smoke test
# =============================================================================

def _run_smoke_test() -> Dict[str, Any]:
    """
    Run a local isolated smoke test.

    Command:
        python agents/security_agent/anomaly_detector.py
    """
    smoke_storage = (
        DEFAULT_STORAGE_DIRECTORY
        / "anomaly_detector_smoke_test.json"
    )

    try:
        smoke_storage.unlink(missing_ok=True)
    except Exception:
        pass

    detector = AnomalyDetector(
        storage_file=smoke_storage,
        enable_agent_events=False,
        enable_audit_logs=False,
    )

    user_id = "smoke_user"
    workspace_id = "smoke_workspace"

    first_device = detector.detect_unusual_device(
        user_id=user_id,
        workspace_id=workspace_id,
        device={
            "device_id": "device_one",
            "platform": "android",
            "os": "Android",
            "os_version": "15",
            "browser": "Chrome",
            "model": "Test Device",
            "country": "PK",
            "city": "lahore",
            "latitude": 31.5204,
            "longitude": 74.3587,
        },
    )

    voice_result = detector.detect_voice_anomaly(
        user_id=user_id,
        workspace_id=workspace_id,
        voice_metrics={
            "speaker_similarity": 0.42,
            "liveness_score": 0.40,
            "replay_score": 0.82,
            "synthetic_voice_suspected": True,
        },
    )

    command_results: List[Dict[str, Any]] = []

    for _ in range(8):
        command_results.append(
            detector.detect_command_anomaly(
                user_id=user_id,
                workspace_id=workspace_id,
                command="delete all project files",
                privileged=True,
                destructive=True,
            )
        )

    failed_results: List[Dict[str, Any]] = []

    for index in range(6):
        failed_results.append(
            detector.detect_failed_attempts(
                user_id=user_id,
                workspace_id=workspace_id,
                failure_type="login_failure",
                source=f"source_{index}",
                reason="invalid_credentials",
            )
        )

    export_result = detector.detect_mass_export(
        user_id=user_id,
        workspace_id=workspace_id,
        record_count=150000,
        byte_count=12 * 1024 * 1024 * 1024,
        export_type="client_data",
        export_scope="workspace_all",
        destination="external_destination",
    )

    summary = detector.get_dashboard_summary(
        user_id=user_id,
        workspace_id=workspace_id,
    )

    health = detector.health_check()

    return {
        "first_device_success": first_device.get("success"),
        "voice_anomaly_detected": (
            voice_result.get("data", {}).get(
                "anomaly_detected"
            )
        ),
        "command_tests_completed": len(command_results),
        "failed_attempt_tests_completed": len(failed_results),
        "mass_export_detected": (
            export_result.get("data", {}).get(
                "anomaly_detected"
            )
        ),
        "dashboard_total_anomalies": (
            summary.get("data", {}).get(
                "total_anomalies"
            )
        ),
        "health_success": health.get("success"),
    }


if __name__ == "__main__":
    print(
        json.dumps(
            _run_smoke_test(),
            indent=2,
            ensure_ascii=False,
            default=str,
        )
    )