"""
agents/security_agent/device_access.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Trusted devices, unknown device blocking, and device permissions.

This module provides a production-oriented device-access security layer for the
William/Jarvis Security Agent. It supports:

    - Trusted-device enrollment and approval.
    - Unknown-device detection and blocking.
    - Device fingerprints without storing raw secrets.
    - Device-specific permissions and permission scopes.
    - User/workspace SaaS isolation.
    - Device suspension, revocation, blocking, and restoration.
    - Verification challenges for new or suspicious devices.
    - Session-to-device binding checks.
    - Device risk signals and configurable access policies.
    - Expiring trust and expiring permissions.
    - Structured JSON/dict results.
    - Audit logging and agent events.
    - Verification Agent and Memory Agent payloads.
    - FastAPI/dashboard-compatible public interfaces.
    - Safe imports when the wider William/Jarvis project is incomplete.

Security notes:
    - Raw device secrets, access tokens, passwords, biometric data, and private
      keys must never be stored in this module.
    - Device fingerprints are generated through one-way HMAC hashing.
    - Production deployments should provide WILLIAM_DEVICE_FINGERPRINT_SECRET.
    - Unknown devices are blocked by default unless explicitly configured.
    - All stored records are isolated by user_id and workspace_id.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Literal, Mapping, Optional, Sequence, Set, Tuple, Union


# =============================================================================
# Optional William/Jarvis imports
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Import-safe fallback BaseAgent.

        The real William/Jarvis BaseAgent can replace this class automatically
        when available.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())
            self.logger = logging.getLogger(self.agent_name)

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback event: %s | %s", event_name, payload)

        def log_audit(self, action: str, payload: Dict[str, Any]) -> None:
            self.logger.info("Fallback audit: %s | %s", action, payload)


try:
    from agents.security_agent.permission_checker import PermissionChecker  # type: ignore
except Exception:  # pragma: no cover
    PermissionChecker = None  # type: ignore


try:
    from agents.security_agent.risk_engine import RiskEngine  # type: ignore
except Exception:  # pragma: no cover
    RiskEngine = None  # type: ignore


try:
    from agents.security_agent.audit_logger import AuditLogger  # type: ignore
except Exception:  # pragma: no cover
    AuditLogger = None  # type: ignore


try:
    from agents.security_agent.approval_manager import ApprovalManager  # type: ignore
except Exception:  # pragma: no cover
    ApprovalManager = None  # type: ignore


# =============================================================================
# Type definitions
# =============================================================================

DeviceStatus = Literal[
    "pending",
    "trusted",
    "limited",
    "suspended",
    "blocked",
    "revoked",
    "expired",
]

DeviceType = Literal[
    "desktop",
    "laptop",
    "mobile",
    "tablet",
    "server",
    "browser",
    "wearable",
    "iot",
    "unknown",
]

TrustLevel = Literal[
    "untrusted",
    "pending",
    "limited",
    "trusted",
    "privileged",
]

PermissionEffect = Literal[
    "allow",
    "deny",
]

PermissionScope = Literal[
    "device",
    "workspace",
    "agent",
    "action",
    "resource",
    "system",
]

ChallengeStatus = Literal[
    "pending",
    "verified",
    "failed",
    "expired",
    "cancelled",
]

RiskLevel = Literal[
    "low",
    "medium",
    "high",
    "critical",
]

UnknownDevicePolicy = Literal[
    "block",
    "challenge",
    "limited",
    "allow",
]


# =============================================================================
# Exceptions
# =============================================================================

class DeviceAccessError(Exception):
    """Base exception for device-access operations."""


class DeviceValidationError(DeviceAccessError):
    """Raised when device data or task context is invalid."""


class DeviceNotFoundError(DeviceAccessError):
    """Raised when a device record cannot be found."""


class DeviceSecurityError(DeviceAccessError):
    """Raised when a security rule blocks an operation."""


class DeviceStorageError(DeviceAccessError):
    """Raised when device storage cannot be read or written."""


# =============================================================================
# Utility functions
# =============================================================================

def _utc_now() -> datetime:
    """Return the current timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def _utc_now_iso() -> str:
    """Return the current UTC datetime in ISO-8601 format."""
    return _utc_now().isoformat()


def _parse_datetime(value: Optional[str]) -> Optional[datetime]:
    """Safely parse an ISO-8601 datetime."""
    if not value:
        return None

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def _safe_text(
    value: Any,
    max_length: int = 1_000,
    *,
    allow_empty: bool = True,
) -> str:
    """Convert a value into a bounded, normalized string."""
    if value is None:
        return ""

    text = str(value).replace("\x00", "").strip()

    if not allow_empty and not text:
        raise DeviceValidationError("A required text value was empty.")

    if len(text) > max_length:
        text = text[:max_length]

    return text


def _normalize_identifier(value: Any, field_name: str) -> str:
    """Normalize and validate a SaaS identifier."""
    text = _safe_text(value, 200)

    if not text:
        raise DeviceValidationError(f"{field_name} is required.")

    if not re.fullmatch(r"[A-Za-z0-9._:@+\-]{1,200}", text):
        raise DeviceValidationError(
            f"{field_name} contains unsupported characters."
        )

    return text


def _normalize_permission_name(value: Any) -> str:
    """Normalize a device permission name."""
    text = _safe_text(value, 200).lower()
    text = re.sub(r"[^a-z0-9._:\-*]+", "_", text)
    text = text.strip("._:")

    if not text:
        raise DeviceValidationError("Permission name cannot be empty.")

    return text


def _normalize_string_list(
    values: Optional[Union[str, Iterable[Any]]],
    *,
    max_items: int = 200,
    max_length: int = 300,
) -> List[str]:
    """Normalize a string or iterable into a deduplicated list."""
    if values is None:
        return []

    if isinstance(values, str):
        source = [values]
    else:
        source = list(values)

    result: List[str] = []
    seen: Set[str] = set()

    for item in source[:max_items]:
        text = _safe_text(item, max_length)
        if not text:
            continue

        key = text.lower()
        if key in seen:
            continue

        seen.add(key)
        result.append(text)

    return result


def _deepcopy_jsonable(value: Any) -> Any:
    """Return a JSON-safe deep copy where possible."""
    try:
        return json.loads(json.dumps(value, default=str))
    except Exception:
        return copy.deepcopy(value)


def _constant_time_equal(left: str, right: str) -> bool:
    """Perform constant-time string comparison."""
    return hmac.compare_digest(
        left.encode("utf-8"),
        right.encode("utf-8"),
    )


def _clamp_int(
    value: Any,
    minimum: int,
    maximum: int,
    default: int,
) -> int:
    """Return an integer constrained to a safe range."""
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default

    return max(minimum, min(parsed, maximum))


# =============================================================================
# Data models
# =============================================================================

@dataclass
class DevicePermission:
    """
    Permission assigned to a specific trusted device.

    A deny permission always takes precedence over a matching allow permission.
    """

    permission: str
    effect: PermissionEffect = "allow"
    scope: PermissionScope = "device"
    resource: Optional[str] = None
    agent_name: Optional[str] = None
    action: Optional[str] = None
    conditions: Dict[str, Any] = field(default_factory=dict)

    granted_by: Optional[str] = None
    granted_at: str = field(default_factory=_utc_now_iso)
    expires_at: Optional[str] = None

    active: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        """Return True when this permission has expired."""
        if not self.expires_at:
            return False

        expires = _parse_datetime(self.expires_at)
        if expires is None:
            return True

        return expires <= (now or _utc_now())

    def matches(
        self,
        permission: str,
        *,
        resource: Optional[str] = None,
        agent_name: Optional[str] = None,
        action: Optional[str] = None,
    ) -> bool:
        """Return True when the permission rule matches a request."""
        if not self.active or self.is_expired():
            return False

        requested = _normalize_permission_name(permission)
        stored = _normalize_permission_name(self.permission)

        permission_match = (
            stored == requested
            or stored == "*"
            or (
                stored.endswith("*")
                and requested.startswith(stored[:-1])
            )
        )

        if not permission_match:
            return False

        if self.resource is not None:
            if resource is None:
                return False
            if not _resource_matches(self.resource, resource):
                return False

        if self.agent_name is not None:
            if agent_name is None:
                return False
            if self.agent_name.lower() != agent_name.lower():
                return False

        if self.action is not None:
            if action is None:
                return False
            if self.action.lower() != action.lower():
                return False

        return True

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-safe dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "DevicePermission":
        """Build a permission object from stored data."""
        data = dict(payload)

        return cls(
            permission=_normalize_permission_name(
                data.get("permission", "unknown")
            ),
            effect=(
                data.get("effect")
                if data.get("effect") in {"allow", "deny"}
                else "allow"
            ),
            scope=(
                data.get("scope")
                if data.get("scope") in {
                    "device",
                    "workspace",
                    "agent",
                    "action",
                    "resource",
                    "system",
                }
                else "device"
            ),
            resource=_safe_text(data.get("resource"), 500) or None,
            agent_name=_safe_text(data.get("agent_name"), 200) or None,
            action=_safe_text(data.get("action"), 200) or None,
            conditions=_deepcopy_jsonable(data.get("conditions") or {}),
            granted_by=_safe_text(data.get("granted_by"), 200) or None,
            granted_at=_safe_text(
                data.get("granted_at") or _utc_now_iso(),
                100,
            ),
            expires_at=_safe_text(data.get("expires_at"), 100) or None,
            active=bool(data.get("active", True)),
            metadata=_deepcopy_jsonable(data.get("metadata") or {}),
        )


@dataclass
class DeviceRecord:
    """
    Trusted or observed device record.

    Raw device identifiers are not stored. The `fingerprint_hash` field contains
    a one-way HMAC fingerprint.
    """

    device_id: str
    user_id: str
    workspace_id: str

    fingerprint_hash: str
    display_name: str
    device_type: DeviceType = "unknown"

    status: DeviceStatus = "pending"
    trust_level: TrustLevel = "pending"

    platform: Optional[str] = None
    operating_system: Optional[str] = None
    browser: Optional[str] = None
    app_version: Optional[str] = None

    public_key_fingerprint: Optional[str] = None

    permissions: List[DevicePermission] = field(default_factory=list)
    denied_permissions: List[str] = field(default_factory=list)

    first_seen_at: str = field(default_factory=_utc_now_iso)
    last_seen_at: str = field(default_factory=_utc_now_iso)
    trusted_at: Optional[str] = None
    trust_expires_at: Optional[str] = None

    last_ip_hash: Optional[str] = None
    last_country_code: Optional[str] = None
    last_region: Optional[str] = None

    failed_verification_attempts: int = 0
    successful_verifications: int = 0
    risk_score: float = 0.0
    risk_level: RiskLevel = "low"
    risk_reasons: List[str] = field(default_factory=list)

    created_by: Optional[str] = None
    updated_by: Optional[str] = None
    revoked_by: Optional[str] = None
    revoked_at: Optional[str] = None
    revoke_reason: Optional[str] = None

    metadata: Dict[str, Any] = field(default_factory=dict)
    version: int = 1
    created_at: str = field(default_factory=_utc_now_iso)
    updated_at: str = field(default_factory=_utc_now_iso)

    def trust_is_expired(self, now: Optional[datetime] = None) -> bool:
        """Return True if the device's trust period has expired."""
        if not self.trust_expires_at:
            return False

        expires = _parse_datetime(self.trust_expires_at)
        if expires is None:
            return True

        return expires <= (now or _utc_now())

    def is_active_trusted_device(self) -> bool:
        """Return True if the device can be considered trusted."""
        return (
            self.status in {"trusted", "limited"}
            and self.trust_level in {"limited", "trusted", "privileged"}
            and not self.trust_is_expired()
        )

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-safe dictionary."""
        payload = asdict(self)
        payload["permissions"] = [
            permission.to_dict()
            for permission in self.permissions
        ]
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "DeviceRecord":
        """Create a device record from persisted data."""
        data = dict(payload)

        permissions = [
            DevicePermission.from_dict(item)
            for item in data.get("permissions", [])
            if isinstance(item, Mapping)
        ]

        device_type = data.get("device_type", "unknown")
        if device_type not in {
            "desktop",
            "laptop",
            "mobile",
            "tablet",
            "server",
            "browser",
            "wearable",
            "iot",
            "unknown",
        }:
            device_type = "unknown"

        status = data.get("status", "pending")
        if status not in {
            "pending",
            "trusted",
            "limited",
            "suspended",
            "blocked",
            "revoked",
            "expired",
        }:
            status = "pending"

        trust_level = data.get("trust_level", "pending")
        if trust_level not in {
            "untrusted",
            "pending",
            "limited",
            "trusted",
            "privileged",
        }:
            trust_level = "pending"

        risk_level = data.get("risk_level", "low")
        if risk_level not in {"low", "medium", "high", "critical"}:
            risk_level = "low"

        return cls(
            device_id=_safe_text(
                data.get("device_id") or f"dev_{uuid.uuid4().hex}",
                200,
            ),
            user_id=_safe_text(data.get("user_id"), 200),
            workspace_id=_safe_text(data.get("workspace_id"), 200),
            fingerprint_hash=_safe_text(
                data.get("fingerprint_hash"),
                256,
            ),
            display_name=_safe_text(
                data.get("display_name") or "Unknown device",
                300,
            ),
            device_type=device_type,
            status=status,
            trust_level=trust_level,
            platform=_safe_text(data.get("platform"), 200) or None,
            operating_system=(
                _safe_text(data.get("operating_system"), 300) or None
            ),
            browser=_safe_text(data.get("browser"), 300) or None,
            app_version=_safe_text(data.get("app_version"), 100) or None,
            public_key_fingerprint=(
                _safe_text(data.get("public_key_fingerprint"), 512) or None
            ),
            permissions=permissions,
            denied_permissions=_normalize_string_list(
                data.get("denied_permissions")
            ),
            first_seen_at=_safe_text(
                data.get("first_seen_at") or _utc_now_iso(),
                100,
            ),
            last_seen_at=_safe_text(
                data.get("last_seen_at") or _utc_now_iso(),
                100,
            ),
            trusted_at=_safe_text(data.get("trusted_at"), 100) or None,
            trust_expires_at=(
                _safe_text(data.get("trust_expires_at"), 100) or None
            ),
            last_ip_hash=_safe_text(data.get("last_ip_hash"), 256) or None,
            last_country_code=(
                _safe_text(data.get("last_country_code"), 10) or None
            ),
            last_region=_safe_text(data.get("last_region"), 200) or None,
            failed_verification_attempts=_clamp_int(
                data.get("failed_verification_attempts", 0),
                0,
                1_000_000,
                0,
            ),
            successful_verifications=_clamp_int(
                data.get("successful_verifications", 0),
                0,
                1_000_000,
                0,
            ),
            risk_score=max(
                0.0,
                min(float(data.get("risk_score", 0.0)), 100.0),
            ),
            risk_level=risk_level,
            risk_reasons=_normalize_string_list(
                data.get("risk_reasons"),
                max_items=100,
                max_length=500,
            ),
            created_by=_safe_text(data.get("created_by"), 200) or None,
            updated_by=_safe_text(data.get("updated_by"), 200) or None,
            revoked_by=_safe_text(data.get("revoked_by"), 200) or None,
            revoked_at=_safe_text(data.get("revoked_at"), 100) or None,
            revoke_reason=_safe_text(data.get("revoke_reason"), 1_000) or None,
            metadata=_deepcopy_jsonable(data.get("metadata") or {}),
            version=_clamp_int(data.get("version", 1), 1, 1_000_000, 1),
            created_at=_safe_text(
                data.get("created_at") or _utc_now_iso(),
                100,
            ),
            updated_at=_safe_text(
                data.get("updated_at") or _utc_now_iso(),
                100,
            ),
        )


@dataclass
class DeviceChallenge:
    """Verification challenge created for a pending or suspicious device."""

    challenge_id: str
    user_id: str
    workspace_id: str
    device_id: str

    challenge_type: str = "device_verification"
    status: ChallengeStatus = "pending"

    token_hash: str = ""
    expires_at: str = ""
    max_attempts: int = 5
    attempts: int = 0

    requested_permissions: List[str] = field(default_factory=list)
    requested_trust_level: TrustLevel = "trusted"

    created_at: str = field(default_factory=_utc_now_iso)
    verified_at: Optional[str] = None
    cancelled_at: Optional[str] = None

    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        """Return True if the challenge has expired."""
        expires = _parse_datetime(self.expires_at)

        if expires is None:
            return True

        return expires <= (now or _utc_now())

    def to_dict(
        self,
        *,
        include_token_hash: bool = False,
    ) -> Dict[str, Any]:
        """Return a JSON-safe challenge dictionary."""
        payload = asdict(self)

        if not include_token_hash:
            payload.pop("token_hash", None)

        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "DeviceChallenge":
        """Create challenge from persisted data."""
        data = dict(payload)

        status = data.get("status", "pending")
        if status not in {
            "pending",
            "verified",
            "failed",
            "expired",
            "cancelled",
        }:
            status = "pending"

        trust_level = data.get("requested_trust_level", "trusted")
        if trust_level not in {
            "untrusted",
            "pending",
            "limited",
            "trusted",
            "privileged",
        }:
            trust_level = "trusted"

        return cls(
            challenge_id=_safe_text(
                data.get("challenge_id")
                or f"dvc_{uuid.uuid4().hex}",
                200,
            ),
            user_id=_safe_text(data.get("user_id"), 200),
            workspace_id=_safe_text(data.get("workspace_id"), 200),
            device_id=_safe_text(data.get("device_id"), 200),
            challenge_type=_safe_text(
                data.get("challenge_type") or "device_verification",
                100,
            ),
            status=status,
            token_hash=_safe_text(data.get("token_hash"), 256),
            expires_at=_safe_text(data.get("expires_at"), 100),
            max_attempts=_clamp_int(
                data.get("max_attempts", 5),
                1,
                20,
                5,
            ),
            attempts=_clamp_int(
                data.get("attempts", 0),
                0,
                1_000,
                0,
            ),
            requested_permissions=[
                _normalize_permission_name(item)
                for item in data.get("requested_permissions", [])
            ],
            requested_trust_level=trust_level,
            created_at=_safe_text(
                data.get("created_at") or _utc_now_iso(),
                100,
            ),
            verified_at=_safe_text(data.get("verified_at"), 100) or None,
            cancelled_at=(
                _safe_text(data.get("cancelled_at"), 100) or None
            ),
            metadata=_deepcopy_jsonable(data.get("metadata") or {}),
        )


@dataclass
class DeviceAccessPolicy:
    """Configurable device-access policy for the module."""

    unknown_device_policy: UnknownDevicePolicy = "block"
    require_device_challenge: bool = True
    auto_register_unknown_devices: bool = True

    default_trust_days: int = 90
    maximum_trust_days: int = 365

    challenge_expiry_minutes: int = 15
    challenge_max_attempts: int = 5

    block_after_failed_attempts: int = 10
    block_high_risk_devices: bool = True
    high_risk_threshold: float = 70.0
    critical_risk_threshold: float = 90.0

    require_public_key_for_privileged: bool = True
    allow_privileged_wildcard_permission: bool = False

    bind_session_to_device: bool = True
    update_last_seen_on_access: bool = True

    default_limited_permissions: List[str] = field(
        default_factory=lambda: [
            "dashboard.read",
            "profile.read",
            "security.device.verify",
            "security.device.view_self",
        ]
    )

    default_trusted_permissions: List[str] = field(
        default_factory=lambda: [
            "dashboard.read",
            "profile.read",
            "profile.update",
            "task.read",
            "task.create",
            "memory.read",
            "security.device.view_self",
        ]
    )

    sensitive_permissions: List[str] = field(
        default_factory=lambda: [
            "system.execute",
            "system.shutdown",
            "system.install",
            "finance.*",
            "payment.*",
            "call.place",
            "message.send",
            "browser.purchase",
            "file.delete",
            "security.policy.update",
            "security.device.manage_all",
            "agent.permission.update",
        ]
    )

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-safe policy dictionary."""
        return asdict(self)


def _resource_matches(stored: str, requested: str) -> bool:
    """Return True when a stored resource pattern matches a requested resource."""
    stored_clean = _safe_text(stored, 500).lower()
    requested_clean = _safe_text(requested, 500).lower()

    if stored_clean == "*":
        return True

    if stored_clean.endswith("*"):
        return requested_clean.startswith(stored_clean[:-1])

    return stored_clean == requested_clean


# =============================================================================
# DeviceAccess
# =============================================================================

class DeviceAccess(BaseAgent):
    """
    Trusted-device and device-permission manager.

    Integration overview
    --------------------

    Master Agent:
        Routes device registration, trust checks, and permission checks to this
        class before allowing sensitive execution.

    Security Agent:
        Uses this class as the source of truth for device trust and device-level
        authorization. Sensitive device-management operations can require an
        external approval through `_request_security_approval`.

    Memory Agent:
        Receives privacy-safe device-security context through
        `_prepare_memory_payload`. Raw fingerprints, IP addresses, verification
        tokens, and secrets are excluded.

    Verification Agent:
        Receives `_prepare_verification_payload` after device enrollment,
        permission updates, trust changes, and access decisions.

    Dashboard/API:
        Public methods return structured dictionaries suitable for FastAPI JSON
        responses and dashboard rendering.

    Agent Registry / Loader / Router:
        `get_agent_manifest` exposes stable capability metadata and public
        methods.
    """

    VERSION = "1.0.0"
    AGENT_NAME = "DeviceAccess"
    AGENT_ID = "security.device_access"
    AGENT_CATEGORY = "security_agent"

    DEFAULT_STORAGE_DIR = "data/security/device_access"

    ALLOWED_DEVICE_TYPES: Set[str] = {
        "desktop",
        "laptop",
        "mobile",
        "tablet",
        "server",
        "browser",
        "wearable",
        "iot",
        "unknown",
    }

    ALLOWED_TRUST_LEVELS: Set[str] = {
        "untrusted",
        "pending",
        "limited",
        "trusted",
        "privileged",
    }

    ALLOWED_STATUSES: Set[str] = {
        "pending",
        "trusted",
        "limited",
        "suspended",
        "blocked",
        "revoked",
        "expired",
    }

    SECRET_PATTERNS: Tuple[re.Pattern[str], ...] = (
        re.compile(
            r"(?i)\b(password|passwd|secret|api[_-]?key|access[_-]?token|"
            r"refresh[_-]?token|private[_-]?key)\b\s*[:=]\s*\S+"
        ),
        re.compile(r"(?i)\bsk-[A-Za-z0-9_-]{16,}\b"),
        re.compile(r"(?i)\bghp_[A-Za-z0-9]{20,}\b"),
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    )

    def __init__(
        self,
        storage_dir: Optional[Union[str, Path]] = None,
        fingerprint_secret: Optional[str] = None,
        policy: Optional[Union[DeviceAccessPolicy, Dict[str, Any]]] = None,
        enable_file_storage: bool = True,
        enable_audit_log: bool = True,
        permission_checker: Optional[Any] = None,
        risk_engine: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        approval_manager: Optional[Any] = None,
        logger: Optional[logging.Logger] = None,
        agent_name: str = AGENT_NAME,
        agent_id: str = AGENT_ID,
        **kwargs: Any,
    ) -> None:
        """Initialize the device-access manager."""
        try:
            super().__init__(
                agent_name=agent_name,
                agent_id=agent_id,
                **kwargs,
            )
        except TypeError:
            try:
                super().__init__(agent_name=agent_name, **kwargs)
            except TypeError:
                super().__init__()

        self.agent_name = agent_name
        self.agent_id = agent_id
        self.logger = logger or logging.getLogger(agent_name)

        self.storage_dir = Path(
            storage_dir
            or os.getenv(
                "WILLIAM_DEVICE_ACCESS_DIR",
                self.DEFAULT_STORAGE_DIR,
            )
        )

        self.enable_file_storage = bool(enable_file_storage)
        self.enable_audit_log = bool(enable_audit_log)

        self.policy = self._build_policy(policy)

        supplied_secret = (
            fingerprint_secret
            or os.getenv("WILLIAM_DEVICE_FINGERPRINT_SECRET")
            or ""
        )

        self._ephemeral_secret = False

        if supplied_secret:
            self._fingerprint_secret = supplied_secret.encode("utf-8")
        else:
            self._fingerprint_secret = secrets.token_bytes(32)
            self._ephemeral_secret = True
            self.logger.warning(
                "WILLIAM_DEVICE_FINGERPRINT_SECRET is not configured. "
                "An ephemeral secret is being used; stored fingerprints will "
                "not remain stable after restart."
            )

        self.permission_checker = (
            permission_checker
            or self._safe_initialize_optional(PermissionChecker)
        )
        self.risk_engine = (
            risk_engine
            or self._safe_initialize_optional(RiskEngine)
        )
        self.audit_logger = (
            audit_logger
            or self._safe_initialize_optional(AuditLogger)
        )
        self.approval_manager = (
            approval_manager
            or self._safe_initialize_optional(ApprovalManager)
        )

        self._lock = threading.RLock()
        self._device_cache: Dict[str, List[DeviceRecord]] = {}
        self._challenge_cache: Dict[str, List[DeviceChallenge]] = {}

        if self.enable_file_storage:
            self.storage_dir.mkdir(parents=True, exist_ok=True)

    # =========================================================================
    # William/Jarvis compatibility hooks
    # =========================================================================

    def _safe_result(
        self,
        message: str = "Success",
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        success: bool = True,
    ) -> Dict[str, Any]:
        """Return the standard William/Jarvis result structure."""
        return {
            "success": bool(success),
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": {
                "agent": self.agent_name,
                "agent_id": self.agent_id,
                "version": self.VERSION,
                "timestamp": _utc_now_iso(),
                **(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Union[str, Exception]] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return the standard William/Jarvis error structure."""
        if isinstance(error, Exception):
            error_type = error.__class__.__name__
            error_message = str(error)
        else:
            error_type = "DeviceAccessError"
            error_message = str(error or message)

        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": {
                "type": error_type,
                "message": error_message,
            },
            "metadata": {
                "agent": self.agent_name,
                "agent_id": self.agent_id,
                "version": self.VERSION,
                "timestamp": _utc_now_iso(),
                **(metadata or {}),
            },
        }

    def _validate_task_context(
        self,
        user_id: Optional[str],
        workspace_id: Optional[str],
        action: str = "device_access",
        device_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Validate the SaaS execution context.

        Device records must never be accessed without both user_id and
        workspace_id.
        """
        try:
            clean_user_id = _normalize_identifier(user_id, "user_id")
            clean_workspace_id = _normalize_identifier(
                workspace_id,
                "workspace_id",
            )

            clean_device_id = None
            if device_id is not None:
                clean_device_id = _normalize_identifier(
                    device_id,
                    "device_id",
                )

            return self._safe_result(
                message="Device-access context validated.",
                data={
                    "user_id": clean_user_id,
                    "workspace_id": clean_workspace_id,
                    "device_id": clean_device_id,
                    "action": _safe_text(action, 200),
                },
                metadata={"validation": "passed"},
            )

        except DeviceValidationError as exc:
            return self._error_result(
                message="Invalid device-access task context.",
                error=exc,
                metadata={
                    "action": _safe_text(action, 200),
                    "validation": "failed",
                },
            )

    def _requires_security_check(
        self,
        action: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Return True for sensitive device-management actions."""
        normalized_action = _safe_text(action, 200).lower()

        sensitive_actions = {
            "trust_device",
            "grant_permission",
            "grant_permissions",
            "revoke_permission",
            "replace_permissions",
            "set_privileged_trust",
            "block_device",
            "unblock_device",
            "revoke_device",
            "delete_device",
            "restore_device",
            "export_device_data",
            "update_device_policy",
            "approve_unknown_device",
        }

        if normalized_action in sensitive_actions:
            return True

        if payload and self._contains_secret_like_content(payload):
            return True

        permission = _safe_text(
            (payload or {}).get("permission"),
            200,
        ).lower()

        if permission and self._is_sensitive_permission(permission):
            return True

        permissions = (payload or {}).get("permissions")
        if isinstance(permissions, Sequence) and not isinstance(
            permissions,
            (str, bytes),
        ):
            if any(
                self._is_sensitive_permission(str(item))
                for item in permissions
            ):
                return True

        return False

    def _request_security_approval(
        self,
        user_id: str,
        workspace_id: str,
        action: str,
        payload: Optional[Dict[str, Any]] = None,
        *,
        approved: bool = False,
        approved_by: Optional[str] = None,
        approval_reference: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Request or verify Security Agent approval.

        The method does not invent approval. When `approved` is false, it returns
        an approval-required response. Production orchestration can route the
        supplied payload to ApprovalManager or Security Agent.
        """
        safe_payload = payload or {}

        if self._contains_secret_like_content(safe_payload):
            return self._error_result(
                message=(
                    "Security approval rejected because secret-like content "
                    "was included in the device-access payload."
                ),
                data={
                    "approved": False,
                    "requires_approval": True,
                    "action": action,
                    "reason": "secret_like_content_detected",
                },
                metadata={"security_status": "blocked"},
            )

        if approved:
            if not _safe_text(approved_by, 200):
                return self._error_result(
                    message=(
                        "approved_by is required when a sensitive device "
                        "operation is marked approved."
                    ),
                    data={
                        "approved": False,
                        "requires_approval": True,
                        "action": action,
                    },
                    metadata={"security_status": "invalid_approval"},
                )

            return self._safe_result(
                message="Security approval accepted.",
                data={
                    "approved": True,
                    "requires_approval": False,
                    "action": action,
                    "approved_by": _safe_text(approved_by, 200),
                    "approval_reference": (
                        _safe_text(approval_reference, 300) or None
                    ),
                },
                metadata={"security_status": "approved"},
            )

        approval_payload = {
            "request_id": f"approval_{uuid.uuid4().hex}",
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "action": action,
            "payload_summary": self._summarize_payload(safe_payload),
            "requested_at": _utc_now_iso(),
        }

        return self._safe_result(
            message="Security approval is required for this operation.",
            data={
                "approved": False,
                "requires_approval": True,
                "action": action,
                "approval_payload": approval_payload,
            },
            metadata={"security_status": "approval_required"},
        )

    def _prepare_verification_payload(
        self,
        action: str,
        *,
        device: Optional[DeviceRecord] = None,
        decision: Optional[Dict[str, Any]] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Prepare a Verification Agent-compatible payload."""
        payload: Dict[str, Any] = {
            "verification_type": "device_access_security",
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "action": action,
            "timestamp": _utc_now_iso(),
        }

        if device:
            payload["device"] = {
                "device_id": device.device_id,
                "user_id": device.user_id,
                "workspace_id": device.workspace_id,
                "display_name": device.display_name,
                "device_type": device.device_type,
                "status": device.status,
                "trust_level": device.trust_level,
                "risk_score": device.risk_score,
                "risk_level": device.risk_level,
                "version": device.version,
                "updated_at": device.updated_at,
            }

        if decision is not None:
            payload["decision"] = _deepcopy_jsonable(decision)

        if extra:
            payload["extra"] = _deepcopy_jsonable(extra)

        return payload

    def _prepare_memory_payload(
        self,
        action: str,
        *,
        device: Optional[DeviceRecord] = None,
        devices: Optional[List[DeviceRecord]] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare privacy-safe Memory Agent context.

        Device fingerprints, IP hashes, challenge tokens, and secret material are
        intentionally excluded.
        """
        items: List[Dict[str, Any]] = []

        if device:
            items.append(self._device_to_memory_item(device))

        if devices:
            items.extend(
                self._device_to_memory_item(item)
                for item in devices
            )

        payload: Dict[str, Any] = {
            "source_agent": self.agent_name,
            "source_file": "agents/security_agent/device_access.py",
            "memory_scope": "security_device",
            "action": action,
            "timestamp": _utc_now_iso(),
            "items": items,
        }

        if extra:
            payload["extra"] = _deepcopy_jsonable(extra)

        return payload

    def _emit_agent_event(
        self,
        event_name: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Emit a non-fatal Agent Registry/dashboard event."""
        event_payload = payload or {}

        try:
            parent_emit = getattr(super(), "emit_event", None)
            if callable(parent_emit):
                parent_emit(event_name, event_payload)
                return
        except Exception as exc:
            self.logger.debug(
                "Parent emit_event failed for %s: %s",
                event_name,
                exc,
            )

        self.logger.debug(
            "DeviceAccess event: %s | %s",
            event_name,
            event_payload,
        )

    def _log_audit_event(
        self,
        action: str,
        user_id: Optional[str],
        workspace_id: Optional[str],
        payload: Optional[Dict[str, Any]] = None,
        *,
        outcome: str = "success",
        severity: str = "info",
    ) -> None:
        """Write a privacy-safe, non-fatal audit event."""
        if not self.enable_audit_log:
            return

        audit_payload = {
            "event_id": f"audit_{uuid.uuid4().hex}",
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "outcome": outcome,
            "severity": severity,
            "payload": self._summarize_payload(payload or {}),
            "timestamp": _utc_now_iso(),
        }

        if self.audit_logger is not None:
            for method_name in (
                "log_event",
                "log",
                "write",
                "record",
            ):
                method = getattr(self.audit_logger, method_name, None)
                if callable(method):
                    try:
                        method(audit_payload)
                        return
                    except Exception as exc:
                        self.logger.debug(
                            "AuditLogger.%s failed: %s",
                            method_name,
                            exc,
                        )

        try:
            parent_audit = getattr(super(), "log_audit", None)
            if callable(parent_audit):
                parent_audit(action, audit_payload)
                return
        except Exception as exc:
            self.logger.debug(
                "Parent log_audit failed for %s: %s",
                action,
                exc,
            )

        self.logger.info("DeviceAccess audit: %s", audit_payload)

    # =========================================================================
    # Registry and health
    # =========================================================================

    def get_agent_manifest(self) -> Dict[str, Any]:
        """Return Agent Registry/Loader-compatible capability metadata."""
        return self._safe_result(
            message="DeviceAccess manifest loaded.",
            data={
                "agent_name": self.agent_name,
                "agent_id": self.agent_id,
                "category": self.AGENT_CATEGORY,
                "version": self.VERSION,
                "class_name": self.__class__.__name__,
                "file_path": "agents/security_agent/device_access.py",
                "purpose": (
                    "Trusted devices, unknown-device blocking, and "
                    "device-level permissions."
                ),
                "requires_context": [
                    "user_id",
                    "workspace_id",
                ],
                "capabilities": [
                    "device.register",
                    "device.challenge",
                    "device.verify",
                    "device.trust",
                    "device.block",
                    "device.suspend",
                    "device.revoke",
                    "device.permission.grant",
                    "device.permission.revoke",
                    "device.access.check",
                    "device.session.bind",
                    "device.risk.evaluate",
                    "device.audit",
                ],
                "public_methods": [
                    "register_device",
                    "identify_device",
                    "create_device_challenge",
                    "verify_device_challenge",
                    "trust_device",
                    "get_device",
                    "list_devices",
                    "check_device_access",
                    "check_device_permission",
                    "grant_device_permission",
                    "grant_device_permissions",
                    "revoke_device_permission",
                    "replace_device_permissions",
                    "suspend_device",
                    "block_device",
                    "unblock_device",
                    "revoke_device",
                    "touch_device",
                    "validate_session_device",
                    "get_device_summary",
                    "expire_stale_devices",
                    "health_check",
                ],
                "compatible_with": [
                    "BaseAgent",
                    "MasterAgent",
                    "SecurityAgent",
                    "VerificationAgent",
                    "MemoryAgent",
                    "AgentRegistry",
                    "AgentLoader",
                    "AgentRouter",
                    "FastAPI",
                    "Dashboard",
                ],
                "unknown_device_policy": self.policy.unknown_device_policy,
            },
        )

    def health_check(self) -> Dict[str, Any]:
        """Check storage and configuration health."""
        storage_ready = True
        storage_error: Optional[str] = None

        if self.enable_file_storage:
            try:
                self.storage_dir.mkdir(parents=True, exist_ok=True)
                health_file = self.storage_dir / ".device_access_health"
                health_file.write_text("ok", encoding="utf-8")
                health_file.unlink(missing_ok=True)
            except Exception as exc:
                storage_ready = False
                storage_error = str(exc)

        data = {
            "healthy": storage_ready,
            "storage_enabled": self.enable_file_storage,
            "storage_ready": storage_ready,
            "storage_dir": str(self.storage_dir),
            "ephemeral_fingerprint_secret": self._ephemeral_secret,
            "unknown_device_policy": self.policy.unknown_device_policy,
            "cached_scopes": len(self._device_cache),
            "version": self.VERSION,
        }

        if not storage_ready:
            return self._error_result(
                message="DeviceAccess health check failed.",
                error=storage_error,
                data=data,
            )

        return self._safe_result(
            message="DeviceAccess is healthy.",
            data=data,
        )

    # =========================================================================
    # Device registration and identification
    # =========================================================================

    def register_device(
        self,
        user_id: str,
        workspace_id: str,
        fingerprint_data: Mapping[str, Any],
        display_name: str,
        *,
        device_type: DeviceType = "unknown",
        platform: Optional[str] = None,
        operating_system: Optional[str] = None,
        browser: Optional[str] = None,
        app_version: Optional[str] = None,
        public_key_fingerprint: Optional[str] = None,
        ip_address: Optional[str] = None,
        country_code: Optional[str] = None,
        region: Optional[str] = None,
        requested_permissions: Optional[Iterable[str]] = None,
        created_by: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Register or identify a device.

        Unknown devices follow `unknown_device_policy`:

            block:
                Device is recorded as blocked.

            challenge:
                Device is pending and receives a verification challenge.

            limited:
                Device receives limited trust and limited permissions.

            allow:
                Device becomes trusted using the default trusted permissions.
        """
        context = self._validate_task_context(
            user_id,
            workspace_id,
            "register_device",
        )
        if not context["success"]:
            return context

        try:
            clean_user_id = context["data"]["user_id"]
            clean_workspace_id = context["data"]["workspace_id"]

            clean_name = _safe_text(
                display_name,
                300,
                allow_empty=False,
            )
            clean_type = self._normalize_device_type(device_type)

            fingerprint_hash = self._create_device_fingerprint(
                clean_user_id,
                clean_workspace_id,
                fingerprint_data,
            )

            ip_hash = (
                self._hash_network_value(ip_address)
                if ip_address
                else None
            )

            with self._lock:
                devices = self._load_devices(
                    clean_user_id,
                    clean_workspace_id,
                )

                existing = self._find_device_by_fingerprint(
                    devices,
                    fingerprint_hash,
                )

                if existing:
                    existing.last_seen_at = _utc_now_iso()
                    existing.updated_at = _utc_now_iso()
                    existing.version += 1

                    if ip_hash:
                        existing.last_ip_hash = ip_hash
                    if country_code:
                        existing.last_country_code = _safe_text(
                            country_code,
                            10,
                        ).upper()
                    if region:
                        existing.last_region = _safe_text(region, 200)

                    if app_version:
                        existing.app_version = _safe_text(
                            app_version,
                            100,
                        )

                    self._refresh_expired_device(existing)
                    self._save_devices(
                        clean_user_id,
                        clean_workspace_id,
                        devices,
                    )

                    access_decision = self._build_device_access_decision(
                        existing
                    )

                    self._log_audit_event(
                        "identify_existing_device",
                        clean_user_id,
                        clean_workspace_id,
                        {
                            "device_id": existing.device_id,
                            "status": existing.status,
                            "trust_level": existing.trust_level,
                        },
                    )

                    return self._safe_result(
                        message="Existing device identified.",
                        data={
                            "is_new_device": False,
                            "device": self._public_device_dict(existing),
                            "access_decision": access_decision,
                            "verification_payload": (
                                self._prepare_verification_payload(
                                    "identify_existing_device",
                                    device=existing,
                                    decision=access_decision,
                                )
                            ),
                            "memory_payload": self._prepare_memory_payload(
                                "identify_existing_device",
                                device=existing,
                            ),
                        },
                    )

                device = self._build_new_device_record(
                    user_id=clean_user_id,
                    workspace_id=clean_workspace_id,
                    fingerprint_hash=fingerprint_hash,
                    display_name=clean_name,
                    device_type=clean_type,
                    platform=platform,
                    operating_system=operating_system,
                    browser=browser,
                    app_version=app_version,
                    public_key_fingerprint=public_key_fingerprint,
                    ip_hash=ip_hash,
                    country_code=country_code,
                    region=region,
                    requested_permissions=requested_permissions,
                    created_by=created_by,
                    metadata=metadata,
                )

                devices.append(device)
                self._save_devices(
                    clean_user_id,
                    clean_workspace_id,
                    devices,
                )

            challenge_result: Optional[Dict[str, Any]] = None

            if (
                device.status == "pending"
                and self.policy.require_device_challenge
            ):
                challenge_result = self.create_device_challenge(
                    user_id=clean_user_id,
                    workspace_id=clean_workspace_id,
                    device_id=device.device_id,
                    requested_permissions=requested_permissions,
                    requested_trust_level="trusted",
                )

            access_decision = self._build_device_access_decision(device)

            event_name = (
                "security.device.unknown_blocked"
                if device.status == "blocked"
                else "security.device.registered"
            )

            self._emit_agent_event(
                event_name,
                {
                    "user_id": clean_user_id,
                    "workspace_id": clean_workspace_id,
                    "device_id": device.device_id,
                    "status": device.status,
                    "trust_level": device.trust_level,
                },
            )

            self._log_audit_event(
                "register_device",
                clean_user_id,
                clean_workspace_id,
                {
                    "device_id": device.device_id,
                    "status": device.status,
                    "trust_level": device.trust_level,
                    "unknown_device_policy": (
                        self.policy.unknown_device_policy
                    ),
                },
                outcome=(
                    "blocked"
                    if device.status == "blocked"
                    else "success"
                ),
                severity=(
                    "warning"
                    if device.status in {"blocked", "pending"}
                    else "info"
                ),
            )

            return self._safe_result(
                message=self._registration_message(device),
                data={
                    "is_new_device": True,
                    "device": self._public_device_dict(device),
                    "access_decision": access_decision,
                    "challenge": (
                        challenge_result.get("data", {}).get("challenge")
                        if challenge_result and challenge_result["success"]
                        else None
                    ),
                    "verification_token": (
                        challenge_result.get("data", {}).get(
                            "verification_token"
                        )
                        if challenge_result and challenge_result["success"]
                        else None
                    ),
                    "verification_payload": (
                        self._prepare_verification_payload(
                            "register_device",
                            device=device,
                            decision=access_decision,
                        )
                    ),
                    "memory_payload": self._prepare_memory_payload(
                        "register_device",
                        device=device,
                    ),
                },
                metadata={
                    "unknown_device_policy": (
                        self.policy.unknown_device_policy
                    ),
                },
            )

        except (DeviceValidationError, DeviceSecurityError) as exc:
            self._log_audit_event(
                "register_device",
                user_id,
                workspace_id,
                {"reason": str(exc)},
                outcome="failed",
                severity="warning",
            )
            return self._error_result(
                message="Device registration failed.",
                error=exc,
            )
        except Exception as exc:
            self.logger.exception("Unexpected device registration error.")
            return self._error_result(
                message="Unexpected error while registering device.",
                error=exc,
            )

    def identify_device(
        self,
        user_id: str,
        workspace_id: str,
        fingerprint_data: Mapping[str, Any],
        *,
        ip_address: Optional[str] = None,
        country_code: Optional[str] = None,
        region: Optional[str] = None,
        update_last_seen: bool = True,
    ) -> Dict[str, Any]:
        """Identify a device without automatically registering it."""
        context = self._validate_task_context(
            user_id,
            workspace_id,
            "identify_device",
        )
        if not context["success"]:
            return context

        try:
            clean_user_id = context["data"]["user_id"]
            clean_workspace_id = context["data"]["workspace_id"]

            fingerprint_hash = self._create_device_fingerprint(
                clean_user_id,
                clean_workspace_id,
                fingerprint_data,
            )

            with self._lock:
                devices = self._load_devices(
                    clean_user_id,
                    clean_workspace_id,
                )
                device = self._find_device_by_fingerprint(
                    devices,
                    fingerprint_hash,
                )

                if not device:
                    decision = self._unknown_device_decision()

                    self._log_audit_event(
                        "identify_unknown_device",
                        clean_user_id,
                        clean_workspace_id,
                        {
                            "allowed": decision["allowed"],
                            "policy": self.policy.unknown_device_policy,
                        },
                        outcome=(
                            "allowed"
                            if decision["allowed"]
                            else "blocked"
                        ),
                        severity="warning",
                    )

                    return self._safe_result(
                        message="Unknown device detected.",
                        data={
                            "known_device": False,
                            "device": None,
                            "access_decision": decision,
                            "verification_payload": (
                                self._prepare_verification_payload(
                                    "identify_unknown_device",
                                    decision=decision,
                                )
                            ),
                        },
                    )

                self._refresh_expired_device(device)

                if update_last_seen:
                    device.last_seen_at = _utc_now_iso()
                    device.updated_at = _utc_now_iso()
                    device.version += 1

                    if ip_address:
                        device.last_ip_hash = self._hash_network_value(
                            ip_address
                        )
                    if country_code:
                        device.last_country_code = _safe_text(
                            country_code,
                            10,
                        ).upper()
                    if region:
                        device.last_region = _safe_text(region, 200)

                    self._save_devices(
                        clean_user_id,
                        clean_workspace_id,
                        devices,
                    )

            decision = self._build_device_access_decision(device)

            return self._safe_result(
                message="Device identified.",
                data={
                    "known_device": True,
                    "device": self._public_device_dict(device),
                    "access_decision": decision,
                    "verification_payload": (
                        self._prepare_verification_payload(
                            "identify_device",
                            device=device,
                            decision=decision,
                        )
                    ),
                    "memory_payload": self._prepare_memory_payload(
                        "identify_device",
                        device=device,
                    ),
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Device identification failed.",
                error=exc,
            )

    # =========================================================================
    # Challenges and trust
    # =========================================================================

    def create_device_challenge(
        self,
        user_id: str,
        workspace_id: str,
        device_id: str,
        *,
        requested_permissions: Optional[Iterable[str]] = None,
        requested_trust_level: TrustLevel = "trusted",
        expiry_minutes: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create a single-use device-verification challenge.

        The plaintext token is returned exactly once. Only its hash is persisted.
        Delivery by email, SMS, authenticator, biometric gate, or another channel
        must be handled by the appropriate William/Jarvis agent.
        """
        context = self._validate_task_context(
            user_id,
            workspace_id,
            "create_device_challenge",
            device_id,
        )
        if not context["success"]:
            return context

        try:
            clean_user_id = context["data"]["user_id"]
            clean_workspace_id = context["data"]["workspace_id"]
            clean_device_id = context["data"]["device_id"]

            trust_level = self._normalize_trust_level(
                requested_trust_level
            )

            if trust_level == "privileged":
                trust_level = "trusted"

            device = self._require_device(
                clean_user_id,
                clean_workspace_id,
                clean_device_id,
            )

            if device.status in {"revoked", "blocked"}:
                raise DeviceSecurityError(
                    "A challenge cannot be created for a blocked or "
                    "revoked device."
                )

            token = secrets.token_urlsafe(32)
            token_hash = self._hash_challenge_token(token)

            expires_in = _clamp_int(
                expiry_minutes,
                1,
                1_440,
                self.policy.challenge_expiry_minutes,
            )

            challenge = DeviceChallenge(
                challenge_id=f"dvc_{uuid.uuid4().hex}",
                user_id=clean_user_id,
                workspace_id=clean_workspace_id,
                device_id=clean_device_id,
                token_hash=token_hash,
                expires_at=(
                    _utc_now() + timedelta(minutes=expires_in)
                ).isoformat(),
                max_attempts=self.policy.challenge_max_attempts,
                requested_permissions=[
                    _normalize_permission_name(item)
                    for item in (
                        requested_permissions
                        or self.policy.default_trusted_permissions
                    )
                ],
                requested_trust_level=trust_level,
                metadata=_deepcopy_jsonable(metadata or {}),
            )

            with self._lock:
                challenges = self._load_challenges(
                    clean_user_id,
                    clean_workspace_id,
                )

                for old_challenge in challenges:
                    if (
                        old_challenge.device_id == clean_device_id
                        and old_challenge.status == "pending"
                    ):
                        old_challenge.status = "cancelled"
                        old_challenge.cancelled_at = _utc_now_iso()

                challenges.append(challenge)
                self._save_challenges(
                    clean_user_id,
                    clean_workspace_id,
                    challenges,
                )

            self._emit_agent_event(
                "security.device.challenge_created",
                {
                    "user_id": clean_user_id,
                    "workspace_id": clean_workspace_id,
                    "device_id": clean_device_id,
                    "challenge_id": challenge.challenge_id,
                },
            )

            self._log_audit_event(
                "create_device_challenge",
                clean_user_id,
                clean_workspace_id,
                {
                    "device_id": clean_device_id,
                    "challenge_id": challenge.challenge_id,
                    "expires_at": challenge.expires_at,
                },
            )

            return self._safe_result(
                message="Device verification challenge created.",
                data={
                    "challenge": challenge.to_dict(),
                    "verification_token": token,
                    "delivery_required": True,
                    "delivery_note": (
                        "Send the token through an approved verification "
                        "channel. The token is returned only in this response."
                    ),
                },
                metadata={
                    "sensitive_response": True,
                    "do_not_log_verification_token": True,
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Unable to create device challenge.",
                error=exc,
            )

    def verify_device_challenge(
        self,
        user_id: str,
        workspace_id: str,
        challenge_id: str,
        verification_token: str,
        *,
        verified_by: Optional[str] = None,
        trust_days: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Verify a challenge and trust the related device."""
        context = self._validate_task_context(
            user_id,
            workspace_id,
            "verify_device_challenge",
        )
        if not context["success"]:
            return context

        try:
            clean_user_id = context["data"]["user_id"]
            clean_workspace_id = context["data"]["workspace_id"]
            clean_challenge_id = _normalize_identifier(
                challenge_id,
                "challenge_id",
            )
            clean_token = _safe_text(
                verification_token,
                2_000,
                allow_empty=False,
            )

            with self._lock:
                challenges = self._load_challenges(
                    clean_user_id,
                    clean_workspace_id,
                )
                challenge = self._find_challenge(
                    challenges,
                    clean_challenge_id,
                )

                if not challenge:
                    raise DeviceValidationError(
                        "Device verification challenge was not found."
                    )

                if challenge.status != "pending":
                    raise DeviceSecurityError(
                        f"Challenge is already {challenge.status}."
                    )

                if challenge.is_expired():
                    challenge.status = "expired"
                    self._save_challenges(
                        clean_user_id,
                        clean_workspace_id,
                        challenges,
                    )
                    raise DeviceSecurityError(
                        "Device verification challenge has expired."
                    )

                if challenge.attempts >= challenge.max_attempts:
                    challenge.status = "failed"
                    self._save_challenges(
                        clean_user_id,
                        clean_workspace_id,
                        challenges,
                    )
                    raise DeviceSecurityError(
                        "Device verification challenge exceeded its "
                        "maximum attempts."
                    )

                challenge.attempts += 1

                supplied_hash = self._hash_challenge_token(clean_token)
                verified = _constant_time_equal(
                    supplied_hash,
                    challenge.token_hash,
                )

                devices = self._load_devices(
                    clean_user_id,
                    clean_workspace_id,
                )
                device = self._find_device(
                    devices,
                    challenge.device_id,
                )

                if not device:
                    raise DeviceNotFoundError(
                        "Device linked to the challenge was not found."
                    )

                if not verified:
                    device.failed_verification_attempts += 1
                    device.updated_at = _utc_now_iso()
                    device.version += 1

                    if (
                        challenge.attempts >= challenge.max_attempts
                        or device.failed_verification_attempts
                        >= self.policy.block_after_failed_attempts
                    ):
                        challenge.status = "failed"
                        device.status = "blocked"
                        device.trust_level = "untrusted"
                        device.risk_score = max(
                            device.risk_score,
                            85.0,
                        )
                        device.risk_level = "high"
                        self._append_risk_reason(
                            device,
                            "Repeated device verification failures.",
                        )

                    self._save_devices(
                        clean_user_id,
                        clean_workspace_id,
                        devices,
                    )
                    self._save_challenges(
                        clean_user_id,
                        clean_workspace_id,
                        challenges,
                    )

                    self._log_audit_event(
                        "verify_device_challenge",
                        clean_user_id,
                        clean_workspace_id,
                        {
                            "device_id": device.device_id,
                            "challenge_id": challenge.challenge_id,
                            "attempts": challenge.attempts,
                        },
                        outcome="failed",
                        severity="warning",
                    )

                    return self._error_result(
                        message="Device verification token is invalid.",
                        data={
                            "verified": False,
                            "attempts": challenge.attempts,
                            "remaining_attempts": max(
                                0,
                                challenge.max_attempts
                                - challenge.attempts,
                            ),
                            "device_status": device.status,
                        },
                    )

                challenge.status = "verified"
                challenge.verified_at = _utc_now_iso()

                days = _clamp_int(
                    trust_days,
                    1,
                    self.policy.maximum_trust_days,
                    self.policy.default_trust_days,
                )

                device.status = (
                    "limited"
                    if challenge.requested_trust_level == "limited"
                    else "trusted"
                )
                device.trust_level = (
                    challenge.requested_trust_level
                    if challenge.requested_trust_level
                    in {"limited", "trusted"}
                    else "trusted"
                )
                device.trusted_at = _utc_now_iso()
                device.trust_expires_at = (
                    _utc_now() + timedelta(days=days)
                ).isoformat()
                device.successful_verifications += 1
                device.failed_verification_attempts = 0
                device.updated_by = (
                    _safe_text(verified_by, 200)
                    or clean_user_id
                )
                device.updated_at = _utc_now_iso()
                device.version += 1

                self._replace_permissions_internal(
                    device,
                    challenge.requested_permissions
                    or self.policy.default_trusted_permissions,
                    granted_by=device.updated_by,
                )

                device.risk_score = min(device.risk_score, 30.0)
                device.risk_level = self._risk_level_for_score(
                    device.risk_score
                )

                self._save_devices(
                    clean_user_id,
                    clean_workspace_id,
                    devices,
                )
                self._save_challenges(
                    clean_user_id,
                    clean_workspace_id,
                    challenges,
                )

            decision = self._build_device_access_decision(device)

            self._emit_agent_event(
                "security.device.verified",
                {
                    "user_id": clean_user_id,
                    "workspace_id": clean_workspace_id,
                    "device_id": device.device_id,
                    "challenge_id": challenge.challenge_id,
                },
            )

            self._log_audit_event(
                "verify_device_challenge",
                clean_user_id,
                clean_workspace_id,
                {
                    "device_id": device.device_id,
                    "challenge_id": challenge.challenge_id,
                    "trust_level": device.trust_level,
                },
            )

            return self._safe_result(
                message="Device verified and trusted.",
                data={
                    "verified": True,
                    "device": self._public_device_dict(device),
                    "access_decision": decision,
                    "verification_payload": (
                        self._prepare_verification_payload(
                            "verify_device_challenge",
                            device=device,
                            decision=decision,
                        )
                    ),
                    "memory_payload": self._prepare_memory_payload(
                        "verify_device_challenge",
                        device=device,
                    ),
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Device verification failed.",
                error=exc,
            )

    def trust_device(
        self,
        user_id: str,
        workspace_id: str,
        device_id: str,
        *,
        trust_level: TrustLevel = "trusted",
        permissions: Optional[Iterable[str]] = None,
        trust_days: Optional[int] = None,
        approved: bool = False,
        approved_by: Optional[str] = None,
        approval_reference: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Manually trust a device after explicit Security Agent approval."""
        context = self._validate_task_context(
            user_id,
            workspace_id,
            "trust_device",
            device_id,
        )
        if not context["success"]:
            return context

        clean_user_id = context["data"]["user_id"]
        clean_workspace_id = context["data"]["workspace_id"]
        clean_device_id = context["data"]["device_id"]

        normalized_trust = self._normalize_trust_level(trust_level)

        if normalized_trust not in {
            "limited",
            "trusted",
            "privileged",
        }:
            return self._error_result(
                message="Invalid trust level for device approval.",
                data={
                    "allowed_trust_levels": [
                        "limited",
                        "trusted",
                        "privileged",
                    ]
                },
            )

        approval = self._request_security_approval(
            clean_user_id,
            clean_workspace_id,
            "trust_device",
            {
                "device_id": clean_device_id,
                "trust_level": normalized_trust,
                "permissions": list(permissions or []),
            },
            approved=approved,
            approved_by=approved_by,
            approval_reference=approval_reference,
        )

        if not approval["success"]:
            return approval

        if approval["data"].get("requires_approval"):
            return approval

        try:
            with self._lock:
                devices = self._load_devices(
                    clean_user_id,
                    clean_workspace_id,
                )
                device = self._find_device(devices, clean_device_id)

                if not device:
                    raise DeviceNotFoundError("Device was not found.")

                if device.status == "revoked":
                    raise DeviceSecurityError(
                        "A revoked device cannot be trusted without first "
                        "restoring it."
                    )

                if (
                    normalized_trust == "privileged"
                    and self.policy.require_public_key_for_privileged
                    and not device.public_key_fingerprint
                ):
                    raise DeviceSecurityError(
                        "Privileged trust requires a public-key fingerprint."
                    )

                days = _clamp_int(
                    trust_days,
                    1,
                    self.policy.maximum_trust_days,
                    self.policy.default_trust_days,
                )

                device.status = (
                    "limited"
                    if normalized_trust == "limited"
                    else "trusted"
                )
                device.trust_level = normalized_trust
                device.trusted_at = _utc_now_iso()
                device.trust_expires_at = (
                    _utc_now() + timedelta(days=days)
                ).isoformat()
                device.updated_by = _safe_text(approved_by, 200)
                device.updated_at = _utc_now_iso()
                device.version += 1

                selected_permissions = list(
                    permissions
                    or (
                        self.policy.default_limited_permissions
                        if normalized_trust == "limited"
                        else self.policy.default_trusted_permissions
                    )
                )

                self._replace_permissions_internal(
                    device,
                    selected_permissions,
                    granted_by=approved_by,
                )

                self._save_devices(
                    clean_user_id,
                    clean_workspace_id,
                    devices,
                )

            decision = self._build_device_access_decision(device)

            self._emit_agent_event(
                "security.device.trusted",
                {
                    "user_id": clean_user_id,
                    "workspace_id": clean_workspace_id,
                    "device_id": device.device_id,
                    "trust_level": device.trust_level,
                },
            )

            self._log_audit_event(
                "trust_device",
                clean_user_id,
                clean_workspace_id,
                {
                    "device_id": device.device_id,
                    "trust_level": device.trust_level,
                    "approved_by": approved_by,
                    "approval_reference": approval_reference,
                },
            )

            return self._safe_result(
                message="Device trust updated.",
                data={
                    "device": self._public_device_dict(device),
                    "access_decision": decision,
                    "verification_payload": (
                        self._prepare_verification_payload(
                            "trust_device",
                            device=device,
                            decision=decision,
                        )
                    ),
                    "memory_payload": self._prepare_memory_payload(
                        "trust_device",
                        device=device,
                    ),
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Unable to trust device.",
                error=exc,
            )

    # =========================================================================
    # Device access and permission checks
    # =========================================================================

    def check_device_access(
        self,
        user_id: str,
        workspace_id: str,
        *,
        device_id: Optional[str] = None,
        fingerprint_data: Optional[Mapping[str, Any]] = None,
        permission: Optional[str] = None,
        resource: Optional[str] = None,
        agent_name: Optional[str] = None,
        action: Optional[str] = None,
        session_device_id: Optional[str] = None,
        risk_context: Optional[Dict[str, Any]] = None,
        update_last_seen: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Evaluate whether a device can access a requested capability.

        Access is denied when:
            - The device is unknown and policy blocks it.
            - Device status is pending, blocked, suspended, revoked, or expired.
            - Trust has expired.
            - Risk exceeds configured thresholds.
            - Session/device binding fails.
            - A deny permission matches.
            - No matching allow permission exists.
        """
        context = self._validate_task_context(
            user_id,
            workspace_id,
            "check_device_access",
        )
        if not context["success"]:
            return context

        try:
            clean_user_id = context["data"]["user_id"]
            clean_workspace_id = context["data"]["workspace_id"]

            device: Optional[DeviceRecord] = None

            with self._lock:
                devices = self._load_devices(
                    clean_user_id,
                    clean_workspace_id,
                )

                if device_id:
                    clean_device_id = _normalize_identifier(
                        device_id,
                        "device_id",
                    )
                    device = self._find_device(
                        devices,
                        clean_device_id,
                    )
                elif fingerprint_data is not None:
                    fingerprint_hash = self._create_device_fingerprint(
                        clean_user_id,
                        clean_workspace_id,
                        fingerprint_data,
                    )
                    device = self._find_device_by_fingerprint(
                        devices,
                        fingerprint_hash,
                    )

                if not device:
                    decision = self._unknown_device_decision()

                    return self._safe_result(
                        message=decision["message"],
                        data={
                            "allowed": decision["allowed"],
                            "device_known": False,
                            "device": None,
                            "decision": decision,
                            "verification_payload": (
                                self._prepare_verification_payload(
                                    "check_device_access",
                                    decision=decision,
                                )
                            ),
                        },
                        metadata={
                            "access_status": (
                                "allowed"
                                if decision["allowed"]
                                else "blocked"
                            )
                        },
                    )

                self._refresh_expired_device(device)

                if risk_context:
                    self._apply_risk_context(device, risk_context)

                binding_decision = self._validate_session_binding_internal(
                    device,
                    session_device_id,
                )

                base_decision = self._build_device_access_decision(
                    device
                )

                if not binding_decision["allowed"]:
                    base_decision = binding_decision

                permission_decision: Optional[Dict[str, Any]] = None

                if base_decision["allowed"] and permission:
                    permission_decision = (
                        self._evaluate_device_permission(
                            device,
                            permission,
                            resource=resource,
                            agent_name=agent_name,
                            action=action,
                        )
                    )
                    base_decision = permission_decision

                should_touch = (
                    self.policy.update_last_seen_on_access
                    if update_last_seen is None
                    else bool(update_last_seen)
                )

                if should_touch:
                    device.last_seen_at = _utc_now_iso()
                    device.updated_at = _utc_now_iso()
                    device.version += 1

                self._save_devices(
                    clean_user_id,
                    clean_workspace_id,
                    devices,
                )

            outcome = (
                "allowed"
                if base_decision["allowed"]
                else "blocked"
            )

            self._log_audit_event(
                "check_device_access",
                clean_user_id,
                clean_workspace_id,
                {
                    "device_id": device.device_id,
                    "permission": permission,
                    "resource": resource,
                    "agent_name": agent_name,
                    "action": action,
                    "decision": base_decision,
                },
                outcome=outcome,
                severity=(
                    "info"
                    if base_decision["allowed"]
                    else "warning"
                ),
            )

            if not base_decision["allowed"]:
                self._emit_agent_event(
                    "security.device.access_blocked",
                    {
                        "user_id": clean_user_id,
                        "workspace_id": clean_workspace_id,
                        "device_id": device.device_id,
                        "reason": base_decision.get("reason"),
                    },
                )

            return self._safe_result(
                message=base_decision["message"],
                data={
                    "allowed": base_decision["allowed"],
                    "device_known": True,
                    "device": self._public_device_dict(device),
                    "decision": base_decision,
                    "permission_decision": permission_decision,
                    "verification_payload": (
                        self._prepare_verification_payload(
                            "check_device_access",
                            device=device,
                            decision=base_decision,
                        )
                    ),
                },
                metadata={"access_status": outcome},
            )

        except Exception as exc:
            return self._error_result(
                message="Device-access evaluation failed.",
                error=exc,
            )

    def check_device_permission(
        self,
        user_id: str,
        workspace_id: str,
        device_id: str,
        permission: str,
        *,
        resource: Optional[str] = None,
        agent_name: Optional[str] = None,
        action: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Check a single permission for a known device."""
        return self.check_device_access(
            user_id=user_id,
            workspace_id=workspace_id,
            device_id=device_id,
            permission=permission,
            resource=resource,
            agent_name=agent_name,
            action=action,
        )

    def validate_session_device(
        self,
        user_id: str,
        workspace_id: str,
        device_id: str,
        session_device_id: Optional[str],
    ) -> Dict[str, Any]:
        """Validate that a session remains bound to its original device."""
        context = self._validate_task_context(
            user_id,
            workspace_id,
            "validate_session_device",
            device_id,
        )
        if not context["success"]:
            return context

        try:
            device = self._require_device(
                context["data"]["user_id"],
                context["data"]["workspace_id"],
                context["data"]["device_id"],
            )

            decision = self._validate_session_binding_internal(
                device,
                session_device_id,
            )

            return self._safe_result(
                message=decision["message"],
                data={
                    "allowed": decision["allowed"],
                    "decision": decision,
                    "device": self._public_device_dict(device),
                },
                metadata={
                    "access_status": (
                        "allowed"
                        if decision["allowed"]
                        else "blocked"
                    )
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Session-device validation failed.",
                error=exc,
            )

    # =========================================================================
    # Device permission management
    # =========================================================================

    def grant_device_permission(
        self,
        user_id: str,
        workspace_id: str,
        device_id: str,
        permission: str,
        *,
        effect: PermissionEffect = "allow",
        scope: PermissionScope = "device",
        resource: Optional[str] = None,
        agent_name: Optional[str] = None,
        action: Optional[str] = None,
        conditions: Optional[Dict[str, Any]] = None,
        expires_at: Optional[str] = None,
        approved: bool = False,
        approved_by: Optional[str] = None,
        approval_reference: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Grant or deny one permission for a device."""
        context = self._validate_task_context(
            user_id,
            workspace_id,
            "grant_permission",
            device_id,
        )
        if not context["success"]:
            return context

        try:
            clean_user_id = context["data"]["user_id"]
            clean_workspace_id = context["data"]["workspace_id"]
            clean_device_id = context["data"]["device_id"]
            clean_permission = _normalize_permission_name(permission)

            if effect not in {"allow", "deny"}:
                raise DeviceValidationError(
                    "Permission effect must be allow or deny."
                )

            if scope not in {
                "device",
                "workspace",
                "agent",
                "action",
                "resource",
                "system",
            }:
                raise DeviceValidationError(
                    "Unsupported device permission scope."
                )

            requires_approval = self._requires_security_check(
                "grant_permission",
                {
                    "permission": clean_permission,
                    "effect": effect,
                    "scope": scope,
                },
            )

            if requires_approval:
                approval = self._request_security_approval(
                    clean_user_id,
                    clean_workspace_id,
                    "grant_permission",
                    {
                        "device_id": clean_device_id,
                        "permission": clean_permission,
                        "effect": effect,
                        "scope": scope,
                        "resource": resource,
                    },
                    approved=approved,
                    approved_by=approved_by,
                    approval_reference=approval_reference,
                )

                if not approval["success"]:
                    return approval

                if approval["data"].get("requires_approval"):
                    return approval

            permission_record = DevicePermission(
                permission=clean_permission,
                effect=effect,
                scope=scope,
                resource=_safe_text(resource, 500) or None,
                agent_name=_safe_text(agent_name, 200) or None,
                action=_safe_text(action, 200) or None,
                conditions=_deepcopy_jsonable(conditions or {}),
                granted_by=_safe_text(approved_by, 200) or clean_user_id,
                expires_at=self._validate_optional_expiry(expires_at),
                metadata=_deepcopy_jsonable(metadata or {}),
            )

            with self._lock:
                devices = self._load_devices(
                    clean_user_id,
                    clean_workspace_id,
                )
                device = self._find_device(
                    devices,
                    clean_device_id,
                )

                if not device:
                    raise DeviceNotFoundError("Device was not found.")

                if device.status in {"blocked", "revoked"}:
                    raise DeviceSecurityError(
                        "Permissions cannot be granted to blocked or "
                        "revoked devices."
                    )

                if (
                    clean_permission == "*"
                    and effect == "allow"
                    and not self.policy.allow_privileged_wildcard_permission
                ):
                    raise DeviceSecurityError(
                        "Wildcard allow permission is disabled by policy."
                    )

                device.permissions = [
                    item
                    for item in device.permissions
                    if not (
                        item.permission == permission_record.permission
                        and item.effect == permission_record.effect
                        and item.scope == permission_record.scope
                        and item.resource == permission_record.resource
                        and item.agent_name == permission_record.agent_name
                        and item.action == permission_record.action
                    )
                ]
                device.permissions.append(permission_record)
                device.updated_by = (
                    _safe_text(approved_by, 200)
                    or clean_user_id
                )
                device.updated_at = _utc_now_iso()
                device.version += 1

                self._save_devices(
                    clean_user_id,
                    clean_workspace_id,
                    devices,
                )

            self._emit_agent_event(
                "security.device.permission_granted",
                {
                    "user_id": clean_user_id,
                    "workspace_id": clean_workspace_id,
                    "device_id": device.device_id,
                    "permission": clean_permission,
                    "effect": effect,
                },
            )

            self._log_audit_event(
                "grant_device_permission",
                clean_user_id,
                clean_workspace_id,
                {
                    "device_id": device.device_id,
                    "permission": clean_permission,
                    "effect": effect,
                    "approved_by": approved_by,
                },
            )

            return self._safe_result(
                message="Device permission saved.",
                data={
                    "device": self._public_device_dict(device),
                    "permission": permission_record.to_dict(),
                    "verification_payload": (
                        self._prepare_verification_payload(
                            "grant_device_permission",
                            device=device,
                            extra={
                                "permission": (
                                    permission_record.to_dict()
                                )
                            },
                        )
                    ),
                    "memory_payload": self._prepare_memory_payload(
                        "grant_device_permission",
                        device=device,
                    ),
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Unable to grant device permission.",
                error=exc,
            )

    def grant_device_permissions(
        self,
        user_id: str,
        workspace_id: str,
        device_id: str,
        permissions: Iterable[str],
        *,
        approved: bool = False,
        approved_by: Optional[str] = None,
        approval_reference: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Grant several simple allow permissions to one device."""
        normalized_permissions = [
            _normalize_permission_name(item)
            for item in permissions
        ]

        context = self._validate_task_context(
            user_id,
            workspace_id,
            "grant_permissions",
            device_id,
        )
        if not context["success"]:
            return context

        clean_user_id = context["data"]["user_id"]
        clean_workspace_id = context["data"]["workspace_id"]
        clean_device_id = context["data"]["device_id"]

        approval = self._request_security_approval(
            clean_user_id,
            clean_workspace_id,
            "grant_permissions",
            {
                "device_id": clean_device_id,
                "permissions": normalized_permissions,
            },
            approved=approved,
            approved_by=approved_by,
            approval_reference=approval_reference,
        )

        if not approval["success"]:
            return approval

        if approval["data"].get("requires_approval"):
            return approval

        try:
            with self._lock:
                devices = self._load_devices(
                    clean_user_id,
                    clean_workspace_id,
                )
                device = self._find_device(
                    devices,
                    clean_device_id,
                )

                if not device:
                    raise DeviceNotFoundError("Device was not found.")

                if device.status in {"blocked", "revoked"}:
                    raise DeviceSecurityError(
                        "Permissions cannot be granted to blocked or "
                        "revoked devices."
                    )

                existing_keys = {
                    (
                        permission.permission,
                        permission.effect,
                        permission.scope,
                    )
                    for permission in device.permissions
                }

                for permission_name in normalized_permissions:
                    if (
                        permission_name == "*"
                        and not self.policy.allow_privileged_wildcard_permission
                    ):
                        raise DeviceSecurityError(
                            "Wildcard allow permission is disabled by policy."
                        )

                    key = (
                        permission_name,
                        "allow",
                        "device",
                    )

                    if key in existing_keys:
                        continue

                    device.permissions.append(
                        DevicePermission(
                            permission=permission_name,
                            effect="allow",
                            scope="device",
                            granted_by=(
                                _safe_text(approved_by, 200)
                                or clean_user_id
                            ),
                        )
                    )
                    existing_keys.add(key)

                device.updated_by = (
                    _safe_text(approved_by, 200)
                    or clean_user_id
                )
                device.updated_at = _utc_now_iso()
                device.version += 1

                self._save_devices(
                    clean_user_id,
                    clean_workspace_id,
                    devices,
                )

            return self._safe_result(
                message="Device permissions granted.",
                data={
                    "device": self._public_device_dict(device),
                    "granted_permissions": normalized_permissions,
                    "verification_payload": (
                        self._prepare_verification_payload(
                            "grant_device_permissions",
                            device=device,
                            extra={
                                "permissions": normalized_permissions
                            },
                        )
                    ),
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Unable to grant device permissions.",
                error=exc,
            )

    def revoke_device_permission(
        self,
        user_id: str,
        workspace_id: str,
        device_id: str,
        permission: str,
        *,
        approved: bool = False,
        approved_by: Optional[str] = None,
        approval_reference: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Remove all matching rules for a device permission."""
        context = self._validate_task_context(
            user_id,
            workspace_id,
            "revoke_permission",
            device_id,
        )
        if not context["success"]:
            return context

        clean_user_id = context["data"]["user_id"]
        clean_workspace_id = context["data"]["workspace_id"]
        clean_device_id = context["data"]["device_id"]
        clean_permission = _normalize_permission_name(permission)

        approval = self._request_security_approval(
            clean_user_id,
            clean_workspace_id,
            "revoke_permission",
            {
                "device_id": clean_device_id,
                "permission": clean_permission,
            },
            approved=approved,
            approved_by=approved_by,
            approval_reference=approval_reference,
        )

        if not approval["success"]:
            return approval

        if approval["data"].get("requires_approval"):
            return approval

        try:
            with self._lock:
                devices = self._load_devices(
                    clean_user_id,
                    clean_workspace_id,
                )
                device = self._find_device(
                    devices,
                    clean_device_id,
                )

                if not device:
                    raise DeviceNotFoundError("Device was not found.")

                before_count = len(device.permissions)
                device.permissions = [
                    item
                    for item in device.permissions
                    if item.permission != clean_permission
                ]
                removed_count = before_count - len(device.permissions)

                device.updated_by = (
                    _safe_text(approved_by, 200)
                    or clean_user_id
                )
                device.updated_at = _utc_now_iso()
                device.version += 1

                self._save_devices(
                    clean_user_id,
                    clean_workspace_id,
                    devices,
                )

            self._log_audit_event(
                "revoke_device_permission",
                clean_user_id,
                clean_workspace_id,
                {
                    "device_id": device.device_id,
                    "permission": clean_permission,
                    "removed_count": removed_count,
                },
            )

            return self._safe_result(
                message="Device permission revoked.",
                data={
                    "device": self._public_device_dict(device),
                    "permission": clean_permission,
                    "removed_rules": removed_count,
                    "verification_payload": (
                        self._prepare_verification_payload(
                            "revoke_device_permission",
                            device=device,
                            extra={
                                "permission": clean_permission,
                                "removed_rules": removed_count,
                            },
                        )
                    ),
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Unable to revoke device permission.",
                error=exc,
            )

    def replace_device_permissions(
        self,
        user_id: str,
        workspace_id: str,
        device_id: str,
        permissions: Iterable[str],
        *,
        approved: bool = False,
        approved_by: Optional[str] = None,
        approval_reference: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Replace all current permission rules with simple allow rules."""
        context = self._validate_task_context(
            user_id,
            workspace_id,
            "replace_permissions",
            device_id,
        )
        if not context["success"]:
            return context

        clean_user_id = context["data"]["user_id"]
        clean_workspace_id = context["data"]["workspace_id"]
        clean_device_id = context["data"]["device_id"]
        normalized_permissions = [
            _normalize_permission_name(item)
            for item in permissions
        ]

        approval = self._request_security_approval(
            clean_user_id,
            clean_workspace_id,
            "replace_permissions",
            {
                "device_id": clean_device_id,
                "permissions": normalized_permissions,
            },
            approved=approved,
            approved_by=approved_by,
            approval_reference=approval_reference,
        )

        if not approval["success"]:
            return approval

        if approval["data"].get("requires_approval"):
            return approval

        try:
            with self._lock:
                devices = self._load_devices(
                    clean_user_id,
                    clean_workspace_id,
                )
                device = self._find_device(
                    devices,
                    clean_device_id,
                )

                if not device:
                    raise DeviceNotFoundError("Device was not found.")

                self._replace_permissions_internal(
                    device,
                    normalized_permissions,
                    granted_by=approved_by or clean_user_id,
                )

                device.updated_by = (
                    _safe_text(approved_by, 200)
                    or clean_user_id
                )
                device.updated_at = _utc_now_iso()
                device.version += 1

                self._save_devices(
                    clean_user_id,
                    clean_workspace_id,
                    devices,
                )

            return self._safe_result(
                message="Device permissions replaced.",
                data={
                    "device": self._public_device_dict(device),
                    "permissions": normalized_permissions,
                    "verification_payload": (
                        self._prepare_verification_payload(
                            "replace_device_permissions",
                            device=device,
                            extra={
                                "permissions": normalized_permissions
                            },
                        )
                    ),
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Unable to replace device permissions.",
                error=exc,
            )

    # =========================================================================
    # Device lifecycle management
    # =========================================================================

    def suspend_device(
        self,
        user_id: str,
        workspace_id: str,
        device_id: str,
        *,
        reason: str,
        suspended_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Temporarily suspend a device."""
        return self._change_device_status(
            user_id=user_id,
            workspace_id=workspace_id,
            device_id=device_id,
            status="suspended",
            trust_level="untrusted",
            reason=reason,
            changed_by=suspended_by,
            action="suspend_device",
            approval_required=False,
        )

    def block_device(
        self,
        user_id: str,
        workspace_id: str,
        device_id: str,
        *,
        reason: str,
        approved: bool = False,
        approved_by: Optional[str] = None,
        approval_reference: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Block a device from all access."""
        return self._change_device_status(
            user_id=user_id,
            workspace_id=workspace_id,
            device_id=device_id,
            status="blocked",
            trust_level="untrusted",
            reason=reason,
            changed_by=approved_by,
            action="block_device",
            approval_required=True,
            approved=approved,
            approval_reference=approval_reference,
        )

    def unblock_device(
        self,
        user_id: str,
        workspace_id: str,
        device_id: str,
        *,
        restore_as: TrustLevel = "pending",
        approved: bool = False,
        approved_by: Optional[str] = None,
        approval_reference: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Unblock a device and return it to pending or limited status."""
        normalized_trust = self._normalize_trust_level(restore_as)

        if normalized_trust not in {"pending", "limited"}:
            return self._error_result(
                message=(
                    "An unblocked device may only return as pending or limited."
                )
            )

        status: DeviceStatus = (
            "limited"
            if normalized_trust == "limited"
            else "pending"
        )

        return self._change_device_status(
            user_id=user_id,
            workspace_id=workspace_id,
            device_id=device_id,
            status=status,
            trust_level=normalized_trust,
            reason="Device unblocked after security review.",
            changed_by=approved_by,
            action="unblock_device",
            approval_required=True,
            approved=approved,
            approval_reference=approval_reference,
        )

    def revoke_device(
        self,
        user_id: str,
        workspace_id: str,
        device_id: str,
        *,
        reason: str,
        approved: bool = False,
        approved_by: Optional[str] = None,
        approval_reference: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Permanently revoke a device's trust and permissions."""
        result = self._change_device_status(
            user_id=user_id,
            workspace_id=workspace_id,
            device_id=device_id,
            status="revoked",
            trust_level="untrusted",
            reason=reason,
            changed_by=approved_by,
            action="revoke_device",
            approval_required=True,
            approved=approved,
            approval_reference=approval_reference,
            clear_permissions=True,
        )
        return result

    def touch_device(
        self,
        user_id: str,
        workspace_id: str,
        device_id: str,
        *,
        ip_address: Optional[str] = None,
        country_code: Optional[str] = None,
        region: Optional[str] = None,
        app_version: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update device last-seen information."""
        context = self._validate_task_context(
            user_id,
            workspace_id,
            "touch_device",
            device_id,
        )
        if not context["success"]:
            return context

        try:
            clean_user_id = context["data"]["user_id"]
            clean_workspace_id = context["data"]["workspace_id"]
            clean_device_id = context["data"]["device_id"]

            with self._lock:
                devices = self._load_devices(
                    clean_user_id,
                    clean_workspace_id,
                )
                device = self._find_device(
                    devices,
                    clean_device_id,
                )

                if not device:
                    raise DeviceNotFoundError("Device was not found.")

                device.last_seen_at = _utc_now_iso()
                device.updated_at = _utc_now_iso()
                device.version += 1

                if ip_address:
                    device.last_ip_hash = self._hash_network_value(
                        ip_address
                    )
                if country_code:
                    device.last_country_code = _safe_text(
                        country_code,
                        10,
                    ).upper()
                if region:
                    device.last_region = _safe_text(region, 200)
                if app_version:
                    device.app_version = _safe_text(
                        app_version,
                        100,
                    )

                self._save_devices(
                    clean_user_id,
                    clean_workspace_id,
                    devices,
                )

            return self._safe_result(
                message="Device activity updated.",
                data={
                    "device": self._public_device_dict(device),
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Unable to update device activity.",
                error=exc,
            )

    def expire_stale_devices(
        self,
        user_id: str,
        workspace_id: str,
    ) -> Dict[str, Any]:
        """Mark trusted devices as expired when their trust period ends."""
        context = self._validate_task_context(
            user_id,
            workspace_id,
            "expire_stale_devices",
        )
        if not context["success"]:
            return context

        try:
            clean_user_id = context["data"]["user_id"]
            clean_workspace_id = context["data"]["workspace_id"]

            expired_ids: List[str] = []

            with self._lock:
                devices = self._load_devices(
                    clean_user_id,
                    clean_workspace_id,
                )

                for device in devices:
                    if (
                        device.status in {"trusted", "limited"}
                        and device.trust_is_expired()
                    ):
                        device.status = "expired"
                        device.trust_level = "untrusted"
                        device.updated_at = _utc_now_iso()
                        device.version += 1
                        expired_ids.append(device.device_id)

                if expired_ids:
                    self._save_devices(
                        clean_user_id,
                        clean_workspace_id,
                        devices,
                    )

            return self._safe_result(
                message="Expired device trust records processed.",
                data={
                    "expired_count": len(expired_ids),
                    "expired_device_ids": expired_ids,
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Unable to expire stale devices.",
                error=exc,
            )

    # =========================================================================
    # Device retrieval and dashboard data
    # =========================================================================

    def get_device(
        self,
        user_id: str,
        workspace_id: str,
        device_id: str,
    ) -> Dict[str, Any]:
        """Load one device within the exact SaaS scope."""
        context = self._validate_task_context(
            user_id,
            workspace_id,
            "get_device",
            device_id,
        )
        if not context["success"]:
            return context

        try:
            device = self._require_device(
                context["data"]["user_id"],
                context["data"]["workspace_id"],
                context["data"]["device_id"],
            )

            self._refresh_expired_device(device)

            return self._safe_result(
                message="Device loaded.",
                data={
                    "device": self._public_device_dict(device),
                    "access_decision": (
                        self._build_device_access_decision(device)
                    ),
                    "memory_payload": self._prepare_memory_payload(
                        "get_device",
                        device=device,
                    ),
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Unable to load device.",
                error=exc,
            )

    def list_devices(
        self,
        user_id: str,
        workspace_id: str,
        *,
        status: Optional[DeviceStatus] = None,
        trust_level: Optional[TrustLevel] = None,
        device_type: Optional[DeviceType] = None,
        search: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        sort_descending: bool = True,
    ) -> Dict[str, Any]:
        """List devices for one user/workspace."""
        context = self._validate_task_context(
            user_id,
            workspace_id,
            "list_devices",
        )
        if not context["success"]:
            return context

        try:
            clean_user_id = context["data"]["user_id"]
            clean_workspace_id = context["data"]["workspace_id"]

            with self._lock:
                devices = list(
                    self._load_devices(
                        clean_user_id,
                        clean_workspace_id,
                    )
                )

            changed = False
            for device in devices:
                old_status = device.status
                self._refresh_expired_device(device)
                if old_status != device.status:
                    changed = True

            if changed:
                with self._lock:
                    self._save_devices(
                        clean_user_id,
                        clean_workspace_id,
                        devices,
                    )

            if status:
                devices = [
                    item
                    for item in devices
                    if item.status == status
                ]

            if trust_level:
                devices = [
                    item
                    for item in devices
                    if item.trust_level == trust_level
                ]

            if device_type:
                devices = [
                    item
                    for item in devices
                    if item.device_type == device_type
                ]

            if search:
                query = _safe_text(search, 300).lower()
                devices = [
                    item
                    for item in devices
                    if query in self._device_search_blob(item)
                ]

            devices.sort(
                key=lambda item: item.last_seen_at,
                reverse=bool(sort_descending),
            )

            total = len(devices)
            clean_limit = _clamp_int(limit, 1, 500, 100)
            clean_offset = _clamp_int(
                offset,
                0,
                10_000_000,
                0,
            )
            page = devices[
                clean_offset: clean_offset + clean_limit
            ]

            return self._safe_result(
                message="Devices loaded.",
                data={
                    "devices": [
                        self._public_device_dict(item)
                        for item in page
                    ],
                    "total": total,
                    "limit": clean_limit,
                    "offset": clean_offset,
                    "has_more": (
                        clean_offset + clean_limit < total
                    ),
                    "memory_payload": self._prepare_memory_payload(
                        "list_devices",
                        devices=page,
                    ),
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Unable to list devices.",
                error=exc,
            )

    def get_device_summary(
        self,
        user_id: str,
        workspace_id: str,
    ) -> Dict[str, Any]:
        """Return dashboard-ready device security metrics."""
        context = self._validate_task_context(
            user_id,
            workspace_id,
            "get_device_summary",
        )
        if not context["success"]:
            return context

        try:
            clean_user_id = context["data"]["user_id"]
            clean_workspace_id = context["data"]["workspace_id"]

            with self._lock:
                devices = list(
                    self._load_devices(
                        clean_user_id,
                        clean_workspace_id,
                    )
                )

            counts_by_status = {
                status: 0
                for status in sorted(self.ALLOWED_STATUSES)
            }
            counts_by_type = {
                device_type: 0
                for device_type in sorted(self.ALLOWED_DEVICE_TYPES)
            }
            counts_by_risk = {
                "low": 0,
                "medium": 0,
                "high": 0,
                "critical": 0,
            }

            for device in devices:
                self._refresh_expired_device(device)
                counts_by_status[device.status] = (
                    counts_by_status.get(device.status, 0) + 1
                )
                counts_by_type[device.device_type] = (
                    counts_by_type.get(device.device_type, 0) + 1
                )
                counts_by_risk[device.risk_level] = (
                    counts_by_risk.get(device.risk_level, 0) + 1
                )

            recent_devices = sorted(
                devices,
                key=lambda item: item.last_seen_at,
                reverse=True,
            )[:10]

            high_risk_devices = [
                self._public_device_dict(item)
                for item in devices
                if item.risk_level in {"high", "critical"}
            ]

            return self._safe_result(
                message="Device security summary generated.",
                data={
                    "summary": {
                        "total_devices": len(devices),
                        "counts_by_status": counts_by_status,
                        "counts_by_type": counts_by_type,
                        "counts_by_risk": counts_by_risk,
                        "trusted_devices": sum(
                            1
                            for item in devices
                            if item.is_active_trusted_device()
                        ),
                        "blocked_devices": counts_by_status.get(
                            "blocked",
                            0,
                        ),
                        "pending_devices": counts_by_status.get(
                            "pending",
                            0,
                        ),
                        "high_risk_devices": high_risk_devices,
                        "recent_devices": [
                            self._public_device_dict(item)
                            for item in recent_devices
                        ],
                    }
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Unable to generate device summary.",
                error=exc,
            )

    # =========================================================================
    # Internal device state operations
    # =========================================================================

    def _change_device_status(
        self,
        *,
        user_id: str,
        workspace_id: str,
        device_id: str,
        status: DeviceStatus,
        trust_level: TrustLevel,
        reason: str,
        changed_by: Optional[str],
        action: str,
        approval_required: bool,
        approved: bool = False,
        approval_reference: Optional[str] = None,
        clear_permissions: bool = False,
    ) -> Dict[str, Any]:
        """Change device lifecycle status with optional approval enforcement."""
        context = self._validate_task_context(
            user_id,
            workspace_id,
            action,
            device_id,
        )
        if not context["success"]:
            return context

        clean_user_id = context["data"]["user_id"]
        clean_workspace_id = context["data"]["workspace_id"]
        clean_device_id = context["data"]["device_id"]
        clean_reason = _safe_text(
            reason,
            1_000,
            allow_empty=False,
        )

        if approval_required:
            approval = self._request_security_approval(
                clean_user_id,
                clean_workspace_id,
                action,
                {
                    "device_id": clean_device_id,
                    "status": status,
                    "reason": clean_reason,
                },
                approved=approved,
                approved_by=changed_by,
                approval_reference=approval_reference,
            )

            if not approval["success"]:
                return approval

            if approval["data"].get("requires_approval"):
                return approval

        try:
            with self._lock:
                devices = self._load_devices(
                    clean_user_id,
                    clean_workspace_id,
                )
                device = self._find_device(
                    devices,
                    clean_device_id,
                )

                if not device:
                    raise DeviceNotFoundError("Device was not found.")

                device.status = status
                device.trust_level = trust_level
                device.updated_by = (
                    _safe_text(changed_by, 200)
                    or clean_user_id
                )
                device.updated_at = _utc_now_iso()
                device.version += 1

                if status == "revoked":
                    device.revoked_by = device.updated_by
                    device.revoked_at = _utc_now_iso()
                    device.revoke_reason = clean_reason

                if status in {"blocked", "revoked", "suspended"}:
                    device.trust_expires_at = None

                if clear_permissions:
                    device.permissions = []
                    device.denied_permissions = ["*"]

                if status == "blocked":
                    self._append_risk_reason(
                        device,
                        f"Device blocked: {clean_reason}",
                    )
                    device.risk_score = max(
                        device.risk_score,
                        80.0,
                    )
                    device.risk_level = self._risk_level_for_score(
                        device.risk_score
                    )

                self._save_devices(
                    clean_user_id,
                    clean_workspace_id,
                    devices,
                )

            self._emit_agent_event(
                f"security.device.{action}",
                {
                    "user_id": clean_user_id,
                    "workspace_id": clean_workspace_id,
                    "device_id": device.device_id,
                    "status": device.status,
                    "reason": clean_reason,
                },
            )

            self._log_audit_event(
                action,
                clean_user_id,
                clean_workspace_id,
                {
                    "device_id": device.device_id,
                    "status": status,
                    "reason": clean_reason,
                    "changed_by": changed_by,
                },
                severity=(
                    "warning"
                    if status in {"blocked", "revoked", "suspended"}
                    else "info"
                ),
            )

            decision = self._build_device_access_decision(device)

            return self._safe_result(
                message=f"Device status changed to {status}.",
                data={
                    "device": self._public_device_dict(device),
                    "access_decision": decision,
                    "verification_payload": (
                        self._prepare_verification_payload(
                            action,
                            device=device,
                            decision=decision,
                            extra={"reason": clean_reason},
                        )
                    ),
                    "memory_payload": self._prepare_memory_payload(
                        action,
                        device=device,
                    ),
                },
            )

        except Exception as exc:
            return self._error_result(
                message=f"Unable to complete {action}.",
                error=exc,
            )

    def _build_new_device_record(
        self,
        *,
        user_id: str,
        workspace_id: str,
        fingerprint_hash: str,
        display_name: str,
        device_type: DeviceType,
        platform: Optional[str],
        operating_system: Optional[str],
        browser: Optional[str],
        app_version: Optional[str],
        public_key_fingerprint: Optional[str],
        ip_hash: Optional[str],
        country_code: Optional[str],
        region: Optional[str],
        requested_permissions: Optional[Iterable[str]],
        created_by: Optional[str],
        metadata: Optional[Dict[str, Any]],
    ) -> DeviceRecord:
        """Build a new record according to unknown-device policy."""
        policy = self.policy.unknown_device_policy

        status: DeviceStatus
        trust_level: TrustLevel
        permissions: List[str]

        if policy == "block":
            status = "blocked"
            trust_level = "untrusted"
            permissions = []
        elif policy == "challenge":
            status = "pending"
            trust_level = "pending"
            permissions = []
        elif policy == "limited":
            status = "limited"
            trust_level = "limited"
            permissions = list(
                requested_permissions
                or self.policy.default_limited_permissions
            )
        else:
            status = "trusted"
            trust_level = "trusted"
            permissions = list(
                requested_permissions
                or self.policy.default_trusted_permissions
            )

        now = _utc_now_iso()

        device = DeviceRecord(
            device_id=f"dev_{uuid.uuid4().hex}",
            user_id=user_id,
            workspace_id=workspace_id,
            fingerprint_hash=fingerprint_hash,
            display_name=display_name,
            device_type=device_type,
            status=status,
            trust_level=trust_level,
            platform=_safe_text(platform, 200) or None,
            operating_system=(
                _safe_text(operating_system, 300) or None
            ),
            browser=_safe_text(browser, 300) or None,
            app_version=_safe_text(app_version, 100) or None,
            public_key_fingerprint=(
                self._normalize_public_key_fingerprint(
                    public_key_fingerprint
                )
                if public_key_fingerprint
                else None
            ),
            first_seen_at=now,
            last_seen_at=now,
            trusted_at=(
                now
                if status in {"trusted", "limited"}
                else None
            ),
            trust_expires_at=(
                (
                    _utc_now()
                    + timedelta(
                        days=self.policy.default_trust_days
                    )
                ).isoformat()
                if status in {"trusted", "limited"}
                else None
            ),
            last_ip_hash=ip_hash,
            last_country_code=(
                _safe_text(country_code, 10).upper()
                if country_code
                else None
            ),
            last_region=(
                _safe_text(region, 200)
                if region
                else None
            ),
            created_by=(
                _safe_text(created_by, 200)
                or user_id
            ),
            updated_by=(
                _safe_text(created_by, 200)
                or user_id
            ),
            metadata=self._sanitize_metadata(metadata or {}),
        )

        self._replace_permissions_internal(
            device,
            permissions,
            granted_by=device.created_by,
        )

        if status == "blocked":
            device.risk_score = 80.0
            device.risk_level = "high"
            device.risk_reasons = [
                "Unknown device blocked by workspace policy."
            ]

        return device

    def _registration_message(self, device: DeviceRecord) -> str:
        """Return user-facing registration status."""
        if device.status == "blocked":
            return "Unknown device was registered and blocked."
        if device.status == "pending":
            return "Device registration is pending verification."
        if device.status == "limited":
            return "Device registered with limited access."
        return "Device registered as trusted."

    # =========================================================================
    # Permission and risk internals
    # =========================================================================

    def _evaluate_device_permission(
        self,
        device: DeviceRecord,
        permission: str,
        *,
        resource: Optional[str] = None,
        agent_name: Optional[str] = None,
        action: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Evaluate one permission against device rules."""
        requested = _normalize_permission_name(permission)

        for denied in device.denied_permissions:
            denied_normalized = _normalize_permission_name(denied)
            if (
                denied_normalized == "*"
                or denied_normalized == requested
                or (
                    denied_normalized.endswith("*")
                    and requested.startswith(
                        denied_normalized[:-1]
                    )
                )
            ):
                return {
                    "allowed": False,
                    "reason": "explicit_device_deny",
                    "message": (
                        "Device permission is explicitly denied."
                    ),
                    "permission": requested,
                }

        matching_rules = [
            rule
            for rule in device.permissions
            if rule.matches(
                requested,
                resource=resource,
                agent_name=agent_name,
                action=action,
            )
        ]

        deny_rules = [
            rule
            for rule in matching_rules
            if rule.effect == "deny"
        ]

        if deny_rules:
            return {
                "allowed": False,
                "reason": "matching_deny_rule",
                "message": (
                    "A device deny rule blocked the requested permission."
                ),
                "permission": requested,
                "matched_rule": deny_rules[0].to_dict(),
            }

        allow_rules = [
            rule
            for rule in matching_rules
            if rule.effect == "allow"
        ]

        if allow_rules:
            if (
                self._is_sensitive_permission(requested)
                and device.trust_level != "privileged"
            ):
                return {
                    "allowed": False,
                    "reason": "privileged_device_required",
                    "message": (
                        "The requested permission requires a privileged "
                        "trusted device."
                    ),
                    "permission": requested,
                }

            return {
                "allowed": True,
                "reason": "matching_allow_rule",
                "message": "Device permission granted.",
                "permission": requested,
                "matched_rule": allow_rules[0].to_dict(),
            }

        return {
            "allowed": False,
            "reason": "permission_not_granted",
            "message": (
                "The device does not have the requested permission."
            ),
            "permission": requested,
        }

    def _build_device_access_decision(
        self,
        device: DeviceRecord,
    ) -> Dict[str, Any]:
        """Build the base trust/access decision for a device."""
        if device.trust_is_expired():
            return {
                "allowed": False,
                "reason": "device_trust_expired",
                "message": "Device trust has expired.",
                "requires_verification": True,
                "status": "expired",
            }

        if device.status == "blocked":
            return {
                "allowed": False,
                "reason": "device_blocked",
                "message": "This device is blocked.",
                "requires_verification": False,
                "status": device.status,
            }

        if device.status == "revoked":
            return {
                "allowed": False,
                "reason": "device_revoked",
                "message": "This device has been revoked.",
                "requires_verification": False,
                "status": device.status,
            }

        if device.status == "suspended":
            return {
                "allowed": False,
                "reason": "device_suspended",
                "message": "This device is suspended.",
                "requires_verification": True,
                "status": device.status,
            }

        if device.status == "pending":
            return {
                "allowed": False,
                "reason": "device_pending_verification",
                "message": "This device requires verification.",
                "requires_verification": True,
                "status": device.status,
            }

        if device.status == "expired":
            return {
                "allowed": False,
                "reason": "device_expired",
                "message": "This device's trust has expired.",
                "requires_verification": True,
                "status": device.status,
            }

        if (
            self.policy.block_high_risk_devices
            and device.risk_score
            >= self.policy.high_risk_threshold
        ):
            return {
                "allowed": False,
                "reason": "device_risk_too_high",
                "message": (
                    "Device access was blocked because the risk score "
                    "is too high."
                ),
                "requires_verification": True,
                "risk_score": device.risk_score,
                "risk_level": device.risk_level,
            }

        if not device.is_active_trusted_device():
            return {
                "allowed": False,
                "reason": "device_not_trusted",
                "message": "Device is not trusted.",
                "requires_verification": True,
                "status": device.status,
            }

        return {
            "allowed": True,
            "reason": "trusted_device",
            "message": "Device access granted.",
            "requires_verification": False,
            "status": device.status,
            "trust_level": device.trust_level,
            "risk_score": device.risk_score,
            "risk_level": device.risk_level,
        }

    def _unknown_device_decision(self) -> Dict[str, Any]:
        """Build an access decision for an unknown device."""
        policy = self.policy.unknown_device_policy

        if policy == "allow":
            return {
                "allowed": True,
                "reason": "unknown_device_allowed_by_policy",
                "message": (
                    "Unknown device access is allowed by workspace policy."
                ),
                "requires_registration": True,
                "requires_verification": False,
                "policy": policy,
            }

        if policy == "limited":
            return {
                "allowed": True,
                "reason": "unknown_device_limited_by_policy",
                "message": (
                    "Unknown device has limited access under workspace policy."
                ),
                "requires_registration": True,
                "requires_verification": True,
                "limited": True,
                "policy": policy,
            }

        if policy == "challenge":
            return {
                "allowed": False,
                "reason": "unknown_device_requires_challenge",
                "message": (
                    "Unknown device must complete verification before access."
                ),
                "requires_registration": True,
                "requires_verification": True,
                "policy": policy,
            }

        return {
            "allowed": False,
            "reason": "unknown_device_blocked",
            "message": "Unknown device access is blocked.",
            "requires_registration": True,
            "requires_verification": True,
            "policy": policy,
        }

    def _validate_session_binding_internal(
        self,
        device: DeviceRecord,
        session_device_id: Optional[str],
    ) -> Dict[str, Any]:
        """Check session/device binding policy."""
        if not self.policy.bind_session_to_device:
            return {
                "allowed": True,
                "reason": "session_binding_disabled",
                "message": "Session-device binding is disabled.",
            }

        if session_device_id is None:
            return {
                "allowed": True,
                "reason": "session_binding_not_provided",
                "message": (
                    "No session-device binding value was provided."
                ),
            }

        clean_session_device_id = _safe_text(
            session_device_id,
            200,
        )

        if _constant_time_equal(
            clean_session_device_id,
            device.device_id,
        ):
            return {
                "allowed": True,
                "reason": "session_device_match",
                "message": "Session is bound to the correct device.",
            }

        return {
            "allowed": False,
            "reason": "session_device_mismatch",
            "message": (
                "Session-device binding failed. Re-authentication is required."
            ),
            "requires_reauthentication": True,
        }

    def _apply_risk_context(
        self,
        device: DeviceRecord,
        risk_context: Dict[str, Any],
    ) -> None:
        """Apply bounded risk signals to a device."""
        score_delta = 0.0
        reasons: List[str] = []

        if bool(risk_context.get("impossible_travel")):
            score_delta += 35.0
            reasons.append("Impossible-travel signal detected.")

        if bool(risk_context.get("new_country")):
            score_delta += 15.0
            reasons.append("Device appeared in a new country.")

        if bool(risk_context.get("tor_or_proxy")):
            score_delta += 25.0
            reasons.append("Tor, proxy, or anonymizer signal detected.")

        if bool(risk_context.get("automation_detected")):
            score_delta += 30.0
            reasons.append("Automated or scripted access was detected.")

        if bool(risk_context.get("fingerprint_changed")):
            score_delta += 40.0
            reasons.append("Device fingerprint changed unexpectedly.")

        if bool(risk_context.get("recent_password_reset")):
            score_delta += 10.0
            reasons.append("Recent password reset increased device risk.")

        external_score = risk_context.get("external_risk_score")
        if external_score is not None:
            try:
                score_delta += max(
                    0.0,
                    min(float(external_score), 100.0),
                ) * 0.5
            except (TypeError, ValueError):
                pass

        device.risk_score = max(
            0.0,
            min(100.0, device.risk_score + score_delta),
        )
        device.risk_level = self._risk_level_for_score(
            device.risk_score
        )

        for reason in reasons:
            self._append_risk_reason(device, reason)

        if (
            self.policy.block_high_risk_devices
            and device.risk_score
            >= self.policy.critical_risk_threshold
        ):
            device.status = "blocked"
            device.trust_level = "untrusted"

        device.updated_at = _utc_now_iso()
        device.version += 1

    def _risk_level_for_score(self, score: float) -> RiskLevel:
        """Map a numerical score to a risk level."""
        if score >= self.policy.critical_risk_threshold:
            return "critical"
        if score >= self.policy.high_risk_threshold:
            return "high"
        if score >= 40.0:
            return "medium"
        return "low"

    def _append_risk_reason(
        self,
        device: DeviceRecord,
        reason: str,
    ) -> None:
        """Append a unique bounded risk reason."""
        clean_reason = _safe_text(reason, 500)

        if clean_reason and clean_reason not in device.risk_reasons:
            device.risk_reasons.append(clean_reason)
            device.risk_reasons = device.risk_reasons[-100:]

    # =========================================================================
    # Fingerprint and token security
    # =========================================================================

    def _create_device_fingerprint(
        self,
        user_id: str,
        workspace_id: str,
        fingerprint_data: Mapping[str, Any],
    ) -> str:
        """
        Create a one-way device fingerprint.

        Accepted values should be stable device/browser characteristics that are
        legally and operationally appropriate for the application. Raw values
        are never persisted by this class.
        """
        if not isinstance(fingerprint_data, Mapping):
            raise DeviceValidationError(
                "fingerprint_data must be a mapping."
            )

        if not fingerprint_data:
            raise DeviceValidationError(
                "fingerprint_data cannot be empty."
            )

        forbidden_keys = {
            "password",
            "passwd",
            "secret",
            "token",
            "access_token",
            "refresh_token",
            "api_key",
            "private_key",
            "credit_card",
            "cvv",
            "biometric_template",
        }

        normalized: Dict[str, Any] = {}

        for key in sorted(fingerprint_data.keys(), key=str):
            clean_key = _safe_text(key, 100).lower()

            if clean_key in forbidden_keys:
                raise DeviceSecurityError(
                    f"Sensitive field '{clean_key}' cannot be used in a "
                    "device fingerprint."
                )

            value = fingerprint_data[key]

            if isinstance(value, (str, int, float, bool)) or value is None:
                normalized[clean_key] = _safe_text(value, 1_000)
            elif isinstance(value, Sequence) and not isinstance(
                value,
                (str, bytes),
            ):
                normalized[clean_key] = [
                    _safe_text(item, 300)
                    for item in list(value)[:50]
                ]
            else:
                normalized[clean_key] = _safe_text(value, 1_000)

        canonical = json.dumps(
            {
                "user_id": user_id,
                "workspace_id": workspace_id,
                "fingerprint": normalized,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")

        digest = hmac.new(
            self._fingerprint_secret,
            canonical,
            hashlib.sha256,
        ).hexdigest()

        return f"fp_hmac_sha256:{digest}"

    def _hash_network_value(self, value: str) -> str:
        """Hash an IP/network value instead of storing it directly."""
        clean = _safe_text(value, 200, allow_empty=False)
        digest = hmac.new(
            self._fingerprint_secret,
            clean.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return f"net_hmac_sha256:{digest}"

    def _hash_challenge_token(self, token: str) -> str:
        """Hash a challenge token with the module HMAC secret."""
        clean = _safe_text(token, 2_000, allow_empty=False)
        digest = hmac.new(
            self._fingerprint_secret,
            clean.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return f"challenge_hmac_sha256:{digest}"

    def _normalize_public_key_fingerprint(
        self,
        value: str,
    ) -> str:
        """Normalize a public-key fingerprint without accepting private keys."""
        clean = _safe_text(value, 512, allow_empty=False)

        if "PRIVATE KEY" in clean.upper():
            raise DeviceSecurityError(
                "Private keys cannot be stored as device fingerprints."
            )

        return clean

    # =========================================================================
    # Storage
    # =========================================================================

    def _scope_key(
        self,
        user_id: str,
        workspace_id: str,
    ) -> str:
        """Return a stable isolated cache/storage key."""
        raw = f"{user_id}\x1f{workspace_id}".encode("utf-8")
        digest = hashlib.sha256(raw).hexdigest()
        return digest

    def _scope_directory(
        self,
        user_id: str,
        workspace_id: str,
    ) -> Path:
        """Return the isolated storage directory."""
        return self.storage_dir / self._scope_key(
            user_id,
            workspace_id,
        )

    def _devices_file(
        self,
        user_id: str,
        workspace_id: str,
    ) -> Path:
        """Return the isolated device-record file."""
        return self._scope_directory(
            user_id,
            workspace_id,
        ) / "devices.json"

    def _challenges_file(
        self,
        user_id: str,
        workspace_id: str,
    ) -> Path:
        """Return the isolated challenge file."""
        return self._scope_directory(
            user_id,
            workspace_id,
        ) / "challenges.json"

    def _load_devices(
        self,
        user_id: str,
        workspace_id: str,
    ) -> List[DeviceRecord]:
        """Load device records from cache or isolated storage."""
        key = self._scope_key(user_id, workspace_id)

        if key in self._device_cache:
            return self._device_cache[key]

        devices: List[DeviceRecord] = []

        if self.enable_file_storage:
            file_path = self._devices_file(
                user_id,
                workspace_id,
            )

            if file_path.exists():
                try:
                    payload = json.loads(
                        file_path.read_text(encoding="utf-8")
                    )

                    if (
                        payload.get("user_id") != user_id
                        or payload.get("workspace_id") != workspace_id
                    ):
                        raise DeviceStorageError(
                            "Stored device scope does not match the "
                            "requested user/workspace."
                        )

                    devices = [
                        DeviceRecord.from_dict(item)
                        for item in payload.get("devices", [])
                        if isinstance(item, Mapping)
                    ]

                except DeviceStorageError:
                    raise
                except Exception as exc:
                    raise DeviceStorageError(
                        f"Unable to load device records: {exc}"
                    ) from exc

        self._device_cache[key] = devices
        return devices

    def _save_devices(
        self,
        user_id: str,
        workspace_id: str,
        devices: List[DeviceRecord],
    ) -> None:
        """Save device records atomically."""
        key = self._scope_key(user_id, workspace_id)
        self._device_cache[key] = devices

        if not self.enable_file_storage:
            return

        directory = self._scope_directory(
            user_id,
            workspace_id,
        )
        directory.mkdir(parents=True, exist_ok=True)

        file_path = self._devices_file(
            user_id,
            workspace_id,
        )
        temporary_path = file_path.with_suffix(".json.tmp")

        payload = {
            "schema": "william.security.device_access.devices.v1",
            "user_id": user_id,
            "workspace_id": workspace_id,
            "updated_at": _utc_now_iso(),
            "devices": [
                device.to_dict()
                for device in devices
            ],
        }

        try:
            temporary_path.write_text(
                json.dumps(
                    payload,
                    indent=2,
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            temporary_path.replace(file_path)
        except Exception as exc:
            temporary_path.unlink(missing_ok=True)
            raise DeviceStorageError(
                f"Unable to save device records: {exc}"
            ) from exc

    def _load_challenges(
        self,
        user_id: str,
        workspace_id: str,
    ) -> List[DeviceChallenge]:
        """Load verification challenges."""
        key = self._scope_key(user_id, workspace_id)

        if key in self._challenge_cache:
            return self._challenge_cache[key]

        challenges: List[DeviceChallenge] = []

        if self.enable_file_storage:
            file_path = self._challenges_file(
                user_id,
                workspace_id,
            )

            if file_path.exists():
                try:
                    payload = json.loads(
                        file_path.read_text(encoding="utf-8")
                    )

                    if (
                        payload.get("user_id") != user_id
                        or payload.get("workspace_id") != workspace_id
                    ):
                        raise DeviceStorageError(
                            "Stored challenge scope does not match the "
                            "requested user/workspace."
                        )

                    challenges = [
                        DeviceChallenge.from_dict(item)
                        for item in payload.get("challenges", [])
                        if isinstance(item, Mapping)
                    ]

                except DeviceStorageError:
                    raise
                except Exception as exc:
                    raise DeviceStorageError(
                        f"Unable to load device challenges: {exc}"
                    ) from exc

        self._challenge_cache[key] = challenges
        return challenges

    def _save_challenges(
        self,
        user_id: str,
        workspace_id: str,
        challenges: List[DeviceChallenge],
    ) -> None:
        """Persist verification challenges atomically."""
        key = self._scope_key(user_id, workspace_id)
        self._challenge_cache[key] = challenges

        if not self.enable_file_storage:
            return

        directory = self._scope_directory(
            user_id,
            workspace_id,
        )
        directory.mkdir(parents=True, exist_ok=True)

        file_path = self._challenges_file(
            user_id,
            workspace_id,
        )
        temporary_path = file_path.with_suffix(".json.tmp")

        payload = {
            "schema": "william.security.device_access.challenges.v1",
            "user_id": user_id,
            "workspace_id": workspace_id,
            "updated_at": _utc_now_iso(),
            "challenges": [
                challenge.to_dict(include_token_hash=True)
                for challenge in challenges
            ],
        }

        try:
            temporary_path.write_text(
                json.dumps(
                    payload,
                    indent=2,
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            temporary_path.replace(file_path)
        except Exception as exc:
            temporary_path.unlink(missing_ok=True)
            raise DeviceStorageError(
                f"Unable to save device challenges: {exc}"
            ) from exc

    # =========================================================================
    # Lookup and serialization helpers
    # =========================================================================

    def _find_device(
        self,
        devices: Iterable[DeviceRecord],
        device_id: str,
    ) -> Optional[DeviceRecord]:
        """Find a device by its public device ID."""
        for device in devices:
            if _constant_time_equal(device.device_id, device_id):
                return device
        return None

    def _find_device_by_fingerprint(
        self,
        devices: Iterable[DeviceRecord],
        fingerprint_hash: str,
    ) -> Optional[DeviceRecord]:
        """Find a device using its one-way fingerprint."""
        for device in devices:
            if _constant_time_equal(
                device.fingerprint_hash,
                fingerprint_hash,
            ):
                return device
        return None

    def _require_device(
        self,
        user_id: str,
        workspace_id: str,
        device_id: str,
    ) -> DeviceRecord:
        """Load one device or raise DeviceNotFoundError."""
        with self._lock:
            devices = self._load_devices(
                user_id,
                workspace_id,
            )
            device = self._find_device(devices, device_id)

        if not device:
            raise DeviceNotFoundError(
                "Device was not found in the requested user/workspace."
            )

        return device

    def _find_challenge(
        self,
        challenges: Iterable[DeviceChallenge],
        challenge_id: str,
    ) -> Optional[DeviceChallenge]:
        """Find a challenge by ID."""
        for challenge in challenges:
            if _constant_time_equal(
                challenge.challenge_id,
                challenge_id,
            ):
                return challenge
        return None

    def _public_device_dict(
        self,
        device: DeviceRecord,
    ) -> Dict[str, Any]:
        """
        Return a dashboard/API-safe device dictionary.

        Fingerprint hashes and network hashes are not exposed.
        """
        payload = device.to_dict()

        payload.pop("fingerprint_hash", None)
        payload.pop("last_ip_hash", None)

        payload["active_permissions"] = [
            item.to_dict()
            for item in device.permissions
            if item.active and not item.is_expired()
        ]
        payload["expired_permission_count"] = sum(
            1
            for item in device.permissions
            if item.is_expired()
        )
        payload.pop("permissions", None)

        return payload

    def _device_to_memory_item(
        self,
        device: DeviceRecord,
    ) -> Dict[str, Any]:
        """Return privacy-safe device context for Memory Agent."""
        return {
            "id": device.device_id,
            "scope": "security_device",
            "user_id": device.user_id,
            "workspace_id": device.workspace_id,
            "title": device.display_name,
            "device_type": device.device_type,
            "status": device.status,
            "trust_level": device.trust_level,
            "platform": device.platform,
            "operating_system": device.operating_system,
            "browser": device.browser,
            "app_version": device.app_version,
            "risk_score": device.risk_score,
            "risk_level": device.risk_level,
            "risk_reasons": list(device.risk_reasons),
            "first_seen_at": device.first_seen_at,
            "last_seen_at": device.last_seen_at,
            "trusted_at": device.trusted_at,
            "trust_expires_at": device.trust_expires_at,
            "permission_names": [
                item.permission
                for item in device.permissions
                if item.active and not item.is_expired()
            ],
            "metadata": {
                "version": device.version,
                "country_code": device.last_country_code,
                "region": device.last_region,
            },
        }

    def _device_search_blob(
        self,
        device: DeviceRecord,
    ) -> str:
        """Build a lower-case search blob."""
        return " ".join(
            [
                device.device_id,
                device.display_name,
                device.device_type,
                device.status,
                device.trust_level,
                device.platform or "",
                device.operating_system or "",
                device.browser or "",
                device.app_version or "",
                device.last_country_code or "",
                device.last_region or "",
                " ".join(
                    permission.permission
                    for permission in device.permissions
                ),
            ]
        ).lower()

    # =========================================================================
    # Configuration and validation helpers
    # =========================================================================

    def _build_policy(
        self,
        policy: Optional[
            Union[DeviceAccessPolicy, Dict[str, Any]]
        ],
    ) -> DeviceAccessPolicy:
        """Build a validated policy object."""
        if policy is None:
            return DeviceAccessPolicy()

        if isinstance(policy, DeviceAccessPolicy):
            return policy

        if not isinstance(policy, dict):
            raise DeviceValidationError(
                "policy must be DeviceAccessPolicy or a dictionary."
            )

        allowed_fields = set(
            DeviceAccessPolicy.__dataclass_fields__.keys()
        )
        clean_data = {
            key: value
            for key, value in policy.items()
            if key in allowed_fields
        }

        built = DeviceAccessPolicy(**clean_data)

        if built.unknown_device_policy not in {
            "block",
            "challenge",
            "limited",
            "allow",
        }:
            built.unknown_device_policy = "block"

        built.default_trust_days = _clamp_int(
            built.default_trust_days,
            1,
            365,
            90,
        )
        built.maximum_trust_days = _clamp_int(
            built.maximum_trust_days,
            built.default_trust_days,
            3_650,
            365,
        )
        built.challenge_expiry_minutes = _clamp_int(
            built.challenge_expiry_minutes,
            1,
            1_440,
            15,
        )
        built.challenge_max_attempts = _clamp_int(
            built.challenge_max_attempts,
            1,
            20,
            5,
        )
        built.block_after_failed_attempts = _clamp_int(
            built.block_after_failed_attempts,
            1,
            100,
            10,
        )

        built.high_risk_threshold = max(
            1.0,
            min(float(built.high_risk_threshold), 99.0),
        )
        built.critical_risk_threshold = max(
            built.high_risk_threshold,
            min(float(built.critical_risk_threshold), 100.0),
        )

        built.default_limited_permissions = [
            _normalize_permission_name(item)
            for item in built.default_limited_permissions
        ]
        built.default_trusted_permissions = [
            _normalize_permission_name(item)
            for item in built.default_trusted_permissions
        ]
        built.sensitive_permissions = [
            _normalize_permission_name(item)
            for item in built.sensitive_permissions
        ]

        return built

    def _normalize_device_type(
        self,
        value: Any,
    ) -> DeviceType:
        """Validate a device type."""
        clean = _safe_text(value, 50).lower()

        if clean not in self.ALLOWED_DEVICE_TYPES:
            return "unknown"

        return clean  # type: ignore[return-value]

    def _normalize_trust_level(
        self,
        value: Any,
    ) -> TrustLevel:
        """Validate a trust level."""
        clean = _safe_text(value, 50).lower()

        if clean not in self.ALLOWED_TRUST_LEVELS:
            raise DeviceValidationError(
                f"Unsupported trust level: {clean}"
            )

        return clean  # type: ignore[return-value]

    def _validate_optional_expiry(
        self,
        value: Optional[str],
    ) -> Optional[str]:
        """Validate an optional future expiry datetime."""
        if not value:
            return None

        parsed = _parse_datetime(value)

        if parsed is None:
            raise DeviceValidationError(
                "expires_at must be a valid ISO-8601 datetime."
            )

        if parsed <= _utc_now():
            raise DeviceValidationError(
                "expires_at must be in the future."
            )

        return parsed.isoformat()

    def _is_sensitive_permission(
        self,
        permission: str,
    ) -> bool:
        """Return True if a permission matches a sensitive policy pattern."""
        requested = _normalize_permission_name(permission)

        for pattern in self.policy.sensitive_permissions:
            normalized = _normalize_permission_name(pattern)

            if normalized == requested:
                return True

            if normalized.endswith("*") and requested.startswith(
                normalized[:-1]
            ):
                return True

        return False

    def _replace_permissions_internal(
        self,
        device: DeviceRecord,
        permissions: Iterable[str],
        *,
        granted_by: Optional[str],
    ) -> None:
        """Replace device permissions with normalized allow rules."""
        normalized = []
        seen: Set[str] = set()

        for item in permissions:
            permission = _normalize_permission_name(item)

            if permission in seen:
                continue

            if (
                permission == "*"
                and not self.policy.allow_privileged_wildcard_permission
            ):
                continue

            seen.add(permission)
            normalized.append(
                DevicePermission(
                    permission=permission,
                    effect="allow",
                    scope="device",
                    granted_by=_safe_text(granted_by, 200) or None,
                )
            )

        device.permissions = normalized
        device.denied_permissions = []

    def _refresh_expired_device(
        self,
        device: DeviceRecord,
    ) -> None:
        """Update device status when trust has expired."""
        if (
            device.status in {"trusted", "limited"}
            and device.trust_is_expired()
        ):
            device.status = "expired"
            device.trust_level = "untrusted"
            device.updated_at = _utc_now_iso()
            device.version += 1

    def _sanitize_metadata(
        self,
        metadata: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Remove secret-like metadata fields and bound metadata size."""
        forbidden_keys = {
            "password",
            "passwd",
            "secret",
            "token",
            "access_token",
            "refresh_token",
            "api_key",
            "private_key",
            "biometric_template",
            "credit_card",
            "cvv",
        }

        sanitized: Dict[str, Any] = {}

        for index, (key, value) in enumerate(metadata.items()):
            if index >= 100:
                break

            clean_key = _safe_text(key, 100)

            if clean_key.lower() in forbidden_keys:
                continue

            if isinstance(value, (str, int, float, bool)) or value is None:
                clean_value = _safe_text(value, 1_000)

                if self._contains_secret_like_content(
                    {clean_key: clean_value}
                ):
                    continue

                sanitized[clean_key] = clean_value
            elif isinstance(value, list):
                sanitized[clean_key] = [
                    _safe_text(item, 300)
                    for item in value[:50]
                ]
            elif isinstance(value, dict):
                sanitized[clean_key] = {
                    _safe_text(sub_key, 100): _safe_text(
                        sub_value,
                        300,
                    )
                    for sub_key, sub_value in list(
                        value.items()
                    )[:50]
                    if _safe_text(sub_key, 100).lower()
                    not in forbidden_keys
                }

        return sanitized

    def _contains_secret_like_content(
        self,
        payload: Any,
    ) -> bool:
        """Detect secret-like content in a payload."""
        try:
            text = json.dumps(
                payload,
                ensure_ascii=False,
                default=str,
            )
        except Exception:
            text = str(payload)

        return any(
            pattern.search(text)
            for pattern in self.SECRET_PATTERNS
        )

    def _summarize_payload(
        self,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Create a bounded audit-safe payload summary."""
        summary: Dict[str, Any] = {}

        sensitive_keys = {
            "verification_token",
            "token",
            "password",
            "secret",
            "fingerprint_data",
            "fingerprint_hash",
            "ip_address",
            "last_ip_hash",
            "private_key",
        }

        for index, (key, value) in enumerate(payload.items()):
            if index >= 100:
                break

            clean_key = _safe_text(key, 100)

            if clean_key.lower() in sensitive_keys:
                summary[clean_key] = "[REDACTED]"
                continue

            if isinstance(value, (str, int, float, bool)) or value is None:
                summary[clean_key] = _safe_text(value, 300)
            elif isinstance(value, dict):
                summary[clean_key] = {
                    "type": "dict",
                    "keys": [
                        _safe_text(item, 100)
                        for item in list(value.keys())[:20]
                    ],
                    "size": len(value),
                }
            elif isinstance(value, list):
                summary[clean_key] = {
                    "type": "list",
                    "size": len(value),
                }
            else:
                summary[clean_key] = {
                    "type": value.__class__.__name__,
                }

        return summary

    def _safe_initialize_optional(
        self,
        class_reference: Optional[Any],
    ) -> Optional[Any]:
        """Safely initialize an optional William/Jarvis component."""
        if class_reference is None:
            return None

        try:
            return class_reference()
        except Exception as exc:
            self.logger.debug(
                "Optional component %s was not initialized: %s",
                getattr(class_reference, "__name__", class_reference),
                exc,
            )
            return None


# =============================================================================
# Standalone smoke test
# =============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    demo = DeviceAccess(
        storage_dir="data/dev_device_access",
        fingerprint_secret="redacted_demo_fingerprint_secret",
        policy={
            "unknown_device_policy": "challenge",
            "require_device_challenge": True,
        },
    )

    registration = demo.register_device(
        user_id="demo_user",
        workspace_id="demo_workspace",
        fingerprint_data={
            "installation_id": "demo-installation-001",
            "platform": "windows",
            "browser_family": "chrome",
        },
        display_name="Roshan Development PC",
        device_type="desktop",
        platform="Windows",
        operating_system="Windows 11",
        browser="Chrome",
        app_version="1.0.0",
    )

    print(json.dumps(registration, indent=2))

    if registration["success"]:
        challenge = registration["data"].get("challenge")
        token = registration["data"].get("verification_token")

        if challenge and token:
            verification = demo.verify_device_challenge(
                user_id="demo_user",
                workspace_id="demo_workspace",
                challenge_id=challenge["challenge_id"],
                verification_token=token,
                verified_by="demo_user",
            )
            print(json.dumps(verification, indent=2))

            device_id = registration["data"]["device"]["device_id"]

            access = demo.check_device_permission(
                user_id="demo_user",
                workspace_id="demo_workspace",
                device_id=device_id,
                permission="dashboard.read",
            )
            print(json.dumps(access, indent=2))

    print(json.dumps(demo.health_check(), indent=2))