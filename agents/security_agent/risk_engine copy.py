"""
agents/security_agent/biometric_gate.py

William / Jarvis Multi-Agent AI SaaS System
Security Agent - Biometric Verification Gate

Purpose:
    Face, fingerprint, voice, PIN, and trusted-device verification layer.

Security principles:
    1. Safety and authorization come first.
    2. Every user-specific operation is isolated by user_id and workspace_id.
    3. Raw biometric samples are never persisted by this module.
    4. Face, fingerprint, and voice verification are delegated to trusted
       provider adapters or registered verifier callbacks.
    5. PINs and trusted-device secrets are stored only as salted hashes.
    6. Verification challenges are short-lived, single-purpose, and resistant
       to replay.
    7. Failed attempts trigger progressive temporary lockouts.
    8. All important actions emit structured audit and verification payloads.
    9. The module remains import-safe before other William modules exist.

Architecture connections:
    - Master Agent:
        Requests step-up authentication before sensitive actions.
    - Security Agent:
        Uses this gate as one authentication and authorization component.
    - Verification Agent:
        Receives structured payloads describing verification outcomes.
    - Memory Agent:
        Receives safe context payloads without raw secrets or biometrics.
    - Dashboard/API:
        Uses structured dict responses for enrollment, challenge, verification,
        trusted-device management, and security status.
    - Agent Registry / Loader / Router:
        Can instantiate and route requests through the public methods exposed by
        BiometricGate.

Important:
    This module does not directly capture webcam, fingerprint sensor, or
    microphone data. Platform-specific clients must capture biometric material
    and submit it to a trusted verifier adapter. The adapter should return a
    signed or otherwise trusted verification decision.

Author:
    Digital Promotix
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import shutil
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import RLock
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Literal,
    Mapping,
    MutableMapping,
    Optional,
    Protocol,
    Sequence,
    Set,
    Tuple,
    Union,
)


# ============================================================================
# Optional William/Jarvis imports
# ============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Import-safe fallback used until the real BaseAgent exists.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)

        def emit_event(self, *args: Any, **kwargs: Any) -> None:
            return None


try:
    from agents.security_agent.config import SecurityAgentConfig  # type: ignore
except Exception:  # pragma: no cover
    class SecurityAgentConfig:  # type: ignore
        """
        Import-safe configuration fallback.

        The future agents/security_agent/config.py can override these values.
        """

        BIOMETRIC_STORAGE_DIR = "data/security_agent/biometric_gate"
        BIOMETRIC_BACKUP_DIR = "data/security_agent/backups/biometric_gate"

        BIOMETRIC_CHALLENGE_TTL_SECONDS = 300
        BIOMETRIC_ASSERTION_MAX_AGE_SECONDS = 120
        BIOMETRIC_MAX_FAILED_ATTEMPTS = 5
        BIOMETRIC_LOCKOUT_SECONDS = 900

        PIN_MIN_LENGTH = 6
        PIN_MAX_LENGTH = 32
        PIN_PBKDF2_ITERATIONS = 310_000

        TRUSTED_DEVICE_TOKEN_BYTES = 32
        TRUSTED_DEVICE_DEFAULT_TTL_DAYS = 30
        TRUSTED_DEVICE_MAX_TTL_DAYS = 365

        ENABLE_BIOMETRIC_AUDIT_LOGGING = True
        ENABLE_BIOMETRIC_AGENT_EVENTS = True
        ENABLE_BIOMETRIC_SECURITY_APPROVAL = True

        REQUIRE_SECURITY_APPROVAL_FOR_ENROLLMENT = True
        REQUIRE_SECURITY_APPROVAL_FOR_DEVICE_TRUST = True
        REQUIRE_SECURITY_APPROVAL_FOR_CREDENTIAL_REMOVAL = True


# ============================================================================
# Logging
# ============================================================================

logger = logging.getLogger("william.security_agent.biometric_gate")

if not logger.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


# ============================================================================
# Type aliases
# ============================================================================

VerificationMethod = Literal[
    "face",
    "fingerprint",
    "voice",
    "pin",
    "trusted_device",
]

ChallengeStatus = Literal[
    "pending",
    "verified",
    "failed",
    "expired",
    "cancelled",
]

CredentialStatus = Literal[
    "active",
    "disabled",
    "revoked",
]

DeviceStatus = Literal[
    "active",
    "revoked",
    "expired",
]

VerificationLevel = Literal[
    "low",
    "standard",
    "high",
    "critical",
]


# ============================================================================
# Constants
# ============================================================================

SUPPORTED_METHODS: Tuple[str, ...] = (
    "face",
    "fingerprint",
    "voice",
    "pin",
    "trusted_device",
)

BIOMETRIC_METHODS: Tuple[str, ...] = (
    "face",
    "fingerprint",
    "voice",
)

VERIFICATION_LEVEL_REQUIREMENTS: Dict[str, Dict[str, Any]] = {
    "low": {
        "minimum_factors": 1,
        "allowed_methods": list(SUPPORTED_METHODS),
        "require_distinct_categories": False,
    },
    "standard": {
        "minimum_factors": 1,
        "allowed_methods": list(SUPPORTED_METHODS),
        "require_distinct_categories": False,
    },
    "high": {
        "minimum_factors": 2,
        "allowed_methods": list(SUPPORTED_METHODS),
        "require_distinct_categories": True,
    },
    "critical": {
        "minimum_factors": 2,
        "allowed_methods": list(SUPPORTED_METHODS),
        "require_distinct_categories": True,
        "disallow_trusted_device_only": True,
    },
}

METHOD_CATEGORIES: Dict[str, str] = {
    "face": "biometric",
    "fingerprint": "biometric",
    "voice": "biometric",
    "pin": "knowledge",
    "trusted_device": "possession",
}


# ============================================================================
# Utility functions
# ============================================================================

def _utc_now() -> datetime:
    """Return the current timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def _utc_now_iso() -> str:
    """Return the current UTC timestamp in ISO-8601 format."""
    return _utc_now().isoformat()


def _parse_iso_datetime(value: Optional[str]) -> Optional[datetime]:
    """Parse an ISO-8601 datetime safely."""
    if not value:
        return None

    try:
        parsed = datetime.fromisoformat(str(value))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def _safe_slug(value: Any, default: str = "unknown") -> str:
    """Convert a tenant identifier into a filesystem-safe slug."""
    text = str(value or "").strip()
    if not text:
        return default

    text = re.sub(r"[^A-Za-z0-9_.-]+", "_", text)
    return text[:128] or default


def _dedupe_strings(values: Optional[Iterable[Any]]) -> List[str]:
    """Return normalized unique strings while preserving order."""
    if not values:
        return []

    seen: Set[str] = set()
    output: List[str] = []

    for item in values:
        text = str(item or "").strip()
        if not text:
            continue

        key = text.lower()
        if key in seen:
            continue

        seen.add(key)
        output.append(text)

    return output


def _constant_time_equal(left: str, right: str) -> bool:
    """Perform constant-time string comparison."""
    return hmac.compare_digest(
        str(left).encode("utf-8"),
        str(right).encode("utf-8"),
    )


def _hash_secret(
    secret_value: str,
    *,
    salt: Optional[bytes] = None,
    iterations: int = 310_000,
) -> Dict[str, Any]:
    """
    Hash a secret using PBKDF2-HMAC-SHA256.

    Used for PINs and trusted-device tokens. The raw secret is never stored.
    """
    if salt is None:
        salt = secrets.token_bytes(32)

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        secret_value.encode("utf-8"),
        salt,
        iterations,
    )

    return {
        "algorithm": "pbkdf2_sha256",
        "iterations": iterations,
        "salt": base64.b64encode(salt).decode("ascii"),
        "digest": base64.b64encode(digest).decode("ascii"),
    }


def _verify_secret(secret_value: str, hash_record: Mapping[str, Any]) -> bool:
    """Verify a secret against a PBKDF2 hash record."""
    try:
        algorithm = str(hash_record.get("algorithm", ""))
        if algorithm != "pbkdf2_sha256":
            return False

        iterations = int(hash_record["iterations"])
        salt = base64.b64decode(str(hash_record["salt"]).encode("ascii"))
        expected = base64.b64decode(str(hash_record["digest"]).encode("ascii"))

        candidate = hashlib.pbkdf2_hmac(
            "sha256",
            secret_value.encode("utf-8"),
            salt,
            iterations,
        )

        return hmac.compare_digest(candidate, expected)
    except (KeyError, TypeError, ValueError):
        return False


def _fingerprint_text(value: str) -> str:
    """
    Create a non-reversible SHA-256 fingerprint.

    Useful for token identifiers, provider subject references, and device
    fingerprints when the raw value should not be persisted.
    """
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _json_default(value: Any) -> Any:
    """Serialize common non-JSON values."""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, set):
        return sorted(value)
    return str(value)


def _bounded_int(
    value: Any,
    *,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    """Parse an integer and constrain it to a safe range."""
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default

    return max(minimum, min(maximum, parsed))


def _mask_identifier(value: Optional[str]) -> Optional[str]:
    """Return a partially masked identifier for logs and UI responses."""
    if not value:
        return None

    text = str(value)
    if len(text) <= 6:
        return "*" * len(text)

    return f"{text[:3]}{'*' * min(8, len(text) - 6)}{text[-3:]}"


# ============================================================================
# Biometric provider protocol
# ============================================================================

class BiometricVerifierProtocol(Protocol):
    """
    Protocol for face, fingerprint, or voice verification providers.

    A provider implementation must validate the assertion with the relevant
    trusted SDK/service and return a structured dictionary.

    Expected return shape:
        {
            "success": True,
            "verified": True,
            "confidence": 0.98,
            "provider": "provider-name",
            "provider_subject_id": "optional-provider-user-reference",
            "assertion_id": "unique-provider-assertion",
            "assertion_timestamp": "ISO timestamp",
            "metadata": {}
        }

    The provider must not return raw biometric templates in metadata.
    """

    def verify(
        self,
        *,
        method: str,
        assertion: Mapping[str, Any],
        expected_credential: Mapping[str, Any],
        context: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Verify a biometric assertion."""
        ...


BiometricVerifier = Union[
    BiometricVerifierProtocol,
    Callable[..., Dict[str, Any]],
]


# ============================================================================
# Data structures
# ============================================================================

@dataclass
class BiometricCredential:
    """
    Reference to an enrolled biometric credential.

    This record stores provider references only. It must never contain a raw
    face image, fingerprint template, or voice recording.
    """

    credential_id: str
    user_id: str
    workspace_id: str
    method: VerificationMethod

    provider: str
    provider_subject_hash: str
    label: Optional[str] = None

    status: CredentialStatus = "active"
    confidence_threshold: float = 0.75

    enrolled_at: str = field(default_factory=_utc_now_iso)
    updated_at: str = field(default_factory=_utc_now_iso)
    last_verified_at: Optional[str] = None
    verification_count: int = 0

    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert the credential into a JSON-safe dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "BiometricCredential":
        """Create a credential from stored data."""
        allowed = set(cls.__dataclass_fields__.keys())  # type: ignore[attr-defined]
        clean = {key: value for key, value in payload.items() if key in allowed}

        clean.setdefault("credential_id", str(uuid.uuid4()))
        clean.setdefault("user_id", "")
        clean.setdefault("workspace_id", "")
        clean.setdefault("method", "face")
        clean.setdefault("provider", "unknown")
        clean.setdefault("provider_subject_hash", "")
        clean.setdefault("metadata", {})

        try:
            clean["confidence_threshold"] = max(
                0.0,
                min(1.0, float(clean.get("confidence_threshold", 0.75))),
            )
        except (TypeError, ValueError):
            clean["confidence_threshold"] = 0.75

        return cls(**clean)


@dataclass
class PinCredential:
    """Salted and hashed PIN credential."""

    credential_id: str
    user_id: str
    workspace_id: str

    hash_record: Dict[str, Any]
    status: CredentialStatus = "active"

    enrolled_at: str = field(default_factory=_utc_now_iso)
    updated_at: str = field(default_factory=_utc_now_iso)
    last_verified_at: Optional[str] = None
    verification_count: int = 0

    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert the PIN credential into a dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "PinCredential":
        """Create a PIN credential from stored data."""
        allowed = set(cls.__dataclass_fields__.keys())  # type: ignore[attr-defined]
        clean = {key: value for key, value in payload.items() if key in allowed}

        clean.setdefault("credential_id", str(uuid.uuid4()))
        clean.setdefault("user_id", "")
        clean.setdefault("workspace_id", "")
        clean.setdefault("hash_record", {})
        clean.setdefault("metadata", {})

        return cls(**clean)


@dataclass
class TrustedDevice:
    """
    Trusted-device record.

    The raw device token is shown once during enrollment and is never stored.
    """

    device_id: str
    user_id: str
    workspace_id: str

    token_hash_record: Dict[str, Any]
    device_fingerprint_hash: str

    device_name: Optional[str] = None
    platform: Optional[str] = None
    app_version: Optional[str] = None

    status: DeviceStatus = "active"
    created_at: str = field(default_factory=_utc_now_iso)
    updated_at: str = field(default_factory=_utc_now_iso)
    expires_at: Optional[str] = None
    last_verified_at: Optional[str] = None
    verification_count: int = 0

    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self, *, include_hash: bool = False) -> Dict[str, Any]:
        """Convert device record to dictionary, redacting token hash by default."""
        data = asdict(self)
        if not include_hash:
            data.pop("token_hash_record", None)
        return data

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "TrustedDevice":
        """Create a trusted-device record from stored data."""
        allowed = set(cls.__dataclass_fields__.keys())  # type: ignore[attr-defined]
        clean = {key: value for key, value in payload.items() if key in allowed}

        clean.setdefault("device_id", str(uuid.uuid4()))
        clean.setdefault("user_id", "")
        clean.setdefault("workspace_id", "")
        clean.setdefault("token_hash_record", {})
        clean.setdefault("device_fingerprint_hash", "")
        clean.setdefault("metadata", {})

        return cls(**clean)


@dataclass
class VerificationChallenge:
    """
    Short-lived verification challenge.

    Challenges bind verification to a specific user, workspace, action, and
    verification policy, reducing replay and cross-action credential misuse.
    """

    challenge_id: str
    user_id: str
    workspace_id: str

    purpose: str
    action_id: Optional[str]
    verification_level: VerificationLevel

    required_methods: List[str]
    minimum_factors: int

    status: ChallengeStatus = "pending"
    nonce_hash: str = ""

    created_at: str = field(default_factory=_utc_now_iso)
    expires_at: str = field(default_factory=_utc_now_iso)
    completed_at: Optional[str] = None

    verified_methods: List[str] = field(default_factory=list)
    method_results: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    attempts: int = 0
    max_attempts: int = 5

    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self, *, include_nonce_hash: bool = False) -> Dict[str, Any]:
        """Convert challenge into a safe dictionary."""
        data = asdict(self)
        if not include_nonce_hash:
            data.pop("nonce_hash", None)
        return data

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "VerificationChallenge":
        """Create challenge from stored data."""
        allowed = set(cls.__dataclass_fields__.keys())  # type: ignore[attr-defined]
        clean = {key: value for key, value in payload.items() if key in allowed}

        clean.setdefault("challenge_id", str(uuid.uuid4()))
        clean.setdefault("user_id", "")
        clean.setdefault("workspace_id", "")
        clean.setdefault("purpose", "unspecified")
        clean.setdefault("action_id", None)
        clean.setdefault("verification_level", "standard")
        clean.setdefault("required_methods", [])
        clean.setdefault("minimum_factors", 1)
        clean.setdefault("nonce_hash", "")
        clean.setdefault("verified_methods", [])
        clean.setdefault("method_results", {})
        clean.setdefault("metadata", {})

        return cls(**clean)


@dataclass
class SecurityAttemptState:
    """Failed-attempt and temporary lockout state."""

    user_id: str
    workspace_id: str
    failed_attempts: int = 0
    first_failed_at: Optional[str] = None
    last_failed_at: Optional[str] = None
    locked_until: Optional[str] = None
    last_success_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert attempt state to a dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "SecurityAttemptState":
        """Create attempt state from stored data."""
        allowed = set(cls.__dataclass_fields__.keys())  # type: ignore[attr-defined]
        clean = {key: value for key, value in payload.items() if key in allowed}

        clean.setdefault("user_id", "")
        clean.setdefault("workspace_id", "")
        clean.setdefault("failed_attempts", 0)

        return cls(**clean)


# ============================================================================
# Main security gate
# ============================================================================

class BiometricGate(BaseAgent):
    """
    William/Jarvis multi-factor biometric and possession verification gate.

    Main public methods:
        - register_biometric_verifier()
        - enroll_biometric_credential()
        - disable_biometric_credential()
        - remove_biometric_credential()
        - enroll_pin()
        - change_pin()
        - remove_pin()
        - trust_device()
        - verify_trusted_device()
        - revoke_trusted_device()
        - list_trusted_devices()
        - create_challenge()
        - verify_challenge_method()
        - verify_multi_factor()
        - cancel_challenge()
        - get_security_status()
        - get_challenge()
        - cleanup_expired_challenges()

    The class intentionally does not process raw biometric samples itself.
    """

    AGENT_NAME = "BiometricGate"
    AGENT_MODULE = "Security Agent"
    FILE_PATH = "agents/security_agent/biometric_gate.py"

    def __init__(
        self,
        *,
        storage_dir: Optional[Union[str, Path]] = None,
        backup_dir: Optional[Union[str, Path]] = None,
        config: Optional[Any] = None,
        security_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        verifier_registry: Optional[Mapping[str, BiometricVerifier]] = None,
    ) -> None:
        """
        Initialize the biometric verification gate.

        Args:
            storage_dir:
                Local JSON storage directory.
            backup_dir:
                Directory for automatic corrupt-file backups.
            config:
                SecurityAgentConfig-compatible object.
            security_agent:
                Parent Security Agent or approval manager.
            verification_agent:
                Optional Verification Agent integration.
            memory_agent:
                Optional Memory Agent integration.
            event_bus:
                Optional agent event bus.
            audit_logger:
                Optional centralized audit logger.
            verifier_registry:
                Optional mapping of biometric method to trusted verifier.
        """
        try:
            super().__init__(agent_name=self.AGENT_NAME)
        except TypeError:
            try:
                super().__init__()
            except Exception:
                pass

        self.config = config or SecurityAgentConfig()
        self.security_agent = security_agent
        self.verification_agent = verification_agent
        self.memory_agent = memory_agent
        self.event_bus = event_bus
        self.audit_logger = audit_logger

        self.storage_dir = Path(
            storage_dir
            or getattr(
                self.config,
                "BIOMETRIC_STORAGE_DIR",
                "data/security_agent/biometric_gate",
            )
        )

        self.backup_dir = Path(
            backup_dir
            or getattr(
                self.config,
                "BIOMETRIC_BACKUP_DIR",
                "data/security_agent/backups/biometric_gate",
            )
        )

        self.challenge_ttl_seconds = _bounded_int(
            getattr(self.config, "BIOMETRIC_CHALLENGE_TTL_SECONDS", 300),
            default=300,
            minimum=30,
            maximum=3600,
        )

        self.assertion_max_age_seconds = _bounded_int(
            getattr(self.config, "BIOMETRIC_ASSERTION_MAX_AGE_SECONDS", 120),
            default=120,
            minimum=15,
            maximum=900,
        )

        self.max_failed_attempts = _bounded_int(
            getattr(self.config, "BIOMETRIC_MAX_FAILED_ATTEMPTS", 5),
            default=5,
            minimum=1,
            maximum=20,
        )

        self.lockout_seconds = _bounded_int(
            getattr(self.config, "BIOMETRIC_LOCKOUT_SECONDS", 900),
            default=900,
            minimum=30,
            maximum=86_400,
        )

        self.pin_min_length = _bounded_int(
            getattr(self.config, "PIN_MIN_LENGTH", 6),
            default=6,
            minimum=4,
            maximum=64,
        )

        self.pin_max_length = _bounded_int(
            getattr(self.config, "PIN_MAX_LENGTH", 32),
            default=32,
            minimum=self.pin_min_length,
            maximum=128,
        )

        self.pin_pbkdf2_iterations = _bounded_int(
            getattr(self.config, "PIN_PBKDF2_ITERATIONS", 310_000),
            default=310_000,
            minimum=100_000,
            maximum=2_000_000,
        )

        self.trusted_device_token_bytes = _bounded_int(
            getattr(self.config, "TRUSTED_DEVICE_TOKEN_BYTES", 32),
            default=32,
            minimum=24,
            maximum=128,
        )

        self.trusted_device_default_ttl_days = _bounded_int(
            getattr(self.config, "TRUSTED_DEVICE_DEFAULT_TTL_DAYS", 30),
            default=30,
            minimum=1,
            maximum=365,
        )

        self.trusted_device_max_ttl_days = _bounded_int(
            getattr(self.config, "TRUSTED_DEVICE_MAX_TTL_DAYS", 365),
            default=365,
            minimum=1,
            maximum=3650,
        )

        self.enable_audit_logging = bool(
            getattr(self.config, "ENABLE_BIOMETRIC_AUDIT_LOGGING", True)
        )

        self.enable_agent_events = bool(
            getattr(self.config, "ENABLE_BIOMETRIC_AGENT_EVENTS", True)
        )

        self.enable_security_approval = bool(
            getattr(self.config, "ENABLE_BIOMETRIC_SECURITY_APPROVAL", True)
        )

        self.require_approval_for_enrollment = bool(
            getattr(
                self.config,
                "REQUIRE_SECURITY_APPROVAL_FOR_ENROLLMENT",
                True,
            )
        )

        self.require_approval_for_device_trust = bool(
            getattr(
                self.config,
                "REQUIRE_SECURITY_APPROVAL_FOR_DEVICE_TRUST",
                True,
            )
        )

        self.require_approval_for_credential_removal = bool(
            getattr(
                self.config,
                "REQUIRE_SECURITY_APPROVAL_FOR_CREDENTIAL_REMOVAL",
                True,
            )
        )

        self._lock = RLock()
        self._verifiers: Dict[str, BiometricVerifier] = {}

        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(parents=True, exist_ok=True)

        if verifier_registry:
            for method, verifier in verifier_registry.items():
                if method in BIOMETRIC_METHODS:
                    self._verifiers[method] = verifier

        logger.info(
            "BiometricGate initialized with storage directory: %s",
            self.storage_dir,
        )

    # ========================================================================
    # Verifier registration
    # ========================================================================

    def register_biometric_verifier(
        self,
        *,
        method: VerificationMethod,
        verifier: BiometricVerifier,
    ) -> Dict[str, Any]:
        """
        Register a trusted face, fingerprint, or voice verifier adapter.

        The verifier remains in memory and is not serialized.
        """
        normalized_method = self._normalize_method(method)

        if normalized_method not in BIOMETRIC_METHODS:
            return self._error_result(
                message="Only face, fingerprint, and voice verifiers can be registered.",
                code="INVALID_BIOMETRIC_VERIFIER_METHOD",
                metadata={"method": normalized_method},
            )

        if not callable(verifier) and not callable(getattr(verifier, "verify", None)):
            return self._error_result(
                message="Verifier must be callable or expose a verify() method.",
                code="INVALID_VERIFIER",
                metadata={"method": normalized_method},
            )

        self._verifiers[normalized_method] = verifier

        return self._safe_result(
            message=f"{normalized_method} verifier registered successfully.",
            data={"method": normalized_method},
        )

    def unregister_biometric_verifier(
        self,
        *,
        method: VerificationMethod,
    ) -> Dict[str, Any]:
        """Remove a registered biometric verifier adapter."""
        normalized_method = self._normalize_method(method)
        existed = normalized_method in self._verifiers
        self._verifiers.pop(normalized_method, None)

        return self._safe_result(
            message=(
                f"{normalized_method} verifier unregistered successfully."
                if existed
                else f"No {normalized_method} verifier was registered."
            ),
            data={
                "method": normalized_method,
                "was_registered": existed,
            },
        )

    # ========================================================================
    # Biometric credential enrollment
    # ========================================================================

    def enroll_biometric_credential(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        method: VerificationMethod,
        provider: str,
        provider_subject_id: str,
        label: Optional[str] = None,
        confidence_threshold: float = 0.75,
        metadata: Optional[Dict[str, Any]] = None,
        approval_context: Optional[Dict[str, Any]] = None,
        require_security: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Enroll a provider-backed face, fingerprint, or voice credential.

        Raw biometric material must never be passed here. Only a provider-side
        subject identifier or credential reference should be supplied.
        """
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
        )
        if not context_result["success"]:
            return context_result

        user_id_str = str(user_id)
        workspace_id_str = str(workspace_id)
        normalized_method = self._normalize_method(method)

        if normalized_method not in BIOMETRIC_METHODS:
            return self._error_result(
                message="Biometric enrollment supports face, fingerprint, or voice.",
                code="UNSUPPORTED_ENROLLMENT_METHOD",
                metadata={"method": normalized_method},
            )

        provider = str(provider or "").strip()
        provider_subject_id = str(provider_subject_id or "").strip()

        if not provider:
            return self._error_result(
                message="Biometric provider name is required.",
                code="MISSING_PROVIDER",
            )

        if not provider_subject_id:
            return self._error_result(
                message="Provider subject identifier is required.",
                code="MISSING_PROVIDER_SUBJECT",
            )

        if self._contains_probable_raw_biometric(metadata or {}):
            return self._error_result(
                message=(
                    "Raw biometric samples or templates cannot be stored in "
                    "biometric credential metadata."
                ),
                code="RAW_BIOMETRIC_STORAGE_REJECTED",
            )

        should_require_security = (
            self.require_approval_for_enrollment
            if require_security is None
            else bool(require_security)
        )

        if should_require_security:
            approval = self._request_security_approval(
                user_id=user_id_str,
                workspace_id=workspace_id_str,
                action="enroll_biometric_credential",
                payload={
                    "method": normalized_method,
                    "provider": provider,
                    "label": label,
                    "approval_context": approval_context or {},
                },
            )

            if not approval.get("approved", False):
                return self._error_result(
                    message="Security approval denied for biometric enrollment.",
                    code="SECURITY_APPROVAL_DENIED",
                    metadata={"approval": approval},
                )

        credential = BiometricCredential(
            credential_id=str(uuid.uuid4()),
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            method=normalized_method,  # type: ignore[arg-type]
            provider=provider,
            provider_subject_hash=_fingerprint_text(provider_subject_id),
            label=str(label).strip() if label else None,
            confidence_threshold=max(
                0.0,
                min(1.0, float(confidence_threshold)),
            ),
            metadata=self._sanitize_metadata(metadata),
        )

        with self._lock:
            state = self._load_tenant_state(user_id_str, workspace_id_str)

            duplicate = self._find_duplicate_biometric_credential(
                state=state,
                method=normalized_method,
                provider=provider,
                provider_subject_hash=credential.provider_subject_hash,
            )

            if duplicate:
                return self._error_result(
                    message="This biometric credential is already enrolled.",
                    code="BIOMETRIC_CREDENTIAL_ALREADY_EXISTS",
                    metadata={
                        "credential_id": duplicate.credential_id,
                        "method": normalized_method,
                    },
                )

            state["biometric_credentials"].append(
                credential.to_dict()
            )
            self._save_tenant_state(user_id_str, workspace_id_str, state)

        verification_payload = self._prepare_verification_payload(
            action="enroll_biometric_credential",
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            success=True,
            data={
                "credential_id": credential.credential_id,
                "method": normalized_method,
                "provider": provider,
            },
        )

        self._emit_agent_event(
            event_name="security.biometric.credential_enrolled",
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            payload={
                "credential_id": credential.credential_id,
                "method": normalized_method,
                "provider": provider,
            },
        )

        self._log_audit_event(
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            action="biometric_credential.enrolled",
            payload={
                "credential_id": credential.credential_id,
                "method": normalized_method,
                "provider": provider,
            },
        )

        return self._safe_result(
            message=f"{normalized_method} credential enrolled successfully.",
            data={
                "credential": credential.to_dict(),
                "verification_payload": verification_payload,
                "memory_payload": self._prepare_memory_payload(
                    action="biometric_credential_enrolled",
                    user_id=user_id_str,
                    workspace_id=workspace_id_str,
                    data={
                        "credential_id": credential.credential_id,
                        "method": normalized_method,
                        "provider": provider,
                    },
                ),
            },
            metadata={
                "user_id": user_id_str,
                "workspace_id": workspace_id_str,
            },
        )

    def disable_biometric_credential(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        credential_id: str,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Disable a biometric credential without deleting its audit history."""
        return self._set_biometric_credential_status(
            user_id=user_id,
            workspace_id=workspace_id,
            credential_id=credential_id,
            status="disabled",
            reason=reason,
        )

    def enable_biometric_credential(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        credential_id: str,
    ) -> Dict[str, Any]:
        """Re-enable a previously disabled biometric credential."""
        return self._set_biometric_credential_status(
            user_id=user_id,
            workspace_id=workspace_id,
            credential_id=credential_id,
            status="active",
            reason=None,
        )

    def remove_biometric_credential(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        credential_id: str,
        reason: Optional[str] = None,
        require_security: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Revoke a biometric credential.

        The record remains for security history, but cannot be used again.
        """
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
        )
        if not context_result["success"]:
            return context_result

        user_id_str = str(user_id)
        workspace_id_str = str(workspace_id)

        should_require_security = (
            self.require_approval_for_credential_removal
            if require_security is None
            else bool(require_security)
        )

        if should_require_security:
            approval = self._request_security_approval(
                user_id=user_id_str,
                workspace_id=workspace_id_str,
                action="remove_biometric_credential",
                payload={
                    "credential_id": credential_id,
                    "reason": reason,
                },
            )

            if not approval.get("approved", False):
                return self._error_result(
                    message="Security approval denied for credential removal.",
                    code="SECURITY_APPROVAL_DENIED",
                    metadata={"approval": approval},
                )

        return self._set_biometric_credential_status(
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            credential_id=credential_id,
            status="revoked",
            reason=reason,
        )

    def list_biometric_credentials(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        include_revoked: bool = False,
    ) -> Dict[str, Any]:
        """List enrolled biometric credential references."""
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
        )
        if not context_result["success"]:
            return context_result

        user_id_str = str(user_id)
        workspace_id_str = str(workspace_id)

        with self._lock:
            state = self._load_tenant_state(user_id_str, workspace_id_str)

        credentials: List[Dict[str, Any]] = []

        for raw in state["biometric_credentials"]:
            credential = BiometricCredential.from_dict(raw)
            if credential.status == "revoked" and not include_revoked:
                continue
            credentials.append(credential.to_dict())

        return self._safe_result(
            message="Biometric credentials listed successfully.",
            data={
                "items": credentials,
                "count": len(credentials),
            },
            metadata={
                "user_id": user_id_str,
                "workspace_id": workspace_id_str,
            },
        )

    # ========================================================================
    # PIN management
    # ========================================================================

    def enroll_pin(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        pin: str,
        metadata: Optional[Dict[str, Any]] = None,
        require_security: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Enroll or replace a PIN.

        The PIN is stored only as a salted PBKDF2-HMAC-SHA256 hash.
        """
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
        )
        if not context_result["success"]:
            return context_result

        user_id_str = str(user_id)
        workspace_id_str = str(workspace_id)

        pin_validation = self._validate_pin(pin)
        if not pin_validation["success"]:
            return pin_validation

        should_require_security = (
            self.require_approval_for_enrollment
            if require_security is None
            else bool(require_security)
        )

        if should_require_security:
            approval = self._request_security_approval(
                user_id=user_id_str,
                workspace_id=workspace_id_str,
                action="enroll_pin",
                payload={
                    "replacing_existing": self._has_active_pin(
                        user_id_str,
                        workspace_id_str,
                    )
                },
            )

            if not approval.get("approved", False):
                return self._error_result(
                    message="Security approval denied for PIN enrollment.",
                    code="SECURITY_APPROVAL_DENIED",
                    metadata={"approval": approval},
                )

        credential = PinCredential(
            credential_id=str(uuid.uuid4()),
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            hash_record=_hash_secret(
                pin,
                iterations=self.pin_pbkdf2_iterations,
            ),
            metadata=self._sanitize_metadata(metadata),
        )

        with self._lock:
            state = self._load_tenant_state(user_id_str, workspace_id_str)

            previous_pin = state.get("pin_credential")
            if previous_pin:
                previous = PinCredential.from_dict(previous_pin)
                previous.status = "revoked"
                previous.updated_at = _utc_now_iso()
                state.setdefault("revoked_pin_credentials", []).append(
                    previous.to_dict()
                )

            state["pin_credential"] = credential.to_dict()
            self._save_tenant_state(user_id_str, workspace_id_str, state)

        self._reset_attempt_state(user_id_str, workspace_id_str)

        self._emit_agent_event(
            event_name="security.pin.enrolled",
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            payload={"credential_id": credential.credential_id},
        )

        self._log_audit_event(
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            action="pin.enrolled",
            payload={"credential_id": credential.credential_id},
        )

        return self._safe_result(
            message="PIN enrolled successfully.",
            data={
                "credential": {
                    "credential_id": credential.credential_id,
                    "status": credential.status,
                    "enrolled_at": credential.enrolled_at,
                },
                "verification_payload": self._prepare_verification_payload(
                    action="enroll_pin",
                    user_id=user_id_str,
                    workspace_id=workspace_id_str,
                    success=True,
                    data={"credential_id": credential.credential_id},
                ),
            },
            metadata={
                "user_id": user_id_str,
                "workspace_id": workspace_id_str,
            },
        )

    def change_pin(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        current_pin: str,
        new_pin: str,
    ) -> Dict[str, Any]:
        """
        Change the current PIN after verifying the existing PIN.
        """
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
        )
        if not context_result["success"]:
            return context_result

        user_id_str = str(user_id)
        workspace_id_str = str(workspace_id)

        lock_result = self._check_lockout(user_id_str, workspace_id_str)
        if not lock_result["success"]:
            return lock_result

        current_result = self._verify_pin_direct(
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            pin=current_pin,
            count_failure=True,
        )

        if not current_result["success"]:
            return current_result

        if _constant_time_equal(current_pin, new_pin):
            return self._error_result(
                message="New PIN must be different from the existing PIN.",
                code="PIN_REUSE_NOT_ALLOWED",
            )

        validation = self._validate_pin(new_pin)
        if not validation["success"]:
            return validation

        return self.enroll_pin(
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            pin=new_pin,
            require_security=False,
            metadata={"changed_from_existing_pin": True},
        )

    def remove_pin(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        require_security: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Revoke the active PIN credential."""
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
        )
        if not context_result["success"]:
            return context_result

        user_id_str = str(user_id)
        workspace_id_str = str(workspace_id)

        should_require_security = (
            self.require_approval_for_credential_removal
            if require_security is None
            else bool(require_security)
        )

        if should_require_security:
            approval = self._request_security_approval(
                user_id=user_id_str,
                workspace_id=workspace_id_str,
                action="remove_pin",
                payload={},
            )

            if not approval.get("approved", False):
                return self._error_result(
                    message="Security approval denied for PIN removal.",
                    code="SECURITY_APPROVAL_DENIED",
                    metadata={"approval": approval},
                )

        with self._lock:
            state = self._load_tenant_state(user_id_str, workspace_id_str)
            raw_pin = state.get("pin_credential")

            if not raw_pin:
                return self._error_result(
                    message="No active PIN credential was found.",
                    code="PIN_NOT_ENROLLED",
                )

            credential = PinCredential.from_dict(raw_pin)
            credential.status = "revoked"
            credential.updated_at = _utc_now_iso()

            state.setdefault("revoked_pin_credentials", []).append(
                credential.to_dict()
            )
            state["pin_credential"] = None

            self._save_tenant_state(user_id_str, workspace_id_str, state)

        self._log_audit_event(
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            action="pin.removed",
            payload={"credential_id": credential.credential_id},
        )

        return self._safe_result(
            message="PIN credential removed successfully.",
            data={"credential_id": credential.credential_id},
            metadata={
                "user_id": user_id_str,
                "workspace_id": workspace_id_str,
            },
        )

    # ========================================================================
    # Trusted-device management
    # ========================================================================

    def trust_device(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        device_fingerprint: str,
        device_name: Optional[str] = None,
        platform: Optional[str] = None,
        app_version: Optional[str] = None,
        ttl_days: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
        require_security: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Register a trusted device and return a one-time device token.

        The raw token must be stored securely by the client. This method stores
        only a salted hash.
        """
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
        )
        if not context_result["success"]:
            return context_result

        user_id_str = str(user_id)
        workspace_id_str = str(workspace_id)
        device_fingerprint = str(device_fingerprint or "").strip()

        if len(device_fingerprint) < 16:
            return self._error_result(
                message="A stable device fingerprint of at least 16 characters is required.",
                code="INVALID_DEVICE_FINGERPRINT",
            )

        should_require_security = (
            self.require_approval_for_device_trust
            if require_security is None
            else bool(require_security)
        )

        if should_require_security:
            approval = self._request_security_approval(
                user_id=user_id_str,
                workspace_id=workspace_id_str,
                action="trust_device",
                payload={
                    "device_name": device_name,
                    "platform": platform,
                    "app_version": app_version,
                },
            )

            if not approval.get("approved", False):
                return self._error_result(
                    message="Security approval denied for trusted-device enrollment.",
                    code="SECURITY_APPROVAL_DENIED",
                    metadata={"approval": approval},
                )

        effective_ttl = _bounded_int(
            ttl_days,
            default=self.trusted_device_default_ttl_days,
            minimum=1,
            maximum=self.trusted_device_max_ttl_days,
        )

        raw_token = secrets.token_urlsafe(self.trusted_device_token_bytes)
        device_id = str(uuid.uuid4())
        expires_at = (_utc_now() + timedelta(days=effective_ttl)).isoformat()

        device = TrustedDevice(
            device_id=device_id,
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            token_hash_record=_hash_secret(
                raw_token,
                iterations=self.pin_pbkdf2_iterations,
            ),
            device_fingerprint_hash=_fingerprint_text(device_fingerprint),
            device_name=str(device_name).strip() if device_name else None,
            platform=str(platform).strip() if platform else None,
            app_version=str(app_version).strip() if app_version else None,
            expires_at=expires_at,
            metadata=self._sanitize_metadata(metadata),
        )

        with self._lock:
            state = self._load_tenant_state(user_id_str, workspace_id_str)

            for raw in state["trusted_devices"]:
                existing = TrustedDevice.from_dict(raw)
                if (
                    existing.device_fingerprint_hash
                    == device.device_fingerprint_hash
                    and existing.status == "active"
                ):
                    existing.status = "revoked"
                    existing.updated_at = _utc_now_iso()
                    raw.update(existing.to_dict(include_hash=True))

            state["trusted_devices"].append(
                device.to_dict(include_hash=True)
            )
            self._save_tenant_state(user_id_str, workspace_id_str, state)

        self._emit_agent_event(
            event_name="security.trusted_device.enrolled",
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            payload={
                "device_id": device.device_id,
                "device_name": device.device_name,
                "platform": device.platform,
            },
        )

        self._log_audit_event(
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            action="trusted_device.enrolled",
            payload={
                "device_id": device.device_id,
                "device_name": device.device_name,
                "platform": device.platform,
                "expires_at": device.expires_at,
            },
        )

        return self._safe_result(
            message=(
                "Trusted device enrolled successfully. Store the returned token "
                "securely because it will not be shown again."
            ),
            data={
                "device": device.to_dict(),
                "device_token": raw_token,
                "token_displayed_once": True,
            },
            metadata={
                "user_id": user_id_str,
                "workspace_id": workspace_id_str,
            },
        )

    def verify_trusted_device(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        device_id: str,
        device_token: str,
        device_fingerprint: str,
    ) -> Dict[str, Any]:
        """Verify a trusted device token and fingerprint."""
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
        )
        if not context_result["success"]:
            return context_result

        user_id_str = str(user_id)
        workspace_id_str = str(workspace_id)

        lock_result = self._check_lockout(user_id_str, workspace_id_str)
        if not lock_result["success"]:
            return lock_result

        result = self._verify_trusted_device_direct(
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            device_id=device_id,
            device_token=device_token,
            device_fingerprint=device_fingerprint,
            count_failure=True,
        )

        return result

    def revoke_trusted_device(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        device_id: str,
        reason: Optional[str] = None,
        require_security: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Revoke a trusted device."""
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
        )
        if not context_result["success"]:
            return context_result

        user_id_str = str(user_id)
        workspace_id_str = str(workspace_id)

        should_require_security = (
            self.require_approval_for_credential_removal
            if require_security is None
            else bool(require_security)
        )

        if should_require_security:
            approval = self._request_security_approval(
                user_id=user_id_str,
                workspace_id=workspace_id_str,
                action="revoke_trusted_device",
                payload={
                    "device_id": device_id,
                    "reason": reason,
                },
            )

            if not approval.get("approved", False):
                return self._error_result(
                    message="Security approval denied for device revocation.",
                    code="SECURITY_APPROVAL_DENIED",
                    metadata={"approval": approval},
                )

        with self._lock:
            state = self._load_tenant_state(user_id_str, workspace_id_str)
            device = self._find_trusted_device(state, device_id)

            if not device:
                return self._error_result(
                    message="Trusted device not found.",
                    code="TRUSTED_DEVICE_NOT_FOUND",
                )

            device.status = "revoked"
            device.updated_at = _utc_now_iso()
            device.metadata["revocation_reason"] = reason

            self._replace_trusted_device(state, device)
            self._save_tenant_state(user_id_str, workspace_id_str, state)

        self._emit_agent_event(
            event_name="security.trusted_device.revoked",
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            payload={"device_id": device_id, "reason": reason},
        )

        self._log_audit_event(
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            action="trusted_device.revoked",
            payload={"device_id": device_id, "reason": reason},
        )

        return self._safe_result(
            message="Trusted device revoked successfully.",
            data={"device": device.to_dict()},
            metadata={
                "user_id": user_id_str,
                "workspace_id": workspace_id_str,
            },
        )

    def revoke_all_trusted_devices(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        reason: Optional[str] = None,
        require_security: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Revoke all active trusted devices for one tenant."""
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
        )
        if not context_result["success"]:
            return context_result

        user_id_str = str(user_id)
        workspace_id_str = str(workspace_id)

        should_require_security = (
            self.require_approval_for_credential_removal
            if require_security is None
            else bool(require_security)
        )

        if should_require_security:
            approval = self._request_security_approval(
                user_id=user_id_str,
                workspace_id=workspace_id_str,
                action="revoke_all_trusted_devices",
                payload={"reason": reason},
            )

            if not approval.get("approved", False):
                return self._error_result(
                    message="Security approval denied for device revocation.",
                    code="SECURITY_APPROVAL_DENIED",
                    metadata={"approval": approval},
                )

        revoked_count = 0

        with self._lock:
            state = self._load_tenant_state(user_id_str, workspace_id_str)

            updated_devices: List[Dict[str, Any]] = []

            for raw in state["trusted_devices"]:
                device = TrustedDevice.from_dict(raw)

                if device.status == "active":
                    device.status = "revoked"
                    device.updated_at = _utc_now_iso()
                    device.metadata["revocation_reason"] = reason
                    revoked_count += 1

                updated_devices.append(device.to_dict(include_hash=True))

            state["trusted_devices"] = updated_devices
            self._save_tenant_state(user_id_str, workspace_id_str, state)

        self._log_audit_event(
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            action="trusted_device.all_revoked",
            payload={
                "revoked_count": revoked_count,
                "reason": reason,
            },
        )

        return self._safe_result(
            message="All active trusted devices were revoked.",
            data={"revoked_count": revoked_count},
            metadata={
                "user_id": user_id_str,
                "workspace_id": workspace_id_str,
            },
        )

    def list_trusted_devices(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        include_revoked: bool = False,
    ) -> Dict[str, Any]:
        """List trusted devices without exposing token hashes."""
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
        )
        if not context_result["success"]:
            return context_result

        user_id_str = str(user_id)
        workspace_id_str = str(workspace_id)

        with self._lock:
            state = self._load_tenant_state(user_id_str, workspace_id_str)

        devices: List[Dict[str, Any]] = []

        for raw in state["trusted_devices"]:
            device = TrustedDevice.from_dict(raw)
            self._mark_device_expired_if_needed(device)

            if device.status == "revoked" and not include_revoked:
                continue

            devices.append(device.to_dict())

        return self._safe_result(
            message="Trusted devices listed successfully.",
            data={
                "items": devices,
                "count": len(devices),
            },
            metadata={
                "user_id": user_id_str,
                "workspace_id": workspace_id_str,
            },
        )

    # ========================================================================
    # Challenge lifecycle
    # ========================================================================

    def create_challenge(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        purpose: str,
        verification_level: VerificationLevel = "standard",
        required_methods: Optional[Sequence[VerificationMethod]] = None,
        minimum_factors: Optional[int] = None,
        action_id: Optional[str] = None,
        ttl_seconds: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create a single-purpose verification challenge.

        The returned nonce must be provided when submitting factor results. Only
        the nonce hash is persisted.
        """
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
        )
        if not context_result["success"]:
            return context_result

        user_id_str = str(user_id)
        workspace_id_str = str(workspace_id)

        lock_result = self._check_lockout(user_id_str, workspace_id_str)
        if not lock_result["success"]:
            return lock_result

        purpose = str(purpose or "").strip()
        if not purpose:
            return self._error_result(
                message="Challenge purpose is required.",
                code="MISSING_CHALLENGE_PURPOSE",
            )

        normalized_level = self._normalize_verification_level(
            verification_level
        )

        available_methods = self._get_available_methods(
            user_id_str,
            workspace_id_str,
        )

        if required_methods:
            normalized_methods = [
                self._normalize_method(method)
                for method in required_methods
            ]
            normalized_methods = _dedupe_strings(normalized_methods)
        else:
            normalized_methods = list(available_methods)

        if not normalized_methods:
            return self._error_result(
                message="No verification methods are enrolled or available.",
                code="NO_VERIFICATION_METHOD_AVAILABLE",
            )

        unavailable = [
            method
            for method in normalized_methods
            if method not in available_methods
        ]

        if unavailable:
            return self._error_result(
                message="One or more requested verification methods are unavailable.",
                code="VERIFICATION_METHOD_UNAVAILABLE",
                metadata={
                    "unavailable_methods": unavailable,
                    "available_methods": available_methods,
                },
            )

        level_policy = VERIFICATION_LEVEL_REQUIREMENTS[normalized_level]
        policy_minimum = int(level_policy["minimum_factors"])

        effective_minimum = (
            policy_minimum
            if minimum_factors is None
            else max(policy_minimum, int(minimum_factors))
        )

        if effective_minimum > len(normalized_methods):
            return self._error_result(
                message="Minimum factors exceed the number of available methods.",
                code="INSUFFICIENT_VERIFICATION_METHODS",
                metadata={
                    "minimum_factors": effective_minimum,
                    "methods": normalized_methods,
                },
            )

        if level_policy.get("require_distinct_categories"):
            categories = {
                METHOD_CATEGORIES[method]
                for method in normalized_methods
            }

            if len(categories) < 2:
                return self._error_result(
                    message=(
                        "This verification level requires factors from at least "
                        "two different authentication categories."
                    ),
                    code="INSUFFICIENT_FACTOR_DIVERSITY",
                    metadata={
                        "method_categories": sorted(categories),
                        "methods": normalized_methods,
                    },
                )

        effective_ttl = _bounded_int(
            ttl_seconds,
            default=self.challenge_ttl_seconds,
            minimum=30,
            maximum=3600,
        )

        nonce = secrets.token_urlsafe(32)
        now = _utc_now()

        challenge = VerificationChallenge(
            challenge_id=str(uuid.uuid4()),
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            purpose=purpose,
            action_id=str(action_id) if action_id else None,
            verification_level=normalized_level,  # type: ignore[arg-type]
            required_methods=normalized_methods,
            minimum_factors=effective_minimum,
            nonce_hash=_fingerprint_text(nonce),
            created_at=now.isoformat(),
            expires_at=(now + timedelta(seconds=effective_ttl)).isoformat(),
            max_attempts=self.max_failed_attempts,
            metadata=self._sanitize_metadata(metadata),
        )

        with self._lock:
            state = self._load_tenant_state(user_id_str, workspace_id_str)
            state["challenges"].append(
                challenge.to_dict(include_nonce_hash=True)
            )
            self._save_tenant_state(user_id_str, workspace_id_str, state)

        self._emit_agent_event(
            event_name="security.biometric.challenge_created",
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            payload={
                "challenge_id": challenge.challenge_id,
                "purpose": purpose,
                "verification_level": normalized_level,
                "required_methods": normalized_methods,
            },
        )

        self._log_audit_event(
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            action="verification_challenge.created",
            payload={
                "challenge_id": challenge.challenge_id,
                "purpose": purpose,
                "verification_level": normalized_level,
                "required_methods": normalized_methods,
                "minimum_factors": effective_minimum,
                "action_id": action_id,
            },
        )

        return self._safe_result(
            message="Verification challenge created successfully.",
            data={
                "challenge": challenge.to_dict(),
                "challenge_nonce": nonce,
                "nonce_displayed_once": True,
            },
            metadata={
                "user_id": user_id_str,
                "workspace_id": workspace_id_str,
            },
        )

    def verify_challenge_method(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        challenge_id: str,
        challenge_nonce: str,
        method: VerificationMethod,
        evidence: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Verify one challenge factor.

        Evidence requirements:
            pin:
                {"pin": "123456"}

            trusted_device:
                {
                    "device_id": "...",
                    "device_token": "...",
                    "device_fingerprint": "..."
                }

            face/fingerprint/voice:
                Provider-specific assertion dictionary. The registered verifier
                adapter validates it.
        """
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
        )
        if not context_result["success"]:
            return context_result

        user_id_str = str(user_id)
        workspace_id_str = str(workspace_id)
        normalized_method = self._normalize_method(method)

        lock_result = self._check_lockout(user_id_str, workspace_id_str)
        if not lock_result["success"]:
            return lock_result

        if normalized_method not in SUPPORTED_METHODS:
            return self._error_result(
                message="Unsupported verification method.",
                code="UNSUPPORTED_VERIFICATION_METHOD",
                metadata={"method": normalized_method},
            )

        if not isinstance(evidence, Mapping):
            return self._error_result(
                message="Verification evidence must be a dictionary.",
                code="INVALID_VERIFICATION_EVIDENCE",
            )

        with self._lock:
            state = self._load_tenant_state(user_id_str, workspace_id_str)
            challenge = self._find_challenge(state, challenge_id)

            if not challenge:
                return self._error_result(
                    message="Verification challenge not found.",
                    code="CHALLENGE_NOT_FOUND",
                )

            challenge_validation = self._validate_challenge_for_use(
                challenge=challenge,
                nonce=challenge_nonce,
                method=normalized_method,
            )

            if not challenge_validation["success"]:
                if challenge_validation["error"]["code"] == "CHALLENGE_EXPIRED":
                    challenge.status = "expired"
                    self._replace_challenge(state, challenge)
                    self._save_tenant_state(
                        user_id_str,
                        workspace_id_str,
                        state,
                    )

                return challenge_validation

            if normalized_method in challenge.verified_methods:
                return self._safe_result(
                    message="This verification method has already passed.",
                    data={
                        "challenge": challenge.to_dict(),
                        "already_verified": True,
                    },
                    metadata={
                        "user_id": user_id_str,
                        "workspace_id": workspace_id_str,
                    },
                )

        factor_result = self._verify_method_direct(
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            method=normalized_method,
            evidence=evidence,
            challenge=challenge,
        )

        with self._lock:
            state = self._load_tenant_state(user_id_str, workspace_id_str)
            challenge = self._find_challenge(state, challenge_id)

            if not challenge:
                return self._error_result(
                    message="Verification challenge no longer exists.",
                    code="CHALLENGE_NOT_FOUND",
                )

            challenge.attempts += 1
            challenge.method_results[normalized_method] = {
                "success": factor_result["success"],
                "message": factor_result["message"],
                "verified_at": _utc_now_iso(),
                "metadata": self._sanitize_verification_result(
                    factor_result.get("data", {})
                ),
            }

            if factor_result["success"]:
                challenge.verified_methods = _dedupe_strings(
                    [
                        *challenge.verified_methods,
                        normalized_method,
                    ]
                )

                completion = self._evaluate_challenge_completion(challenge)

                if completion["complete"]:
                    challenge.status = "verified"
                    challenge.completed_at = _utc_now_iso()
                    self._reset_attempt_state(
                        user_id_str,
                        workspace_id_str,
                    )
                else:
                    challenge.status = "pending"
            else:
                self._record_failed_attempt(
                    user_id_str,
                    workspace_id_str,
                )

                if challenge.attempts >= challenge.max_attempts:
                    challenge.status = "failed"
                    challenge.completed_at = _utc_now_iso()

            self._replace_challenge(state, challenge)
            self._save_tenant_state(user_id_str, workspace_id_str, state)

        if factor_result["success"]:
            self._emit_agent_event(
                event_name="security.biometric.factor_verified",
                user_id=user_id_str,
                workspace_id=workspace_id_str,
                payload={
                    "challenge_id": challenge.challenge_id,
                    "method": normalized_method,
                    "challenge_status": challenge.status,
                },
            )
        else:
            self._emit_agent_event(
                event_name="security.biometric.factor_failed",
                user_id=user_id_str,
                workspace_id=workspace_id_str,
                payload={
                    "challenge_id": challenge.challenge_id,
                    "method": normalized_method,
                    "challenge_status": challenge.status,
                },
            )

        self._log_audit_event(
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            action=(
                "verification_factor.verified"
                if factor_result["success"]
                else "verification_factor.failed"
            ),
            payload={
                "challenge_id": challenge.challenge_id,
                "method": normalized_method,
                "challenge_status": challenge.status,
                "purpose": challenge.purpose,
                "action_id": challenge.action_id,
            },
        )

        verification_payload = self._prepare_verification_payload(
            action="verify_challenge_method",
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            success=factor_result["success"],
            data={
                "challenge_id": challenge.challenge_id,
                "method": normalized_method,
                "challenge_status": challenge.status,
                "verified_methods": challenge.verified_methods,
                "minimum_factors": challenge.minimum_factors,
                "purpose": challenge.purpose,
                "action_id": challenge.action_id,
            },
        )

        if not factor_result["success"]:
            return self._error_result(
                message=factor_result["message"],
                code=factor_result["error"]["code"],
                error=factor_result["error"],
                metadata={
                    "challenge": challenge.to_dict(),
                    "verification_payload": verification_payload,
                },
            )

        return self._safe_result(
            message=(
                "Verification challenge completed successfully."
                if challenge.status == "verified"
                else "Verification factor passed. Additional factors are required."
            ),
            data={
                "factor": factor_result.get("data", {}),
                "challenge": challenge.to_dict(),
                "challenge_complete": challenge.status == "verified",
                "verification_payload": verification_payload,
                "memory_payload": self._prepare_memory_payload(
                    action="verification_factor_completed",
                    user_id=user_id_str,
                    workspace_id=workspace_id_str,
                    data={
                        "challenge_id": challenge.challenge_id,
                        "method": normalized_method,
                        "challenge_status": challenge.status,
                        "purpose": challenge.purpose,
                    },
                ),
            },
            metadata={
                "user_id": user_id_str,
                "workspace_id": workspace_id_str,
            },
        )

    def verify_multi_factor(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        challenge_id: str,
        challenge_nonce: str,
        factors: Sequence[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """
        Verify multiple factors against one challenge.

        Example:
            factors=[
                {"method": "pin", "evidence": {"pin": "123456"}},
                {
                    "method": "trusted_device",
                    "evidence": {
                        "device_id": "...",
                        "device_token": "...",
                        "device_fingerprint": "..."
                    }
                }
            ]
        """
        if not factors:
            return self._error_result(
                message="At least one verification factor is required.",
                code="NO_VERIFICATION_FACTORS",
            )

        factor_results: List[Dict[str, Any]] = []

        for factor in factors:
            method = factor.get("method")
            evidence = factor.get("evidence", {})

            result = self.verify_challenge_method(
                user_id=user_id,
                workspace_id=workspace_id,
                challenge_id=challenge_id,
                challenge_nonce=challenge_nonce,
                method=str(method),  # type: ignore[arg-type]
                evidence=evidence if isinstance(evidence, Mapping) else {},
            )

            factor_results.append(
                {
                    "method": method,
                    "success": result["success"],
                    "message": result["message"],
                    "error": result.get("error"),
                }
            )

            challenge_data = (
                result.get("data", {}).get("challenge")
                or result.get("metadata", {}).get("challenge")
            )

            if isinstance(challenge_data, dict):
                if challenge_data.get("status") == "verified":
                    return self._safe_result(
                        message="Multi-factor verification completed successfully.",
                        data={
                            "challenge": challenge_data,
                            "factor_results": factor_results,
                            "challenge_complete": True,
                        },
                        metadata={
                            "user_id": str(user_id),
                            "workspace_id": str(workspace_id),
                        },
                    )

                if challenge_data.get("status") in {
                    "failed",
                    "expired",
                    "cancelled",
                }:
                    break

        challenge_result = self.get_challenge(
            user_id=user_id,
            workspace_id=workspace_id,
            challenge_id=challenge_id,
        )

        challenge = challenge_result.get("data", {}).get("challenge", {})
        complete = challenge.get("status") == "verified"

        if complete:
            return self._safe_result(
                message="Multi-factor verification completed successfully.",
                data={
                    "challenge": challenge,
                    "factor_results": factor_results,
                    "challenge_complete": True,
                },
                metadata={
                    "user_id": str(user_id),
                    "workspace_id": str(workspace_id),
                },
            )

        return self._error_result(
            message="Multi-factor verification is incomplete or failed.",
            code="MULTI_FACTOR_VERIFICATION_INCOMPLETE",
            metadata={
                "challenge": challenge,
                "factor_results": factor_results,
            },
        )

    def get_challenge(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        challenge_id: str,
    ) -> Dict[str, Any]:
        """Return one challenge with tenant isolation."""
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
        )
        if not context_result["success"]:
            return context_result

        user_id_str = str(user_id)
        workspace_id_str = str(workspace_id)

        with self._lock:
            state = self._load_tenant_state(user_id_str, workspace_id_str)
            challenge = self._find_challenge(state, challenge_id)

            if not challenge:
                return self._error_result(
                    message="Verification challenge not found.",
                    code="CHALLENGE_NOT_FOUND",
                )

            if self._is_challenge_expired(challenge) and challenge.status == "pending":
                challenge.status = "expired"
                self._replace_challenge(state, challenge)
                self._save_tenant_state(
                    user_id_str,
                    workspace_id_str,
                    state,
                )

        return self._safe_result(
            message="Verification challenge fetched successfully.",
            data={"challenge": challenge.to_dict()},
            metadata={
                "user_id": user_id_str,
                "workspace_id": workspace_id_str,
            },
        )

    def cancel_challenge(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        challenge_id: str,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Cancel a pending verification challenge."""
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
        )
        if not context_result["success"]:
            return context_result

        user_id_str = str(user_id)
        workspace_id_str = str(workspace_id)

        with self._lock:
            state = self._load_tenant_state(user_id_str, workspace_id_str)
            challenge = self._find_challenge(state, challenge_id)

            if not challenge:
                return self._error_result(
                    message="Verification challenge not found.",
                    code="CHALLENGE_NOT_FOUND",
                )

            if challenge.status != "pending":
                return self._error_result(
                    message="Only pending challenges can be cancelled.",
                    code="CHALLENGE_NOT_PENDING",
                    metadata={"status": challenge.status},
                )

            challenge.status = "cancelled"
            challenge.completed_at = _utc_now_iso()
            challenge.metadata["cancellation_reason"] = reason

            self._replace_challenge(state, challenge)
            self._save_tenant_state(user_id_str, workspace_id_str, state)

        self._log_audit_event(
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            action="verification_challenge.cancelled",
            payload={
                "challenge_id": challenge_id,
                "reason": reason,
            },
        )

        return self._safe_result(
            message="Verification challenge cancelled successfully.",
            data={"challenge": challenge.to_dict()},
            metadata={
                "user_id": user_id_str,
                "workspace_id": workspace_id_str,
            },
        )

    def cleanup_expired_challenges(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        retention_days: int = 30,
    ) -> Dict[str, Any]:
        """
        Mark expired challenges and remove old terminal challenge records.
        """
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
        )
        if not context_result["success"]:
            return context_result

        user_id_str = str(user_id)
        workspace_id_str = str(workspace_id)
        retention_days = max(1, min(int(retention_days), 3650))
        cutoff = _utc_now() - timedelta(days=retention_days)

        marked_expired = 0
        removed = 0

        with self._lock:
            state = self._load_tenant_state(user_id_str, workspace_id_str)
            retained: List[Dict[str, Any]] = []

            for raw in state["challenges"]:
                challenge = VerificationChallenge.from_dict(raw)

                if (
                    challenge.status == "pending"
                    and self._is_challenge_expired(challenge)
                ):
                    challenge.status = "expired"
                    challenge.completed_at = _utc_now_iso()
                    marked_expired += 1

                terminal_time = _parse_iso_datetime(
                    challenge.completed_at or challenge.created_at
                )

                if (
                    challenge.status in {
                        "verified",
                        "failed",
                        "expired",
                        "cancelled",
                    }
                    and terminal_time
                    and terminal_time < cutoff
                ):
                    removed += 1
                    continue

                retained.append(
                    challenge.to_dict(include_nonce_hash=True)
                )

            state["challenges"] = retained
            self._save_tenant_state(user_id_str, workspace_id_str, state)

        return self._safe_result(
            message="Expired challenge cleanup completed.",
            data={
                "marked_expired": marked_expired,
                "removed": removed,
            },
            metadata={
                "user_id": user_id_str,
                "workspace_id": workspace_id_str,
            },
        )

    # ========================================================================
    # Status and administrative information
    # ========================================================================

    def get_security_status(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
    ) -> Dict[str, Any]:
        """Return safe enrollment, device, challenge, and lockout status."""
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
        )
        if not context_result["success"]:
            return context_result

        user_id_str = str(user_id)
        workspace_id_str = str(workspace_id)

        with self._lock:
            state = self._load_tenant_state(user_id_str, workspace_id_str)

        active_biometrics: Dict[str, int] = {
            "face": 0,
            "fingerprint": 0,
            "voice": 0,
        }

        for raw in state["biometric_credentials"]:
            credential = BiometricCredential.from_dict(raw)
            if credential.status == "active":
                active_biometrics[credential.method] = (
                    active_biometrics.get(credential.method, 0) + 1
                )

        pin_active = False
        if state.get("pin_credential"):
            pin_credential = PinCredential.from_dict(
                state["pin_credential"]
            )
            pin_active = pin_credential.status == "active"

        active_devices = 0
        for raw in state["trusted_devices"]:
            device = TrustedDevice.from_dict(raw)
            self._mark_device_expired_if_needed(device)
            if device.status == "active":
                active_devices += 1

        pending_challenges = 0
        for raw in state["challenges"]:
            challenge = VerificationChallenge.from_dict(raw)
            if (
                challenge.status == "pending"
                and not self._is_challenge_expired(challenge)
            ):
                pending_challenges += 1

        attempt_state = SecurityAttemptState.from_dict(
            state.get("attempt_state", {})
        )

        locked = self._attempt_state_is_locked(attempt_state)

        available_methods = self._get_available_methods(
            user_id_str,
            workspace_id_str,
        )

        return self._safe_result(
            message="Biometric gate security status fetched successfully.",
            data={
                "available_methods": available_methods,
                "active_biometric_credentials": active_biometrics,
                "pin_enrolled": pin_active,
                "active_trusted_devices": active_devices,
                "pending_challenges": pending_challenges,
                "locked": locked,
                "locked_until": (
                    attempt_state.locked_until if locked else None
                ),
                "failed_attempts": attempt_state.failed_attempts,
                "registered_verifiers": sorted(self._verifiers.keys()),
            },
            metadata={
                "user_id": user_id_str,
                "workspace_id": workspace_id_str,
            },
        )

    def backup_tenant_security_state(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        require_security: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Create a protected local backup of one tenant security state file."""
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
        )
        if not context_result["success"]:
            return context_result

        user_id_str = str(user_id)
        workspace_id_str = str(workspace_id)

        if require_security is not False:
            approval = self._request_security_approval(
                user_id=user_id_str,
                workspace_id=workspace_id_str,
                action="backup_biometric_security_state",
                payload={},
            )

            if not approval.get("approved", False):
                return self._error_result(
                    message="Security approval denied for security-state backup.",
                    code="SECURITY_APPROVAL_DENIED",
                    metadata={"approval": approval},
                )

        with self._lock:
            source_path = self._tenant_file_path(
                user_id_str,
                workspace_id_str,
            )

            if not source_path.exists():
                state = self._default_tenant_state(
                    user_id_str,
                    workspace_id_str,
                )
                self._save_tenant_state(
                    user_id_str,
                    workspace_id_str,
                    state,
                )

            timestamp = _utc_now().strftime("%Y%m%dT%H%M%SZ")
            backup_name = (
                f"user_{_safe_slug(user_id_str)}__"
                f"workspace_{_safe_slug(workspace_id_str)}__"
                f"{timestamp}.json"
            )
            backup_path = self.backup_dir / backup_name
            backup_path.parent.mkdir(parents=True, exist_ok=True)

            shutil.copy2(source_path, backup_path)

        self._log_audit_event(
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            action="biometric_security_state.backup_created",
            payload={"backup_path": str(backup_path)},
        )

        return self._safe_result(
            message="Tenant biometric security-state backup created.",
            data={
                "backup_path": str(backup_path),
                "created_at": _utc_now_iso(),
            },
            metadata={
                "user_id": user_id_str,
                "workspace_id": workspace_id_str,
            },
        )

    # ========================================================================
    # Required William compatibility hooks
    # ========================================================================

    def _validate_task_context(
        self,
        *,
        user_id: Union[str, int, None],
        workspace_id: Union[str, int, None],
        **_: Any,
    ) -> Dict[str, Any]:
        """
        Enforce SaaS tenant isolation.

        No user-specific security operation is allowed without both IDs.
        """
        if user_id is None or not str(user_id).strip():
            return self._error_result(
                message="user_id is required for biometric security operations.",
                code="MISSING_USER_ID",
            )

        if workspace_id is None or not str(workspace_id).strip():
            return self._error_result(
                message="workspace_id is required for biometric security operations.",
                code="MISSING_WORKSPACE_ID",
                metadata={"user_id": str(user_id)},
            )

        return self._safe_result(
            message="Security task context validated.",
            data={
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
            },
        )

    def _requires_security_check(
        self,
        *,
        action: str,
        require_security: Optional[bool] = None,
        **_: Any,
    ) -> bool:
        """Determine whether the parent Security Agent must approve an action."""
        if require_security is not None:
            return bool(require_security)

        if not self.enable_security_approval:
            return False

        protected_actions = {
            "enroll_biometric_credential",
            "remove_biometric_credential",
            "enroll_pin",
            "remove_pin",
            "trust_device",
            "revoke_trusted_device",
            "revoke_all_trusted_devices",
            "backup_biometric_security_state",
        }

        return action in protected_actions

    def _request_security_approval(
        self,
        *,
        user_id: str,
        workspace_id: str,
        action: str,
        payload: Dict[str, Any],
        **_: Any,
    ) -> Dict[str, Any]:
        """
        Request approval from the parent Security Agent.

        Unlike low-risk helper modules, this gate uses a fail-closed fallback for
        protected operations when a configured Security Agent throws an error.

        During standalone development where no Security Agent exists, approval
        is allowed but clearly identified as development fallback. Production
        deployments should inject the real Security Agent.
        """
        approval_request = {
            "request_id": str(uuid.uuid4()),
            "user_id": user_id,
            "workspace_id": workspace_id,
            "requesting_agent": self.AGENT_NAME,
            "action": action,
            "payload": self._sanitize_metadata(payload),
            "requested_at": _utc_now_iso(),
        }

        if self.security_agent is not None:
            for method_name in (
                "request_approval",
                "approve_action",
                "validate_action",
                "check_permission",
            ):
                method = getattr(self.security_agent, method_name, None)

                if not callable(method):
                    continue

                try:
                    result = method(approval_request)

                    if isinstance(result, Mapping):
                        approved = bool(
                            result.get("approved")
                            or result.get("allowed")
                            or result.get("success")
                        )

                        return {
                            "approved": approved,
                            "source": f"security_agent.{method_name}",
                            "request_id": approval_request["request_id"],
                            "raw": dict(result),
                        }

                    return {
                        "approved": bool(result),
                        "source": f"security_agent.{method_name}",
                        "request_id": approval_request["request_id"],
                    }

                except Exception as exc:
                    logger.exception(
                        "Security approval request failed for action %s: %s",
                        action,
                        exc,
                    )

                    return {
                        "approved": False,
                        "source": f"security_agent.{method_name}",
                        "request_id": approval_request["request_id"],
                        "error": str(exc),
                    }

        environment = str(
            os.getenv("WILLIAM_ENV", "development")
        ).strip().lower()

        if environment in {"production", "prod"}:
            return {
                "approved": False,
                "source": "missing_security_agent",
                "request_id": approval_request["request_id"],
                "error": (
                    "Protected operation denied because no Security Agent "
                    "approval provider is configured in production."
                ),
            }

        return {
            "approved": True,
            "source": "development_fallback",
            "request_id": approval_request["request_id"],
            "warning": (
                "No parent Security Agent is configured. Development fallback "
                "approval was used."
            ),
        }

    def _prepare_verification_payload(
        self,
        *,
        action: str,
        user_id: str,
        workspace_id: str,
        success: bool,
        data: Optional[Dict[str, Any]] = None,
        **extra: Any,
    ) -> Dict[str, Any]:
        """Prepare a standardized payload for the Verification Agent."""
        return {
            "schema": "william.verification_payload.v1",
            "payload_id": str(uuid.uuid4()),
            "agent": self.AGENT_NAME,
            "module": self.AGENT_MODULE,
            "file_path": self.FILE_PATH,
            "action": action,
            "success": success,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "data": self._sanitize_verification_result(data or {}),
            "extra": self._sanitize_metadata(extra),
            "created_at": _utc_now_iso(),
        }

    def _prepare_memory_payload(
        self,
        *,
        action: str,
        user_id: str,
        workspace_id: str,
        data: Optional[Dict[str, Any]] = None,
        **extra: Any,
    ) -> Dict[str, Any]:
        """
        Prepare safe Memory Agent context.

        Raw PINs, device tokens, biometric assertions, hash records, and raw
        biometric information are excluded.
        """
        return {
            "schema": "william.memory_payload.v1",
            "memory_type": "security_context",
            "agent": self.AGENT_NAME,
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "data": self._sanitize_verification_result(data or {}),
            "extra": self._sanitize_metadata(extra),
            "created_at": _utc_now_iso(),
        }

    def _emit_agent_event(
        self,
        *,
        event_name: str,
        user_id: str,
        workspace_id: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Emit a structured event without breaking the main security action."""
        if not self.enable_agent_events:
            return

        event = {
            "event_id": str(uuid.uuid4()),
            "event_name": event_name,
            "agent": self.AGENT_NAME,
            "module": self.AGENT_MODULE,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "payload": self._sanitize_metadata(payload or {}),
            "created_at": _utc_now_iso(),
        }

        try:
            if self.event_bus is not None:
                for method_name in (
                    "emit",
                    "publish",
                    "dispatch",
                    "send",
                ):
                    method = getattr(self.event_bus, method_name, None)

                    if callable(method):
                        method(event)
                        return

            parent_emit = getattr(super(), "emit_event", None)
            if callable(parent_emit):
                parent_emit(event_name, event)

        except Exception as exc:
            logger.warning(
                "Failed to emit biometric gate event %s: %s",
                event_name,
                exc,
            )

    def _log_audit_event(
        self,
        *,
        user_id: str,
        workspace_id: str,
        action: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Write a safe structured audit record."""
        if not self.enable_audit_logging:
            return

        event = {
            "audit_id": str(uuid.uuid4()),
            "agent": self.AGENT_NAME,
            "module": self.AGENT_MODULE,
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "payload": self._sanitize_metadata(payload or {}),
            "created_at": _utc_now_iso(),
        }

        try:
            if self.audit_logger is not None:
                for method_name in (
                    "log",
                    "write",
                    "record",
                    "emit",
                ):
                    method = getattr(self.audit_logger, method_name, None)

                    if callable(method):
                        method(event)
                        return

            logger.info(
                "SECURITY_AUDIT | %s",
                json.dumps(event, default=_json_default),
            )

        except Exception as exc:
            logger.warning(
                "Failed to write biometric security audit event: %s",
                exc,
            )

    def _safe_result(
        self,
        *,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return the standard William/Jarvis success structure."""
        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": {
                "agent": self.AGENT_NAME,
                "module": self.AGENT_MODULE,
                "timestamp": _utc_now_iso(),
                **(metadata or {}),
            },
        }

    def _error_result(
        self,
        *,
        message: str,
        code: str = "BIOMETRIC_GATE_ERROR",
        error: Optional[Union[str, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return the standard William/Jarvis error structure."""
        if isinstance(error, dict):
            error_payload = error
        else:
            error_payload = {
                "code": code,
                "details": error or message,
            }

        return {
            "success": False,
            "message": message,
            "data": {},
            "error": error_payload,
            "metadata": {
                "agent": self.AGENT_NAME,
                "module": self.AGENT_MODULE,
                "timestamp": _utc_now_iso(),
                **(metadata or {}),
            },
        }

    # ========================================================================
    # Direct verification implementations
    # ========================================================================

    def _verify_method_direct(
        self,
        *,
        user_id: str,
        workspace_id: str,
        method: str,
        evidence: Mapping[str, Any],
        challenge: VerificationChallenge,
    ) -> Dict[str, Any]:
        """Dispatch one factor to the correct verification implementation."""
        if method == "pin":
            pin = str(evidence.get("pin", ""))
            return self._verify_pin_direct(
                user_id=user_id,
                workspace_id=workspace_id,
                pin=pin,
                count_failure=False,
            )

        if method == "trusted_device":
            return self._verify_trusted_device_direct(
                user_id=user_id,
                workspace_id=workspace_id,
                device_id=str(evidence.get("device_id", "")),
                device_token=str(evidence.get("device_token", "")),
                device_fingerprint=str(
                    evidence.get("device_fingerprint", "")
                ),
                count_failure=False,
            )

        if method in BIOMETRIC_METHODS:
            return self._verify_biometric_direct(
                user_id=user_id,
                workspace_id=workspace_id,
                method=method,
                assertion=evidence,
                challenge=challenge,
            )

        return self._error_result(
            message="Unsupported verification method.",
            code="UNSUPPORTED_VERIFICATION_METHOD",
            metadata={"method": method},
        )

    def _verify_pin_direct(
        self,
        *,
        user_id: str,
        workspace_id: str,
        pin: str,
        count_failure: bool,
    ) -> Dict[str, Any]:
        """Verify a PIN without creating a challenge."""
        if not pin:
            return self._error_result(
                message="PIN is required.",
                code="MISSING_PIN",
            )

        with self._lock:
            state = self._load_tenant_state(user_id, workspace_id)
            raw_pin = state.get("pin_credential")

            if not raw_pin:
                return self._error_result(
                    message="No PIN is enrolled.",
                    code="PIN_NOT_ENROLLED",
                )

            credential = PinCredential.from_dict(raw_pin)

            if credential.status != "active":
                return self._error_result(
                    message="PIN credential is not active.",
                    code="PIN_CREDENTIAL_INACTIVE",
                )

            verified = _verify_secret(pin, credential.hash_record)

            if not verified:
                if count_failure:
                    self._record_failed_attempt(user_id, workspace_id)

                return self._error_result(
                    message="PIN verification failed.",
                    code="PIN_VERIFICATION_FAILED",
                )

            credential.last_verified_at = _utc_now_iso()
            credential.verification_count += 1
            credential.updated_at = _utc_now_iso()

            state["pin_credential"] = credential.to_dict()
            self._save_tenant_state(user_id, workspace_id, state)

        if count_failure:
            self._reset_attempt_state(user_id, workspace_id)

        return self._safe_result(
            message="PIN verified successfully.",
            data={
                "method": "pin",
                "credential_id": credential.credential_id,
                "verified": True,
            },
        )

    def _verify_trusted_device_direct(
        self,
        *,
        user_id: str,
        workspace_id: str,
        device_id: str,
        device_token: str,
        device_fingerprint: str,
        count_failure: bool,
    ) -> Dict[str, Any]:
        """Verify a trusted device directly."""
        if not device_id or not device_token or not device_fingerprint:
            return self._error_result(
                message=(
                    "device_id, device_token, and device_fingerprint are required."
                ),
                code="MISSING_TRUSTED_DEVICE_EVIDENCE",
            )

        with self._lock:
            state = self._load_tenant_state(user_id, workspace_id)
            device = self._find_trusted_device(state, device_id)

            if not device:
                if count_failure:
                    self._record_failed_attempt(user_id, workspace_id)

                return self._error_result(
                    message="Trusted device not found.",
                    code="TRUSTED_DEVICE_NOT_FOUND",
                )

            self._mark_device_expired_if_needed(device)

            if device.status != "active":
                return self._error_result(
                    message="Trusted device is not active.",
                    code="TRUSTED_DEVICE_INACTIVE",
                    metadata={"status": device.status},
                )

            fingerprint_matches = _constant_time_equal(
                device.device_fingerprint_hash,
                _fingerprint_text(device_fingerprint),
            )

            token_matches = _verify_secret(
                device_token,
                device.token_hash_record,
            )

            if not fingerprint_matches or not token_matches:
                if count_failure:
                    self._record_failed_attempt(user_id, workspace_id)

                return self._error_result(
                    message="Trusted-device verification failed.",
                    code="TRUSTED_DEVICE_VERIFICATION_FAILED",
                )

            device.last_verified_at = _utc_now_iso()
            device.verification_count += 1
            device.updated_at = _utc_now_iso()

            self._replace_trusted_device(state, device)
            self._save_tenant_state(user_id, workspace_id, state)

        if count_failure:
            self._reset_attempt_state(user_id, workspace_id)

        return self._safe_result(
            message="Trusted device verified successfully.",
            data={
                "method": "trusted_device",
                "device_id": device.device_id,
                "device_name": device.device_name,
                "verified": True,
            },
        )

    def _verify_biometric_direct(
        self,
        *,
        user_id: str,
        workspace_id: str,
        method: str,
        assertion: Mapping[str, Any],
        challenge: VerificationChallenge,
    ) -> Dict[str, Any]:
        """
        Verify face, fingerprint, or voice using a registered provider adapter.
        """
        verifier = self._verifiers.get(method)

        if verifier is None:
            return self._error_result(
                message=f"No trusted {method} verifier is registered.",
                code="BIOMETRIC_VERIFIER_NOT_CONFIGURED",
                metadata={"method": method},
            )

        assertion_validation = self._validate_biometric_assertion(assertion)
        if not assertion_validation["success"]:
            return assertion_validation

        credential_id = str(assertion.get("credential_id", "")).strip()

        with self._lock:
            state = self._load_tenant_state(user_id, workspace_id)

            credential = self._find_biometric_credential(
                state=state,
                credential_id=credential_id,
                method=method,
            )

            if not credential:
                return self._error_result(
                    message="Matching biometric credential not found.",
                    code="BIOMETRIC_CREDENTIAL_NOT_FOUND",
                    metadata={
                        "method": method,
                        "credential_id": credential_id,
                    },
                )

            if credential.status != "active":
                return self._error_result(
                    message="Biometric credential is not active.",
                    code="BIOMETRIC_CREDENTIAL_INACTIVE",
                    metadata={
                        "credential_id": credential.credential_id,
                        "status": credential.status,
                    },
                )

        context = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "challenge_id": challenge.challenge_id,
            "purpose": challenge.purpose,
            "action_id": challenge.action_id,
            "verification_level": challenge.verification_level,
            "assertion_max_age_seconds": self.assertion_max_age_seconds,
        }

        expected_credential = {
            "credential_id": credential.credential_id,
            "method": credential.method,
            "provider": credential.provider,
            "provider_subject_hash": credential.provider_subject_hash,
            "confidence_threshold": credential.confidence_threshold,
        }

        try:
            if callable(getattr(verifier, "verify", None)):
                provider_result = verifier.verify(  # type: ignore[union-attr]
                    method=method,
                    assertion=assertion,
                    expected_credential=expected_credential,
                    context=context,
                )
            else:
                provider_result = verifier(  # type: ignore[operator]
                    method=method,
                    assertion=assertion,
                    expected_credential=expected_credential,
                    context=context,
                )

        except Exception as exc:
            logger.exception(
                "%s biometric verifier raised an exception: %s",
                method,
                exc,
            )

            return self._error_result(
                message=f"{method} verification provider failed safely.",
                code="BIOMETRIC_PROVIDER_ERROR",
                error={
                    "code": "BIOMETRIC_PROVIDER_ERROR",
                    "details": str(exc),
                },
            )

        provider_validation = self._validate_provider_result(
            method=method,
            result=provider_result,
            credential=credential,
        )

        if not provider_validation["success"]:
            return provider_validation

        with self._lock:
            state = self._load_tenant_state(user_id, workspace_id)
            current = self._find_biometric_credential(
                state=state,
                credential_id=credential.credential_id,
                method=method,
            )

            if current:
                current.last_verified_at = _utc_now_iso()
                current.verification_count += 1
                current.updated_at = _utc_now_iso()
                self._replace_biometric_credential(state, current)
                self._save_tenant_state(user_id, workspace_id, state)

        return self._safe_result(
            message=f"{method} verification passed.",
            data={
                "method": method,
                "credential_id": credential.credential_id,
                "provider": credential.provider,
                "confidence": provider_validation["data"]["confidence"],
                "assertion_id_hash": provider_validation["data"][
                    "assertion_id_hash"
                ],
                "verified": True,
            },
        )

    # ========================================================================
    # Verification validation helpers
    # ========================================================================

    def _validate_biometric_assertion(
        self,
        assertion: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Validate required safe biometric assertion fields."""
        credential_id = str(assertion.get("credential_id", "")).strip()
        assertion_id = str(assertion.get("assertion_id", "")).strip()
        assertion_timestamp = str(
            assertion.get("assertion_timestamp", "")
        ).strip()

        if not credential_id:
            return self._error_result(
                message="Biometric assertion requires credential_id.",
                code="MISSING_BIOMETRIC_CREDENTIAL_ID",
            )

        if not assertion_id:
            return self._error_result(
                message="Biometric assertion requires a unique assertion_id.",
                code="MISSING_BIOMETRIC_ASSERTION_ID",
            )

        parsed_timestamp = _parse_iso_datetime(assertion_timestamp)
        if not parsed_timestamp:
            return self._error_result(
                message="Biometric assertion timestamp is invalid.",
                code="INVALID_BIOMETRIC_ASSERTION_TIMESTAMP",
            )

        age_seconds = (_utc_now() - parsed_timestamp).total_seconds()

        if age_seconds < -30:
            return self._error_result(
                message="Biometric assertion timestamp is in the future.",
                code="BIOMETRIC_ASSERTION_FUTURE_TIMESTAMP",
            )

        if age_seconds > self.assertion_max_age_seconds:
            return self._error_result(
                message="Biometric assertion has expired.",
                code="BIOMETRIC_ASSERTION_EXPIRED",
                metadata={
                    "age_seconds": round(age_seconds, 2),
                    "max_age_seconds": self.assertion_max_age_seconds,
                },
            )

        if self._contains_probable_raw_biometric(assertion):
            return self._error_result(
                message=(
                    "Raw biometric data must not be submitted to the generic "
                    "BiometricGate interface."
                ),
                code="RAW_BIOMETRIC_ASSERTION_REJECTED",
            )

        return self._safe_result(
            message="Biometric assertion structure validated.",
            data={
                "credential_id": credential_id,
                "assertion_id_hash": _fingerprint_text(assertion_id),
            },
        )

    def _validate_provider_result(
        self,
        *,
        method: str,
        result: Any,
        credential: BiometricCredential,
    ) -> Dict[str, Any]:
        """Validate the trusted provider's verification decision."""
        if not isinstance(result, Mapping):
            return self._error_result(
                message="Biometric verifier returned an invalid result.",
                code="INVALID_BIOMETRIC_PROVIDER_RESULT",
            )

        provider_success = bool(result.get("success", False))
        verified = bool(result.get("verified", False))

        if not provider_success or not verified:
            return self._error_result(
                message=f"{method} verification failed.",
                code="BIOMETRIC_VERIFICATION_FAILED",
                metadata={
                    "provider": credential.provider,
                    "provider_message": str(result.get("message", ""))[:250],
                },
            )

        result_provider = str(result.get("provider", "")).strip()
        if result_provider and result_provider != credential.provider:
            return self._error_result(
                message="Biometric provider mismatch.",
                code="BIOMETRIC_PROVIDER_MISMATCH",
            )

        try:
            confidence = float(result.get("confidence", 0.0))
        except (TypeError, ValueError):
            confidence = 0.0

        if confidence < credential.confidence_threshold:
            return self._error_result(
                message="Biometric confidence did not meet the required threshold.",
                code="BIOMETRIC_CONFIDENCE_TOO_LOW",
                metadata={
                    "confidence": confidence,
                    "required_confidence": credential.confidence_threshold,
                },
            )

        provider_subject_id = str(
            result.get("provider_subject_id", "")
        ).strip()

        if provider_subject_id:
            provider_subject_hash = _fingerprint_text(provider_subject_id)

            if not _constant_time_equal(
                provider_subject_hash,
                credential.provider_subject_hash,
            ):
                return self._error_result(
                    message="Biometric provider subject mismatch.",
                    code="BIOMETRIC_SUBJECT_MISMATCH",
                )

        assertion_id = str(result.get("assertion_id", "")).strip()
        if not assertion_id:
            return self._error_result(
                message="Biometric provider result requires assertion_id.",
                code="MISSING_PROVIDER_ASSERTION_ID",
            )

        return self._safe_result(
            message="Biometric provider result validated.",
            data={
                "confidence": confidence,
                "assertion_id_hash": _fingerprint_text(assertion_id),
            },
        )

    def _validate_challenge_for_use(
        self,
        *,
        challenge: VerificationChallenge,
        nonce: str,
        method: str,
    ) -> Dict[str, Any]:
        """Validate challenge state, expiry, nonce, and method binding."""
        if challenge.status != "pending":
            return self._error_result(
                message="Verification challenge is no longer pending.",
                code="CHALLENGE_NOT_PENDING",
                metadata={"status": challenge.status},
            )

        if self._is_challenge_expired(challenge):
            return self._error_result(
                message="Verification challenge has expired.",
                code="CHALLENGE_EXPIRED",
            )

        if challenge.attempts >= challenge.max_attempts:
            return self._error_result(
                message="Verification challenge attempt limit has been reached.",
                code="CHALLENGE_ATTEMPT_LIMIT_REACHED",
            )

        if not nonce:
            return self._error_result(
                message="Challenge nonce is required.",
                code="MISSING_CHALLENGE_NONCE",
            )

        if not _constant_time_equal(
            challenge.nonce_hash,
            _fingerprint_text(nonce),
        ):
            return self._error_result(
                message="Challenge nonce verification failed.",
                code="INVALID_CHALLENGE_NONCE",
            )

        if method not in challenge.required_methods:
            return self._error_result(
                message="This verification method is not allowed for the challenge.",
                code="METHOD_NOT_ALLOWED_FOR_CHALLENGE",
                metadata={
                    "method": method,
                    "allowed_methods": challenge.required_methods,
                },
            )

        return self._safe_result(
            message="Verification challenge validated.",
            data={"challenge_id": challenge.challenge_id},
        )

    def _evaluate_challenge_completion(
        self,
        challenge: VerificationChallenge,
    ) -> Dict[str, Any]:
        """Determine whether the challenge has satisfied its policy."""
        verified = set(challenge.verified_methods)

        if len(verified) < challenge.minimum_factors:
            return {
                "complete": False,
                "reason": "minimum_factors_not_met",
            }

        policy = VERIFICATION_LEVEL_REQUIREMENTS[
            challenge.verification_level
        ]

        if policy.get("require_distinct_categories"):
            categories = {
                METHOD_CATEGORIES[method]
                for method in verified
                if method in METHOD_CATEGORIES
            }

            if len(categories) < 2:
                return {
                    "complete": False,
                    "reason": "factor_diversity_not_met",
                }

        if policy.get("disallow_trusted_device_only"):
            if verified == {"trusted_device"}:
                return {
                    "complete": False,
                    "reason": "trusted_device_only_not_allowed",
                }

        return {
            "complete": True,
            "reason": "policy_satisfied",
        }

    # ========================================================================
    # Lockout helpers
    # ========================================================================

    def _check_lockout(
        self,
        user_id: str,
        workspace_id: str,
    ) -> Dict[str, Any]:
        """Reject verification while a tenant/user lockout is active."""
        with self._lock:
            state = self._load_tenant_state(user_id, workspace_id)
            attempt_state = SecurityAttemptState.from_dict(
                state.get("attempt_state", {})
            )

            if not self._attempt_state_is_locked(attempt_state):
                if attempt_state.locked_until:
                    attempt_state.locked_until = None
                    attempt_state.failed_attempts = 0
                    attempt_state.first_failed_at = None
                    state["attempt_state"] = attempt_state.to_dict()
                    self._save_tenant_state(
                        user_id,
                        workspace_id,
                        state,
                    )

                return self._safe_result(
                    message="No active biometric security lockout.",
                    data={"locked": False},
                )

            locked_until = _parse_iso_datetime(
                attempt_state.locked_until
            )
            remaining_seconds = 0

            if locked_until:
                remaining_seconds = max(
                    0,
                    int((locked_until - _utc_now()).total_seconds()),
                )

            return self._error_result(
                message="Verification is temporarily locked due to failed attempts.",
                code="BIOMETRIC_GATE_LOCKED",
                metadata={
                    "locked_until": attempt_state.locked_until,
                    "remaining_seconds": remaining_seconds,
                    "failed_attempts": attempt_state.failed_attempts,
                },
            )

    def _record_failed_attempt(
        self,
        user_id: str,
        workspace_id: str,
    ) -> None:
        """Record a failed verification and apply temporary lockout if needed."""
        with self._lock:
            state = self._load_tenant_state(user_id, workspace_id)
            attempt_state = SecurityAttemptState.from_dict(
                state.get("attempt_state", {})
            )

            now = _utc_now()

            if not attempt_state.first_failed_at:
                attempt_state.first_failed_at = now.isoformat()

            attempt_state.failed_attempts += 1
            attempt_state.last_failed_at = now.isoformat()

            if attempt_state.failed_attempts >= self.max_failed_attempts:
                multiplier = min(
                    4,
                    max(
                        1,
                        attempt_state.failed_attempts
                        // self.max_failed_attempts,
                    ),
                )

                lockout_duration = self.lockout_seconds * multiplier
                attempt_state.locked_until = (
                    now + timedelta(seconds=lockout_duration)
                ).isoformat()

            state["attempt_state"] = attempt_state.to_dict()
            self._save_tenant_state(user_id, workspace_id, state)

        self._log_audit_event(
            user_id=user_id,
            workspace_id=workspace_id,
            action="biometric_gate.failed_attempt_recorded",
            payload={
                "failed_attempts": attempt_state.failed_attempts,
                "locked_until": attempt_state.locked_until,
            },
        )

    def _reset_attempt_state(
        self,
        user_id: str,
        workspace_id: str,
    ) -> None:
        """Reset failed-attempt state after successful verification."""
        with self._lock:
            state = self._load_tenant_state(user_id, workspace_id)

            attempt_state = SecurityAttemptState(
                user_id=user_id,
                workspace_id=workspace_id,
                failed_attempts=0,
                first_failed_at=None,
                last_failed_at=None,
                locked_until=None,
                last_success_at=_utc_now_iso(),
            )

            state["attempt_state"] = attempt_state.to_dict()
            self._save_tenant_state(user_id, workspace_id, state)

    def _attempt_state_is_locked(
        self,
        attempt_state: SecurityAttemptState,
    ) -> bool:
        """Return True while lockout expiration is still in the future."""
        locked_until = _parse_iso_datetime(attempt_state.locked_until)

        if not locked_until:
            return False

        return locked_until > _utc_now()

    # ========================================================================
    # Tenant storage
    # ========================================================================

    def _tenant_file_path(
        self,
        user_id: str,
        workspace_id: str,
    ) -> Path:
        """Return tenant-isolated security-state file path."""
        user_directory = (
            self.storage_dir
            / f"user_{_safe_slug(user_id)}"
        )
        user_directory.mkdir(parents=True, exist_ok=True)

        return (
            user_directory
            / f"workspace_{_safe_slug(workspace_id)}.json"
        )

    def _default_tenant_state(
        self,
        user_id: str,
        workspace_id: str,
    ) -> Dict[str, Any]:
        """Create an empty tenant security-state structure."""
        return {
            "schema": "william.security_agent.biometric_gate.v1",
            "user_id": user_id,
            "workspace_id": workspace_id,
            "biometric_credentials": [],
            "pin_credential": None,
            "revoked_pin_credentials": [],
            "trusted_devices": [],
            "challenges": [],
            "attempt_state": SecurityAttemptState(
                user_id=user_id,
                workspace_id=workspace_id,
            ).to_dict(),
            "created_at": _utc_now_iso(),
            "updated_at": _utc_now_iso(),
        }

    def _load_tenant_state(
        self,
        user_id: str,
        workspace_id: str,
    ) -> Dict[str, Any]:
        """Load a tenant's isolated security state."""
        path = self._tenant_file_path(user_id, workspace_id)

        if not path.exists():
            return self._default_tenant_state(
                user_id,
                workspace_id,
            )

        try:
            with path.open("r", encoding="utf-8") as file:
                raw = json.load(file)

            if not isinstance(raw, MutableMapping):
                raise ValueError("Tenant security state must be a JSON object.")

            stored_user = str(raw.get("user_id", ""))
            stored_workspace = str(raw.get("workspace_id", ""))

            if (
                stored_user
                and stored_user != user_id
            ) or (
                stored_workspace
                and stored_workspace != workspace_id
            ):
                raise ValueError(
                    "Stored tenant identifiers do not match requested context."
                )

            raw["user_id"] = user_id
            raw["workspace_id"] = workspace_id
            raw.setdefault("schema", "william.security_agent.biometric_gate.v1")
            raw.setdefault("biometric_credentials", [])
            raw.setdefault("pin_credential", None)
            raw.setdefault("revoked_pin_credentials", [])
            raw.setdefault("trusted_devices", [])
            raw.setdefault("challenges", [])
            raw.setdefault(
                "attempt_state",
                SecurityAttemptState(
                    user_id=user_id,
                    workspace_id=workspace_id,
                ).to_dict(),
            )
            raw.setdefault("created_at", _utc_now_iso())
            raw.setdefault("updated_at", _utc_now_iso())

            return dict(raw)

        except Exception as exc:
            logger.exception(
                "Failed to load biometric security state %s: %s",
                path,
                exc,
            )

            self._backup_corrupt_file(path)

            return self._default_tenant_state(
                user_id,
                workspace_id,
            )

    def _save_tenant_state(
        self,
        user_id: str,
        workspace_id: str,
        state: Dict[str, Any],
    ) -> None:
        """Atomically save tenant security state."""
        state["schema"] = "william.security_agent.biometric_gate.v1"
        state["user_id"] = user_id
        state["workspace_id"] = workspace_id
        state["updated_at"] = _utc_now_iso()

        path = self._tenant_file_path(user_id, workspace_id)
        temp_path = path.with_suffix(".tmp")

        with temp_path.open("w", encoding="utf-8") as file:
            json.dump(
                state,
                file,
                ensure_ascii=False,
                indent=2,
                default=_json_default,
            )
            file.flush()
            os.fsync(file.fileno())

        os.replace(temp_path, path)

        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    def _backup_corrupt_file(self, path: Path) -> None:
        """Back up a corrupt tenant state file before recovery."""
        try:
            if not path.exists():
                return

            timestamp = _utc_now().strftime("%Y%m%dT%H%M%SZ")
            backup_path = (
                self.backup_dir
                / f"corrupt__{path.stem}__{timestamp}.json"
            )
            backup_path.parent.mkdir(parents=True, exist_ok=True)

            shutil.copy2(path, backup_path)

            logger.warning(
                "Corrupt biometric security file backed up to %s",
                backup_path,
            )

        except Exception as exc:
            logger.warning(
                "Failed to back up corrupt biometric state file %s: %s",
                path,
                exc,
            )

    # ========================================================================
    # State-record helpers
    # ========================================================================

    def _find_biometric_credential(
        self,
        *,
        state: Mapping[str, Any],
        credential_id: str,
        method: Optional[str] = None,
    ) -> Optional[BiometricCredential]:
        """Find one biometric credential."""
        for raw in state.get("biometric_credentials", []):
            credential = BiometricCredential.from_dict(raw)

            if credential.credential_id != credential_id:
                continue

            if method and credential.method != method:
                continue

            return credential

        return None

    def _find_duplicate_biometric_credential(
        self,
        *,
        state: Mapping[str, Any],
        method: str,
        provider: str,
        provider_subject_hash: str,
    ) -> Optional[BiometricCredential]:
        """Find an existing active enrollment for one provider subject."""
        for raw in state.get("biometric_credentials", []):
            credential = BiometricCredential.from_dict(raw)

            if (
                credential.method == method
                and credential.provider == provider
                and credential.provider_subject_hash
                == provider_subject_hash
                and credential.status == "active"
            ):
                return credential

        return None

    def _replace_biometric_credential(
        self,
        state: Dict[str, Any],
        updated: BiometricCredential,
    ) -> None:
        """Replace one biometric credential in state."""
        output: List[Dict[str, Any]] = []

        for raw in state["biometric_credentials"]:
            credential = BiometricCredential.from_dict(raw)

            if credential.credential_id == updated.credential_id:
                output.append(updated.to_dict())
            else:
                output.append(credential.to_dict())

        state["biometric_credentials"] = output

    def _set_biometric_credential_status(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        credential_id: str,
        status: CredentialStatus,
        reason: Optional[str],
    ) -> Dict[str, Any]:
        """Set biometric credential status."""
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
        )
        if not context_result["success"]:
            return context_result

        user_id_str = str(user_id)
        workspace_id_str = str(workspace_id)

        with self._lock:
            state = self._load_tenant_state(user_id_str, workspace_id_str)

            credential = self._find_biometric_credential(
                state=state,
                credential_id=credential_id,
            )

            if not credential:
                return self._error_result(
                    message="Biometric credential not found.",
                    code="BIOMETRIC_CREDENTIAL_NOT_FOUND",
                )

            credential.status = status
            credential.updated_at = _utc_now_iso()

            if reason:
                credential.metadata["status_reason"] = reason

            self._replace_biometric_credential(state, credential)
            self._save_tenant_state(user_id_str, workspace_id_str, state)

        self._emit_agent_event(
            event_name=f"security.biometric.credential_{status}",
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            payload={
                "credential_id": credential.credential_id,
                "method": credential.method,
                "status": status,
            },
        )

        self._log_audit_event(
            user_id=user_id_str,
            workspace_id=workspace_id_str,
            action=f"biometric_credential.{status}",
            payload={
                "credential_id": credential.credential_id,
                "method": credential.method,
                "reason": reason,
            },
        )

        return self._safe_result(
            message=f"Biometric credential status changed to {status}.",
            data={"credential": credential.to_dict()},
            metadata={
                "user_id": user_id_str,
                "workspace_id": workspace_id_str,
            },
        )

    def _find_trusted_device(
        self,
        state: Mapping[str, Any],
        device_id: str,
    ) -> Optional[TrustedDevice]:
        """Find one trusted device."""
        for raw in state.get("trusted_devices", []):
            device = TrustedDevice.from_dict(raw)
            if device.device_id == device_id:
                return device

        return None

    def _replace_trusted_device(
        self,
        state: Dict[str, Any],
        updated: TrustedDevice,
    ) -> None:
        """Replace one trusted device in state."""
        output: List[Dict[str, Any]] = []

        for raw in state["trusted_devices"]:
            device = TrustedDevice.from_dict(raw)

            if device.device_id == updated.device_id:
                output.append(
                    updated.to_dict(include_hash=True)
                )
            else:
                output.append(
                    device.to_dict(include_hash=True)
                )

        state["trusted_devices"] = output

    def _find_challenge(
        self,
        state: Mapping[str, Any],
        challenge_id: str,
    ) -> Optional[VerificationChallenge]:
        """Find one verification challenge."""
        for raw in state.get("challenges", []):
            challenge = VerificationChallenge.from_dict(raw)

            if challenge.challenge_id == challenge_id:
                return challenge

        return None

    def _replace_challenge(
        self,
        state: Dict[str, Any],
        updated: VerificationChallenge,
    ) -> None:
        """Replace one challenge in state."""
        output: List[Dict[str, Any]] = []

        for raw in state["challenges"]:
            challenge = VerificationChallenge.from_dict(raw)

            if challenge.challenge_id == updated.challenge_id:
                output.append(
                    updated.to_dict(include_nonce_hash=True)
                )
            else:
                output.append(
                    challenge.to_dict(include_nonce_hash=True)
                )

        state["challenges"] = output

    # ========================================================================
    # General helpers
    # ========================================================================

    def _get_available_methods(
        self,
        user_id: str,
        workspace_id: str,
    ) -> List[str]:
        """Return currently usable verification methods."""
        with self._lock:
            state = self._load_tenant_state(user_id, workspace_id)

        methods: List[str] = []

        active_biometric_methods: Set[str] = set()

        for raw in state["biometric_credentials"]:
            credential = BiometricCredential.from_dict(raw)

            if (
                credential.status == "active"
                and credential.method in self._verifiers
            ):
                active_biometric_methods.add(credential.method)

        methods.extend(sorted(active_biometric_methods))

        raw_pin = state.get("pin_credential")
        if raw_pin:
            pin = PinCredential.from_dict(raw_pin)
            if pin.status == "active":
                methods.append("pin")

        for raw in state["trusted_devices"]:
            device = TrustedDevice.from_dict(raw)
            self._mark_device_expired_if_needed(device)

            if device.status == "active":
                methods.append("trusted_device")
                break

        return _dedupe_strings(methods)

    def _has_active_pin(
        self,
        user_id: str,
        workspace_id: str,
    ) -> bool:
        """Return whether a tenant/user has an active PIN."""
        with self._lock:
            state = self._load_tenant_state(user_id, workspace_id)

        raw_pin = state.get("pin_credential")

        if not raw_pin:
            return False

        return PinCredential.from_dict(raw_pin).status == "active"

    def _validate_pin(self, pin: str) -> Dict[str, Any]:
        """Validate PIN format and reject commonly weak patterns."""
        pin = str(pin or "")

        if len(pin) < self.pin_min_length:
            return self._error_result(
                message=f"PIN must contain at least {self.pin_min_length} characters.",
                code="PIN_TOO_SHORT",
            )

        if len(pin) > self.pin_max_length:
            return self._error_result(
                message=f"PIN cannot exceed {self.pin_max_length} characters.",
                code="PIN_TOO_LONG",
            )

        if not pin.isdigit():
            return self._error_result(
                message="PIN must contain digits only.",
                code="PIN_MUST_BE_NUMERIC",
            )

        if len(set(pin)) == 1:
            return self._error_result(
                message="PIN cannot use the same digit repeatedly.",
                code="WEAK_PIN_REPEATED_DIGIT",
            )

        weak_patterns = {
            "012345",
            "123456",
            "654321",
            "111111",
            "000000",
            "121212",
            "112233",
            "123123",
            "12345678",
            "87654321",
        }

        if pin in weak_patterns:
            return self._error_result(
                message="This PIN is too common and cannot be used.",
                code="WEAK_COMMON_PIN",
            )

        ascending = "".join(
            str(index % 10)
            for index in range(len(pin))
        )
        descending = "".join(
            str((9 - index) % 10)
            for index in range(len(pin))
        )

        if pin == ascending or pin == descending:
            return self._error_result(
                message="Sequential PINs are not allowed.",
                code="WEAK_SEQUENTIAL_PIN",
            )

        return self._safe_result(
            message="PIN format validated.",
            data={"valid": True},
        )

    def _normalize_method(self, method: Any) -> str:
        """Normalize verification method name."""
        return str(method or "").strip().lower().replace("-", "_")

    def _normalize_verification_level(
        self,
        level: Any,
    ) -> str:
        """Normalize verification level with a secure fallback."""
        normalized = str(level or "standard").strip().lower()

        if normalized not in VERIFICATION_LEVEL_REQUIREMENTS:
            return "standard"

        return normalized

    def _is_challenge_expired(
        self,
        challenge: VerificationChallenge,
    ) -> bool:
        """Return whether challenge expiration is in the past."""
        expiration = _parse_iso_datetime(challenge.expires_at)

        if not expiration:
            return True

        return expiration <= _utc_now()

    def _mark_device_expired_if_needed(
        self,
        device: TrustedDevice,
    ) -> None:
        """Mark an active trusted device expired when its TTL ends."""
        expiration = _parse_iso_datetime(device.expires_at)

        if (
            device.status == "active"
            and expiration
            and expiration <= _utc_now()
        ):
            device.status = "expired"
            device.updated_at = _utc_now_iso()

    def _contains_probable_raw_biometric(
        self,
        payload: Mapping[str, Any],
    ) -> bool:
        """
        Detect keys that suggest raw biometric samples or templates.

        This is a defensive safeguard, not a substitute for API validation.
        """
        prohibited_fragments = {
            "raw_image",
            "image_bytes",
            "face_image",
            "raw_audio",
            "audio_bytes",
            "voice_recording",
            "fingerprint_image",
            "fingerprint_template",
            "biometric_template",
            "template_bytes",
            "base64_image",
            "base64_audio",
            "wav_data",
            "pcm_data",
        }

        for key, value in payload.items():
            normalized_key = str(key).strip().lower()

            if normalized_key in prohibited_fragments:
                return True

            if isinstance(value, Mapping):
                if self._contains_probable_raw_biometric(value):
                    return True

        return False

    def _sanitize_metadata(
        self,
        metadata: Optional[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """
        Remove secrets and raw biometric material from metadata.

        Unknown safe metadata is retained for dashboard and auditing.
        """
        if not metadata:
            return {}

        prohibited_keys = {
            "pin",
            "password",
            "secret",
            "token",
            "device_token",
            "raw_image",
            "image_bytes",
            "face_image",
            "raw_audio",
            "audio_bytes",
            "voice_recording",
            "fingerprint_image",
            "fingerprint_template",
            "biometric_template",
            "template_bytes",
            "hash_record",
            "token_hash_record",
        }

        sanitized: Dict[str, Any] = {}

        for key, value in metadata.items():
            normalized_key = str(key).strip().lower()

            if normalized_key in prohibited_keys:
                sanitized[str(key)] = "[REDACTED]"
                continue

            if isinstance(value, Mapping):
                sanitized[str(key)] = self._sanitize_metadata(value)
            elif isinstance(value, (list, tuple)):
                sanitized[str(key)] = [
                    self._sanitize_metadata(item)
                    if isinstance(item, Mapping)
                    else item
                    for item in value
                ]
            elif isinstance(value, bytes):
                sanitized[str(key)] = "[BINARY_REDACTED]"
            else:
                sanitized[str(key)] = value

        return sanitized

    def _sanitize_verification_result(
        self,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Sanitize result data before routing it to other agents."""
        sanitized = self._sanitize_metadata(payload)

        for key in list(sanitized.keys()):
            normalized = key.lower()

            if normalized in {
                "provider_subject_id",
                "device_fingerprint",
                "assertion",
                "evidence",
            }:
                original = sanitized.pop(key)
                sanitized[f"{key}_masked"] = _mask_identifier(
                    str(original)
                )

        return sanitized


# ============================================================================
# Standalone smoke test
# ============================================================================

if __name__ == "__main__":
    class DemoFaceVerifier:
        """
        Local test verifier.

        This is only a smoke-test adapter. Production must use a trusted,
        platform-specific verification provider.
        """

        def verify(
            self,
            *,
            method: str,
            assertion: Mapping[str, Any],
            expected_credential: Mapping[str, Any],
            context: Mapping[str, Any],
        ) -> Dict[str, Any]:
            provider_subject_id = str(
                assertion.get("provider_subject_id", "")
            )

            subject_matches = _constant_time_equal(
                _fingerprint_text(provider_subject_id),
                str(expected_credential["provider_subject_hash"]),
            )

            return {
                "success": subject_matches,
                "verified": subject_matches,
                "confidence": 0.98 if subject_matches else 0.0,
                "provider": expected_credential["provider"],
                "provider_subject_id": provider_subject_id,
                "assertion_id": assertion.get(
                    "assertion_id",
                    str(uuid.uuid4()),
                ),
                "assertion_timestamp": assertion.get(
                    "assertion_timestamp",
                    _utc_now_iso(),
                ),
            }

    gate = BiometricGate(
        storage_dir="data/dev_security_agent/biometric_gate",
        verifier_registry={"face": DemoFaceVerifier()},
    )

    user_id = "demo_user"
    workspace_id = "demo_workspace"

    pin_result = gate.enroll_pin(
        user_id=user_id,
        workspace_id=workspace_id,
        pin="739184",
        require_security=False,
    )
    print(json.dumps(pin_result, indent=2, default=_json_default))

    face_result = gate.enroll_biometric_credential(
        user_id=user_id,
        workspace_id=workspace_id,
        method="face",
        provider="demo_provider",
        provider_subject_id="demo-provider-user-001",
        label="Primary face credential",
        require_security=False,
    )
    print(json.dumps(face_result, indent=2, default=_json_default))

    challenge_result = gate.create_challenge(
        user_id=user_id,
        workspace_id=workspace_id,
        purpose="Approve a sensitive William action",
        verification_level="high",
        required_methods=["pin", "face"],
        minimum_factors=2,
        action_id="demo-action-001",
    )
    print(json.dumps(challenge_result, indent=2, default=_json_default))

    if challenge_result["success"]:
        challenge = challenge_result["data"]["challenge"]
        nonce = challenge_result["data"]["challenge_nonce"]

        pin_verify = gate.verify_challenge_method(
            user_id=user_id,
            workspace_id=workspace_id,
            challenge_id=challenge["challenge_id"],
            challenge_nonce=nonce,
            method="pin",
            evidence={"pin": "739184"},
        )
        print(json.dumps(pin_verify, indent=2, default=_json_default))

        credential_id = face_result["data"]["credential"]["credential_id"]

        face_verify = gate.verify_challenge_method(
            user_id=user_id,
            workspace_id=workspace_id,
            challenge_id=challenge["challenge_id"],
            challenge_nonce=nonce,
            method="face",
            evidence={
                "credential_id": credential_id,
                "assertion_id": str(uuid.uuid4()),
                "assertion_timestamp": _utc_now_iso(),
                "provider_subject_id": "demo-provider-user-001",
            },
        )
        print(json.dumps(face_verify, indent=2, default=_json_default))