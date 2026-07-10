"""
security/encryption.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix

Purpose:
    Encryption/decryption helpers for sensitive stored data with safe key handling.

Core Responsibilities:
    - Encrypt/decrypt sensitive stored data.
    - Keep encryption keys out of code.
    - Load keys safely from SecretsManager or environment variables.
    - Support SaaS isolation using user_id/workspace_id authenticated context.
    - Never log raw plaintext, ciphertext, or secret keys.
    - Return structured William/Jarvis result dictionaries.
    - Remain import-safe even before the full William/Jarvis system exists.

Architecture Compatibility:
    - Master Agent / Agent Router:
        Exposes async run(task) and stable public methods.
    - Security Agent:
        Sensitive encryption/decryption operations pass through security hooks.
    - Verification Agent:
        Every completed public action prepares a verification payload.
    - Memory Agent:
        Only safe metadata is prepared. Plaintext and keys are never stored.
    - Dashboard / FastAPI:
        Results use success/message/data/error/metadata format.
    - SaaS Isolation:
        user_id/workspace_id are validated for scoped encryption/decryption.

Security Design:
    - Uses AES-GCM from cryptography when available.
    - Uses HKDF-SHA256 to derive per-scope encryption keys from a master key.
    - Uses authenticated additional data, also called AAD, to bind ciphertext
      to user_id, workspace_id, purpose, algorithm, and key_id.
    - Fails closed if cryptography is not installed.
    - Does not implement weak fallback encryption.

Required external dependency for real encryption:
    cryptography

Install:
    pip install cryptography
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
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Iterable, Mapping, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Optional crypto imports.
# File stays import-safe if cryptography is missing.
# Encryption/decryption operations fail closed until dependency is installed.
# ---------------------------------------------------------------------------

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    CRYPTOGRAPHY_AVAILABLE = True
except Exception:  # pragma: no cover - dependency availability varies
    AESGCM = None  # type: ignore
    SHA256 = None  # type: ignore
    HKDF = None  # type: ignore
    CRYPTOGRAPHY_AVAILABLE = False


# ---------------------------------------------------------------------------
# Optional William/Jarvis imports with safe fallbacks.
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for early project stages
    class BaseAgent:  # type: ignore
        """
        Minimal fallback BaseAgent so this file can import before the full
        William/Jarvis framework exists.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)

        async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent cannot execute tasks.",
                "data": {},
                "error": "BaseAgent framework is not available.",
                "metadata": {"agent_name": self.agent_name},
            }


try:
    from security.secrets_manager import SecretsManager, SecretsContext  # type: ignore
except Exception:  # pragma: no cover - fallback for early project stages
    SecretsManager = None  # type: ignore

    @dataclass(frozen=True)
    class SecretsContext:  # type: ignore
        user_id: Optional[str] = None
        workspace_id: Optional[str] = None
        role: Optional[str] = None
        request_id: Optional[str] = None
        trace_id: Optional[str] = None
        ip_address: Optional[str] = None
        user_agent: Optional[str] = None
        scoped: bool = False
        metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Logging setup.
# ---------------------------------------------------------------------------

logger = logging.getLogger("william.security.encryption")
logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Constants.
# ---------------------------------------------------------------------------

DEFAULT_KEY_ENV_NAME = "WILLIAM_ENCRYPTION_KEY"
DEFAULT_KEY_ID_ENV_NAME = "WILLIAM_ENCRYPTION_KEY_ID"
DEFAULT_ALGORITHM = "AES-256-GCM-HKDF-SHA256"
DEFAULT_VERSION = "william.enc.v1"

AES_256_KEY_LENGTH = 32
AES_GCM_NONCE_LENGTH = 12
MIN_MASTER_KEY_LENGTH = 32

MAX_PLAINTEXT_BYTES = 10 * 1024 * 1024
MAX_TOKEN_BYTES = 20 * 1024 * 1024

SAFE_KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.:/@-]{1,128}$")

SENSITIVE_NAME_HINTS = (
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASS",
    "PWD",
    "KEY",
    "PRIVATE",
    "CREDENTIAL",
    "AUTH",
    "API",
    "BEARER",
    "CERT",
    "SIGNING",
    "PLAINTEXT",
    "CIPHERTEXT",
    "ENCRYPTION",
)


# ---------------------------------------------------------------------------
# Enums and data structures.
# ---------------------------------------------------------------------------

class EncryptionAction(str, Enum):
    """Supported EncryptionManager actions."""

    ENCRYPT_TEXT = "encrypt_text"
    DECRYPT_TEXT = "decrypt_text"
    ENCRYPT_BYTES = "encrypt_bytes"
    DECRYPT_BYTES = "decrypt_bytes"
    ENCRYPT_JSON = "encrypt_json"
    DECRYPT_JSON = "decrypt_json"
    GENERATE_KEY = "generate_key"
    HASH_VALUE = "hash_value"
    VERIFY_HASH = "verify_hash"
    HEALTH_CHECK = "health_check"


class KeySource(str, Enum):
    """Where the encryption key was loaded from."""

    SECRETS_MANAGER = "secrets_manager"
    ENVIRONMENT = "environment"
    DIRECT_PROVIDER = "direct_provider"
    UNAVAILABLE = "unavailable"


class EncryptionSensitivity(str, Enum):
    """Sensitivity label for safe metadata."""

    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class EncryptionContext:
    """
    SaaS-safe encryption context.

    When scoped=True, user_id and workspace_id are required. The values are
    included in authenticated additional data, so ciphertext encrypted for one
    workspace/user cannot be decrypted in another context.
    """

    user_id: Optional[str] = None
    workspace_id: Optional[str] = None
    role: Optional[str] = None
    request_id: Optional[str] = None
    trace_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    scoped: bool = False
    purpose: str = "general"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class EncryptionKeyMaterial:
    """
    Resolved master key material.

    key_bytes must never be logged or returned in public result payloads.
    """

    key_bytes: bytes
    key_id: str
    source: KeySource


@dataclass(frozen=True)
class EncryptionEnvelope:
    """
    Serializable encryption envelope.

    The encrypted token returned by public methods is a base64url-encoded JSON
    version of this structure.
    """

    version: str
    algorithm: str
    key_id: str
    nonce: str
    ciphertext: str
    aad_hash: str
    created_at: str


AuditSink = Callable[[Dict[str, Any]], None]
EventSink = Callable[[Dict[str, Any]], None]
KeyProvider = Callable[[EncryptionContext], Optional[Union[str, bytes]]]


# ---------------------------------------------------------------------------
# EncryptionManager
# ---------------------------------------------------------------------------

class EncryptionManager(BaseAgent):
    """
    Production-safe encryption helper for William/Jarvis.

    Public methods:
        - encrypt_text()
        - decrypt_text()
        - encrypt_bytes()
        - decrypt_bytes()
        - encrypt_json()
        - decrypt_json()
        - generate_key()
        - hash_value()
        - verify_hash()
        - health_check()

    Notes:
        - This class does not hardcode encryption keys.
        - Master key is loaded from SecretsManager, environment, or direct
          key provider.
        - Raw plaintext, raw keys, and raw ciphertext are never logged.
    """

    module_name = "security.encryption"
    agent_type = "security_utility"
    registry_name = "EncryptionManager"
    version = "1.0.0"

    def __init__(
        self,
        *,
        secrets_manager: Optional[Any] = None,
        key_provider: Optional[KeyProvider] = None,
        key_env_name: str = DEFAULT_KEY_ENV_NAME,
        key_id_env_name: str = DEFAULT_KEY_ID_ENV_NAME,
        default_key_id: str = "default",
        audit_sink: Optional[AuditSink] = None,
        event_sink: Optional[EventSink] = None,
        allow_environment_key: bool = True,
        strict_scoped_context: bool = True,
        agent_name: str = "EncryptionManager",
    ) -> None:
        super().__init__(agent_name=agent_name)

        self.secrets_manager = secrets_manager
        self.key_provider = key_provider
        self.key_env_name = key_env_name
        self.key_id_env_name = key_id_env_name
        self.default_key_id = default_key_id
        self.audit_sink = audit_sink
        self.event_sink = event_sink
        self.allow_environment_key = bool(allow_environment_key)
        self.strict_scoped_context = bool(strict_scoped_context)

        self._lock = threading.RLock()

        self._emit_agent_event(
            event_type="encryption_manager_initialized",
            payload={
                "module": self.module_name,
                "algorithm": DEFAULT_ALGORITHM,
                "cryptography_available": CRYPTOGRAPHY_AVAILABLE,
                "key_env_name": self.key_env_name,
                "key_id_env_name": self.key_id_env_name,
                "has_secrets_manager": self.secrets_manager is not None,
                "has_key_provider": self.key_provider is not None,
                "allow_environment_key": self.allow_environment_key,
            },
        )

    # ------------------------------------------------------------------
    # Public API: encryption/decryption
    # ------------------------------------------------------------------

    def encrypt_text(
        self,
        plaintext: str,
        *,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        role: Optional[str] = None,
        request_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        scoped: bool = False,
        purpose: str = "general",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Encrypt UTF-8 text and return a safe token.

        Args:
            plaintext:
                Sensitive text to encrypt.
            scoped:
                If True, user_id and workspace_id are required and bound to the
                ciphertext through authenticated context.
            purpose:
                A stable purpose string such as "memory", "audit_metadata",
                "oauth_token", "workspace_config", etc.

        Returns:
            data["token"] contains the encrypted token.
        """
        if not isinstance(plaintext, str):
            return self._error_result(
                message="Plaintext must be a string.",
                error="INVALID_PLAINTEXT_TYPE",
            )

        return self.encrypt_bytes(
            plaintext.encode("utf-8"),
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            request_id=request_id,
            trace_id=trace_id,
            scoped=scoped,
            purpose=purpose,
            metadata=metadata,
        )

    def decrypt_text(
        self,
        token: str,
        *,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        role: Optional[str] = None,
        request_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        scoped: bool = False,
        purpose: str = "general",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Decrypt a token into UTF-8 text.

        Raw plaintext is returned only in data["plaintext"] for trusted internal
        callers. It is never logged or included in audit/memory payloads.
        """
        decrypted = self.decrypt_bytes(
            token,
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            request_id=request_id,
            trace_id=trace_id,
            scoped=scoped,
            purpose=purpose,
            metadata=metadata,
        )

        if not decrypted.get("success"):
            return decrypted

        try:
            plaintext_bytes = decrypted.get("data", {}).get("plaintext_bytes")
            if not isinstance(plaintext_bytes, bytes):
                return self._error_result(
                    message="Decrypted payload was not bytes.",
                    error="INVALID_DECRYPTED_PAYLOAD",
                    metadata=decrypted.get("metadata", {}),
                )

            plaintext = plaintext_bytes.decode("utf-8")

            data = dict(decrypted.get("data", {}))
            data.pop("plaintext_bytes", None)
            data["plaintext"] = plaintext

            return self._safe_result(
                success=True,
                message="Text decrypted successfully.",
                data=data,
                metadata=decrypted.get("metadata", {}),
            )

        except UnicodeDecodeError:
            return self._error_result(
                message="Decrypted payload is not valid UTF-8 text.",
                error="INVALID_UTF8_PLAINTEXT",
                metadata=decrypted.get("metadata", {}),
            )

    def encrypt_bytes(
        self,
        plaintext: bytes,
        *,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        role: Optional[str] = None,
        request_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        scoped: bool = False,
        purpose: str = "general",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Encrypt bytes and return an encoded token.

        AES-GCM provides confidentiality and integrity. AAD binds ciphertext to
        SaaS context, purpose, algorithm, and key_id.
        """
        started_at = time.time()

        context = EncryptionContext(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            request_id=request_id,
            trace_id=trace_id,
            scoped=scoped,
            purpose=purpose,
            metadata=metadata or {},
        )

        validation = self._validate_encrypt_request(plaintext, context)
        if not validation["success"]:
            return validation

        if self._requires_security_check("encrypt_bytes", context):
            approval = self._request_security_approval(
                action="encrypt_bytes",
                context=context,
                payload={
                    "plaintext_size": len(plaintext),
                    "scoped": scoped,
                    "purpose": purpose,
                },
            )
            if not approval["success"]:
                return approval

        if not CRYPTOGRAPHY_AVAILABLE:
            return self._error_result(
                message="Encryption dependency is not installed.",
                error="CRYPTOGRAPHY_NOT_AVAILABLE",
                metadata={
                    "install": "pip install cryptography",
                    "duration_ms": self._duration_ms(started_at),
                },
            )

        try:
            key_material_result = self._resolve_key_material(context)
            if not key_material_result["success"]:
                return key_material_result

            key_material = key_material_result["data"]["key_material"]
            if not isinstance(key_material, EncryptionKeyMaterial):
                return self._error_result(
                    message="Invalid encryption key material.",
                    error="INVALID_KEY_MATERIAL",
                )

            aad = self._build_aad(context, key_material.key_id)
            derived_key = self._derive_scoped_key(key_material.key_bytes, context, key_material.key_id)
            nonce = secrets.token_bytes(AES_GCM_NONCE_LENGTH)

            aesgcm = AESGCM(derived_key)  # type: ignore[operator]
            ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

            envelope = EncryptionEnvelope(
                version=DEFAULT_VERSION,
                algorithm=DEFAULT_ALGORITHM,
                key_id=key_material.key_id,
                nonce=self._b64e(nonce),
                ciphertext=self._b64e(ciphertext),
                aad_hash=self._hash_bytes(aad),
                created_at=self._now(),
            )

            token = self._encode_envelope(envelope)

            verification_payload = self._prepare_verification_payload(
                action="encrypt_bytes",
                context=context,
                success=True,
                data={
                    "algorithm": DEFAULT_ALGORITHM,
                    "key_id": key_material.key_id,
                    "plaintext_size": len(plaintext),
                    "token_size": len(token),
                    "aad_hash": envelope.aad_hash,
                },
            )

            memory_payload = self._prepare_memory_payload(
                action="encrypt_bytes",
                context=context,
                data={
                    "algorithm": DEFAULT_ALGORITHM,
                    "key_id": key_material.key_id,
                    "plaintext_size": len(plaintext),
                    "token_size": len(token),
                },
            )

            result = self._safe_result(
                success=True,
                message="Data encrypted successfully.",
                data={
                    "token": token,
                    "algorithm": DEFAULT_ALGORITHM,
                    "version": DEFAULT_VERSION,
                    "key_id": key_material.key_id,
                    "aad_hash": envelope.aad_hash,
                },
                metadata={
                    "scoped": scoped,
                    "purpose": purpose,
                    "plaintext_size": len(plaintext),
                    "token_size": len(token),
                    "key_source": key_material.source.value,
                    "duration_ms": self._duration_ms(started_at),
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
            )

            self._log_audit_event(
                action="encrypt_bytes",
                context=context,
                outcome="success",
                payload={
                    "algorithm": DEFAULT_ALGORITHM,
                    "version": DEFAULT_VERSION,
                    "key_id": key_material.key_id,
                    "plaintext_size": len(plaintext),
                    "token_size": len(token),
                    "aad_hash": envelope.aad_hash,
                    "key_source": key_material.source.value,
                },
            )

            return result

        except Exception as exc:
            logger.exception("Encryption failed.")
            return self._error_result(
                message="Encryption failed.",
                error=str(exc),
                metadata={
                    "duration_ms": self._duration_ms(started_at),
                    "purpose": purpose,
                    "scoped": scoped,
                },
            )

    def decrypt_bytes(
        self,
        token: str,
        *,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        role: Optional[str] = None,
        request_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        scoped: bool = False,
        purpose: str = "general",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Decrypt an encrypted token into bytes.

        The same user_id/workspace_id/purpose/scope used during encryption must
        be supplied during decryption when scoped=True.
        """
        started_at = time.time()

        context = EncryptionContext(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            request_id=request_id,
            trace_id=trace_id,
            scoped=scoped,
            purpose=purpose,
            metadata=metadata or {},
        )

        validation = self._validate_decrypt_request(token, context)
        if not validation["success"]:
            return validation

        if self._requires_security_check("decrypt_bytes", context):
            approval = self._request_security_approval(
                action="decrypt_bytes",
                context=context,
                payload={
                    "token_size": len(token),
                    "scoped": scoped,
                    "purpose": purpose,
                },
            )
            if not approval["success"]:
                return approval

        if not CRYPTOGRAPHY_AVAILABLE:
            return self._error_result(
                message="Decryption dependency is not installed.",
                error="CRYPTOGRAPHY_NOT_AVAILABLE",
                metadata={
                    "install": "pip install cryptography",
                    "duration_ms": self._duration_ms(started_at),
                },
            )

        try:
            envelope = self._decode_envelope(token)

            if envelope.version != DEFAULT_VERSION:
                return self._error_result(
                    message="Unsupported encryption token version.",
                    error="UNSUPPORTED_TOKEN_VERSION",
                    metadata={"version": envelope.version},
                )

            if envelope.algorithm != DEFAULT_ALGORITHM:
                return self._error_result(
                    message="Unsupported encryption algorithm.",
                    error="UNSUPPORTED_ENCRYPTION_ALGORITHM",
                    metadata={"algorithm": envelope.algorithm},
                )

            key_material_result = self._resolve_key_material(context, expected_key_id=envelope.key_id)
            if not key_material_result["success"]:
                return key_material_result

            key_material = key_material_result["data"]["key_material"]
            if not isinstance(key_material, EncryptionKeyMaterial):
                return self._error_result(
                    message="Invalid encryption key material.",
                    error="INVALID_KEY_MATERIAL",
                )

            aad = self._build_aad(context, envelope.key_id)

            actual_aad_hash = self._hash_bytes(aad)
            if not hmac.compare_digest(actual_aad_hash, envelope.aad_hash):
                return self._error_result(
                    message="Encryption context does not match this token.",
                    error="AAD_CONTEXT_MISMATCH",
                    metadata={
                        "expected_aad_hash": envelope.aad_hash,
                        "actual_aad_hash": actual_aad_hash,
                        "purpose": purpose,
                        "scoped": scoped,
                    },
                )

            derived_key = self._derive_scoped_key(key_material.key_bytes, context, envelope.key_id)
            nonce = self._b64d(envelope.nonce)
            ciphertext = self._b64d(envelope.ciphertext)

            aesgcm = AESGCM(derived_key)  # type: ignore[operator]
            plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, aad)

            verification_payload = self._prepare_verification_payload(
                action="decrypt_bytes",
                context=context,
                success=True,
                data={
                    "algorithm": envelope.algorithm,
                    "key_id": envelope.key_id,
                    "token_size": len(token),
                    "plaintext_size": len(plaintext_bytes),
                    "aad_hash": envelope.aad_hash,
                },
            )

            memory_payload = self._prepare_memory_payload(
                action="decrypt_bytes",
                context=context,
                data={
                    "algorithm": envelope.algorithm,
                    "key_id": envelope.key_id,
                    "token_size": len(token),
                    "plaintext_size": len(plaintext_bytes),
                },
            )

            result = self._safe_result(
                success=True,
                message="Data decrypted successfully.",
                data={
                    "plaintext_bytes": plaintext_bytes,
                    "algorithm": envelope.algorithm,
                    "version": envelope.version,
                    "key_id": envelope.key_id,
                    "aad_hash": envelope.aad_hash,
                },
                metadata={
                    "scoped": scoped,
                    "purpose": purpose,
                    "token_size": len(token),
                    "plaintext_size": len(plaintext_bytes),
                    "key_source": key_material.source.value,
                    "duration_ms": self._duration_ms(started_at),
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
            )

            self._log_audit_event(
                action="decrypt_bytes",
                context=context,
                outcome="success",
                payload={
                    "algorithm": envelope.algorithm,
                    "version": envelope.version,
                    "key_id": envelope.key_id,
                    "token_size": len(token),
                    "plaintext_size": len(plaintext_bytes),
                    "aad_hash": envelope.aad_hash,
                    "key_source": key_material.source.value,
                },
            )

            return result

        except Exception as exc:
            logger.exception("Decryption failed.")
            return self._error_result(
                message="Decryption failed. Token may be invalid, corrupted, or used with the wrong context.",
                error=str(exc),
                metadata={
                    "duration_ms": self._duration_ms(started_at),
                    "purpose": purpose,
                    "scoped": scoped,
                },
            )

    def encrypt_json(
        self,
        payload: Union[Dict[str, Any], list],
        *,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        role: Optional[str] = None,
        request_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        scoped: bool = False,
        purpose: str = "json",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Encrypt a JSON-serializable dictionary/list.
        """
        started_at = time.time()

        if not isinstance(payload, (dict, list)):
            return self._error_result(
                message="JSON payload must be a dictionary or list.",
                error="INVALID_JSON_PAYLOAD_TYPE",
            )

        try:
            encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
        except Exception as exc:
            return self._error_result(
                message="JSON payload serialization failed.",
                error=str(exc),
                metadata={"duration_ms": self._duration_ms(started_at)},
            )

        return self.encrypt_bytes(
            encoded,
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            request_id=request_id,
            trace_id=trace_id,
            scoped=scoped,
            purpose=purpose,
            metadata=metadata,
        )

    def decrypt_json(
        self,
        token: str,
        *,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        role: Optional[str] = None,
        request_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        scoped: bool = False,
        purpose: str = "json",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Decrypt token and parse JSON payload.
        """
        decrypted = self.decrypt_bytes(
            token,
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            request_id=request_id,
            trace_id=trace_id,
            scoped=scoped,
            purpose=purpose,
            metadata=metadata,
        )

        if not decrypted.get("success"):
            return decrypted

        try:
            plaintext_bytes = decrypted.get("data", {}).get("plaintext_bytes")
            if not isinstance(plaintext_bytes, bytes):
                return self._error_result(
                    message="Decrypted JSON payload was not bytes.",
                    error="INVALID_DECRYPTED_PAYLOAD",
                    metadata=decrypted.get("metadata", {}),
                )

            parsed = json.loads(plaintext_bytes.decode("utf-8"))

            data = dict(decrypted.get("data", {}))
            data.pop("plaintext_bytes", None)
            data["payload"] = parsed

            return self._safe_result(
                success=True,
                message="JSON decrypted successfully.",
                data=data,
                metadata=decrypted.get("metadata", {}),
            )

        except Exception as exc:
            return self._error_result(
                message="Decrypted payload is not valid JSON.",
                error=str(exc),
                metadata=decrypted.get("metadata", {}),
            )

    # ------------------------------------------------------------------
    # Public API: key/hash helpers
    # ------------------------------------------------------------------

    def generate_key(
        self,
        *,
        as_env_value: bool = True,
        key_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Generate a new 256-bit encryption key.

        This returns the new key once so an admin can store it in a secure
        secret store. The key is not logged or audited raw.

        Args:
            as_env_value:
                If True, returns URL-safe base64 string suitable for env vars.
            key_id:
                Optional safe key id metadata.

        Returns:
            data["key"] contains the generated key. Handle it carefully.
        """
        started_at = time.time()

        if key_id is not None:
            validation = self._validate_key_id(key_id)
            if not validation["success"]:
                return validation

        raw_key = secrets.token_bytes(AES_256_KEY_LENGTH)
        key_value: Union[str, bytes]

        if as_env_value:
            key_value = self._b64e(raw_key)
        else:
            key_value = raw_key

        result = self._safe_result(
            success=True,
            message="Encryption key generated. Store it immediately in a secure secret store.",
            data={
                "key": key_value,
                "key_id": key_id or self._suggest_key_id(),
                "encoding": "base64url" if as_env_value else "bytes",
                "bytes": AES_256_KEY_LENGTH,
            },
            metadata={
                "duration_ms": self._duration_ms(started_at),
                "warning": "Generated key is returned once and must not be logged or committed.",
            },
        )

        self._log_audit_event(
            action="generate_key",
            context=EncryptionContext(scoped=False, purpose="key_generation"),
            outcome="success",
            payload={
                "key_id": key_id or "<generated>",
                "encoding": "base64url" if as_env_value else "bytes",
                "bytes": AES_256_KEY_LENGTH,
            },
        )

        return result

    def hash_value(
        self,
        value: Union[str, bytes],
        *,
        salt: Optional[Union[str, bytes]] = None,
        purpose: str = "general_hash",
    ) -> Dict[str, Any]:
        """
        Create a safe SHA-256 hash for lookup/deduplication.

        This is not password hashing. For passwords, use a dedicated password
        hashing algorithm such as Argon2id or bcrypt.
        """
        started_at = time.time()

        try:
            value_bytes = self._to_bytes(value, field_name="value")
            salt_bytes = self._to_bytes(salt or "", field_name="salt")

            digest = hashlib.sha256(
                b"william.hash.v1|" + purpose.encode("utf-8") + b"|" + salt_bytes + b"|" + value_bytes
            ).hexdigest()

            return self._safe_result(
                success=True,
                message="Value hashed successfully.",
                data={
                    "hash": digest,
                    "algorithm": "SHA-256",
                    "purpose": purpose,
                },
                metadata={
                    "duration_ms": self._duration_ms(started_at),
                    "value_size": len(value_bytes),
                    "salt_used": bool(salt),
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Hashing failed.",
                error=str(exc),
                metadata={"duration_ms": self._duration_ms(started_at)},
            )

    def verify_hash(
        self,
        value: Union[str, bytes],
        expected_hash: str,
        *,
        salt: Optional[Union[str, bytes]] = None,
        purpose: str = "general_hash",
    ) -> Dict[str, Any]:
        """
        Verify value against SHA-256 hash using constant-time comparison.
        """
        started_at = time.time()

        if not isinstance(expected_hash, str) or not expected_hash:
            return self._error_result(
                message="expected_hash must be a non-empty string.",
                error="INVALID_EXPECTED_HASH",
            )

        hashed = self.hash_value(value, salt=salt, purpose=purpose)
        if not hashed.get("success"):
            return hashed

        actual_hash = hashed.get("data", {}).get("hash")
        valid = hmac.compare_digest(str(actual_hash), expected_hash)

        return self._safe_result(
            success=True,
            message="Hash verification completed.",
            data={
                "valid": valid,
                "algorithm": "SHA-256",
                "purpose": purpose,
            },
            metadata={
                "duration_ms": self._duration_ms(started_at),
            },
        )

    def health_check(self) -> Dict[str, Any]:
        """
        Return safe health information for dashboard/API checks.
        """
        key_available = False
        key_source = KeySource.UNAVAILABLE.value

        try:
            context = EncryptionContext(scoped=False, purpose="health_check")
            key_result = self._resolve_key_material(context)
            key_available = bool(key_result.get("success"))
            if key_available:
                key_material = key_result.get("data", {}).get("key_material")
                if isinstance(key_material, EncryptionKeyMaterial):
                    key_source = key_material.source.value
        except Exception:
            key_available = False
            key_source = KeySource.UNAVAILABLE.value

        return self._safe_result(
            success=True,
            message="EncryptionManager health checked.",
            data={
                "module": self.module_name,
                "version": self.version,
                "algorithm": DEFAULT_ALGORITHM,
                "token_version": DEFAULT_VERSION,
                "cryptography_available": CRYPTOGRAPHY_AVAILABLE,
                "key_available": key_available,
                "key_source": key_source,
                "strict_scoped_context": self.strict_scoped_context,
            },
            metadata={
                "safe_for_dashboard": True,
                "values_included": False,
            },
        )

    async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        BaseAgent-compatible runner for MasterAgent/AgentRouter.

        Supported actions:
            - encrypt_text
            - decrypt_text
            - encrypt_bytes
            - decrypt_bytes
            - encrypt_json
            - decrypt_json
            - generate_key
            - hash_value
            - verify_hash
            - health_check
        """
        validation = self._validate_task_context(task)
        if not validation["success"]:
            return validation

        action = str(task.get("action") or "").strip()
        payload = task.get("payload") or {}

        if not isinstance(payload, dict):
            return self._error_result(
                message="Task payload must be a dictionary.",
                error="INVALID_TASK_PAYLOAD",
                metadata={"action": action},
            )

        try:
            if action == EncryptionAction.ENCRYPT_TEXT.value:
                return self.encrypt_text(**payload)

            if action == EncryptionAction.DECRYPT_TEXT.value:
                return self.decrypt_text(**payload)

            if action == EncryptionAction.ENCRYPT_BYTES.value:
                return self.encrypt_bytes(**payload)

            if action == EncryptionAction.DECRYPT_BYTES.value:
                return self.decrypt_bytes(**payload)

            if action == EncryptionAction.ENCRYPT_JSON.value:
                return self.encrypt_json(**payload)

            if action == EncryptionAction.DECRYPT_JSON.value:
                return self.decrypt_json(**payload)

            if action == EncryptionAction.GENERATE_KEY.value:
                return self.generate_key(**payload)

            if action == EncryptionAction.HASH_VALUE.value:
                return self.hash_value(**payload)

            if action == EncryptionAction.VERIFY_HASH.value:
                return self.verify_hash(**payload)

            if action == EncryptionAction.HEALTH_CHECK.value:
                return self.health_check()

            return self._error_result(
                message=f"Unsupported EncryptionManager action: {action}",
                error="UNSUPPORTED_ACTION",
                metadata={
                    "supported_actions": [item.value for item in EncryptionAction],
                },
            )

        except Exception as exc:
            logger.exception("EncryptionManager task execution failed.")
            return self._error_result(
                message="EncryptionManager task execution failed.",
                error=str(exc),
                metadata={"action": action},
            )

    # ------------------------------------------------------------------
    # William/Jarvis compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate task-level SaaS context.

        If scoped=True, user_id and workspace_id are mandatory. This prevents
        cross-user/workspace cryptographic misuse.
        """
        if not isinstance(task, dict):
            return self._error_result(
                message="Task context must be a dictionary.",
                error="INVALID_TASK_CONTEXT",
            )

        scoped = bool(task.get("scoped", False))
        user_id = task.get("user_id")
        workspace_id = task.get("workspace_id")

        payload = task.get("payload")
        if isinstance(payload, dict):
            scoped = bool(payload.get("scoped", scoped))
            user_id = payload.get("user_id", user_id)
            workspace_id = payload.get("workspace_id", workspace_id)

        if scoped and self.strict_scoped_context and not user_id:
            return self._error_result(
                message="user_id is required for scoped encryption operations.",
                error="MISSING_USER_ID",
                metadata={"scoped": scoped},
            )

        if scoped and self.strict_scoped_context and not workspace_id:
            return self._error_result(
                message="workspace_id is required for scoped encryption operations.",
                error="MISSING_WORKSPACE_ID",
                metadata={"scoped": scoped},
            )

        return self._safe_result(
            success=True,
            message="Task context validated.",
            data={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "scoped": scoped,
            },
            metadata={"validation": "passed"},
        )

    def _requires_security_check(self, action: str, context: EncryptionContext) -> bool:
        """
        All encryption/decryption actions are sensitive.

        A future Security Agent can enforce role policies, workspace policies,
        key access permissions, or decrypt restrictions here.
        """
        sensitive_actions = {
            "encrypt_text",
            "decrypt_text",
            "encrypt_bytes",
            "decrypt_bytes",
            "encrypt_json",
            "decrypt_json",
            "generate_key",
        }

        if context.scoped:
            return True

        return action in sensitive_actions

    def _request_security_approval(
        self,
        *,
        action: str,
        context: EncryptionContext,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Security Agent approval bridge.

        This local fallback denies invalid scoped operations and otherwise allows
        execution. In the full system, Security Agent can replace/wrap this hook.
        """
        denied = False
        reason = None

        if context.scoped and self.strict_scoped_context:
            if not context.user_id or not context.workspace_id:
                denied = True
                reason = "Scoped encryption operation missing user_id or workspace_id."

        if action.startswith("decrypt") and context.metadata.get("deny_decrypt") is True:
            denied = True
            reason = "Decrypt operation denied by request metadata policy."

        if denied:
            self._log_audit_event(
                action=action,
                context=context,
                outcome="security_denied",
                payload={
                    "reason": reason,
                    "safe_payload": self._sanitize_for_audit(payload),
                },
            )
            return self._error_result(
                message="Security approval denied.",
                error="SECURITY_APPROVAL_DENIED",
                metadata={
                    "action": action,
                    "reason": reason,
                },
            )

        return self._safe_result(
            success=True,
            message="Security approval granted.",
            data={
                "approved": True,
                "action": action,
            },
            metadata={
                "security_agent_available": False,
                "approval_mode": "local_policy_fallback",
            },
        )

    def _prepare_verification_payload(
        self,
        *,
        action: str,
        context: EncryptionContext,
        success: bool,
        data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare a Verification Agent-safe payload.

        Does not include raw plaintext, ciphertext, tokens, or keys.
        """
        return {
            "module": self.module_name,
            "agent": self.registry_name,
            "action": action,
            "success": success,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "trace_id": context.trace_id,
            "purpose": context.purpose,
            "scoped": context.scoped,
            "timestamp": self._now(),
            "data": self._sanitize_for_audit(data),
        }

    def _prepare_memory_payload(
        self,
        *,
        action: str,
        context: EncryptionContext,
        data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent-compatible safe context.

        No plaintext, ciphertext, tokens, or keys are included.
        """
        return {
            "memory_type": "security_encryption_event",
            "module": self.module_name,
            "action": action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "purpose": context.purpose,
            "scoped": context.scoped,
            "timestamp": self._now(),
            "safe_summary": {
                "algorithm": data.get("algorithm"),
                "key_id": data.get("key_id"),
                "plaintext_size": data.get("plaintext_size"),
                "token_size": data.get("token_size"),
            },
            "contains_plaintext": False,
            "contains_ciphertext": False,
            "contains_key": False,
        }

    def _emit_agent_event(self, event_type: str, payload: Dict[str, Any]) -> None:
        """
        Emit safe event for future dashboard/event bus integration.
        """
        event = {
            "event_type": event_type,
            "module": self.module_name,
            "agent": self.registry_name,
            "timestamp": self._now(),
            "payload": self._sanitize_for_audit(payload),
        }

        if self.event_sink:
            try:
                self.event_sink(event)
            except Exception:
                logger.exception("EncryptionManager event sink failed.")
        else:
            logger.debug("EncryptionManager event: %s", event)

    def _log_audit_event(
        self,
        *,
        action: str,
        context: EncryptionContext,
        outcome: str,
        payload: Dict[str, Any],
    ) -> None:
        """
        Log safe audit event.

        Raw plaintext, ciphertext, tokens, and keys are stripped/masked.
        """
        audit_event = {
            "module": self.module_name,
            "agent": self.registry_name,
            "action": action,
            "outcome": outcome,
            "timestamp": self._now(),
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "role": context.role,
            "request_id": context.request_id,
            "trace_id": context.trace_id,
            "purpose": context.purpose,
            "scoped": context.scoped,
            "payload": self._sanitize_for_audit(payload),
        }

        if self.audit_sink:
            try:
                self.audit_sink(audit_event)
            except Exception:
                logger.exception("EncryptionManager audit sink failed.")
        else:
            logger.info("EncryptionManager audit event: %s", audit_event)

    def _safe_result(
        self,
        *,
        success: bool,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        error: Optional[Union[str, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard William/Jarvis result shape.
        """
        return {
            "success": bool(success),
            "message": message,
            "data": data or {},
            "error": error,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        *,
        message: str,
        error: Union[str, Dict[str, Any], Exception],
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard William/Jarvis error shape.
        """
        return self._safe_result(
            success=False,
            message=message,
            data=data or {},
            error=str(error),
            metadata=metadata or {},
        )

    # ------------------------------------------------------------------
    # Validation helpers
    # ------------------------------------------------------------------

    def _validate_encrypt_request(
        self,
        plaintext: bytes,
        context: EncryptionContext,
    ) -> Dict[str, Any]:
        if not isinstance(plaintext, bytes):
            return self._error_result(
                message="Plaintext must be bytes.",
                error="INVALID_PLAINTEXT_TYPE",
            )

        if len(plaintext) == 0:
            return self._error_result(
                message="Plaintext cannot be empty.",
                error="EMPTY_PLAINTEXT",
            )

        if len(plaintext) > MAX_PLAINTEXT_BYTES:
            return self._error_result(
                message="Plaintext exceeds maximum allowed size.",
                error="PLAINTEXT_TOO_LARGE",
                metadata={
                    "max_bytes": MAX_PLAINTEXT_BYTES,
                    "actual_bytes": len(plaintext),
                },
            )

        return self._validate_context(context)

    def _validate_decrypt_request(
        self,
        token: str,
        context: EncryptionContext,
    ) -> Dict[str, Any]:
        if not isinstance(token, str):
            return self._error_result(
                message="Token must be a string.",
                error="INVALID_TOKEN_TYPE",
            )

        if not token.strip():
            return self._error_result(
                message="Token cannot be empty.",
                error="EMPTY_TOKEN",
            )

        if len(token.encode("utf-8")) > MAX_TOKEN_BYTES:
            return self._error_result(
                message="Token exceeds maximum allowed size.",
                error="TOKEN_TOO_LARGE",
                metadata={
                    "max_bytes": MAX_TOKEN_BYTES,
                    "actual_bytes": len(token.encode("utf-8")),
                },
            )

        return self._validate_context(context)

    def _validate_context(self, context: EncryptionContext) -> Dict[str, Any]:
        if context.scoped and self.strict_scoped_context:
            if not context.user_id:
                return self._error_result(
                    message="user_id is required for scoped encryption.",
                    error="MISSING_USER_ID",
                    metadata={"scoped": context.scoped},
                )

            if not context.workspace_id:
                return self._error_result(
                    message="workspace_id is required for scoped encryption.",
                    error="MISSING_WORKSPACE_ID",
                    metadata={"scoped": context.scoped},
                )

        if not isinstance(context.purpose, str) or not context.purpose.strip():
            return self._error_result(
                message="Encryption purpose must be a non-empty string.",
                error="INVALID_PURPOSE",
            )

        if len(context.purpose) > 128:
            return self._error_result(
                message="Encryption purpose is too long.",
                error="PURPOSE_TOO_LONG",
                metadata={"max_length": 128},
            )

        return self._safe_result(
            success=True,
            message="Encryption context validated.",
            data={
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
                "scoped": context.scoped,
                "purpose": context.purpose,
            },
        )

    def _validate_key_id(self, key_id: str) -> Dict[str, Any]:
        if not isinstance(key_id, str) or not key_id.strip():
            return self._error_result(
                message="key_id must be a non-empty string.",
                error="INVALID_KEY_ID",
            )

        if not SAFE_KEY_ID_PATTERN.match(key_id):
            return self._error_result(
                message="key_id contains unsupported characters.",
                error="INVALID_KEY_ID_FORMAT",
                metadata={"allowed_pattern": SAFE_KEY_ID_PATTERN.pattern},
            )

        return self._safe_result(
            success=True,
            message="key_id validated.",
            data={"key_id": key_id},
        )

    # ------------------------------------------------------------------
    # Key handling
    # ------------------------------------------------------------------

    def _resolve_key_material(
        self,
        context: EncryptionContext,
        *,
        expected_key_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Resolve encryption master key from safe sources.

        Priority:
            1. Direct key_provider callback
            2. SecretsManager
            3. Environment variable, if enabled

        Raw key value is never logged or returned outside internal data object.
        """
        with self._lock:
            if self.key_provider is not None:
                try:
                    provided = self.key_provider(context)
                    if provided:
                        key_bytes = self._normalize_key_material(provided)
                        key_id = expected_key_id or self._resolve_key_id(context)
                        validation = self._validate_key_id(key_id)
                        if not validation["success"]:
                            return validation

                        return self._safe_result(
                            success=True,
                            message="Encryption key resolved from direct provider.",
                            data={
                                "key_material": EncryptionKeyMaterial(
                                    key_bytes=key_bytes,
                                    key_id=key_id,
                                    source=KeySource.DIRECT_PROVIDER,
                                )
                            },
                            metadata={"key_source": KeySource.DIRECT_PROVIDER.value},
                        )
                except Exception as exc:
                    return self._error_result(
                        message="Direct key provider failed.",
                        error=str(exc),
                        metadata={"key_source": KeySource.DIRECT_PROVIDER.value},
                    )

            if self.secrets_manager is not None:
                try:
                    secret_result = self.secrets_manager.get_secret(
                        self.key_env_name,
                        user_id=context.user_id,
                        workspace_id=context.workspace_id,
                        role=context.role,
                        request_id=context.request_id,
                        trace_id=context.trace_id,
                        scoped=False,
                        required=False,
                        include_value=True,
                    )

                    if secret_result.get("success") and secret_result.get("data", {}).get("found"):
                        secret_value = secret_result.get("data", {}).get("value")
                        key_bytes = self._normalize_key_material(secret_value)
                        key_id = expected_key_id or self._resolve_key_id(context)

                        validation = self._validate_key_id(key_id)
                        if not validation["success"]:
                            return validation

                        return self._safe_result(
                            success=True,
                            message="Encryption key resolved from SecretsManager.",
                            data={
                                "key_material": EncryptionKeyMaterial(
                                    key_bytes=key_bytes,
                                    key_id=key_id,
                                    source=KeySource.SECRETS_MANAGER,
                                )
                            },
                            metadata={"key_source": KeySource.SECRETS_MANAGER.value},
                        )
                except Exception as exc:
                    return self._error_result(
                        message="SecretsManager key resolution failed.",
                        error=str(exc),
                        metadata={"key_source": KeySource.SECRETS_MANAGER.value},
                    )

            if self.allow_environment_key:
                env_value = os.environ.get(self.key_env_name)
                if env_value:
                    try:
                        key_bytes = self._normalize_key_material(env_value)
                        key_id = expected_key_id or self._resolve_key_id(context)

                        validation = self._validate_key_id(key_id)
                        if not validation["success"]:
                            return validation

                        return self._safe_result(
                            success=True,
                            message="Encryption key resolved from environment.",
                            data={
                                "key_material": EncryptionKeyMaterial(
                                    key_bytes=key_bytes,
                                    key_id=key_id,
                                    source=KeySource.ENVIRONMENT,
                                )
                            },
                            metadata={"key_source": KeySource.ENVIRONMENT.value},
                        )
                    except Exception as exc:
                        return self._error_result(
                            message="Environment encryption key is invalid.",
                            error=str(exc),
                            metadata={"key_env_name": self.key_env_name},
                        )

        return self._error_result(
            message="Encryption key is not configured.",
            error="ENCRYPTION_KEY_NOT_CONFIGURED",
            metadata={
                "key_env_name": self.key_env_name,
                "has_secrets_manager": self.secrets_manager is not None,
                "has_key_provider": self.key_provider is not None,
                "allow_environment_key": self.allow_environment_key,
            },
        )

    def _resolve_key_id(self, context: EncryptionContext) -> str:
        """
        Resolve non-secret key id.

        key_id is metadata, not secret material.
        """
        if self.secrets_manager is not None:
            try:
                result = self.secrets_manager.get_secret(
                    self.key_id_env_name,
                    user_id=context.user_id,
                    workspace_id=context.workspace_id,
                    role=context.role,
                    request_id=context.request_id,
                    trace_id=context.trace_id,
                    scoped=False,
                    required=False,
                    include_value=True,
                )
                if result.get("success") and result.get("data", {}).get("found"):
                    value = str(result.get("data", {}).get("value") or "").strip()
                    if value:
                        return value
            except Exception:
                logger.debug("SecretsManager key_id lookup skipped.", exc_info=True)

        env_key_id = os.environ.get(self.key_id_env_name)
        if env_key_id:
            return env_key_id.strip()

        return self.default_key_id

    def _normalize_key_material(self, value: Union[str, bytes, None]) -> bytes:
        """
        Convert configured key material into exactly 32 bytes.

        Accepts:
            - base64url/base64 encoded 32-byte key
            - raw 32+ byte string/bytes

        If raw material is longer than 32 bytes, SHA-256 is used to normalize it.
        If raw material is shorter than 32 bytes, it is rejected.
        """
        if value is None:
            raise ValueError("Encryption key is empty.")

        if isinstance(value, bytes):
            raw = value
        elif isinstance(value, str):
            clean = value.strip()
            if not clean:
                raise ValueError("Encryption key is empty.")

            raw = self._try_decode_base64_key(clean)
            if raw is None:
                raw = clean.encode("utf-8")
        else:
            raise TypeError("Encryption key must be string or bytes.")

        if len(raw) == AES_256_KEY_LENGTH:
            return raw

        if len(raw) < MIN_MASTER_KEY_LENGTH:
            raise ValueError(
                f"Encryption key must be at least {MIN_MASTER_KEY_LENGTH} bytes after decoding."
            )

        return hashlib.sha256(raw).digest()

    def _try_decode_base64_key(self, value: str) -> Optional[bytes]:
        candidates = [value]

        padding_needed = (-len(value)) % 4
        if padding_needed:
            candidates.append(value + ("=" * padding_needed))

        for candidate in candidates:
            try:
                decoded = base64.urlsafe_b64decode(candidate.encode("utf-8"))
                if len(decoded) >= MIN_MASTER_KEY_LENGTH:
                    return decoded
            except Exception:
                pass

            try:
                decoded = base64.b64decode(candidate.encode("utf-8"))
                if len(decoded) >= MIN_MASTER_KEY_LENGTH:
                    return decoded
            except Exception:
                pass

        return None

    def _derive_scoped_key(
        self,
        master_key: bytes,
        context: EncryptionContext,
        key_id: str,
    ) -> bytes:
        """
        Derive a per-context AES-256 key from master key.

        Even if the same master key is used globally, encryption keys differ by
        workspace/user/purpose/key_id where scoped context is used.
        """
        if not CRYPTOGRAPHY_AVAILABLE:
            raise RuntimeError("cryptography is not available.")

        salt_material = {
            "version": DEFAULT_VERSION,
            "algorithm": DEFAULT_ALGORITHM,
            "key_id": key_id,
            "user_id": context.user_id if context.scoped else None,
            "workspace_id": context.workspace_id if context.scoped else None,
            "purpose": context.purpose,
            "scoped": context.scoped,
        }

        salt = hashlib.sha256(
            json.dumps(salt_material, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).digest()

        info = f"{self.module_name}|{DEFAULT_ALGORITHM}|{context.purpose}|{key_id}".encode("utf-8")

        hkdf = HKDF(  # type: ignore[operator]
            algorithm=SHA256(),  # type: ignore[operator]
            length=AES_256_KEY_LENGTH,
            salt=salt,
            info=info,
        )

        return hkdf.derive(master_key)

    # ------------------------------------------------------------------
    # Envelope/AAD helpers
    # ------------------------------------------------------------------

    def _build_aad(self, context: EncryptionContext, key_id: str) -> bytes:
        """
        Build authenticated additional data.

        This is not secret, but it is integrity-protected by AES-GCM.
        """
        aad = {
            "version": DEFAULT_VERSION,
            "algorithm": DEFAULT_ALGORITHM,
            "key_id": key_id,
            "user_id": context.user_id if context.scoped else None,
            "workspace_id": context.workspace_id if context.scoped else None,
            "purpose": context.purpose,
            "scoped": context.scoped,
        }

        return json.dumps(aad, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _encode_envelope(self, envelope: EncryptionEnvelope) -> str:
        payload = {
            "version": envelope.version,
            "algorithm": envelope.algorithm,
            "key_id": envelope.key_id,
            "nonce": envelope.nonce,
            "ciphertext": envelope.ciphertext,
            "aad_hash": envelope.aad_hash,
            "created_at": envelope.created_at,
        }

        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return self._b64e(raw)

    def _decode_envelope(self, token: str) -> EncryptionEnvelope:
        try:
            raw = self._b64d(token)
            parsed = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise ValueError("Invalid encrypted token format.") from exc

        required_fields = {
            "version",
            "algorithm",
            "key_id",
            "nonce",
            "ciphertext",
            "aad_hash",
            "created_at",
        }

        missing = sorted(required_fields - set(parsed.keys()))
        if missing:
            raise ValueError(f"Encrypted token missing required fields: {missing}")

        return EncryptionEnvelope(
            version=str(parsed["version"]),
            algorithm=str(parsed["algorithm"]),
            key_id=str(parsed["key_id"]),
            nonce=str(parsed["nonce"]),
            ciphertext=str(parsed["ciphertext"]),
            aad_hash=str(parsed["aad_hash"]),
            created_at=str(parsed["created_at"]),
        )

    # ------------------------------------------------------------------
    # Encoding/hash helpers
    # ------------------------------------------------------------------

    def _b64e(self, value: bytes) -> str:
        return base64.urlsafe_b64encode(value).decode("utf-8").rstrip("=")

    def _b64d(self, value: str) -> bytes:
        clean = value.strip()
        padding = "=" * ((4 - len(clean) % 4) % 4)
        return base64.urlsafe_b64decode((clean + padding).encode("utf-8"))

    def _hash_bytes(self, value: bytes) -> str:
        return hashlib.sha256(value).hexdigest()

    def _to_bytes(self, value: Union[str, bytes], *, field_name: str) -> bytes:
        if isinstance(value, bytes):
            return value

        if isinstance(value, str):
            return value.encode("utf-8")

        raise TypeError(f"{field_name} must be string or bytes.")

    def _suggest_key_id(self) -> str:
        return f"william-key-{time.strftime('%Y%m%d%H%M%S', time.gmtime())}"

    # ------------------------------------------------------------------
    # Sanitization/logging helpers
    # ------------------------------------------------------------------

    def _sanitize_for_audit(self, payload: Any) -> Any:
        """
        Recursively sanitize payloads before logs/audit/events.

        Raw plaintext/ciphertext/token/key values are masked.
        """
        if isinstance(payload, dict):
            sanitized: Dict[str, Any] = {}
            for key, value in payload.items():
                key_str = str(key)
                if self._looks_sensitive(key_str):
                    sanitized[key_str] = self._mask_value(value)
                else:
                    sanitized[key_str] = self._sanitize_for_audit(value)
            return sanitized

        if isinstance(payload, list):
            return [self._sanitize_for_audit(item) for item in payload]

        if isinstance(payload, tuple):
            return tuple(self._sanitize_for_audit(item) for item in payload)

        if isinstance(payload, bytes):
            return f"<bytes:{len(payload)}>"

        return payload

    def _looks_sensitive(self, key: str) -> bool:
        upper = key.upper()
        return any(hint in upper for hint in SENSITIVE_NAME_HINTS) or upper in {
            "VALUE",
            "PLAINTEXT",
            "PLAINTEXT_BYTES",
            "CIPHERTEXT",
            "TOKEN",
            "KEY",
            "KEY_BYTES",
            "KEY_MATERIAL",
        }

    def _mask_value(self, value: Any) -> str:
        if value is None:
            return "<none>"

        if isinstance(value, bytes):
            return f"<masked-bytes:{len(value)}>"

        text = str(value)
        if not text:
            return ""

        if len(text) <= 8:
            return "*" * min(max(len(text), 3), 12)

        return text[:2] + ("*" * min(max(len(text) - 4, 4), 24)) + text[-2:]

    def _duration_ms(self, started_at: float) -> int:
        return int((time.time() - started_at) * 1000)

    def _now(self) -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ---------------------------------------------------------------------------
# Convenience singleton helpers.
# ---------------------------------------------------------------------------

_DEFAULT_MANAGER_LOCK = threading.RLock()
_DEFAULT_MANAGER: Optional[EncryptionManager] = None


def get_default_encryption_manager() -> EncryptionManager:
    """
    Return a process-local default EncryptionManager instance.
    """
    global _DEFAULT_MANAGER

    with _DEFAULT_MANAGER_LOCK:
        if _DEFAULT_MANAGER is None:
            _DEFAULT_MANAGER = EncryptionManager()
        return _DEFAULT_MANAGER


def encrypt_text(plaintext: str, **kwargs: Any) -> Dict[str, Any]:
    """
    Convenience wrapper around the default manager.
    """
    return get_default_encryption_manager().encrypt_text(plaintext, **kwargs)


def decrypt_text(token: str, **kwargs: Any) -> Dict[str, Any]:
    """
    Convenience wrapper around the default manager.
    """
    return get_default_encryption_manager().decrypt_text(token, **kwargs)


def encrypt_json(payload: Union[Dict[str, Any], list], **kwargs: Any) -> Dict[str, Any]:
    """
    Convenience wrapper around the default manager.
    """
    return get_default_encryption_manager().encrypt_json(payload, **kwargs)


def decrypt_json(token: str, **kwargs: Any) -> Dict[str, Any]:
    """
    Convenience wrapper around the default manager.
    """
    return get_default_encryption_manager().decrypt_json(token, **kwargs)


__all__ = [
    "EncryptionManager",
    "EncryptionContext",
    "EncryptionEnvelope",
    "EncryptionKeyMaterial",
    "EncryptionAction",
    "EncryptionSensitivity",
    "KeySource",
    "get_default_encryption_manager",
    "encrypt_text",
    "decrypt_text",
    "encrypt_json",
    "decrypt_json",
]