"""
security/secrets_manager.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix

Purpose:
    Reads secrets from environment variables and optional secret stores safely.
    This file never hardcodes secret values and never logs raw secrets.

Architecture Compatibility:
    - Master Agent / Agent Router:
        Provides stable public methods and structured dict results.
    - Security Agent:
        Sensitive operations are identified through _requires_security_check()
        and routed through _request_security_approval().
    - Verification Agent:
        Every completed public action can prepare a verification payload.
    - Memory Agent:
        Only non-sensitive context is prepared for memory compatibility.
    - Dashboard / API:
        All results follow success/message/data/error/metadata shape.
    - SaaS Isolation:
        Every user/workspace scoped operation validates user_id and workspace_id.
    - Agent Registry / Loader:
        Safe to import even if BaseAgent or other William modules do not exist yet.

Important:
    This manager may return a secret value to trusted internal callers through
    get_secret()/require_secret(). It never logs raw values, never includes them
    in audit payloads, and never stores them in memory payloads.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Optional William/Jarvis imports with safe fallbacks.
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for early project stages
    class BaseAgent:  # type: ignore
        """
        Minimal fallback BaseAgent so this file is import-safe before the full
        William/Jarvis agent framework exists.
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


# ---------------------------------------------------------------------------
# Logging setup.
# ---------------------------------------------------------------------------

logger = logging.getLogger("william.security.secrets_manager")
logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Constants and safe patterns.
# ---------------------------------------------------------------------------

SECRET_KEY_PATTERN = re.compile(r"^[A-Z0-9_][A-Z0-9_\-./:]{0,255}$", re.IGNORECASE)

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
    "WEBHOOK",
)

DEFAULT_ALLOWED_FILE_SUFFIXES = {".json", ".env"}

DEFAULT_ENV_PREFIXES = (
    "WILLIAM_",
    "JARVIS_",
    "DIGITAL_PROMOTIX_",
    "DP_",
)

DEFAULT_CACHE_TTL_SECONDS = 300


# ---------------------------------------------------------------------------
# Enums and data structures.
# ---------------------------------------------------------------------------

class SecretSource(str, Enum):
    """Supported secret sources."""

    ENVIRONMENT = "environment"
    FILE = "file"
    RUNTIME = "runtime"
    EXTERNAL_PROVIDER = "external_provider"


class SecretSensitivity(str, Enum):
    """Sensitivity levels for audit/dashboard metadata."""

    LOW = "low"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class SecretsContext:
    """
    SaaS-safe context for secret operations.

    user_id/workspace_id are optional for truly global system secrets, but when
    scoped=True they are required to prevent cross-user/workspace leakage.
    """

    user_id: Optional[str] = None
    workspace_id: Optional[str] = None
    role: Optional[str] = None
    request_id: Optional[str] = None
    trace_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    scoped: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SecretLookupRequest:
    """A normalized request for looking up one secret."""

    key: str
    context: SecretsContext = field(default_factory=SecretsContext)
    required: bool = False
    default: Optional[str] = None
    allow_file: bool = True
    allow_environment: bool = True
    allow_runtime: bool = True
    allow_external_provider: bool = True
    scoped: bool = False
    include_value: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SecretRecord:
    """
    Internal representation of a resolved secret.

    value is intentionally not displayed in repr to avoid accidental leaks.
    """

    key: str
    value: Optional[str]
    source: Optional[SecretSource]
    found: bool
    masked_value: Optional[str]
    sensitivity: SecretSensitivity
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        return (
            "SecretRecord("
            f"key={self.key!r}, "
            f"value=<masked>, "
            f"source={self.source!r}, "
            f"found={self.found!r}, "
            f"masked_value={self.masked_value!r}, "
            f"sensitivity={self.sensitivity!r}, "
            f"metadata={self.metadata!r}"
            ")"
        )


@dataclass
class CacheEntry:
    """Internal cache entry with expiration."""

    value: Optional[str]
    source: Optional[SecretSource]
    created_at: float
    expires_at: float
    metadata: Dict[str, Any] = field(default_factory=dict)


ExternalSecretProvider = Callable[[str, SecretsContext], Optional[str]]
AuditSink = Callable[[Dict[str, Any]], None]
EventSink = Callable[[Dict[str, Any]], None]


# ---------------------------------------------------------------------------
# SecretsManager
# ---------------------------------------------------------------------------

class SecretsManager(BaseAgent):
    """
    Production-safe secret manager for William/Jarvis.

    Responsibilities:
        - Read secrets from environment variables.
        - Read secrets from optional local secret files.
        - Read secrets from optional external provider callbacks.
        - Support runtime-only overrides for tests/local development.
        - Validate SaaS user/workspace context for scoped secret operations.
        - Never hardcode secret values.
        - Never log raw secret values.
        - Return structured result dictionaries.

    Public Methods:
        - get_secret()
        - require_secret()
        - get_many()
        - has_secret()
        - register_external_provider()
        - set_runtime_secret()
        - delete_runtime_secret()
        - clear_cache()
        - load_secret_file()
        - mask_secret()
        - list_configured_keys()
        - health_check()
    """

    module_name = "security.secrets_manager"
    agent_type = "security_utility"
    registry_name = "SecretsManager"
    version = "1.0.0"

    def __init__(
        self,
        *,
        env_prefixes: Optional[Iterable[str]] = None,
        secret_file_paths: Optional[Iterable[Union[str, Path]]] = None,
        external_providers: Optional[Mapping[str, ExternalSecretProvider]] = None,
        cache_enabled: bool = True,
        cache_ttl_seconds: int = DEFAULT_CACHE_TTL_SECONDS,
        allow_unprefixed_env: bool = True,
        audit_sink: Optional[AuditSink] = None,
        event_sink: Optional[EventSink] = None,
        strict_key_validation: bool = True,
        agent_name: str = "SecretsManager",
    ) -> None:
        super().__init__(agent_name=agent_name)

        self.env_prefixes: Tuple[str, ...] = tuple(env_prefixes or DEFAULT_ENV_PREFIXES)
        self.secret_file_paths: List[Path] = [Path(p).expanduser() for p in (secret_file_paths or [])]
        self.external_providers: Dict[str, ExternalSecretProvider] = dict(external_providers or {})
        self.cache_enabled = bool(cache_enabled)
        self.cache_ttl_seconds = max(0, int(cache_ttl_seconds))
        self.allow_unprefixed_env = bool(allow_unprefixed_env)
        self.audit_sink = audit_sink
        self.event_sink = event_sink
        self.strict_key_validation = bool(strict_key_validation)

        self._lock = threading.RLock()
        self._runtime_secrets: Dict[str, str] = {}
        self._file_secrets: Dict[str, str] = {}
        self._cache: Dict[str, CacheEntry] = {}
        self._loaded_files: List[str] = []

        for path in self.secret_file_paths:
            result = self.load_secret_file(path)
            if not result.get("success"):
                logger.warning(
                    "Secret file load skipped: %s",
                    result.get("error") or result.get("message"),
                )

        self._emit_agent_event(
            event_type="secrets_manager_initialized",
            payload={
                "module": self.module_name,
                "cache_enabled": self.cache_enabled,
                "cache_ttl_seconds": self.cache_ttl_seconds,
                "env_prefixes": list(self.env_prefixes),
                "secret_file_count": len(self.secret_file_paths),
                "external_provider_count": len(self.external_providers),
            },
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_secret(
        self,
        key: str,
        *,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        role: Optional[str] = None,
        request_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        scoped: bool = False,
        default: Optional[str] = None,
        required: bool = False,
        allow_file: bool = True,
        allow_environment: bool = True,
        allow_runtime: bool = True,
        allow_external_provider: bool = True,
        include_value: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Resolve a secret by key.

        Args:
            key:
                Secret key name. Example: OPENAI_API_KEY.
            user_id/workspace_id:
                Required when scoped=True.
            scoped:
                Enables SaaS isolation validation.
            default:
                Returned only when secret is not found and required=False.
            required:
                If True, missing secret returns success=False.
            include_value:
                Trusted internal callers may keep True. Dashboard/API status
                checks should pass False to avoid returning raw values.

        Returns:
            Structured dict with secret value only in data["value"] when
            include_value=True.
        """
        context = SecretsContext(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            request_id=request_id,
            trace_id=trace_id,
            scoped=scoped,
            metadata=metadata or {},
        )

        request = SecretLookupRequest(
            key=key,
            context=context,
            required=required,
            default=default,
            allow_file=allow_file,
            allow_environment=allow_environment,
            allow_runtime=allow_runtime,
            allow_external_provider=allow_external_provider,
            scoped=scoped,
            include_value=include_value,
            metadata=metadata or {},
        )

        validation = self._validate_lookup_request(request)
        if not validation["success"]:
            return validation

        if self._requires_security_check("get_secret", context):
            approval = self._request_security_approval(
                action="get_secret",
                context=context,
                payload={
                    "key": key,
                    "scoped": scoped,
                    "include_value": include_value,
                    "required": required,
                },
            )
            if not approval["success"]:
                return approval

        started_at = time.time()

        try:
            record = self._resolve_secret(request)

            if not record.found and default is not None:
                record = SecretRecord(
                    key=key,
                    value=default,
                    source=None,
                    found=True,
                    masked_value=self.mask_secret(default),
                    sensitivity=self._classify_sensitivity(key),
                    metadata={"used_default": True},
                )

            if required and not record.found:
                result = self._error_result(
                    message=f"Required secret '{key}' was not found.",
                    error="SECRET_NOT_FOUND",
                    metadata={
                        "key": key,
                        "found": False,
                        "required": True,
                        "source": None,
                        "duration_ms": self._duration_ms(started_at),
                    },
                )
                self._log_audit_event(
                    action="get_secret",
                    context=context,
                    outcome="missing_required_secret",
                    payload={
                        "key": key,
                        "found": False,
                        "required": True,
                    },
                )
                return result

            data: Dict[str, Any] = {
                "key": key,
                "found": record.found,
                "source": record.source.value if record.source else None,
                "masked_value": record.masked_value,
                "sensitivity": record.sensitivity.value,
            }

            if include_value:
                data["value"] = record.value

            verification_payload = self._prepare_verification_payload(
                action="get_secret",
                context=context,
                success=True,
                data={
                    "key": key,
                    "found": record.found,
                    "source": record.source.value if record.source else None,
                    "masked_value": record.masked_value,
                },
            )

            memory_payload = self._prepare_memory_payload(
                action="get_secret",
                context=context,
                data={
                    "key": key,
                    "found": record.found,
                    "source": record.source.value if record.source else None,
                },
            )

            result = self._safe_result(
                success=True,
                message="Secret resolved successfully." if record.found else "Secret was not found.",
                data=data,
                metadata={
                    "key": key,
                    "found": record.found,
                    "required": required,
                    "scoped": scoped,
                    "source": record.source.value if record.source else None,
                    "duration_ms": self._duration_ms(started_at),
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
            )

            self._log_audit_event(
                action="get_secret",
                context=context,
                outcome="success" if record.found else "not_found",
                payload={
                    "key": key,
                    "found": record.found,
                    "source": record.source.value if record.source else None,
                    "masked_value": record.masked_value,
                    "include_value": include_value,
                },
            )

            return result

        except Exception as exc:
            logger.exception("Secret resolution failed for key=%s", self._safe_key_for_log(key))
            return self._error_result(
                message="Secret resolution failed.",
                error=str(exc),
                metadata={
                    "key": self._safe_key_for_log(key),
                    "duration_ms": self._duration_ms(started_at),
                },
            )

    def require_secret(
        self,
        key: str,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Resolve a required secret.

        This is a convenience wrapper around get_secret(required=True).
        """
        kwargs["required"] = True
        return self.get_secret(key, **kwargs)

    def get_many(
        self,
        keys: Iterable[str],
        *,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        role: Optional[str] = None,
        request_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        scoped: bool = False,
        required: bool = False,
        include_values: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Resolve multiple secrets safely.

        Returns:
            data["secrets"] as a mapping of key -> resolved metadata/value.
            Missing required keys are listed under data["missing"].
        """
        started_at = time.time()
        key_list = list(keys or [])

        context = SecretsContext(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            request_id=request_id,
            trace_id=trace_id,
            scoped=scoped,
            metadata=metadata or {},
        )

        context_validation = self._validate_task_context(
            {
                "user_id": user_id,
                "workspace_id": workspace_id,
                "scoped": scoped,
                "operation": "get_many",
            }
        )
        if not context_validation["success"]:
            return context_validation

        if not key_list:
            return self._error_result(
                message="No secret keys were provided.",
                error="NO_KEYS_PROVIDED",
                metadata={"duration_ms": self._duration_ms(started_at)},
            )

        if self._requires_security_check("get_many", context):
            approval = self._request_security_approval(
                action="get_many",
                context=context,
                payload={
                    "key_count": len(key_list),
                    "scoped": scoped,
                    "include_values": include_values,
                },
            )
            if not approval["success"]:
                return approval

        resolved: Dict[str, Any] = {}
        missing: List[str] = []
        errors: Dict[str, str] = {}

        for key in key_list:
            item = self.get_secret(
                key,
                user_id=user_id,
                workspace_id=workspace_id,
                role=role,
                request_id=request_id,
                trace_id=trace_id,
                scoped=scoped,
                required=False,
                include_value=include_values,
                metadata=metadata,
            )

            if not item.get("success"):
                errors[key] = str(item.get("error") or item.get("message"))
                if required:
                    missing.append(key)
                continue

            item_data = item.get("data", {})
            if not item_data.get("found"):
                missing.append(key)

            resolved[key] = item_data

        success = not (required and missing) and not errors

        result = self._safe_result(
            success=success,
            message=(
                "Secrets resolved successfully."
                if success
                else "One or more secrets could not be resolved."
            ),
            data={
                "secrets": resolved,
                "missing": missing,
                "errors": errors,
            },
            metadata={
                "requested_count": len(key_list),
                "resolved_count": len([k for k, v in resolved.items() if v.get("found")]),
                "missing_count": len(missing),
                "error_count": len(errors),
                "scoped": scoped,
                "duration_ms": self._duration_ms(started_at),
            },
            error=None if success else "SECRETS_MISSING_OR_FAILED",
        )

        self._log_audit_event(
            action="get_many",
            context=context,
            outcome="success" if success else "partial_or_failed",
            payload={
                "requested_count": len(key_list),
                "missing": missing,
                "error_keys": list(errors.keys()),
                "include_values": include_values,
            },
        )

        return result

    def has_secret(
        self,
        key: str,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Check if a secret exists without returning the raw value.
        """
        kwargs["include_value"] = False
        kwargs["required"] = False
        result = self.get_secret(key, **kwargs)
        if not result.get("success"):
            return result

        data = result.get("data", {})
        return self._safe_result(
            success=True,
            message="Secret availability checked.",
            data={
                "key": key,
                "exists": bool(data.get("found")),
                "source": data.get("source"),
                "masked_value": data.get("masked_value"),
            },
            metadata=result.get("metadata", {}),
        )

    def set_runtime_secret(
        self,
        key: str,
        value: str,
        *,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        role: Optional[str] = None,
        request_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        scoped: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Set a runtime-only secret.

        This does not write to disk, environment variables, or external stores.
        Useful for tests, local dev, worker bootstrapping, and temporary session
        configuration.
        """
        started_at = time.time()
        context = SecretsContext(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            request_id=request_id,
            trace_id=trace_id,
            scoped=scoped,
            metadata=metadata or {},
        )

        validation = self._validate_key_value(key, value, scoped=scoped, context=context)
        if not validation["success"]:
            return validation

        if self._requires_security_check("set_runtime_secret", context):
            approval = self._request_security_approval(
                action="set_runtime_secret",
                context=context,
                payload={
                    "key": key,
                    "scoped": scoped,
                    "masked_value": self.mask_secret(value),
                },
            )
            if not approval["success"]:
                return approval

        runtime_key = self._scoped_key(key, context) if scoped else key

        with self._lock:
            self._runtime_secrets[runtime_key] = value
            self._invalidate_cache_for_key(runtime_key)

        result = self._safe_result(
            success=True,
            message="Runtime secret set successfully.",
            data={
                "key": key,
                "scoped_key": runtime_key,
                "source": SecretSource.RUNTIME.value,
                "masked_value": self.mask_secret(value),
            },
            metadata={
                "scoped": scoped,
                "duration_ms": self._duration_ms(started_at),
            },
        )

        self._log_audit_event(
            action="set_runtime_secret",
            context=context,
            outcome="success",
            payload={
                "key": key,
                "scoped_key": runtime_key,
                "masked_value": self.mask_secret(value),
            },
        )

        return result

    def delete_runtime_secret(
        self,
        key: str,
        *,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        role: Optional[str] = None,
        request_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        scoped: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Delete a runtime-only secret from memory.
        """
        started_at = time.time()
        context = SecretsContext(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            request_id=request_id,
            trace_id=trace_id,
            scoped=scoped,
            metadata=metadata or {},
        )

        validation = self._validate_secret_key(key)
        if not validation["success"]:
            return validation

        context_validation = self._validate_task_context(
            {
                "user_id": user_id,
                "workspace_id": workspace_id,
                "scoped": scoped,
                "operation": "delete_runtime_secret",
            }
        )
        if not context_validation["success"]:
            return context_validation

        if self._requires_security_check("delete_runtime_secret", context):
            approval = self._request_security_approval(
                action="delete_runtime_secret",
                context=context,
                payload={"key": key, "scoped": scoped},
            )
            if not approval["success"]:
                return approval

        runtime_key = self._scoped_key(key, context) if scoped else key

        with self._lock:
            existed = runtime_key in self._runtime_secrets
            self._runtime_secrets.pop(runtime_key, None)
            self._invalidate_cache_for_key(runtime_key)

        result = self._safe_result(
            success=True,
            message="Runtime secret deleted." if existed else "Runtime secret was not present.",
            data={
                "key": key,
                "scoped_key": runtime_key,
                "deleted": existed,
            },
            metadata={
                "scoped": scoped,
                "duration_ms": self._duration_ms(started_at),
            },
        )

        self._log_audit_event(
            action="delete_runtime_secret",
            context=context,
            outcome="success",
            payload={
                "key": key,
                "scoped_key": runtime_key,
                "deleted": existed,
            },
        )

        return result

    def register_external_provider(
        self,
        name: str,
        provider: ExternalSecretProvider,
        *,
        overwrite: bool = False,
    ) -> Dict[str, Any]:
        """
        Register an external secret provider callback.

        Provider signature:
            provider(secret_key: str, context: SecretsContext) -> Optional[str]

        This allows future integration with AWS Secrets Manager, Azure Key Vault,
        HashiCorp Vault, GCP Secret Manager, Doppler, 1Password, etc., without
        coupling this file to any vendor SDK.
        """
        started_at = time.time()

        if not name or not isinstance(name, str):
            return self._error_result(
                message="Provider name must be a non-empty string.",
                error="INVALID_PROVIDER_NAME",
            )

        if not callable(provider):
            return self._error_result(
                message="Provider must be callable.",
                error="INVALID_PROVIDER_CALLBACK",
            )

        safe_name = name.strip()

        with self._lock:
            if safe_name in self.external_providers and not overwrite:
                return self._error_result(
                    message=f"External provider '{safe_name}' is already registered.",
                    error="PROVIDER_ALREADY_EXISTS",
                    metadata={"provider": safe_name},
                )
            self.external_providers[safe_name] = provider

        result = self._safe_result(
            success=True,
            message="External secret provider registered.",
            data={"provider": safe_name},
            metadata={
                "provider_count": len(self.external_providers),
                "duration_ms": self._duration_ms(started_at),
            },
        )

        self._emit_agent_event(
            event_type="external_secret_provider_registered",
            payload={"provider": safe_name},
        )

        return result

    def load_secret_file(self, path: Union[str, Path]) -> Dict[str, Any]:
        """
        Load secrets from a local JSON or .env style file.

        Supported formats:
            JSON:
                {
                    "OPENAI_API_KEY": "..."
                }

            .env:
                OPENAI_API_KEY=...
                # comments are ignored

        Notes:
            - Values are loaded into memory only.
            - Raw values are never logged.
            - File path is configurable; no secret file is hardcoded.
        """
        started_at = time.time()
        file_path = Path(path).expanduser()

        try:
            if not file_path.exists():
                return self._error_result(
                    message="Secret file does not exist.",
                    error="SECRET_FILE_NOT_FOUND",
                    metadata={"path": str(file_path)},
                )

            if not file_path.is_file():
                return self._error_result(
                    message="Secret path is not a file.",
                    error="SECRET_PATH_NOT_FILE",
                    metadata={"path": str(file_path)},
                )

            if file_path.suffix.lower() not in DEFAULT_ALLOWED_FILE_SUFFIXES:
                return self._error_result(
                    message="Unsupported secret file format.",
                    error="UNSUPPORTED_SECRET_FILE_FORMAT",
                    metadata={
                        "path": str(file_path),
                        "allowed_suffixes": sorted(DEFAULT_ALLOWED_FILE_SUFFIXES),
                    },
                )

            loaded: Dict[str, str]
            if file_path.suffix.lower() == ".json":
                loaded = self._load_json_secret_file(file_path)
            else:
                loaded = self._load_env_secret_file(file_path)

            with self._lock:
                self._file_secrets.update(loaded)
                self._loaded_files.append(str(file_path))
                self.clear_cache(source_only=True)

            masked_keys = {
                key: self.mask_secret(value)
                for key, value in loaded.items()
            }

            result = self._safe_result(
                success=True,
                message="Secret file loaded successfully.",
                data={
                    "path": str(file_path),
                    "loaded_count": len(loaded),
                    "masked_keys": masked_keys,
                },
                metadata={
                    "duration_ms": self._duration_ms(started_at),
                    "format": file_path.suffix.lower(),
                },
            )

            self._log_audit_event(
                action="load_secret_file",
                context=SecretsContext(scoped=False),
                outcome="success",
                payload={
                    "path": str(file_path),
                    "loaded_count": len(loaded),
                    "keys": list(loaded.keys()),
                },
            )

            return result

        except Exception as exc:
            logger.exception("Secret file load failed for path=%s", file_path)
            return self._error_result(
                message="Secret file load failed.",
                error=str(exc),
                metadata={
                    "path": str(file_path),
                    "duration_ms": self._duration_ms(started_at),
                },
            )

    def clear_cache(self, *, source_only: bool = False) -> Dict[str, Any]:
        """
        Clear resolved secret cache.

        Args:
            source_only:
                Internal flag used after secret-file reloads. Kept public-safe.
        """
        with self._lock:
            count = len(self._cache)
            self._cache.clear()

        return self._safe_result(
            success=True,
            message="Secret cache cleared.",
            data={"cleared_count": count},
            metadata={"source_only": source_only},
        )

    def list_configured_keys(
        self,
        *,
        include_environment: bool = False,
        include_file: bool = True,
        include_runtime: bool = True,
        include_external_providers: bool = True,
    ) -> Dict[str, Any]:
        """
        List known/configured secret keys without returning values.

        By default environment keys are not listed because process environments
        can be noisy and may contain unrelated sensitive values.
        """
        started_at = time.time()

        keys: Dict[str, List[str]] = {
            SecretSource.FILE.value: [],
            SecretSource.RUNTIME.value: [],
            SecretSource.ENVIRONMENT.value: [],
            SecretSource.EXTERNAL_PROVIDER.value: [],
        }

        with self._lock:
            if include_file:
                keys[SecretSource.FILE.value] = sorted(self._file_secrets.keys())
            if include_runtime:
                keys[SecretSource.RUNTIME.value] = sorted(self._runtime_secrets.keys())
            if include_external_providers:
                keys[SecretSource.EXTERNAL_PROVIDER.value] = sorted(self.external_providers.keys())

        if include_environment:
            env_keys = []
            for env_key in os.environ.keys():
                if self._is_allowed_environment_key(env_key):
                    env_keys.append(env_key)
            keys[SecretSource.ENVIRONMENT.value] = sorted(env_keys)

        total = sum(len(v) for v in keys.values())

        return self._safe_result(
            success=True,
            message="Configured secret keys listed safely.",
            data={
                "keys": keys,
                "total_count": total,
            },
            metadata={
                "values_included": False,
                "duration_ms": self._duration_ms(started_at),
            },
        )

    def health_check(self) -> Dict[str, Any]:
        """
        Return safe health information for dashboard/API checks.
        """
        with self._lock:
            runtime_count = len(self._runtime_secrets)
            file_count = len(self._file_secrets)
            cache_count = len(self._cache)
            provider_count = len(self.external_providers)

        return self._safe_result(
            success=True,
            message="SecretsManager is healthy.",
            data={
                "module": self.module_name,
                "version": self.version,
                "cache_enabled": self.cache_enabled,
                "cache_ttl_seconds": self.cache_ttl_seconds,
                "runtime_secret_count": runtime_count,
                "file_secret_count": file_count,
                "cache_entry_count": cache_count,
                "external_provider_count": provider_count,
                "loaded_files": list(self._loaded_files),
            },
            metadata={
                "safe_for_dashboard": True,
                "values_included": False,
            },
        )

    async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        BaseAgent-compatible task runner.

        Supported task actions:
            - get_secret
            - require_secret
            - has_secret
            - get_many
            - health_check
            - list_configured_keys
            - clear_cache

        This makes the utility routable by MasterAgent/AgentRouter while still
        keeping direct Python method usage clean.
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
            if action == "get_secret":
                return self.get_secret(**payload)

            if action == "require_secret":
                return self.require_secret(**payload)

            if action == "has_secret":
                return self.has_secret(**payload)

            if action == "get_many":
                return self.get_many(**payload)

            if action == "health_check":
                return self.health_check()

            if action == "list_configured_keys":
                return self.list_configured_keys(**payload)

            if action == "clear_cache":
                return self.clear_cache()

            return self._error_result(
                message=f"Unsupported SecretsManager action: {action}",
                error="UNSUPPORTED_ACTION",
                metadata={
                    "supported_actions": [
                        "get_secret",
                        "require_secret",
                        "has_secret",
                        "get_many",
                        "health_check",
                        "list_configured_keys",
                        "clear_cache",
                    ]
                },
            )

        except Exception as exc:
            logger.exception("SecretsManager task execution failed.")
            return self._error_result(
                message="SecretsManager task execution failed.",
                error=str(exc),
                metadata={"action": action},
            )

    # ------------------------------------------------------------------
    # William/Jarvis compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate SaaS context for tasks/actions.

        If scoped=True, both user_id and workspace_id are mandatory.
        This prevents accidental cross-user/workspace secret access.
        """
        if not isinstance(task, dict):
            return self._error_result(
                message="Task context must be a dictionary.",
                error="INVALID_TASK_CONTEXT",
            )

        scoped = bool(task.get("scoped", False))
        user_id = task.get("user_id")
        workspace_id = task.get("workspace_id")

        if scoped and not user_id:
            return self._error_result(
                message="user_id is required for scoped secret operations.",
                error="MISSING_USER_ID",
                metadata={"scoped": scoped},
            )

        if scoped and not workspace_id:
            return self._error_result(
                message="workspace_id is required for scoped secret operations.",
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

    def _requires_security_check(self, action: str, context: SecretsContext) -> bool:
        """
        Identify actions that should pass through Security Agent.

        In this utility, any scoped operation, mutation, or raw secret retrieval
        is security-sensitive.
        """
        sensitive_actions = {
            "get_secret",
            "get_many",
            "set_runtime_secret",
            "delete_runtime_secret",
            "load_secret_file",
        }

        if context.scoped:
            return True

        return action in sensitive_actions

    def _request_security_approval(
        self,
        *,
        action: str,
        context: SecretsContext,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Security Agent approval bridge.

        This file remains import-safe before Security Agent exists. The default
        implementation permits safe internal use but creates a structured hook
        so future Security Agent policy enforcement can be attached here.

        A future Security Agent can replace this method or wrap this manager.
        """
        denied = False
        reason = None

        if context.scoped and (not context.user_id or not context.workspace_id):
            denied = True
            reason = "Scoped operation missing user_id or workspace_id."

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
        context: SecretsContext,
        success: bool,
        data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare non-secret payload for Verification Agent.

        No raw secret values are included.
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
            "timestamp": self._now(),
            "data": self._sanitize_for_audit(data),
        }

    def _prepare_memory_payload(
        self,
        *,
        action: str,
        context: SecretsContext,
        data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare safe, non-sensitive memory-compatible context.

        Secrets themselves are never written to Memory Agent. Only operational
        metadata is included.
        """
        return {
            "memory_type": "security_utility_event",
            "module": self.module_name,
            "action": action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "timestamp": self._now(),
            "safe_summary": {
                "key": data.get("key"),
                "found": data.get("found"),
                "source": data.get("source"),
            },
            "contains_secret_value": False,
        }

    def _emit_agent_event(self, event_type: str, payload: Dict[str, Any]) -> None:
        """
        Emit a safe event for future dashboard/event bus integration.
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
                logger.exception("SecretsManager event sink failed.")
        else:
            logger.debug("SecretsManager event: %s", event)

    def _log_audit_event(
        self,
        *,
        action: str,
        context: SecretsContext,
        outcome: str,
        payload: Dict[str, Any],
    ) -> None:
        """
        Log a safe audit event.

        Raw secret values are removed/masked before leaving this class.
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
            "scoped": context.scoped,
            "payload": self._sanitize_for_audit(payload),
        }

        if self.audit_sink:
            try:
                self.audit_sink(audit_event)
            except Exception:
                logger.exception("SecretsManager audit sink failed.")
        else:
            logger.info("SecretsManager audit event: %s", audit_event)

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
    # Internal resolution logic
    # ------------------------------------------------------------------

    def _validate_lookup_request(self, request: SecretLookupRequest) -> Dict[str, Any]:
        key_validation = self._validate_secret_key(request.key)
        if not key_validation["success"]:
            return key_validation

        context_validation = self._validate_task_context(
            {
                "user_id": request.context.user_id,
                "workspace_id": request.context.workspace_id,
                "scoped": request.scoped or request.context.scoped,
                "operation": "secret_lookup",
            }
        )
        if not context_validation["success"]:
            return context_validation

        if not any(
            [
                request.allow_runtime,
                request.allow_environment,
                request.allow_file,
                request.allow_external_provider,
            ]
        ):
            return self._error_result(
                message="At least one secret source must be enabled.",
                error="NO_SECRET_SOURCE_ENABLED",
                metadata={"key": request.key},
            )

        return self._safe_result(
            success=True,
            message="Secret lookup request validated.",
            data={"key": request.key},
            metadata={"validation": "passed"},
        )

    def _validate_key_value(
        self,
        key: str,
        value: str,
        *,
        scoped: bool,
        context: SecretsContext,
    ) -> Dict[str, Any]:
        key_validation = self._validate_secret_key(key)
        if not key_validation["success"]:
            return key_validation

        context_validation = self._validate_task_context(
            {
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
                "scoped": scoped,
                "operation": "set_runtime_secret",
            }
        )
        if not context_validation["success"]:
            return context_validation

        if not isinstance(value, str):
            return self._error_result(
                message="Secret value must be a string.",
                error="INVALID_SECRET_VALUE_TYPE",
                metadata={"key": key},
            )

        if value == "":
            return self._error_result(
                message="Secret value cannot be empty.",
                error="EMPTY_SECRET_VALUE",
                metadata={"key": key},
            )

        return self._safe_result(
            success=True,
            message="Secret key/value validated.",
            data={"key": key},
        )

    def _validate_secret_key(self, key: str) -> Dict[str, Any]:
        if not isinstance(key, str):
            return self._error_result(
                message="Secret key must be a string.",
                error="INVALID_SECRET_KEY_TYPE",
            )

        normalized = key.strip()
        if not normalized:
            return self._error_result(
                message="Secret key cannot be empty.",
                error="EMPTY_SECRET_KEY",
            )

        if len(normalized) > 256:
            return self._error_result(
                message="Secret key is too long.",
                error="SECRET_KEY_TOO_LONG",
                metadata={"max_length": 256},
            )

        if self.strict_key_validation and not SECRET_KEY_PATTERN.match(normalized):
            return self._error_result(
                message="Secret key contains unsupported characters.",
                error="INVALID_SECRET_KEY_FORMAT",
                metadata={
                    "key": self._safe_key_for_log(normalized),
                    "allowed_pattern": SECRET_KEY_PATTERN.pattern,
                },
            )

        return self._safe_result(
            success=True,
            message="Secret key validated.",
            data={"key": normalized},
        )

    def _resolve_secret(self, request: SecretLookupRequest) -> SecretRecord:
        key = request.key.strip()
        context = request.context
        scoped = request.scoped or context.scoped

        candidate_keys = self._candidate_keys(key, context, scoped=scoped)

        cache_key = self._cache_key(candidate_keys, request)

        cached = self._get_cache(cache_key)
        if cached:
            return SecretRecord(
                key=key,
                value=cached.value,
                source=cached.source,
                found=cached.value is not None,
                masked_value=self.mask_secret(cached.value),
                sensitivity=self._classify_sensitivity(key),
                metadata={"cache_hit": True, **cached.metadata},
            )

        source_order: List[Tuple[SecretSource, bool]] = [
            (SecretSource.RUNTIME, request.allow_runtime),
            (SecretSource.ENVIRONMENT, request.allow_environment),
            (SecretSource.FILE, request.allow_file),
            (SecretSource.EXTERNAL_PROVIDER, request.allow_external_provider),
        ]

        for source, enabled in source_order:
            if not enabled:
                continue

            value = self._lookup_from_source(source, candidate_keys, context)

            if value is not None:
                self._set_cache(
                    cache_key,
                    CacheEntry(
                        value=value,
                        source=source,
                        created_at=time.time(),
                        expires_at=time.time() + self.cache_ttl_seconds,
                        metadata={"candidate_count": len(candidate_keys)},
                    ),
                )
                return SecretRecord(
                    key=key,
                    value=value,
                    source=source,
                    found=True,
                    masked_value=self.mask_secret(value),
                    sensitivity=self._classify_sensitivity(key),
                    metadata={"candidate_count": len(candidate_keys)},
                )

        self._set_cache(
            cache_key,
            CacheEntry(
                value=None,
                source=None,
                created_at=time.time(),
                expires_at=time.time() + self.cache_ttl_seconds,
                metadata={"candidate_count": len(candidate_keys)},
            ),
        )

        return SecretRecord(
            key=key,
            value=None,
            source=None,
            found=False,
            masked_value=None,
            sensitivity=self._classify_sensitivity(key),
            metadata={"candidate_count": len(candidate_keys)},
        )

    def _lookup_from_source(
        self,
        source: SecretSource,
        candidate_keys: List[str],
        context: SecretsContext,
    ) -> Optional[str]:
        if source == SecretSource.RUNTIME:
            with self._lock:
                for candidate in candidate_keys:
                    if candidate in self._runtime_secrets:
                        return self._runtime_secrets[candidate]
            return None

        if source == SecretSource.ENVIRONMENT:
            for candidate in candidate_keys:
                if candidate in os.environ:
                    value = os.environ.get(candidate)
                    if value is not None and value != "":
                        return value
            return None

        if source == SecretSource.FILE:
            with self._lock:
                for candidate in candidate_keys:
                    if candidate in self._file_secrets:
                        return self._file_secrets[candidate]
            return None

        if source == SecretSource.EXTERNAL_PROVIDER:
            with self._lock:
                providers = dict(self.external_providers)

            for provider_name, provider in providers.items():
                for candidate in candidate_keys:
                    try:
                        value = provider(candidate, context)
                    except Exception:
                        logger.exception(
                            "External secret provider failed: %s",
                            provider_name,
                        )
                        continue

                    if value is not None and value != "":
                        return str(value)

            return None

        return None

    def _candidate_keys(
        self,
        key: str,
        context: SecretsContext,
        *,
        scoped: bool,
    ) -> List[str]:
        """
        Generate safe candidate keys for lookup.

        For scoped secrets, this supports per-workspace/user namespacing without
        allowing one workspace to read another workspace's values.
        """
        clean_key = key.strip()
        candidates: List[str] = []

        if scoped:
            user_part = self._normalize_scope_part(context.user_id)
            workspace_part = self._normalize_scope_part(context.workspace_id)

            candidates.extend(
                [
                    f"WILLIAM_WORKSPACE_{workspace_part}_USER_{user_part}_{clean_key}",
                    f"JARVIS_WORKSPACE_{workspace_part}_USER_{user_part}_{clean_key}",
                    f"WORKSPACE_{workspace_part}_USER_{user_part}_{clean_key}",
                    f"{workspace_part}_{user_part}_{clean_key}",
                ]
            )

        for prefix in self.env_prefixes:
            prefixed = f"{prefix}{clean_key}"
            if prefixed not in candidates:
                candidates.append(prefixed)

        if self.allow_unprefixed_env and clean_key not in candidates:
            candidates.append(clean_key)

        return candidates

    def _scoped_key(self, key: str, context: SecretsContext) -> str:
        user_part = self._normalize_scope_part(context.user_id)
        workspace_part = self._normalize_scope_part(context.workspace_id)
        return f"WORKSPACE_{workspace_part}_USER_{user_part}_{key.strip()}"

    def _normalize_scope_part(self, value: Optional[str]) -> str:
        clean = str(value or "").strip()
        clean = re.sub(r"[^A-Za-z0-9_\-]", "_", clean)
        clean = clean.upper()
        return clean[:128]

    # ------------------------------------------------------------------
    # File parsers
    # ------------------------------------------------------------------

    def _load_json_secret_file(self, file_path: Path) -> Dict[str, str]:
        raw = file_path.read_text(encoding="utf-8")
        parsed = json.loads(raw)

        if not isinstance(parsed, dict):
            raise ValueError("JSON secret file must contain an object mapping keys to values.")

        loaded: Dict[str, str] = {}
        for key, value in parsed.items():
            key_str = str(key).strip()
            validation = self._validate_secret_key(key_str)
            if not validation["success"]:
                logger.warning("Skipping invalid secret key in JSON file: %s", self._safe_key_for_log(key_str))
                continue

            if value is None:
                continue

            value_str = str(value)
            if value_str == "":
                continue

            loaded[key_str] = value_str

        return loaded

    def _load_env_secret_file(self, file_path: Path) -> Dict[str, str]:
        loaded: Dict[str, str] = {}

        for raw_line in file_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()

            if not line or line.startswith("#"):
                continue

            if line.lower().startswith("export "):
                line = line[7:].strip()

            if "=" not in line:
                continue

            key, value = line.split("=", 1)
            key = key.strip()
            value = self._strip_env_value(value.strip())

            validation = self._validate_secret_key(key)
            if not validation["success"]:
                logger.warning("Skipping invalid secret key in env file: %s", self._safe_key_for_log(key))
                continue

            if value == "":
                continue

            loaded[key] = value

        return loaded

    def _strip_env_value(self, value: str) -> str:
        if len(value) >= 2:
            if value[0] == value[-1] and value[0] in {"'", '"'}:
                return value[1:-1]
        return value

    # ------------------------------------------------------------------
    # Cache helpers
    # ------------------------------------------------------------------

    def _cache_key(self, candidate_keys: List[str], request: SecretLookupRequest) -> str:
        source_flags = [
            "runtime" if request.allow_runtime else "",
            "env" if request.allow_environment else "",
            "file" if request.allow_file else "",
            "external" if request.allow_external_provider else "",
        ]
        return "|".join(candidate_keys + source_flags)

    def _get_cache(self, cache_key: str) -> Optional[CacheEntry]:
        if not self.cache_enabled or self.cache_ttl_seconds <= 0:
            return None

        now = time.time()
        with self._lock:
            entry = self._cache.get(cache_key)
            if not entry:
                return None

            if entry.expires_at < now:
                self._cache.pop(cache_key, None)
                return None

            return entry

    def _set_cache(self, cache_key: str, entry: CacheEntry) -> None:
        if not self.cache_enabled or self.cache_ttl_seconds <= 0:
            return

        with self._lock:
            self._cache[cache_key] = entry

    def _invalidate_cache_for_key(self, key: str) -> None:
        with self._lock:
            keys_to_delete = [cache_key for cache_key in self._cache if key in cache_key]
            for cache_key in keys_to_delete:
                self._cache.pop(cache_key, None)

    # ------------------------------------------------------------------
    # Safety helpers
    # ------------------------------------------------------------------

    def mask_secret(
        self,
        value: Optional[Union[str, bytes]],
        *,
        visible_start: int = 2,
        visible_end: int = 2,
        mask_char: str = "*",
    ) -> Optional[str]:
        """
        Mask a secret for safe display.

        Examples:
            abcdefgh -> ab****gh
            abc -> ***
        """
        if value is None:
            return None

        if isinstance(value, bytes):
            try:
                value_str = value.decode("utf-8", errors="replace")
            except Exception:
                value_str = "<bytes>"
        else:
            value_str = str(value)

        if value_str == "":
            return ""

        length = len(value_str)
        if length <= visible_start + visible_end + 2:
            return mask_char * min(max(length, 3), 12)

        return (
            value_str[:visible_start]
            + (mask_char * min(max(length - visible_start - visible_end, 4), 24))
            + value_str[-visible_end:]
        )

    def _sanitize_for_audit(self, payload: Any) -> Any:
        """
        Recursively sanitize payloads before logging/audit/event emission.
        """
        if isinstance(payload, dict):
            sanitized: Dict[str, Any] = {}
            for key, value in payload.items():
                key_str = str(key)
                if self._looks_sensitive(key_str):
                    sanitized[key_str] = self.mask_secret(value)
                else:
                    sanitized[key_str] = self._sanitize_for_audit(value)
            return sanitized

        if isinstance(payload, list):
            return [self._sanitize_for_audit(item) for item in payload]

        if isinstance(payload, tuple):
            return tuple(self._sanitize_for_audit(item) for item in payload)

        return payload

    def _looks_sensitive(self, key: str) -> bool:
        upper = key.upper()
        return any(hint in upper for hint in SENSITIVE_NAME_HINTS) or upper in {"VALUE", "SECRET_VALUE"}

    def _classify_sensitivity(self, key: str) -> SecretSensitivity:
        upper = key.upper()

        if any(hint in upper for hint in ("PRIVATE", "PASSWORD", "ROOT", "MASTER", "SIGNING")):
            return SecretSensitivity.CRITICAL

        if any(hint in upper for hint in SENSITIVE_NAME_HINTS):
            return SecretSensitivity.HIGH

        return SecretSensitivity.LOW

    def _safe_key_for_log(self, key: str) -> str:
        """
        Secret keys are usually safe, but this keeps log output controlled.
        """
        clean = str(key or "").strip()
        if len(clean) <= 96:
            return clean
        return clean[:96] + "...<truncated>"

    def _is_allowed_environment_key(self, env_key: str) -> bool:
        if self.allow_unprefixed_env:
            return self._looks_sensitive(env_key)
        return any(env_key.startswith(prefix) for prefix in self.env_prefixes)

    def _duration_ms(self, started_at: float) -> int:
        return int((time.time() - started_at) * 1000)

    def _now(self) -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ---------------------------------------------------------------------------
# Convenience singleton helpers.
# ---------------------------------------------------------------------------

_DEFAULT_MANAGER_LOCK = threading.RLock()
_DEFAULT_MANAGER: Optional[SecretsManager] = None


def get_default_secrets_manager() -> SecretsManager:
    """
    Return a process-local default SecretsManager instance.

    Useful for modules that need a lightweight shared manager without manually
    wiring dependencies.
    """
    global _DEFAULT_MANAGER

    with _DEFAULT_MANAGER_LOCK:
        if _DEFAULT_MANAGER is None:
            _DEFAULT_MANAGER = SecretsManager()
        return _DEFAULT_MANAGER


def get_secret(key: str, **kwargs: Any) -> Dict[str, Any]:
    """
    Convenience wrapper around the default manager.
    """
    return get_default_secrets_manager().get_secret(key, **kwargs)


def require_secret(key: str, **kwargs: Any) -> Dict[str, Any]:
    """
    Convenience wrapper for required secrets.
    """
    return get_default_secrets_manager().require_secret(key, **kwargs)


__all__ = [
    "SecretsManager",
    "SecretsContext",
    "SecretLookupRequest",
    "SecretRecord",
    "SecretSource",
    "SecretSensitivity",
    "get_default_secrets_manager",
    "get_secret",
    "require_secret",
]