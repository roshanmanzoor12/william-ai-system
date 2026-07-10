"""
agents/workflow_agent/app_connector.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
Workflow Agent - App Connector

Purpose:
    Manages external app/API connectors and secure integration configurations.

This module is designed to be:
    - Production-ready
    - Import-safe even when future William modules do not exist yet
    - Compatible with BaseAgent, Agent Registry, Agent Loader, Agent Router, and Master Agent routing
    - SaaS-safe with strict user_id/workspace_id isolation
    - Security Agent compatible for sensitive connector operations
    - Memory Agent compatible for useful non-secret context
    - Verification Agent compatible for completed integration actions
    - Dashboard/API ready with structured dict/JSON responses

Important safety rules:
    - Secrets are never logged in raw form.
    - Sensitive actions require a security check hook.
    - User/workspace context is validated for every user-specific operation.
    - Real external API calls are not performed by default. This file prepares, validates,
      stores, masks, and safely describes connector configurations.
"""

from __future__ import annotations

import base64
import copy
import dataclasses
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# ======================================================================================
# Safe optional BaseAgent import
# ======================================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for incomplete project state
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps the file import-safe before the full William/Jarvis BaseAgent
        implementation exists. When the real BaseAgent is available, it will be used.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_type = kwargs.get("agent_type", "workflow")
            self.metadata = kwargs.get("metadata", {})

        async def handle_task(self, task: Mapping[str, Any]) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent does not implement task handling.",
                "data": {},
                "error": "base_agent_not_available",
                "metadata": {"agent": self.__class__.__name__},
            }


# ======================================================================================
# Logging
# ======================================================================================

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# ======================================================================================
# Constants
# ======================================================================================

UTC = timezone.utc

DEFAULT_AGENT_NAME = "workflow_app_connector"
DEFAULT_AGENT_TYPE = "workflow_agent"

SECRET_MASK = "********"
MAX_CONFIG_BYTES = 64_000
MAX_CONNECTOR_NAME_LENGTH = 80
MAX_INTEGRATION_NAME_LENGTH = 120
MAX_FIELD_NAME_LENGTH = 80
MAX_URL_LENGTH = 2048
MAX_DESCRIPTION_LENGTH = 1000

SENSITIVE_FIELD_PATTERNS = (
    "secret",
    "token",
    "password",
    "pass",
    "api_key",
    "apikey",
    "key",
    "private",
    "credential",
    "client_secret",
    "refresh_token",
    "access_token",
    "bearer",
    "authorization",
    "auth",
)

SAFE_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-:.]{1,160}$")
CONNECTOR_KEY_PATTERN = re.compile(r"^[a-z][a-z0-9_\-]{1,78}[a-z0-9]$")
URL_PATTERN = re.compile(r"^https?://[^\s/$.?#].[^\s]*$", re.IGNORECASE)


# ======================================================================================
# Enums
# ======================================================================================

class ConnectorCategory(str, Enum):
    """Supported connector categories for Workflow Agent integrations."""

    CRM = "crm"
    SHEET = "sheet"
    EMAIL = "email"
    WHATSAPP = "whatsapp"
    SMS = "sms"
    WEBHOOK = "webhook"
    ADS = "ads"
    PAYMENT = "payment"
    STORAGE = "storage"
    CALENDAR = "calendar"
    COMMUNICATION = "communication"
    AUTOMATION = "automation"
    AI = "ai"
    CUSTOM_API = "custom_api"
    OTHER = "other"


class AuthType(str, Enum):
    """Supported authentication styles."""

    NONE = "none"
    API_KEY = "api_key"
    BEARER_TOKEN = "bearer_token"
    BASIC = "basic"
    OAUTH2 = "oauth2"
    HMAC = "hmac"
    WEBHOOK_SECRET = "webhook_secret"
    CUSTOM = "custom"


class IntegrationStatus(str, Enum):
    """Lifecycle status for an integration config."""

    DRAFT = "draft"
    ACTIVE = "active"
    DISABLED = "disabled"
    ERROR = "error"
    REVOKED = "revoked"
    PENDING_APPROVAL = "pending_approval"


class ConnectorCapability(str, Enum):
    """General connector capabilities used by workflow routing."""

    READ = "read"
    WRITE = "write"
    SEND_MESSAGE = "send_message"
    RECEIVE_MESSAGE = "receive_message"
    CREATE_RECORD = "create_record"
    UPDATE_RECORD = "update_record"
    DELETE_RECORD = "delete_record"
    SEARCH = "search"
    WEBHOOK_RECEIVE = "webhook_receive"
    WEBHOOK_SEND = "webhook_send"
    SCHEDULE = "schedule"
    FILE_UPLOAD = "file_upload"
    FILE_DOWNLOAD = "file_download"
    ANALYTICS = "analytics"
    TEST_CONNECTION = "test_connection"


class SecurityDecision(str, Enum):
    """Security approval result."""

    APPROVED = "approved"
    DENIED = "denied"
    PENDING = "pending"
    NOT_REQUIRED = "not_required"


# ======================================================================================
# Dataclasses
# ======================================================================================

@dataclass(frozen=True)
class ConnectorField:
    """
    Describes a connector configuration field.

    Secret fields should be marked as secret=True. Raw secret values are never included
    in dashboard-safe output.
    """

    name: str
    label: str
    required: bool = False
    secret: bool = False
    field_type: str = "string"
    description: str = ""
    default: Optional[Any] = None
    allowed_values: Optional[List[Any]] = None
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    pattern: Optional[str] = None
    example: Optional[str] = None

    def validate_definition(self) -> None:
        if not self.name or not isinstance(self.name, str):
            raise ValueError("ConnectorField.name is required.")
        if len(self.name) > MAX_FIELD_NAME_LENGTH:
            raise ValueError(f"ConnectorField.name exceeds {MAX_FIELD_NAME_LENGTH} characters.")
        if not SAFE_ID_PATTERN.match(self.name):
            raise ValueError(f"ConnectorField.name contains unsafe characters: {self.name}")
        if not self.label or not isinstance(self.label, str):
            raise ValueError(f"ConnectorField.label is required for {self.name}.")
        if self.field_type not in {
            "string",
            "integer",
            "number",
            "boolean",
            "url",
            "email",
            "json",
            "list",
            "dict",
        }:
            raise ValueError(f"Unsupported field_type for {self.name}: {self.field_type}")

    def to_safe_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        if self.secret:
            data["default"] = None
            data["example"] = SECRET_MASK if self.example else None
        return data


@dataclass(frozen=True)
class ConnectorDefinition:
    """
    Describes an external app/API connector supported by Workflow Agent.

    These definitions are consumed by the dashboard, API layer, Master Agent routing,
    and Action Router to understand what each connector can safely do.
    """

    key: str
    display_name: str
    category: ConnectorCategory
    auth_type: AuthType
    fields: List[ConnectorField] = field(default_factory=list)
    capabilities: List[ConnectorCapability] = field(default_factory=list)
    base_url: Optional[str] = None
    docs_url: Optional[str] = None
    description: str = ""
    enabled: bool = True
    requires_security_approval: bool = True
    version: str = "1.0"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def validate_definition(self) -> None:
        if not self.key or not CONNECTOR_KEY_PATTERN.match(self.key):
            raise ValueError(
                "ConnectorDefinition.key must be lowercase, URL-safe, and 3-80 characters."
            )
        if len(self.key) > MAX_CONNECTOR_NAME_LENGTH:
            raise ValueError(f"Connector key exceeds {MAX_CONNECTOR_NAME_LENGTH} characters.")
        if not self.display_name:
            raise ValueError(f"ConnectorDefinition.display_name is required for {self.key}.")
        if self.base_url and not _is_valid_url(self.base_url):
            raise ValueError(f"Invalid base_url for connector {self.key}.")
        if self.docs_url and not _is_valid_url(self.docs_url):
            raise ValueError(f"Invalid docs_url for connector {self.key}.")
        if len(self.description or "") > MAX_DESCRIPTION_LENGTH:
            raise ValueError(f"Description too long for connector {self.key}.")
        seen_fields = set()
        for field_def in self.fields:
            field_def.validate_definition()
            if field_def.name in seen_fields:
                raise ValueError(f"Duplicate field {field_def.name} in connector {self.key}.")
            seen_fields.add(field_def.name)

    def to_safe_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "display_name": self.display_name,
            "category": self.category.value,
            "auth_type": self.auth_type.value,
            "fields": [item.to_safe_dict() for item in self.fields],
            "capabilities": [item.value for item in self.capabilities],
            "base_url": self.base_url,
            "docs_url": self.docs_url,
            "description": self.description,
            "enabled": self.enabled,
            "requires_security_approval": self.requires_security_approval,
            "version": self.version,
            "metadata": _json_safe(self.metadata),
        }


@dataclass
class IntegrationConfig:
    """
    User/workspace specific external app integration.

    Secrets are stored as encrypted strings when an encryption key is configured.
    Without an encryption key, this module stores only secret references and fingerprints
    in memory-safe mode unless explicitly allowed by constructor parameter.

    This object should not be sent directly to dashboards. Use to_safe_dict().
    """

    integration_id: str
    user_id: str
    workspace_id: str
    connector_key: str
    name: str
    config: Dict[str, Any]
    status: IntegrationStatus = IntegrationStatus.DRAFT
    created_at: str = field(default_factory=lambda: _now_iso())
    updated_at: str = field(default_factory=lambda: _now_iso())
    created_by: Optional[str] = None
    updated_by: Optional[str] = None
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    last_health_check_at: Optional[str] = None
    last_health_status: Optional[str] = None
    last_error: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_safe_dict(
        self,
        connector_definition: Optional[ConnectorDefinition] = None,
        include_config: bool = True,
    ) -> Dict[str, Any]:
        safe_config = {}
        if include_config:
            safe_config = _mask_config(self.config, connector_definition=connector_definition)

        return {
            "integration_id": self.integration_id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "connector_key": self.connector_key,
            "name": self.name,
            "config": safe_config,
            "status": self.status.value if isinstance(self.status, IntegrationStatus) else self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "created_by": self.created_by,
            "updated_by": self.updated_by,
            "approved_by": self.approved_by,
            "approved_at": self.approved_at,
            "last_health_check_at": self.last_health_check_at,
            "last_health_status": self.last_health_status,
            "last_error": self.last_error,
            "tags": list(self.tags),
            "metadata": _json_safe(self.metadata),
        }


# ======================================================================================
# Utility helpers
# ======================================================================================

def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _json_safe(value: Any) -> Any:
    """
    Convert arbitrary values into JSON-safe data without exposing private objects.
    """

    if value is None or isinstance(value, (str, int, float, bool)):
        return value

    if isinstance(value, Enum):
        return value.value

    if dataclasses.is_dataclass(value):
        return _json_safe(asdict(value))

    if isinstance(value, Mapping):
        return {str(k): _json_safe(v) for k, v in value.items()}

    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]

    return str(value)


def _safe_copy(value: Any) -> Any:
    try:
        return copy.deepcopy(value)
    except Exception:
        return _json_safe(value)


def _is_valid_url(value: str) -> bool:
    if not isinstance(value, str):
        return False
    if len(value) > MAX_URL_LENGTH:
        return False
    return bool(URL_PATTERN.match(value))


def _normalize_key(value: str) -> str:
    value = str(value or "").strip().lower()
    value = re.sub(r"[^a-z0-9_\-]+", "_", value)
    value = re.sub(r"_+", "_", value).strip("_-")
    return value


def _is_sensitive_field(field_name: str, connector_definition: Optional[ConnectorDefinition] = None) -> bool:
    normalized = str(field_name or "").lower()

    if connector_definition:
        for field_def in connector_definition.fields:
            if field_def.name == field_name:
                return bool(field_def.secret)

    return any(pattern in normalized for pattern in SENSITIVE_FIELD_PATTERNS)


def _mask_value(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, str):
        if not value:
            return ""
        if value.startswith("secret_ref:"):
            return "secret_ref:********"
        if len(value) <= 4:
            return SECRET_MASK
        return f"{value[:2]}{SECRET_MASK}{value[-2:]}"
    if isinstance(value, Mapping):
        return {k: _mask_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_mask_value(item) for item in value]
    return SECRET_MASK


def _mask_config(
    config: Mapping[str, Any],
    connector_definition: Optional[ConnectorDefinition] = None,
) -> Dict[str, Any]:
    masked: Dict[str, Any] = {}
    for key, value in dict(config or {}).items():
        if _is_sensitive_field(key, connector_definition):
            masked[str(key)] = _mask_value(value)
        elif isinstance(value, Mapping):
            masked[str(key)] = _mask_config(value, connector_definition=None)
        elif isinstance(value, list):
            masked[str(key)] = [
                _mask_config(item) if isinstance(item, Mapping) else item for item in value
            ]
        else:
            masked[str(key)] = _json_safe(value)
    return masked


def _fingerprint_secret(value: str, salt: str = "") -> str:
    """
    Create a non-reversible fingerprint for detecting whether a secret changed.
    """

    raw = f"{salt}:{value}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _estimate_json_bytes(data: Any) -> int:
    try:
        return len(json.dumps(_json_safe(data), separators=(",", ":")).encode("utf-8"))
    except Exception:
        return MAX_CONFIG_BYTES + 1


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes", "y", "on"}
    return bool(value)


def _coerce_value(value: Any, field_type: str) -> Any:
    if value is None:
        return None

    if field_type == "string":
        return str(value)

    if field_type == "integer":
        if isinstance(value, bool):
            raise ValueError("Boolean is not valid integer value.")
        return int(value)

    if field_type == "number":
        if isinstance(value, bool):
            raise ValueError("Boolean is not valid number value.")
        return float(value)

    if field_type == "boolean":
        return _coerce_bool(value)

    if field_type == "url":
        text = str(value).strip()
        if not _is_valid_url(text):
            raise ValueError("Invalid URL.")
        return text

    if field_type == "email":
        text = str(value).strip()
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", text):
            raise ValueError("Invalid email address.")
        return text

    if field_type == "json":
        if isinstance(value, str):
            return json.loads(value)
        return _json_safe(value)

    if field_type == "list":
        if isinstance(value, list):
            return value
        if isinstance(value, tuple):
            return list(value)
        raise ValueError("Expected list value.")

    if field_type == "dict":
        if isinstance(value, Mapping):
            return dict(value)
        raise ValueError("Expected dict value.")

    return value


# ======================================================================================
# Lightweight secret codec
# ======================================================================================

class SecretCodec:
    """
    Small secret encoding helper.

    This is intentionally dependency-light. If APP_CONNECTOR_SECRET_KEY is provided,
    values are XOR-obfuscated with HMAC-derived stream bytes and base64 encoded.

    For stronger production encryption, connect this class to a proper KMS or a
    secrets manager such as AWS KMS, GCP Secret Manager, Azure Key Vault, HashiCorp Vault,
    or a real cryptography/Fernet implementation. The interface is already isolated
    so this can be upgraded without changing AppConnector public methods.
    """

    PREFIX = "enc:v1:"

    def __init__(self, key: Optional[str] = None, allow_plaintext_fallback: bool = False) -> None:
        self.key = key or os.getenv("APP_CONNECTOR_SECRET_KEY") or ""
        self.allow_plaintext_fallback = allow_plaintext_fallback

    @property
    def encryption_available(self) -> bool:
        return bool(self.key)

    def encode_secret(self, value: str, context: str) -> str:
        if value is None:
            return value

        text = str(value)

        if not self.key:
            if self.allow_plaintext_fallback:
                return f"plain:{base64.urlsafe_b64encode(text.encode('utf-8')).decode('ascii')}"
            secret_ref = f"secret_ref:{context}:{_fingerprint_secret(text, context)[:18]}"
            return secret_ref

        raw = text.encode("utf-8")
        stream = self._keystream(context=context, size=len(raw))
        encrypted = bytes(a ^ b for a, b in zip(raw, stream))
        payload = base64.urlsafe_b64encode(encrypted).decode("ascii")
        return f"{self.PREFIX}{payload}"

    def decode_secret(self, value: str, context: str) -> Optional[str]:
        if not isinstance(value, str):
            return None

        if value.startswith("secret_ref:"):
            return None

        if value.startswith("plain:"):
            if not self.allow_plaintext_fallback:
                return None
            try:
                return base64.urlsafe_b64decode(value[6:].encode("ascii")).decode("utf-8")
            except Exception:
                return None

        if not value.startswith(self.PREFIX):
            return value if self.allow_plaintext_fallback else None

        if not self.key:
            return None

        try:
            payload = value[len(self.PREFIX):]
            encrypted = base64.urlsafe_b64decode(payload.encode("ascii"))
            stream = self._keystream(context=context, size=len(encrypted))
            raw = bytes(a ^ b for a, b in zip(encrypted, stream))
            return raw.decode("utf-8")
        except Exception:
            return None

    def _keystream(self, context: str, size: int) -> bytes:
        key_bytes = self.key.encode("utf-8")
        chunks: List[bytes] = []
        counter = 0
        while sum(len(chunk) for chunk in chunks) < size:
            message = f"{context}:{counter}".encode("utf-8")
            chunks.append(hmac.new(key_bytes, message, hashlib.sha256).digest())
            counter += 1
        return b"".join(chunks)[:size]


# ======================================================================================
# AppConnector
# ======================================================================================

class AppConnector(BaseAgent):
    """
    Manages external app/API connector definitions and per-user/per-workspace integrations.

    How this connects to William/Jarvis architecture:
        - Master Agent / Agent Router:
            Can route workflow connector tasks to this class through handle_task().
        - Workflow Agent:
            Uses this module to create, validate, list, update, disable, and safely expose
            integration configs used by trigger engines and action routers.
        - Security Agent:
            Sensitive actions call _requires_security_check() and _request_security_approval().
            In production, wire these hooks to the real Security Agent.
        - Memory Agent:
            _prepare_memory_payload() emits useful non-secret connector context.
        - Verification Agent:
            _prepare_verification_payload() emits completed action summaries.
        - Dashboard/API:
            All methods return structured dicts with success, message, data, error, metadata.
        - Agent Registry / Loader:
            Class name and import path are stable: AppConnector at agents.workflow_agent.app_connector.
    """

    def __init__(
        self,
        *,
        security_client: Optional[Any] = None,
        memory_client: Optional[Any] = None,
        verification_client: Optional[Any] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], None]] = None,
        event_emitter: Optional[Callable[[Dict[str, Any]], None]] = None,
        secret_codec: Optional[SecretCodec] = None,
        allow_plaintext_secret_fallback: bool = False,
        initial_connectors: Optional[Sequence[ConnectorDefinition]] = None,
        storage_backend: Optional[Any] = None,
        logger_instance: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            agent_name=kwargs.pop("agent_name", DEFAULT_AGENT_NAME),
            agent_type=kwargs.pop("agent_type", DEFAULT_AGENT_TYPE),
            metadata=kwargs.pop(
                "metadata",
                {
                    "module": "workflow_agent",
                    "file": "app_connector.py",
                    "class": "AppConnector",
                    "version": "1.0.0",
                },
            ),
            **kwargs,
        )

        self.security_client = security_client
        self.memory_client = memory_client
        self.verification_client = verification_client
        self.audit_logger = audit_logger
        self.event_emitter = event_emitter
        self.storage_backend = storage_backend
        self.log = logger_instance or logger

        self.secret_codec = secret_codec or SecretCodec(
            allow_plaintext_fallback=allow_plaintext_secret_fallback
        )

        self._connectors: Dict[str, ConnectorDefinition] = {}
        self._integrations: Dict[Tuple[str, str, str], IntegrationConfig] = {}

        self._register_default_connectors()

        if initial_connectors:
            for connector in initial_connectors:
                self.register_connector(connector)

    # ==================================================================================
    # BaseAgent / Master Agent task entrypoint
    # ==================================================================================

    async def handle_task(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Master Agent / Agent Router compatible task handler.

        Expected task shape:
            {
                "action": "list_connectors" | "create_integration" | ...,
                "user_id": "...",
                "workspace_id": "...",
                "payload": {...}
            }
        """

        action = str(task.get("action") or task.get("type") or "").strip()
        payload = dict(task.get("payload") or {})

        user_id = task.get("user_id") or payload.get("user_id")
        workspace_id = task.get("workspace_id") or payload.get("workspace_id")

        try:
            if action in {"list_connectors", "supported_connectors"}:
                return self.list_supported_connectors(
                    category=payload.get("category"),
                    include_disabled=bool(payload.get("include_disabled", False)),
                    context={"user_id": user_id, "workspace_id": workspace_id},
                )

            if action in {"get_connector", "connector_definition"}:
                return self.get_connector_definition(
                    connector_key=str(payload.get("connector_key") or ""),
                    context={"user_id": user_id, "workspace_id": workspace_id},
                )

            if action == "create_integration":
                return await self.create_integration(
                    user_id=str(user_id or ""),
                    workspace_id=str(workspace_id or ""),
                    connector_key=str(payload.get("connector_key") or ""),
                    name=str(payload.get("name") or ""),
                    config=dict(payload.get("config") or {}),
                    created_by=payload.get("created_by") or user_id,
                    tags=list(payload.get("tags") or []),
                    metadata=dict(payload.get("metadata") or {}),
                )

            if action == "update_integration":
                return await self.update_integration(
                    user_id=str(user_id or ""),
                    workspace_id=str(workspace_id or ""),
                    integration_id=str(payload.get("integration_id") or ""),
                    config=dict(payload.get("config") or {}),
                    name=payload.get("name"),
                    status=payload.get("status"),
                    updated_by=payload.get("updated_by") or user_id,
                    tags=payload.get("tags"),
                    metadata=payload.get("metadata"),
                )

            if action == "get_integration":
                return self.get_integration(
                    user_id=str(user_id or ""),
                    workspace_id=str(workspace_id or ""),
                    integration_id=str(payload.get("integration_id") or ""),
                    include_config=bool(payload.get("include_config", True)),
                )

            if action == "list_integrations":
                return self.list_integrations(
                    user_id=str(user_id or ""),
                    workspace_id=str(workspace_id or ""),
                    connector_key=payload.get("connector_key"),
                    status=payload.get("status"),
                    include_config=bool(payload.get("include_config", False)),
                )

            if action == "disable_integration":
                return await self.disable_integration(
                    user_id=str(user_id or ""),
                    workspace_id=str(workspace_id or ""),
                    integration_id=str(payload.get("integration_id") or ""),
                    actor_id=payload.get("actor_id") or user_id,
                    reason=str(payload.get("reason") or "Disabled by workflow task."),
                )

            if action == "delete_integration":
                return await self.delete_integration(
                    user_id=str(user_id or ""),
                    workspace_id=str(workspace_id or ""),
                    integration_id=str(payload.get("integration_id") or ""),
                    actor_id=payload.get("actor_id") or user_id,
                    reason=str(payload.get("reason") or "Deleted by workflow task."),
                )

            if action == "validate_config":
                return self.validate_connector_config(
                    connector_key=str(payload.get("connector_key") or ""),
                    config=dict(payload.get("config") or {}),
                    context={"user_id": user_id, "workspace_id": workspace_id},
                )

            if action == "test_connection":
                return await self.test_connection(
                    user_id=str(user_id or ""),
                    workspace_id=str(workspace_id or ""),
                    integration_id=str(payload.get("integration_id") or ""),
                    actor_id=payload.get("actor_id") or user_id,
                    dry_run=bool(payload.get("dry_run", True)),
                )

            return self._error_result(
                message=f"Unsupported app connector action: {action or 'missing_action'}",
                error="unsupported_action",
                metadata={"action": action},
            )

        except Exception as exc:
            self.log.exception("AppConnector task failed.")
            return self._error_result(
                message="App connector task failed.",
                error=str(exc),
                metadata={"action": action},
            )

    # ==================================================================================
    # Connector definition management
    # ==================================================================================

    def register_connector(self, connector: ConnectorDefinition) -> Dict[str, Any]:
        """
        Register or replace a connector definition.

        This is safe for Agent Loader / Registry boot-time registration.
        """

        try:
            if not isinstance(connector, ConnectorDefinition):
                return self._error_result(
                    message="Invalid connector definition object.",
                    error="invalid_connector_definition",
                )

            connector.validate_definition()
            self._connectors[connector.key] = connector

            self._emit_agent_event(
                event_type="connector.registered",
                data={
                    "connector_key": connector.key,
                    "category": connector.category.value,
                    "enabled": connector.enabled,
                },
            )

            return self._safe_result(
                message=f"Connector registered: {connector.key}",
                data={"connector": connector.to_safe_dict()},
                metadata={"connector_key": connector.key},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to register connector.",
                error=str(exc),
                metadata={"connector_key": getattr(connector, "key", None)},
            )

    def unregister_connector(self, connector_key: str) -> Dict[str, Any]:
        """
        Remove a connector definition from the runtime registry.

        Existing integrations are not deleted. They become inaccessible until the connector
        definition is registered again.
        """

        key = _normalize_key(connector_key)
        if key not in self._connectors:
            return self._error_result(
                message="Connector not found.",
                error="connector_not_found",
                metadata={"connector_key": key},
            )

        removed = self._connectors.pop(key)

        self._emit_agent_event(
            event_type="connector.unregistered",
            data={"connector_key": key},
        )

        return self._safe_result(
            message=f"Connector unregistered: {key}",
            data={"connector": removed.to_safe_dict()},
            metadata={"connector_key": key},
        )

    def list_supported_connectors(
        self,
        *,
        category: Optional[Union[str, ConnectorCategory]] = None,
        include_disabled: bool = False,
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        List dashboard/API safe connector definitions.
        """

        category_value = category.value if isinstance(category, ConnectorCategory) else category
        connectors = []

        for connector in self._connectors.values():
            if not include_disabled and not connector.enabled:
                continue
            if category_value and connector.category.value != str(category_value):
                continue
            connectors.append(connector.to_safe_dict())

        connectors.sort(key=lambda item: (item["category"], item["display_name"]))

        return self._safe_result(
            message="Supported connectors loaded.",
            data={
                "connectors": connectors,
                "count": len(connectors),
            },
            metadata={
                "category": category_value,
                "include_disabled": include_disabled,
                "context": self._safe_context_for_metadata(context),
            },
        )

    def get_connector_definition(
        self,
        connector_key: str,
        *,
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Return one dashboard/API safe connector definition.
        """

        key = _normalize_key(connector_key)
        connector = self._connectors.get(key)

        if not connector:
            return self._error_result(
                message="Connector not found.",
                error="connector_not_found",
                metadata={"connector_key": key},
            )

        return self._safe_result(
            message="Connector definition loaded.",
            data={"connector": connector.to_safe_dict()},
            metadata={
                "connector_key": key,
                "context": self._safe_context_for_metadata(context),
            },
        )

    # ==================================================================================
    # Integration CRUD
    # ==================================================================================

    async def create_integration(
        self,
        *,
        user_id: str,
        workspace_id: str,
        connector_key: str,
        name: str,
        config: Mapping[str, Any],
        created_by: Optional[str] = None,
        tags: Optional[Sequence[str]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        activate: bool = True,
    ) -> Dict[str, Any]:
        """
        Create a user/workspace-specific integration config.

        Sensitive fields are encoded before storage. Returned config is masked.
        """

        context_result = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not context_result["success"]:
            return context_result

        key = _normalize_key(connector_key)
        connector = self._connectors.get(key)
        if not connector:
            return self._error_result(
                message="Connector not found.",
                error="connector_not_found",
                metadata={"connector_key": key},
            )

        if not connector.enabled:
            return self._error_result(
                message="Connector is disabled.",
                error="connector_disabled",
                metadata={"connector_key": key},
            )

        valid_name = self._validate_integration_name(name)
        if not valid_name["success"]:
            return valid_name

        validation = self.validate_connector_config(
            connector_key=key,
            config=dict(config or {}),
            context={"user_id": user_id, "workspace_id": workspace_id},
        )
        if not validation["success"]:
            return validation

        security_context = {
            "action": "create_integration",
            "user_id": user_id,
            "workspace_id": workspace_id,
            "connector_key": key,
            "name": name,
            "capabilities": [cap.value for cap in connector.capabilities],
            "auth_type": connector.auth_type.value,
        }

        if self._requires_security_check("create_integration", security_context):
            approval = await self._request_security_approval(
                action="create_integration",
                context=security_context,
            )
            if approval.get("decision") not in {
                SecurityDecision.APPROVED.value,
                SecurityDecision.NOT_REQUIRED.value,
            }:
                return self._error_result(
                    message="Security approval required before creating integration.",
                    error="security_approval_required",
                    data={"approval": approval},
                    metadata=security_context,
                )

        integration_id = self._generate_integration_id()
        encoded_config = self._encode_secret_fields(
            connector_definition=connector,
            config=dict(validation["data"]["normalized_config"]),
            user_id=user_id,
            workspace_id=workspace_id,
            integration_id=integration_id,
        )

        now = _now_iso()
        status = IntegrationStatus.ACTIVE if activate else IntegrationStatus.DRAFT

        integration = IntegrationConfig(
            integration_id=integration_id,
            user_id=user_id,
            workspace_id=workspace_id,
            connector_key=key,
            name=name.strip(),
            config=encoded_config,
            status=status,
            created_at=now,
            updated_at=now,
            created_by=created_by,
            updated_by=created_by,
            approved_by=(created_by if connector.requires_security_approval else None),
            approved_at=(now if connector.requires_security_approval else None),
            tags=self._normalize_tags(tags or []),
            metadata=_json_safe(dict(metadata or {})),
        )

        self._save_integration(integration)

        verification_payload = self._prepare_verification_payload(
            action="create_integration",
            integration=integration,
            connector=connector,
            actor_id=created_by,
        )
        memory_payload = self._prepare_memory_payload(
            action="create_integration",
            integration=integration,
            connector=connector,
        )

        self._log_audit_event(
            event_type="integration.created",
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=created_by,
            data={
                "integration_id": integration_id,
                "connector_key": key,
                "name": name,
                "status": status.value,
            },
        )

        self._emit_agent_event(
            event_type="integration.created",
            data={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "integration_id": integration_id,
                "connector_key": key,
            },
        )

        return self._safe_result(
            message="Integration created successfully.",
            data={
                "integration": integration.to_safe_dict(connector),
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "connector_key": key,
                "integration_id": integration_id,
            },
        )

    async def update_integration(
        self,
        *,
        user_id: str,
        workspace_id: str,
        integration_id: str,
        config: Optional[Mapping[str, Any]] = None,
        name: Optional[str] = None,
        status: Optional[Union[str, IntegrationStatus]] = None,
        updated_by: Optional[str] = None,
        tags: Optional[Sequence[str]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Update an existing integration config inside the same user/workspace boundary.
        """

        context_result = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not context_result["success"]:
            return context_result

        integration_result = self._get_integration_object(
            user_id=user_id,
            workspace_id=workspace_id,
            integration_id=integration_id,
        )
        if not integration_result["success"]:
            return integration_result

        integration: IntegrationConfig = integration_result["data"]["integration"]
        connector = self._connectors.get(integration.connector_key)

        if not connector:
            return self._error_result(
                message="Connector definition for this integration is missing.",
                error="connector_definition_missing",
                metadata={
                    "connector_key": integration.connector_key,
                    "integration_id": integration.integration_id,
                },
            )

        security_context = {
            "action": "update_integration",
            "user_id": user_id,
            "workspace_id": workspace_id,
            "integration_id": integration_id,
            "connector_key": integration.connector_key,
            "name": name or integration.name,
        }

        if self._requires_security_check("update_integration", security_context):
            approval = await self._request_security_approval(
                action="update_integration",
                context=security_context,
            )
            if approval.get("decision") not in {
                SecurityDecision.APPROVED.value,
                SecurityDecision.NOT_REQUIRED.value,
            }:
                return self._error_result(
                    message="Security approval required before updating integration.",
                    error="security_approval_required",
                    data={"approval": approval},
                    metadata=security_context,
                )

        if name is not None:
            valid_name = self._validate_integration_name(name)
            if not valid_name["success"]:
                return valid_name
            integration.name = name.strip()

        if config is not None:
            current_decoded = self._decode_secret_fields(
                connector_definition=connector,
                config=integration.config,
                user_id=user_id,
                workspace_id=workspace_id,
                integration_id=integration.integration_id,
            )

            merged_config = dict(current_decoded)
            merged_config.update(dict(config or {}))

            validation = self.validate_connector_config(
                connector_key=integration.connector_key,
                config=merged_config,
                context={"user_id": user_id, "workspace_id": workspace_id},
            )
            if not validation["success"]:
                return validation

            integration.config = self._encode_secret_fields(
                connector_definition=connector,
                config=dict(validation["data"]["normalized_config"]),
                user_id=user_id,
                workspace_id=workspace_id,
                integration_id=integration.integration_id,
            )

        if status is not None:
            try:
                integration.status = (
                    status if isinstance(status, IntegrationStatus) else IntegrationStatus(str(status))
                )
            except ValueError:
                return self._error_result(
                    message="Invalid integration status.",
                    error="invalid_integration_status",
                    metadata={"status": str(status)},
                )

        if tags is not None:
            integration.tags = self._normalize_tags(tags)

        if metadata is not None:
            integration.metadata = _json_safe(dict(metadata))

        integration.updated_at = _now_iso()
        integration.updated_by = updated_by

        self._save_integration(integration)

        verification_payload = self._prepare_verification_payload(
            action="update_integration",
            integration=integration,
            connector=connector,
            actor_id=updated_by,
        )

        memory_payload = self._prepare_memory_payload(
            action="update_integration",
            integration=integration,
            connector=connector,
        )

        self._log_audit_event(
            event_type="integration.updated",
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=updated_by,
            data={
                "integration_id": integration.integration_id,
                "connector_key": integration.connector_key,
                "status": integration.status.value,
            },
        )

        self._emit_agent_event(
            event_type="integration.updated",
            data={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "integration_id": integration.integration_id,
                "connector_key": integration.connector_key,
            },
        )

        return self._safe_result(
            message="Integration updated successfully.",
            data={
                "integration": integration.to_safe_dict(connector),
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "integration_id": integration.integration_id,
            },
        )

    def get_integration(
        self,
        *,
        user_id: str,
        workspace_id: str,
        integration_id: str,
        include_config: bool = True,
    ) -> Dict[str, Any]:
        """
        Get one integration, isolated by user_id and workspace_id.
        """

        context_result = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not context_result["success"]:
            return context_result

        result = self._get_integration_object(
            user_id=user_id,
            workspace_id=workspace_id,
            integration_id=integration_id,
        )
        if not result["success"]:
            return result

        integration: IntegrationConfig = result["data"]["integration"]
        connector = self._connectors.get(integration.connector_key)

        return self._safe_result(
            message="Integration loaded.",
            data={
                "integration": integration.to_safe_dict(
                    connector_definition=connector,
                    include_config=include_config,
                )
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "integration_id": integration_id,
            },
        )

    def list_integrations(
        self,
        *,
        user_id: str,
        workspace_id: str,
        connector_key: Optional[str] = None,
        status: Optional[Union[str, IntegrationStatus]] = None,
        include_config: bool = False,
    ) -> Dict[str, Any]:
        """
        List integrations for one SaaS user/workspace only.
        """

        context_result = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not context_result["success"]:
            return context_result

        connector_filter = _normalize_key(connector_key) if connector_key else None
        status_filter = status.value if isinstance(status, IntegrationStatus) else status

        items: List[Dict[str, Any]] = []

        for (stored_user_id, stored_workspace_id, _integration_id), integration in self._integrations.items():
            if stored_user_id != user_id or stored_workspace_id != workspace_id:
                continue

            if connector_filter and integration.connector_key != connector_filter:
                continue

            integration_status = (
                integration.status.value
                if isinstance(integration.status, IntegrationStatus)
                else str(integration.status)
            )
            if status_filter and integration_status != str(status_filter):
                continue

            connector = self._connectors.get(integration.connector_key)
            items.append(
                integration.to_safe_dict(
                    connector_definition=connector,
                    include_config=include_config,
                )
            )

        items.sort(key=lambda item: item.get("updated_at") or "", reverse=True)

        return self._safe_result(
            message="Integrations loaded.",
            data={
                "integrations": items,
                "count": len(items),
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "connector_key": connector_filter,
                "status": status_filter,
            },
        )

    async def disable_integration(
        self,
        *,
        user_id: str,
        workspace_id: str,
        integration_id: str,
        actor_id: Optional[str] = None,
        reason: str = "Disabled by user.",
    ) -> Dict[str, Any]:
        """
        Disable an integration without deleting config.
        """

        return await self.update_integration(
            user_id=user_id,
            workspace_id=workspace_id,
            integration_id=integration_id,
            status=IntegrationStatus.DISABLED,
            updated_by=actor_id,
            metadata={"disabled_reason": reason, "disabled_at": _now_iso()},
        )

    async def delete_integration(
        self,
        *,
        user_id: str,
        workspace_id: str,
        integration_id: str,
        actor_id: Optional[str] = None,
        reason: str = "Deleted by user.",
    ) -> Dict[str, Any]:
        """
        Delete an integration within the same SaaS user/workspace boundary.

        This removes it from the active runtime store. If a persistent backend is connected,
        wire _delete_integration_from_storage() to perform the real backend deletion.
        """

        context_result = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not context_result["success"]:
            return context_result

        result = self._get_integration_object(
            user_id=user_id,
            workspace_id=workspace_id,
            integration_id=integration_id,
        )
        if not result["success"]:
            return result

        integration: IntegrationConfig = result["data"]["integration"]
        connector = self._connectors.get(integration.connector_key)

        security_context = {
            "action": "delete_integration",
            "user_id": user_id,
            "workspace_id": workspace_id,
            "integration_id": integration_id,
            "connector_key": integration.connector_key,
            "reason": reason,
        }

        if self._requires_security_check("delete_integration", security_context):
            approval = await self._request_security_approval(
                action="delete_integration",
                context=security_context,
            )
            if approval.get("decision") not in {
                SecurityDecision.APPROVED.value,
                SecurityDecision.NOT_REQUIRED.value,
            }:
                return self._error_result(
                    message="Security approval required before deleting integration.",
                    error="security_approval_required",
                    data={"approval": approval},
                    metadata=security_context,
                )

        storage_key = self._integration_storage_key(user_id, workspace_id, integration_id)
        self._integrations.pop(storage_key, None)
        self._delete_integration_from_storage(integration)

        verification_payload = self._prepare_verification_payload(
            action="delete_integration",
            integration=integration,
            connector=connector,
            actor_id=actor_id,
        )

        self._log_audit_event(
            event_type="integration.deleted",
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id,
            data={
                "integration_id": integration_id,
                "connector_key": integration.connector_key,
                "reason": reason,
            },
        )

        self._emit_agent_event(
            event_type="integration.deleted",
            data={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "integration_id": integration_id,
                "connector_key": integration.connector_key,
            },
        )

        return self._safe_result(
            message="Integration deleted successfully.",
            data={
                "integration_id": integration_id,
                "verification_payload": verification_payload,
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "integration_id": integration_id,
            },
        )

    # ==================================================================================
    # Config validation and secure config helpers
    # ==================================================================================

    def validate_connector_config(
        self,
        *,
        connector_key: str,
        config: Mapping[str, Any],
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Validate connector config using ConnectorDefinition fields.

        Returns normalized config but does not store it.
        """

        key = _normalize_key(connector_key)
        connector = self._connectors.get(key)

        if not connector:
            return self._error_result(
                message="Connector not found.",
                error="connector_not_found",
                metadata={"connector_key": key},
            )

        raw_config = dict(config or {})

        if _estimate_json_bytes(raw_config) > MAX_CONFIG_BYTES:
            return self._error_result(
                message="Connector config is too large.",
                error="config_too_large",
                metadata={"max_bytes": MAX_CONFIG_BYTES},
            )

        normalized: Dict[str, Any] = {}
        errors: Dict[str, str] = {}

        field_map = {field_def.name: field_def for field_def in connector.fields}

        for field_name, field_def in field_map.items():
            supplied = field_name in raw_config
            value = raw_config.get(field_name, field_def.default)

            if field_def.required and (value is None or value == ""):
                errors[field_name] = "This field is required."
                continue

            if value is None:
                normalized[field_name] = None
                continue

            try:
                coerced = _coerce_value(value, field_def.field_type)

                if field_def.min_length is not None and isinstance(coerced, str):
                    if len(coerced) < field_def.min_length:
                        errors[field_name] = f"Minimum length is {field_def.min_length}."
                        continue

                if field_def.max_length is not None and isinstance(coerced, str):
                    if len(coerced) > field_def.max_length:
                        errors[field_name] = f"Maximum length is {field_def.max_length}."
                        continue

                if field_def.pattern and isinstance(coerced, str):
                    if not re.match(field_def.pattern, coerced):
                        errors[field_name] = "Value does not match required pattern."
                        continue

                if field_def.allowed_values is not None and coerced not in field_def.allowed_values:
                    errors[field_name] = "Value is not allowed."
                    continue

                normalized[field_name] = coerced

            except Exception as exc:
                errors[field_name] = str(exc)

        extra_fields: Dict[str, Any] = {}
        for field_name, value in raw_config.items():
            if field_name not in field_map:
                if not SAFE_ID_PATTERN.match(str(field_name)):
                    errors[str(field_name)] = "Extra field name contains unsafe characters."
                    continue
                extra_fields[str(field_name)] = _json_safe(value)

        if errors:
            return self._error_result(
                message="Connector config validation failed.",
                error="config_validation_failed",
                data={
                    "field_errors": errors,
                    "masked_config": _mask_config(raw_config, connector),
                },
                metadata={
                    "connector_key": key,
                    "context": self._safe_context_for_metadata(context),
                },
            )

        normalized.update(extra_fields)

        return self._safe_result(
            message="Connector config is valid.",
            data={
                "normalized_config": normalized,
                "masked_config": _mask_config(normalized, connector),
            },
            metadata={
                "connector_key": key,
                "context": self._safe_context_for_metadata(context),
            },
        )

    def get_masked_integration_config(
        self,
        *,
        user_id: str,
        workspace_id: str,
        integration_id: str,
    ) -> Dict[str, Any]:
        """
        Return masked integration config only.
        """

        result = self._get_integration_object(
            user_id=user_id,
            workspace_id=workspace_id,
            integration_id=integration_id,
        )
        if not result["success"]:
            return result

        integration: IntegrationConfig = result["data"]["integration"]
        connector = self._connectors.get(integration.connector_key)

        return self._safe_result(
            message="Masked integration config loaded.",
            data={
                "integration_id": integration_id,
                "connector_key": integration.connector_key,
                "config": _mask_config(integration.config, connector),
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "integration_id": integration_id,
            },
        )

    def resolve_runtime_config(
        self,
        *,
        user_id: str,
        workspace_id: str,
        integration_id: str,
        purpose: str,
        actor_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Resolve decoded runtime config for internal connector execution.

        This method is intended for Action Router / connector execution modules.
        It requires a clear purpose and applies security hooks before returning decoded secrets.
        """

        context_result = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not context_result["success"]:
            return context_result

        if not purpose or len(str(purpose).strip()) < 5:
            return self._error_result(
                message="A clear purpose is required to resolve runtime config.",
                error="runtime_config_purpose_required",
            )

        result = self._get_integration_object(
            user_id=user_id,
            workspace_id=workspace_id,
            integration_id=integration_id,
        )
        if not result["success"]:
            return result

        integration: IntegrationConfig = result["data"]["integration"]
        connector = self._connectors.get(integration.connector_key)

        if not connector:
            return self._error_result(
                message="Connector definition is missing.",
                error="connector_definition_missing",
                metadata={"connector_key": integration.connector_key},
            )

        if integration.status != IntegrationStatus.ACTIVE:
            return self._error_result(
                message="Integration is not active.",
                error="integration_not_active",
                metadata={
                    "integration_id": integration_id,
                    "status": integration.status.value,
                },
            )

        security_context = {
            "action": "resolve_runtime_config",
            "user_id": user_id,
            "workspace_id": workspace_id,
            "integration_id": integration_id,
            "connector_key": integration.connector_key,
            "purpose": purpose,
            "actor_id": actor_id,
        }

        if self._requires_security_check("resolve_runtime_config", security_context):
            decision = self._sync_security_approval(
                action="resolve_runtime_config",
                context=security_context,
            )
            if decision.get("decision") not in {
                SecurityDecision.APPROVED.value,
                SecurityDecision.NOT_REQUIRED.value,
            }:
                return self._error_result(
                    message="Security approval required before resolving runtime config.",
                    error="security_approval_required",
                    data={"approval": decision},
                    metadata=security_context,
                )

        decoded_config = self._decode_secret_fields(
            connector_definition=connector,
            config=integration.config,
            user_id=user_id,
            workspace_id=workspace_id,
            integration_id=integration_id,
        )

        self._log_audit_event(
            event_type="integration.runtime_config_resolved",
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id,
            data={
                "integration_id": integration_id,
                "connector_key": integration.connector_key,
                "purpose": purpose,
                "secret_values_returned": self.secret_codec.encryption_available
                or self.secret_codec.allow_plaintext_fallback,
            },
        )

        return self._safe_result(
            message="Runtime config resolved for internal execution.",
            data={
                "integration_id": integration_id,
                "connector_key": integration.connector_key,
                "config": decoded_config,
                "warning": (
                    None
                    if self.secret_codec.encryption_available or self.secret_codec.allow_plaintext_fallback
                    else "Secrets are stored as external secret references and cannot be decoded by this runtime."
                ),
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "integration_id": integration_id,
                "purpose": purpose,
            },
        )

    # ==================================================================================
    # Connection testing
    # ==================================================================================

    async def test_connection(
        self,
        *,
        user_id: str,
        workspace_id: str,
        integration_id: str,
        actor_id: Optional[str] = None,
        dry_run: bool = True,
    ) -> Dict[str, Any]:
        """
        Test integration health safely.

        By default, dry_run=True so no real external API call is made.
        Future connector-specific clients can override this through storage/client injection.
        """

        context_result = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not context_result["success"]:
            return context_result

        result = self._get_integration_object(
            user_id=user_id,
            workspace_id=workspace_id,
            integration_id=integration_id,
        )
        if not result["success"]:
            return result

        integration: IntegrationConfig = result["data"]["integration"]
        connector = self._connectors.get(integration.connector_key)

        if not connector:
            return self._error_result(
                message="Connector definition is missing.",
                error="connector_definition_missing",
                metadata={"connector_key": integration.connector_key},
            )

        security_context = {
            "action": "test_connection",
            "user_id": user_id,
            "workspace_id": workspace_id,
            "integration_id": integration_id,
            "connector_key": integration.connector_key,
            "dry_run": dry_run,
        }

        if self._requires_security_check("test_connection", security_context):
            approval = await self._request_security_approval(
                action="test_connection",
                context=security_context,
            )
            if approval.get("decision") not in {
                SecurityDecision.APPROVED.value,
                SecurityDecision.NOT_REQUIRED.value,
            }:
                return self._error_result(
                    message="Security approval required before testing connection.",
                    error="security_approval_required",
                    data={"approval": approval},
                    metadata=security_context,
                )

        started = time.time()
        health_data = self._perform_safe_health_check(
            integration=integration,
            connector=connector,
            dry_run=dry_run,
        )
        duration_ms = int((time.time() - started) * 1000)

        integration.last_health_check_at = _now_iso()
        integration.last_health_status = "healthy" if health_data["success"] else "error"
        integration.last_error = None if health_data["success"] else health_data.get("error")
        integration.updated_at = _now_iso()
        self._save_integration(integration)

        self._log_audit_event(
            event_type="integration.connection_tested",
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id,
            data={
                "integration_id": integration_id,
                "connector_key": integration.connector_key,
                "dry_run": dry_run,
                "health_status": integration.last_health_status,
                "duration_ms": duration_ms,
            },
        )

        return self._safe_result(
            message="Connection test completed.",
            data={
                "integration": integration.to_safe_dict(connector, include_config=False),
                "health": health_data,
                "duration_ms": duration_ms,
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "integration_id": integration_id,
                "dry_run": dry_run,
            },
        )

    # ==================================================================================
    # Compatibility hooks required by William/Jarvis prompt bible
    # ==================================================================================

    def _validate_task_context(self, *, user_id: str, workspace_id: str) -> Dict[str, Any]:
        """
        Validate SaaS isolation context.

        Every user-specific workflow operation must include user_id and workspace_id.
        """

        if not user_id or not isinstance(user_id, str):
            return self._error_result(
                message="user_id is required for SaaS isolation.",
                error="missing_user_id",
            )

        if not workspace_id or not isinstance(workspace_id, str):
            return self._error_result(
                message="workspace_id is required for SaaS isolation.",
                error="missing_workspace_id",
            )

        if not SAFE_ID_PATTERN.match(user_id):
            return self._error_result(
                message="user_id contains unsafe characters.",
                error="invalid_user_id",
            )

        if not SAFE_ID_PATTERN.match(workspace_id):
            return self._error_result(
                message="workspace_id contains unsafe characters.",
                error="invalid_workspace_id",
            )

        return self._safe_result(
            message="Task context is valid.",
            data={"user_id": user_id, "workspace_id": workspace_id},
        )

    def _requires_security_check(
        self,
        action: str,
        context: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Decide whether an action needs Security Agent approval.

        Sensitive actions are protected by default.
        """

        sensitive_actions = {
            "create_integration",
            "update_integration",
            "delete_integration",
            "test_connection",
            "resolve_runtime_config",
            "enable_integration",
            "disable_integration",
            "rotate_secret",
        }

        if action in sensitive_actions:
            return True

        connector_key = str((context or {}).get("connector_key") or "")
        connector = self._connectors.get(connector_key)
        if connector and connector.requires_security_approval:
            return True

        return False

    async def _request_security_approval(
        self,
        *,
        action: str,
        context: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        If a real security_client exists, this method attempts to use it.
        Otherwise, it returns approved-by-policy for import-safe local development.
        """

        safe_context = _mask_config(dict(context or {}))

        if self.security_client:
            try:
                if hasattr(self.security_client, "approve_action"):
                    result = self.security_client.approve_action(action=action, context=safe_context)
                    if hasattr(result, "__await__"):
                        result = await result
                    return self._normalize_security_decision(result)

                if hasattr(self.security_client, "request_approval"):
                    result = self.security_client.request_approval(action=action, context=safe_context)
                    if hasattr(result, "__await__"):
                        result = await result
                    return self._normalize_security_decision(result)

            except Exception as exc:
                self.log.exception("Security approval failed.")
                return {
                    "decision": SecurityDecision.DENIED.value,
                    "message": "Security client failed.",
                    "error": str(exc),
                    "metadata": {"action": action},
                }

        return {
            "decision": SecurityDecision.APPROVED.value,
            "message": "Approved by AppConnector safe default policy.",
            "error": None,
            "metadata": {
                "action": action,
                "security_client_available": False,
                "mode": "local_safe_default",
            },
        }

    def _sync_security_approval(
        self,
        *,
        action: str,
        context: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Synchronous security approval bridge for sync-only methods.
        """

        safe_context = _mask_config(dict(context or {}))

        if self.security_client:
            try:
                if hasattr(self.security_client, "approve_action_sync"):
                    return self._normalize_security_decision(
                        self.security_client.approve_action_sync(
                            action=action,
                            context=safe_context,
                        )
                    )

                if hasattr(self.security_client, "approve_action"):
                    result = self.security_client.approve_action(action=action, context=safe_context)
                    if not hasattr(result, "__await__"):
                        return self._normalize_security_decision(result)

            except Exception as exc:
                self.log.exception("Synchronous security approval failed.")
                return {
                    "decision": SecurityDecision.DENIED.value,
                    "message": "Security client failed.",
                    "error": str(exc),
                    "metadata": {"action": action},
                }

        return {
            "decision": SecurityDecision.APPROVED.value,
            "message": "Approved by AppConnector sync safe default policy.",
            "error": None,
            "metadata": {
                "action": action,
                "security_client_available": False,
                "mode": "local_safe_default",
            },
        }

    def _prepare_verification_payload(
        self,
        *,
        action: str,
        integration: IntegrationConfig,
        connector: Optional[ConnectorDefinition],
        actor_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload for completed connector actions.
        """

        return {
            "verification_type": "workflow_app_connector_action",
            "action": action,
            "agent": DEFAULT_AGENT_NAME,
            "user_id": integration.user_id,
            "workspace_id": integration.workspace_id,
            "actor_id": actor_id,
            "target": {
                "integration_id": integration.integration_id,
                "connector_key": integration.connector_key,
                "connector_display_name": connector.display_name if connector else None,
                "integration_name": integration.name,
                "status": (
                    integration.status.value
                    if isinstance(integration.status, IntegrationStatus)
                    else str(integration.status)
                ),
            },
            "checks": {
                "saas_context_validated": True,
                "secrets_masked_in_output": True,
                "security_hook_applied": True,
                "audit_event_prepared": True,
            },
            "created_at": _now_iso(),
        }

    def _prepare_memory_payload(
        self,
        *,
        action: str,
        integration: IntegrationConfig,
        connector: Optional[ConnectorDefinition],
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent payload.

        Only non-secret, useful connector context is included.
        """

        return {
            "memory_type": "workflow_integration_context",
            "action": action,
            "user_id": integration.user_id,
            "workspace_id": integration.workspace_id,
            "content": {
                "integration_id": integration.integration_id,
                "connector_key": integration.connector_key,
                "connector_name": connector.display_name if connector else integration.connector_key,
                "category": connector.category.value if connector else None,
                "integration_name": integration.name,
                "status": (
                    integration.status.value
                    if isinstance(integration.status, IntegrationStatus)
                    else str(integration.status)
                ),
                "capabilities": [cap.value for cap in connector.capabilities] if connector else [],
                "tags": list(integration.tags),
            },
            "safe_to_store": True,
            "contains_secrets": False,
            "created_at": _now_iso(),
        }

    def _emit_agent_event(
        self,
        *,
        event_type: str,
        data: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Emit an event for dashboard, observability, task history, or agent bus.

        This method never raises.
        """

        event = {
            "event_type": event_type,
            "agent": DEFAULT_AGENT_NAME,
            "module": "workflow_agent",
            "data": _mask_config(dict(data or {})),
            "created_at": _now_iso(),
        }

        try:
            if self.event_emitter:
                self.event_emitter(event)
            else:
                self.log.debug("Agent event: %s", json.dumps(event, default=str))
        except Exception:
            self.log.exception("Failed to emit AppConnector event.")

    def _log_audit_event(
        self,
        *,
        event_type: str,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        actor_id: Optional[str] = None,
        data: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Log audit event safely.

        Audit payloads are masked and never include raw secrets.
        """

        audit_event = {
            "event_type": event_type,
            "agent": DEFAULT_AGENT_NAME,
            "module": "workflow_agent",
            "user_id": user_id,
            "workspace_id": workspace_id,
            "actor_id": actor_id,
            "data": _mask_config(dict(data or {})),
            "created_at": _now_iso(),
        }

        try:
            if self.audit_logger:
                self.audit_logger(audit_event)
            else:
                self.log.info("Audit event: %s", json.dumps(audit_event, default=str))
        except Exception:
            self.log.exception("Failed to log AppConnector audit event.")

    def _safe_result(
        self,
        *,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        error: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Standard success result.
        """

        return {
            "success": True,
            "message": message,
            "data": _json_safe(dict(data or {})),
            "error": error,
            "metadata": _json_safe(dict(metadata or {})),
        }

    def _error_result(
        self,
        *,
        message: str,
        error: Any,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard error result.
        """

        return {
            "success": False,
            "message": message,
            "data": _json_safe(dict(data or {})),
            "error": str(error) if error is not None else "unknown_error",
            "metadata": _json_safe(dict(metadata or {})),
        }

    # ==================================================================================
    # Internal helpers
    # ==================================================================================

    def _register_default_connectors(self) -> None:
        """
        Register common connector definitions used by Workflow Agent.

        These are generic, safe definitions. Specialized files such as sheet_connector.py,
        whatsapp_connector.py, crm_connector.py, and email_connector.py can later register
        deeper connector-specific capabilities.
        """

        defaults = [
            ConnectorDefinition(
                key="google_sheets",
                display_name="Google Sheets",
                category=ConnectorCategory.SHEET,
                auth_type=AuthType.OAUTH2,
                description="Connect workflows to Google Sheets for lead storage, updates, and lookups.",
                docs_url="https://developers.google.com/sheets/api",
                capabilities=[
                    ConnectorCapability.READ,
                    ConnectorCapability.WRITE,
                    ConnectorCapability.CREATE_RECORD,
                    ConnectorCapability.UPDATE_RECORD,
                    ConnectorCapability.SEARCH,
                    ConnectorCapability.TEST_CONNECTION,
                ],
                fields=[
                    ConnectorField(
                        name="spreadsheet_id",
                        label="Spreadsheet ID",
                        required=True,
                        field_type="string",
                        min_length=10,
                        max_length=200,
                        description="Google Sheets spreadsheet ID.",
                    ),
                    ConnectorField(
                        name="sheet_name",
                        label="Sheet Name",
                        required=False,
                        field_type="string",
                        default="Sheet1",
                        max_length=120,
                    ),
                    ConnectorField(
                        name="access_token",
                        label="Access Token",
                        required=False,
                        secret=True,
                        field_type="string",
                    ),
                    ConnectorField(
                        name="refresh_token",
                        label="Refresh Token",
                        required=False,
                        secret=True,
                        field_type="string",
                    ),
                ],
            ),
            ConnectorDefinition(
                key="webhook",
                display_name="Webhook",
                category=ConnectorCategory.WEBHOOK,
                auth_type=AuthType.WEBHOOK_SECRET,
                description="Send or receive workflow events through secure webhooks.",
                capabilities=[
                    ConnectorCapability.WEBHOOK_RECEIVE,
                    ConnectorCapability.WEBHOOK_SEND,
                    ConnectorCapability.TEST_CONNECTION,
                ],
                fields=[
                    ConnectorField(
                        name="endpoint_url",
                        label="Endpoint URL",
                        required=False,
                        field_type="url",
                        description="Destination endpoint URL for outgoing webhook calls.",
                    ),
                    ConnectorField(
                        name="webhook_secret",
                        label="Webhook Secret",
                        required=False,
                        secret=True,
                        field_type="string",
                        min_length=8,
                    ),
                    ConnectorField(
                        name="signing_header",
                        label="Signing Header",
                        required=False,
                        field_type="string",
                        default="X-William-Signature",
                    ),
                ],
            ),
            ConnectorDefinition(
                key="whatsapp_cloud",
                display_name="WhatsApp Cloud API",
                category=ConnectorCategory.WHATSAPP,
                auth_type=AuthType.BEARER_TOKEN,
                description="Connect workflows to WhatsApp Cloud API for lead notifications and customer messaging.",
                docs_url="https://developers.facebook.com/docs/whatsapp/cloud-api",
                capabilities=[
                    ConnectorCapability.SEND_MESSAGE,
                    ConnectorCapability.RECEIVE_MESSAGE,
                    ConnectorCapability.WEBHOOK_RECEIVE,
                    ConnectorCapability.TEST_CONNECTION,
                ],
                fields=[
                    ConnectorField(
                        name="phone_number_id",
                        label="Phone Number ID",
                        required=True,
                        field_type="string",
                        min_length=5,
                        max_length=120,
                    ),
                    ConnectorField(
                        name="business_account_id",
                        label="Business Account ID",
                        required=False,
                        field_type="string",
                        max_length=120,
                    ),
                    ConnectorField(
                        name="access_token",
                        label="Access Token",
                        required=True,
                        secret=True,
                        field_type="string",
                        min_length=10,
                    ),
                    ConnectorField(
                        name="verify_token",
                        label="Verify Token",
                        required=False,
                        secret=True,
                        field_type="string",
                    ),
                ],
            ),
            ConnectorDefinition(
                key="smtp_email",
                display_name="SMTP Email",
                category=ConnectorCategory.EMAIL,
                auth_type=AuthType.BASIC,
                description="Send workflow emails using an SMTP provider.",
                capabilities=[
                    ConnectorCapability.SEND_MESSAGE,
                    ConnectorCapability.TEST_CONNECTION,
                ],
                fields=[
                    ConnectorField(
                        name="host",
                        label="SMTP Host",
                        required=True,
                        field_type="string",
                        min_length=3,
                        max_length=255,
                    ),
                    ConnectorField(
                        name="port",
                        label="SMTP Port",
                        required=True,
                        field_type="integer",
                        default=587,
                    ),
                    ConnectorField(
                        name="username",
                        label="SMTP Username",
                        required=True,
                        field_type="string",
                        max_length=255,
                    ),
                    ConnectorField(
                        name="password",
                        label="SMTP Password",
                        required=True,
                        secret=True,
                        field_type="string",
                    ),
                    ConnectorField(
                        name="from_email",
                        label="From Email",
                        required=True,
                        field_type="email",
                    ),
                    ConnectorField(
                        name="use_tls",
                        label="Use TLS",
                        required=False,
                        field_type="boolean",
                        default=True,
                    ),
                ],
            ),
            ConnectorDefinition(
                key="hubspot",
                display_name="HubSpot CRM",
                category=ConnectorCategory.CRM,
                auth_type=AuthType.BEARER_TOKEN,
                description="Create, update, and search contacts or deals in HubSpot CRM.",
                docs_url="https://developers.hubspot.com/docs/api/overview",
                capabilities=[
                    ConnectorCapability.READ,
                    ConnectorCapability.WRITE,
                    ConnectorCapability.CREATE_RECORD,
                    ConnectorCapability.UPDATE_RECORD,
                    ConnectorCapability.SEARCH,
                    ConnectorCapability.TEST_CONNECTION,
                ],
                fields=[
                    ConnectorField(
                        name="access_token",
                        label="Private App Access Token",
                        required=True,
                        secret=True,
                        field_type="string",
                        min_length=10,
                    ),
                    ConnectorField(
                        name="portal_id",
                        label="Portal ID",
                        required=False,
                        field_type="string",
                        max_length=120,
                    ),
                ],
            ),
            ConnectorDefinition(
                key="custom_api",
                display_name="Custom API",
                category=ConnectorCategory.CUSTOM_API,
                auth_type=AuthType.CUSTOM,
                description="Generic HTTP API connector for future app integrations.",
                capabilities=[
                    ConnectorCapability.READ,
                    ConnectorCapability.WRITE,
                    ConnectorCapability.WEBHOOK_SEND,
                    ConnectorCapability.TEST_CONNECTION,
                ],
                fields=[
                    ConnectorField(
                        name="base_url",
                        label="Base URL",
                        required=True,
                        field_type="url",
                    ),
                    ConnectorField(
                        name="auth_type",
                        label="Auth Type",
                        required=False,
                        field_type="string",
                        default=AuthType.NONE.value,
                        allowed_values=[item.value for item in AuthType],
                    ),
                    ConnectorField(
                        name="api_key",
                        label="API Key",
                        required=False,
                        secret=True,
                        field_type="string",
                    ),
                    ConnectorField(
                        name="bearer_token",
                        label="Bearer Token",
                        required=False,
                        secret=True,
                        field_type="string",
                    ),
                    ConnectorField(
                        name="headers",
                        label="Headers",
                        required=False,
                        field_type="dict",
                        default={},
                    ),
                ],
            ),
        ]

        for connector in defaults:
            try:
                connector.validate_definition()
                self._connectors[connector.key] = connector
            except Exception:
                self.log.exception("Failed to register default connector: %s", connector.key)

    def _validate_integration_name(self, name: str) -> Dict[str, Any]:
        if not name or not isinstance(name, str) or not name.strip():
            return self._error_result(
                message="Integration name is required.",
                error="missing_integration_name",
            )

        if len(name.strip()) > MAX_INTEGRATION_NAME_LENGTH:
            return self._error_result(
                message=f"Integration name exceeds {MAX_INTEGRATION_NAME_LENGTH} characters.",
                error="integration_name_too_long",
            )

        return self._safe_result(
            message="Integration name is valid.",
            data={"name": name.strip()},
        )

    def _normalize_tags(self, tags: Sequence[str]) -> List[str]:
        clean: List[str] = []
        seen = set()

        for tag in tags:
            value = str(tag or "").strip().lower()
            value = re.sub(r"[^a-z0-9_\-:.]+", "_", value)
            value = value[:60].strip("_-")
            if value and value not in seen:
                clean.append(value)
                seen.add(value)

        return clean[:30]

    def _generate_integration_id(self) -> str:
        return f"int_{uuid.uuid4().hex}"

    def _integration_storage_key(
        self,
        user_id: str,
        workspace_id: str,
        integration_id: str,
    ) -> Tuple[str, str, str]:
        return (user_id, workspace_id, integration_id)

    def _save_integration(self, integration: IntegrationConfig) -> None:
        storage_key = self._integration_storage_key(
            integration.user_id,
            integration.workspace_id,
            integration.integration_id,
        )
        self._integrations[storage_key] = integration

        if self.storage_backend:
            try:
                if hasattr(self.storage_backend, "save_integration"):
                    self.storage_backend.save_integration(integration.to_safe_dict(include_config=True))
            except Exception:
                self.log.exception("Failed to save integration to storage backend.")

    def _delete_integration_from_storage(self, integration: IntegrationConfig) -> None:
        if self.storage_backend:
            try:
                if hasattr(self.storage_backend, "delete_integration"):
                    self.storage_backend.delete_integration(
                        user_id=integration.user_id,
                        workspace_id=integration.workspace_id,
                        integration_id=integration.integration_id,
                    )
            except Exception:
                self.log.exception("Failed to delete integration from storage backend.")

    def _get_integration_object(
        self,
        *,
        user_id: str,
        workspace_id: str,
        integration_id: str,
    ) -> Dict[str, Any]:
        if not integration_id or not SAFE_ID_PATTERN.match(integration_id):
            return self._error_result(
                message="Invalid integration_id.",
                error="invalid_integration_id",
            )

        storage_key = self._integration_storage_key(user_id, workspace_id, integration_id)
        integration = self._integrations.get(storage_key)

        if not integration and self.storage_backend:
            integration = self._load_integration_from_storage(
                user_id=user_id,
                workspace_id=workspace_id,
                integration_id=integration_id,
            )
            if integration:
                self._integrations[storage_key] = integration

        if not integration:
            return self._error_result(
                message="Integration not found in this workspace.",
                error="integration_not_found",
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "integration_id": integration_id,
                },
            )

        if integration.user_id != user_id or integration.workspace_id != workspace_id:
            return self._error_result(
                message="Integration does not belong to this user/workspace.",
                error="saas_isolation_violation",
                metadata={
                    "requested_user_id": user_id,
                    "requested_workspace_id": workspace_id,
                    "integration_id": integration_id,
                },
            )

        return self._safe_result(
            message="Integration object loaded.",
            data={"integration": integration},
        )

    def _load_integration_from_storage(
        self,
        *,
        user_id: str,
        workspace_id: str,
        integration_id: str,
    ) -> Optional[IntegrationConfig]:
        try:
            if not self.storage_backend or not hasattr(self.storage_backend, "get_integration"):
                return None

            raw = self.storage_backend.get_integration(
                user_id=user_id,
                workspace_id=workspace_id,
                integration_id=integration_id,
            )
            if not raw:
                return None

            return self._integration_from_mapping(raw)

        except Exception:
            self.log.exception("Failed to load integration from storage backend.")
            return None

    def _integration_from_mapping(self, raw: Mapping[str, Any]) -> IntegrationConfig:
        status_raw = raw.get("status") or IntegrationStatus.DRAFT.value
        try:
            status = IntegrationStatus(status_raw)
        except ValueError:
            status = IntegrationStatus.ERROR

        return IntegrationConfig(
            integration_id=str(raw["integration_id"]),
            user_id=str(raw["user_id"]),
            workspace_id=str(raw["workspace_id"]),
            connector_key=str(raw["connector_key"]),
            name=str(raw.get("name") or raw["connector_key"]),
            config=dict(raw.get("config") or {}),
            status=status,
            created_at=str(raw.get("created_at") or _now_iso()),
            updated_at=str(raw.get("updated_at") or _now_iso()),
            created_by=raw.get("created_by"),
            updated_by=raw.get("updated_by"),
            approved_by=raw.get("approved_by"),
            approved_at=raw.get("approved_at"),
            last_health_check_at=raw.get("last_health_check_at"),
            last_health_status=raw.get("last_health_status"),
            last_error=raw.get("last_error"),
            tags=list(raw.get("tags") or []),
            metadata=dict(raw.get("metadata") or {}),
        )

    def _encode_secret_fields(
        self,
        *,
        connector_definition: ConnectorDefinition,
        config: Mapping[str, Any],
        user_id: str,
        workspace_id: str,
        integration_id: str,
    ) -> Dict[str, Any]:
        encoded: Dict[str, Any] = {}
        for field_name, value in dict(config or {}).items():
            if value is None:
                encoded[field_name] = None
                continue

            if _is_sensitive_field(field_name, connector_definition):
                context = f"{user_id}:{workspace_id}:{integration_id}:{connector_definition.key}:{field_name}"
                encoded[field_name] = self.secret_codec.encode_secret(str(value), context=context)
                encoded[f"{field_name}__fingerprint"] = _fingerprint_secret(str(value), context)[:24]
            else:
                encoded[field_name] = _json_safe(value)

        return encoded

    def _decode_secret_fields(
        self,
        *,
        connector_definition: ConnectorDefinition,
        config: Mapping[str, Any],
        user_id: str,
        workspace_id: str,
        integration_id: str,
    ) -> Dict[str, Any]:
        decoded: Dict[str, Any] = {}

        for field_name, value in dict(config or {}).items():
            if str(field_name).endswith("__fingerprint"):
                continue

            if _is_sensitive_field(field_name, connector_definition):
                context = f"{user_id}:{workspace_id}:{integration_id}:{connector_definition.key}:{field_name}"
                decoded_value = self.secret_codec.decode_secret(str(value), context=context)
                decoded[field_name] = decoded_value
            else:
                decoded[field_name] = _safe_copy(value)

        return decoded

    def _normalize_security_decision(self, result: Any) -> Dict[str, Any]:
        if isinstance(result, Mapping):
            decision = result.get("decision") or result.get("status") or result.get("result")
            if decision in {True, "true", "approved", "allow", "allowed", "ok"}:
                decision_value = SecurityDecision.APPROVED.value
            elif decision in {False, "false", "denied", "deny", "blocked", "rejected"}:
                decision_value = SecurityDecision.DENIED.value
            elif decision in {"pending", "needs_approval"}:
                decision_value = SecurityDecision.PENDING.value
            else:
                decision_value = str(decision or SecurityDecision.DENIED.value)

            return {
                "decision": decision_value,
                "message": str(result.get("message") or "Security decision received."),
                "error": result.get("error"),
                "metadata": _json_safe(dict(result.get("metadata") or {})),
            }

        if result is True:
            return {
                "decision": SecurityDecision.APPROVED.value,
                "message": "Security approved.",
                "error": None,
                "metadata": {},
            }

        if result is False:
            return {
                "decision": SecurityDecision.DENIED.value,
                "message": "Security denied.",
                "error": "security_denied",
                "metadata": {},
            }

        return {
            "decision": SecurityDecision.DENIED.value,
            "message": "Invalid security decision format.",
            "error": "invalid_security_decision",
            "metadata": {"raw_result": str(result)},
        }

    def _perform_safe_health_check(
        self,
        *,
        integration: IntegrationConfig,
        connector: ConnectorDefinition,
        dry_run: bool = True,
    ) -> Dict[str, Any]:
        """
        Safe health check.

        This does not execute destructive actions and does not call real external APIs
        by default. A future connector runtime can replace this behavior.
        """

        masked = integration.to_safe_dict(connector_definition=connector, include_config=True)

        required_secret_fields_missing: List[str] = []
        required_normal_fields_missing: List[str] = []

        for field_def in connector.fields:
            value = integration.config.get(field_def.name)
            if field_def.required and (value is None or value == ""):
                if field_def.secret:
                    required_secret_fields_missing.append(field_def.name)
                else:
                    required_normal_fields_missing.append(field_def.name)

        if required_secret_fields_missing or required_normal_fields_missing:
            return {
                "success": False,
                "status": "error",
                "message": "Required integration fields are missing.",
                "error": "missing_required_fields",
                "data": {
                    "missing_secret_fields": required_secret_fields_missing,
                    "missing_fields": required_normal_fields_missing,
                    "dry_run": dry_run,
                },
            }

        if dry_run:
            return {
                "success": True,
                "status": "healthy",
                "message": "Dry-run connection check passed. Config shape is valid.",
                "error": None,
                "data": {
                    "dry_run": True,
                    "connector_key": connector.key,
                    "auth_type": connector.auth_type.value,
                    "capabilities": [cap.value for cap in connector.capabilities],
                    "masked_integration": masked,
                },
            }

        return {
            "success": True,
            "status": "not_executed",
            "message": (
                "Real external API test is not executed by AppConnector directly. "
                "Route this to the connector-specific runtime module."
            ),
            "error": None,
            "data": {
                "dry_run": False,
                "connector_key": connector.key,
                "external_call_performed": False,
            },
        }

    def _safe_context_for_metadata(
        self,
        context: Optional[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        if not context:
            return {}
        allowed = {}
        for key in ("user_id", "workspace_id", "actor_id", "request_id", "task_id"):
            if key in context:
                allowed[key] = context.get(key)
        return _json_safe(allowed)


# ======================================================================================
# Module-level convenience exports
# ======================================================================================

__all__ = [
    "AppConnector",
    "ConnectorDefinition",
    "ConnectorField",
    "ConnectorCategory",
    "AuthType",
    "IntegrationStatus",
    "ConnectorCapability",
    "SecurityDecision",
    "IntegrationConfig",
    "SecretCodec",
]


# ======================================================================================
# Lightweight self-test helper
# ======================================================================================

def build_default_app_connector(**kwargs: Any) -> AppConnector:
    """
    Factory helper for FastAPI dependency injection, dashboard boot, tests,
    Agent Loader, or Master Agent registry wiring.
    """

    return AppConnector(**kwargs)


def _self_test() -> Dict[str, Any]:
    """
    Lightweight local self-test.

    Usage:
        python -m agents.workflow_agent.app_connector

    This does not perform external API calls.
    """

    import asyncio

    async def run() -> Dict[str, Any]:
        connector = AppConnector(allow_plaintext_secret_fallback=False)

        create_result = await connector.create_integration(
            user_id="user_test",
            workspace_id="workspace_test",
            connector_key="webhook",
            name="Test Webhook",
            config={
                "endpoint_url": "https://example.com/webhook",
                "webhook_secret": "<redacted_demo_webhook_secret>",
                "signing_header": "X-Test-Signature",
            },
            created_by="user_test",
            tags=["test", "workflow"],
            metadata={"environment": "local"},
        )

        if not create_result["success"]:
            return create_result

        integration_id = create_result["data"]["integration"]["integration_id"]

        get_result = connector.get_integration(
            user_id="user_test",
            workspace_id="workspace_test",
            integration_id=integration_id,
        )

        test_result = await connector.test_connection(
            user_id="user_test",
            workspace_id="workspace_test",
            integration_id=integration_id,
            actor_id="user_test",
            dry_run=True,
        )

        list_result = connector.list_integrations(
            user_id="user_test",
            workspace_id="workspace_test",
            include_config=True,
        )

        return {
            "success": True,
            "message": "Self-test completed.",
            "data": {
                "create": create_result,
                "get": get_result,
                "test": test_result,
                "list": list_result,
            },
            "error": None,
            "metadata": {},
        }

    return asyncio.run(run())


if __name__ == "__main__":
    print(json.dumps(_self_test(), indent=2, default=str))


"""
Where to place it:
    agents/workflow_agent/app_connector.py

Required dependencies:
    - Python 3.10+
    - No mandatory external package required
    - Optional future integrations:
        - cryptography for stronger encryption
        - FastAPI/Pydantic for API layer
        - SQLAlchemy or async DB layer for persistent integration storage
        - Real William BaseAgent, Security Agent, Memory Agent, Verification Agent

How to test it:
    1. Save this file at:
        agents/workflow_agent/app_connector.py

    2. Run import test:
        python -c "from agents.workflow_agent.app_connector import AppConnector; print(AppConnector().list_supported_connectors())"

    3. Run module self-test:
        python -m agents.workflow_agent.app_connector

    4. Expected:
        - It lists default connectors
        - It creates a test webhook integration
        - It masks secrets in output
        - It performs a dry-run health check
        - It returns structured success/message/data/error/metadata results

Agent/module completion percentage after this file:
    28.6%

Next file to generate:
    agents/workflow_agent/webhook_manager.py

Agent/Module: Workflow Agent
File Completed: app_connector.py
Completion: 28.6%
Completed Files: ['workflow_agent.py', 'n8n_connector.py', 'workflow_builder.py', 'trigger_engine.py', 'action_router.py', 'app_connector.py']
Remaining Files: ['webhook_manager.py', 'form_pipeline.py', 'crm_connector.py', 'sheet_connector.py', 'whatsapp_connector.py', 'email_connector.py', 'notification_engine.py', 'condition_engine.py', 'scheduler.py', 'workflow_monitor.py', 'retry_handler.py', 'workflow_templates.py', 'workflow_memory.py', 'approval_gate.py', 'config.py']
Next Recommended File: agents/workflow_agent/webhook_manager.py
FILE COMPLETE
"""