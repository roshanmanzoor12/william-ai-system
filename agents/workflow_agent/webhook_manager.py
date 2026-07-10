"""
agents/workflow_agent/webhook_manager.py

Purpose:
    Creates, validates, normalizes, and routes webhook payloads for the William / Jarvis
    Workflow Agent.

Architecture Fit:
    - Master Agent can call this manager to create webhook configs and process inbound payloads.
    - Security Agent approval is requested for sensitive webhook actions.
    - Verification Agent payloads are prepared after completed webhook routing.
    - Memory Agent compatible payloads are prepared for useful context persistence.
    - Dashboard/API/FastAPI can use the public methods in this file directly.
    - Agent Registry / Agent Loader compatibility is preserved through safe imports and
      BaseAgent-compatible lifecycle hooks.

Safety / SaaS Isolation:
    - Every webhook operation requires user_id and workspace_id unless explicitly marked
      system-level by trusted internal callers.
    - Payloads, audit events, memory payloads, and route outputs include user/workspace context.
    - Secrets are never hardcoded.
    - Signature verification supports HMAC SHA-256/384/512.
    - Idempotency controls protect against duplicate event processing.
    - Sensitive actions are never executed directly without security approval hooks.

Public Class:
    WebhookManager
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import json
import logging
import re
import secrets
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Tuple,
    Union,
)


# ---------------------------------------------------------------------------
# Safe optional BaseAgent import
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback keeps this file import-safe
    class BaseAgent:  # type: ignore
        """
        Minimal fallback BaseAgent.

        This stub allows webhook_manager.py to import safely before the real
        William/Jarvis BaseAgent exists. When the real BaseAgent is available,
        it will be used automatically.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())
            self.logger = logging.getLogger(self.agent_name)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
if not logger.handlers:
    logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_MAX_PAYLOAD_BYTES = 2 * 1024 * 1024  # 2 MB
DEFAULT_IDEMPOTENCY_TTL_SECONDS = 60 * 60 * 24  # 24 hours
DEFAULT_MAX_IDEMPOTENCY_KEYS = 10_000
DEFAULT_WEBHOOK_VERSION = "v1"

SAFE_HEADER_ALLOWLIST = {
    "content-type",
    "user-agent",
    "x-request-id",
    "x-correlation-id",
    "x-event-id",
    "x-event-type",
    "x-webhook-id",
    "x-signature",
    "x-hub-signature",
    "x-hub-signature-256",
    "x-william-signature",
    "x-jarvis-signature",
    "x-timestamp",
    "x-workspace-id",
    "x-user-id",
}

SENSITIVE_FIELD_PATTERNS = (
    re.compile(r"password", re.IGNORECASE),
    re.compile(r"secret", re.IGNORECASE),
    re.compile(r"token", re.IGNORECASE),
    re.compile(r"api[_-]?key", re.IGNORECASE),
    re.compile(r"authorization", re.IGNORECASE),
    re.compile(r"private[_-]?key", re.IGNORECASE),
    re.compile(r"access[_-]?key", re.IGNORECASE),
    re.compile(r"refresh[_-]?token", re.IGNORECASE),
)

SENSITIVE_EVENT_KEYWORDS = {
    "delete",
    "remove",
    "archive",
    "send",
    "email",
    "sms",
    "whatsapp",
    "call",
    "payment",
    "invoice",
    "refund",
    "subscription",
    "browser",
    "external_api",
    "financial",
    "bank",
    "transfer",
    "admin",
    "permission",
    "credential",
    "destructive",
}

SUPPORTED_SIGNATURE_ALGORITHMS = {"sha256", "sha384", "sha512"}


# ---------------------------------------------------------------------------
# Enums / Data Structures
# ---------------------------------------------------------------------------

class WebhookStatus(str, Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    DISABLED = "disabled"


class WebhookAuthMode(str, Enum):
    NONE = "none"
    HMAC = "hmac"
    TOKEN = "token"


class RouteTargetType(str, Enum):
    AGENT = "agent"
    CONNECTOR = "connector"
    WORKFLOW = "workflow"
    HANDLER = "handler"
    QUEUE = "queue"
    LOG_ONLY = "log_only"


class WebhookRouteMode(str, Enum):
    EXACT = "exact"
    PREFIX = "prefix"
    REGEX = "regex"
    ANY = "any"


@dataclass
class WebhookConfig:
    """
    Webhook endpoint configuration.

    This does not store raw secrets unless explicitly passed by the caller.
    For production persistence, store secret material in a vault and pass only
    references into this config.
    """

    webhook_id: str
    name: str
    user_id: str
    workspace_id: str
    endpoint_path: str
    status: WebhookStatus = WebhookStatus.ACTIVE
    auth_mode: WebhookAuthMode = WebhookAuthMode.HMAC
    signature_header: str = "x-william-signature"
    signature_algorithm: str = "sha256"
    secret_ref: Optional[str] = None
    token_ref: Optional[str] = None
    event_types: List[str] = field(default_factory=list)
    allowed_sources: List[str] = field(default_factory=list)
    max_payload_bytes: int = DEFAULT_MAX_PAYLOAD_BYTES
    require_timestamp: bool = False
    timestamp_tolerance_seconds: int = 300
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: utc_now_iso())
    updated_at: str = field(default_factory=lambda: utc_now_iso())

    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        data = dataclasses.asdict(self)
        data["status"] = self.status.value
        data["auth_mode"] = self.auth_mode.value

        if not include_sensitive:
            data.pop("secret_ref", None)
            data.pop("token_ref", None)

        return data


@dataclass
class WebhookRoute:
    """
    Route rule for webhook events.

    The route does not execute unsafe side effects by itself. It describes the
    target and optional callable handler. A dashboard/API layer, ActionRouter,
    or Workflow Agent can bind handlers later.
    """

    route_id: str
    name: str
    workspace_id: str
    user_id: str
    target_type: RouteTargetType
    target_name: str
    event_pattern: str = "*"
    mode: WebhookRouteMode = WebhookRouteMode.EXACT
    priority: int = 100
    enabled: bool = True
    requires_security: bool = False
    allowed_webhook_ids: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    handler: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None
    created_at: str = field(default_factory=lambda: utc_now_iso())
    updated_at: str = field(default_factory=lambda: utc_now_iso())

    def to_dict(self, include_handler: bool = False) -> Dict[str, Any]:
        data = dataclasses.asdict(self)
        data["target_type"] = self.target_type.value
        data["mode"] = self.mode.value

        if not include_handler:
            data.pop("handler", None)
        else:
            data["handler"] = repr(self.handler)

        return data


@dataclass
class WebhookPayloadEnvelope:
    """
    Normalized inbound webhook envelope.

    This envelope is the canonical payload format passed from WebhookManager to
    Workflow Agent, Action Router, Verification Agent, Memory Agent, dashboard,
    and future queue workers.
    """

    event_id: str
    webhook_id: str
    event_type: str
    user_id: str
    workspace_id: str
    payload: Dict[str, Any]
    headers: Dict[str, str]
    source_ip: Optional[str] = None
    received_at: str = field(default_factory=lambda: utc_now_iso())
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    raw_size_bytes: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self, redact: bool = True) -> Dict[str, Any]:
        data = dataclasses.asdict(self)
        if redact:
            data["payload"] = redact_sensitive(data.get("payload", {}))
            data["headers"] = redact_sensitive(data.get("headers", {}))
        return data


# ---------------------------------------------------------------------------
# Utility Functions
# ---------------------------------------------------------------------------

def utc_now_iso() -> str:
    """Return an ISO-8601 UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def normalize_header_key(key: str) -> str:
    return str(key or "").strip().lower()


def normalize_headers(headers: Optional[Mapping[str, Any]]) -> Dict[str, str]:
    normalized: Dict[str, str] = {}
    if not headers:
        return normalized

    for key, value in headers.items():
        normalized[normalize_header_key(key)] = str(value)
    return normalized


def safe_json_dumps(value: Any) -> str:
    """Stable JSON dump used for HMAC signing and safe logs."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def parse_json_body(body: Union[str, bytes, bytearray, Dict[str, Any], None]) -> Tuple[Dict[str, Any], int]:
    """
    Parse a webhook body into a dict and return raw byte size.

    Accepted body forms:
        - dict
        - JSON string
        - bytes / bytearray containing JSON
        - None -> {}
    """
    if body is None:
        return {}, 0

    if isinstance(body, dict):
        raw = safe_json_dumps(body).encode("utf-8")
        return dict(body), len(raw)

    if isinstance(body, bytearray):
        body = bytes(body)

    if isinstance(body, bytes):
        size = len(body)
        text = body.decode("utf-8")
    else:
        text = str(body)
        size = len(text.encode("utf-8"))

    if not text.strip():
        return {}, size

    parsed = json.loads(text)
    if not isinstance(parsed, dict):
        raise ValueError("webhook_body_must_be_json_object")

    return parsed, size


def redact_sensitive(value: Any) -> Any:
    """
    Recursively redact sensitive fields from dict/list structures.

    This is used for audit logs, dashboard metadata, memory payload preparation,
    and error reporting.
    """
    if isinstance(value, Mapping):
        redacted: Dict[str, Any] = {}
        for key, item in value.items():
            key_str = str(key)
            if any(pattern.search(key_str) for pattern in SENSITIVE_FIELD_PATTERNS):
                redacted[key_str] = "***REDACTED***"
            else:
                redacted[key_str] = redact_sensitive(item)
        return redacted

    if isinstance(value, list):
        return [redact_sensitive(item) for item in value]

    if isinstance(value, tuple):
        return tuple(redact_sensitive(item) for item in value)

    return value


def constant_time_equals(left: str, right: str) -> bool:
    """Constant-time comparison for signatures/tokens."""
    return hmac.compare_digest(str(left or ""), str(right or ""))


def build_hmac_signature(
    secret: str,
    body: Union[str, bytes, Dict[str, Any]],
    algorithm: str = "sha256",
    prefix: Optional[str] = None,
) -> str:
    """
    Build an HMAC signature for a webhook payload.

    Returns:
        signature string, optionally with prefix like "sha256=<digest>"
    """
    algorithm = algorithm.lower().strip()
    if algorithm not in SUPPORTED_SIGNATURE_ALGORITHMS:
        raise ValueError(f"unsupported_signature_algorithm:{algorithm}")

    if isinstance(body, dict):
        body_bytes = safe_json_dumps(body).encode("utf-8")
    elif isinstance(body, str):
        body_bytes = body.encode("utf-8")
    else:
        body_bytes = bytes(body)

    digestmod = getattr(hashlib, algorithm)
    digest = hmac.new(secret.encode("utf-8"), body_bytes, digestmod).hexdigest()
    return f"{prefix}{digest}" if prefix else digest


def extract_signature_parts(signature_value: str) -> Tuple[Optional[str], str]:
    """
    Parse signature headers such as:
        sha256=abc123
        t=123,v1=abc123
        abc123
    """
    value = str(signature_value or "").strip()
    if not value:
        return None, ""

    if "," in value:
        parts = [p.strip() for p in value.split(",") if p.strip()]
        for part in parts:
            if "=" in part:
                key, val = part.split("=", 1)
                if key.strip().lower() in {"v1", "signature", "sig", "sha256", "sha384", "sha512"}:
                    return key.strip().lower(), val.strip()
        return None, parts[-1]

    if "=" in value:
        key, val = value.split("=", 1)
        return key.strip().lower(), val.strip()

    return None, value


def generate_webhook_secret(num_bytes: int = 32) -> str:
    """Generate a URL-safe webhook secret. Caller should store it in a vault."""
    return secrets.token_urlsafe(num_bytes)


def generate_webhook_id(prefix: str = "wh") -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def generate_event_id(prefix: str = "evt") -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def slugify_path(value: str) -> str:
    clean = re.sub(r"[^a-zA-Z0-9_\-/]", "-", value.strip())
    clean = re.sub(r"-+", "-", clean)
    clean = clean.strip("-/")
    return f"/{clean}" if clean else f"/webhooks/{uuid.uuid4().hex}"


class TTLIdempotencyStore:
    """
    Small in-memory TTL store for idempotency protection.

    Production deployments can replace this with Redis, Postgres, or another
    shared storage backend. This in-memory implementation is safe to import and
    useful for local tests.
    """

    def __init__(
        self,
        ttl_seconds: int = DEFAULT_IDEMPOTENCY_TTL_SECONDS,
        max_keys: int = DEFAULT_MAX_IDEMPOTENCY_KEYS,
    ) -> None:
        self.ttl_seconds = ttl_seconds
        self.max_keys = max_keys
        self._items: "OrderedDict[str, float]" = OrderedDict()

    def seen(self, key: str) -> bool:
        self.prune()
        return key in self._items

    def mark(self, key: str) -> None:
        self.prune()
        self._items[key] = time.time()
        self._items.move_to_end(key)
        while len(self._items) > self.max_keys:
            self._items.popitem(last=False)

    def prune(self) -> None:
        now = time.time()
        expired = [
            key for key, created_at in self._items.items()
            if now - created_at > self.ttl_seconds
        ]
        for key in expired:
            self._items.pop(key, None)


# ---------------------------------------------------------------------------
# Webhook Manager
# ---------------------------------------------------------------------------

class WebhookManager(BaseAgent):
    """
    Production-ready webhook manager for William / Jarvis Workflow Agent.

    Responsibilities:
        1. Create webhook configurations.
        2. Validate inbound webhook body, headers, context, auth, size, timestamp.
        3. Normalize payloads into WebhookPayloadEnvelope.
        4. Route webhook payloads to workflow/agent/connector/handler route definitions.
        5. Prepare verification and memory payloads.
        6. Emit audit and agent events in import-safe format.

    This manager intentionally avoids executing real external side effects unless
    a route has an explicitly registered callable handler and security checks pass.
    """

    def __init__(
        self,
        *,
        agent_name: str = "WorkflowWebhookManager",
        agent_id: str = "workflow.webhook_manager",
        security_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        event_emitter: Optional[Callable[[Dict[str, Any]], None]] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], None]] = None,
        secret_resolver: Optional[Callable[[str], Optional[str]]] = None,
        token_resolver: Optional[Callable[[str], Optional[str]]] = None,
        idempotency_store: Optional[TTLIdempotencyStore] = None,
        max_payload_bytes: int = DEFAULT_MAX_PAYLOAD_BYTES,
        strict_workspace_isolation: bool = True,
    ) -> None:
        try:
            super().__init__(agent_name=agent_name, agent_id=agent_id)
        except TypeError:
            super().__init__()

        self.agent_name = agent_name
        self.agent_id = agent_id
        self.logger = getattr(self, "logger", logging.getLogger(agent_name))

        self.security_agent = security_agent
        self.verification_agent = verification_agent
        self.memory_agent = memory_agent
        self.event_emitter = event_emitter
        self.audit_logger = audit_logger
        self.secret_resolver = secret_resolver
        self.token_resolver = token_resolver

        self.max_payload_bytes = max_payload_bytes
        self.strict_workspace_isolation = strict_workspace_isolation
        self.idempotency_store = idempotency_store or TTLIdempotencyStore()

        self._webhooks: Dict[str, WebhookConfig] = {}
        self._webhooks_by_path: Dict[str, str] = {}
        self._routes: Dict[str, WebhookRoute] = {}

    # ------------------------------------------------------------------
    # Public Webhook Config Methods
    # ------------------------------------------------------------------

    def create_webhook(
        self,
        *,
        name: str,
        user_id: str,
        workspace_id: str,
        endpoint_path: Optional[str] = None,
        auth_mode: Union[WebhookAuthMode, str] = WebhookAuthMode.HMAC,
        event_types: Optional[Sequence[str]] = None,
        allowed_sources: Optional[Sequence[str]] = None,
        signature_algorithm: str = "sha256",
        signature_header: str = "x-william-signature",
        secret_ref: Optional[str] = None,
        token_ref: Optional[str] = None,
        require_timestamp: bool = False,
        timestamp_tolerance_seconds: int = 300,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create a webhook config.

        Returns a structured result with config data. If auth_mode is HMAC and
        secret_ref is not provided, a generated secret is returned once in the
        result. Production callers should store this secret in a vault and save
        only the secret reference.
        """
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            operation="create_webhook",
        )
        if not context_result["success"]:
            return context_result

        try:
            auth_mode_enum = WebhookAuthMode(str(auth_mode).lower())
            signature_algorithm = signature_algorithm.lower().strip()

            if signature_algorithm not in SUPPORTED_SIGNATURE_ALGORITHMS:
                return self._error_result(
                    message="Unsupported webhook signature algorithm.",
                    error="unsupported_signature_algorithm",
                    metadata={"supported": sorted(SUPPORTED_SIGNATURE_ALGORITHMS)},
                )

            webhook_id = generate_webhook_id()
            clean_path = slugify_path(
                endpoint_path or f"/webhooks/{workspace_id}/{webhook_id}"
            )

            if clean_path in self._webhooks_by_path:
                return self._error_result(
                    message="Webhook endpoint path already exists.",
                    error="webhook_path_already_exists",
                    metadata={"endpoint_path": clean_path},
                )

            generated_secret: Optional[str] = None
            generated_token: Optional[str] = None

            if auth_mode_enum == WebhookAuthMode.HMAC and not secret_ref:
                generated_secret = generate_webhook_secret()
                secret_ref = f"generated_once:{webhook_id}"

            if auth_mode_enum == WebhookAuthMode.TOKEN and not token_ref:
                generated_token = generate_webhook_secret()
                token_ref = f"generated_once:{webhook_id}"

            config = WebhookConfig(
                webhook_id=webhook_id,
                name=name.strip() or webhook_id,
                user_id=user_id,
                workspace_id=workspace_id,
                endpoint_path=clean_path,
                auth_mode=auth_mode_enum,
                signature_header=normalize_header_key(signature_header),
                signature_algorithm=signature_algorithm,
                secret_ref=secret_ref,
                token_ref=token_ref,
                event_types=list(event_types or []),
                allowed_sources=list(allowed_sources or []),
                require_timestamp=require_timestamp,
                timestamp_tolerance_seconds=timestamp_tolerance_seconds,
                metadata=metadata or {},
            )

            self._webhooks[webhook_id] = config
            self._webhooks_by_path[clean_path] = webhook_id

            self._log_audit_event(
                event_type="webhook.created",
                user_id=user_id,
                workspace_id=workspace_id,
                data={
                    "webhook_id": webhook_id,
                    "endpoint_path": clean_path,
                    "auth_mode": auth_mode_enum.value,
                    "event_types": list(event_types or []),
                },
            )

            result_data: Dict[str, Any] = {
                "webhook": config.to_dict(include_sensitive=False),
                "auth_mode": auth_mode_enum.value,
            }

            if generated_secret:
                result_data["generated_secret_once"] = generated_secret
                result_data["secret_storage_note"] = (
                    "Store this secret in a vault. It is returned only by this create call."
                )

            if generated_token:
                result_data["generated_token_once"] = generated_token
                result_data["token_storage_note"] = (
                    "Store this token in a vault. It is returned only by this create call."
                )

            return self._safe_result(
                message="Webhook created successfully.",
                data=result_data,
                metadata={
                    "agent_id": self.agent_id,
                    "created_at": config.created_at,
                },
            )

        except Exception as exc:
            self.logger.exception("Failed to create webhook.")
            return self._error_result(
                message="Failed to create webhook.",
                error=str(exc),
                metadata={"operation": "create_webhook"},
            )

    def get_webhook(
        self,
        webhook_id: Optional[str] = None,
        endpoint_path: Optional[str] = None,
        *,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return one webhook config by ID or endpoint path."""
        try:
            config = self._resolve_webhook(webhook_id=webhook_id, endpoint_path=endpoint_path)
            if not config:
                return self._error_result(
                    message="Webhook not found.",
                    error="webhook_not_found",
                    metadata={"webhook_id": webhook_id, "endpoint_path": endpoint_path},
                )

            isolation = self._validate_resource_isolation(
                resource_user_id=config.user_id,
                resource_workspace_id=config.workspace_id,
                user_id=user_id,
                workspace_id=workspace_id,
            )
            if not isolation["success"]:
                return isolation

            return self._safe_result(
                message="Webhook found.",
                data={"webhook": config.to_dict(include_sensitive=False)},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to get webhook.",
                error=str(exc),
                metadata={"operation": "get_webhook"},
            )

    def list_webhooks(
        self,
        *,
        user_id: str,
        workspace_id: str,
        status: Optional[Union[WebhookStatus, str]] = None,
    ) -> Dict[str, Any]:
        """List webhook configs for one SaaS user/workspace."""
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            operation="list_webhooks",
        )
        if not context_result["success"]:
            return context_result

        try:
            status_value = str(status.value if isinstance(status, WebhookStatus) else status).lower() if status else None
            webhooks = []
            for config in self._webhooks.values():
                if config.user_id != user_id or config.workspace_id != workspace_id:
                    continue
                if status_value and config.status.value != status_value:
                    continue
                webhooks.append(config.to_dict(include_sensitive=False))

            return self._safe_result(
                message="Webhooks listed successfully.",
                data={"webhooks": webhooks, "count": len(webhooks)},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to list webhooks.",
                error=str(exc),
                metadata={"operation": "list_webhooks"},
            )

    def update_webhook_status(
        self,
        *,
        webhook_id: str,
        user_id: str,
        workspace_id: str,
        status: Union[WebhookStatus, str],
    ) -> Dict[str, Any]:
        """Enable, pause, or disable a webhook."""
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            operation="update_webhook_status",
        )
        if not context_result["success"]:
            return context_result

        try:
            config = self._webhooks.get(webhook_id)
            if not config:
                return self._error_result(
                    message="Webhook not found.",
                    error="webhook_not_found",
                    metadata={"webhook_id": webhook_id},
                )

            isolation = self._validate_resource_isolation(
                resource_user_id=config.user_id,
                resource_workspace_id=config.workspace_id,
                user_id=user_id,
                workspace_id=workspace_id,
            )
            if not isolation["success"]:
                return isolation

            config.status = WebhookStatus(str(status).lower())
            config.updated_at = utc_now_iso()

            self._log_audit_event(
                event_type="webhook.status_updated",
                user_id=user_id,
                workspace_id=workspace_id,
                data={"webhook_id": webhook_id, "status": config.status.value},
            )

            return self._safe_result(
                message="Webhook status updated.",
                data={"webhook": config.to_dict(include_sensitive=False)},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to update webhook status.",
                error=str(exc),
                metadata={"operation": "update_webhook_status"},
            )

    # ------------------------------------------------------------------
    # Public Route Methods
    # ------------------------------------------------------------------

    def register_route(
        self,
        *,
        name: str,
        user_id: str,
        workspace_id: str,
        target_type: Union[RouteTargetType, str],
        target_name: str,
        event_pattern: str = "*",
        mode: Union[WebhookRouteMode, str] = WebhookRouteMode.EXACT,
        priority: int = 100,
        requires_security: bool = False,
        allowed_webhook_ids: Optional[Sequence[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        handler: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Register a route for inbound webhook events.

        target_type examples:
            - agent: route to another William/Jarvis agent
            - connector: route to app connector
            - workflow: route to workflow engine
            - handler: route to a Python callable
            - log_only: audit only, no side effects
        """
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            operation="register_webhook_route",
        )
        if not context_result["success"]:
            return context_result

        try:
            route_id = f"route_{uuid.uuid4().hex}"
            route = WebhookRoute(
                route_id=route_id,
                name=name.strip() or route_id,
                user_id=user_id,
                workspace_id=workspace_id,
                target_type=RouteTargetType(str(target_type).lower()),
                target_name=target_name.strip(),
                event_pattern=event_pattern.strip() or "*",
                mode=WebhookRouteMode(str(mode).lower()),
                priority=priority,
                requires_security=requires_security,
                allowed_webhook_ids=list(allowed_webhook_ids or []),
                metadata=metadata or {},
                handler=handler,
            )

            self._routes[route_id] = route

            self._log_audit_event(
                event_type="webhook.route_registered",
                user_id=user_id,
                workspace_id=workspace_id,
                data={
                    "route_id": route_id,
                    "target_type": route.target_type.value,
                    "target_name": route.target_name,
                    "event_pattern": route.event_pattern,
                },
            )

            return self._safe_result(
                message="Webhook route registered.",
                data={"route": route.to_dict(include_handler=False)},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to register webhook route.",
                error=str(exc),
                metadata={"operation": "register_route"},
            )

    def list_routes(
        self,
        *,
        user_id: str,
        workspace_id: str,
        enabled_only: bool = False,
    ) -> Dict[str, Any]:
        """List webhook routes for one SaaS user/workspace."""
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            operation="list_webhook_routes",
        )
        if not context_result["success"]:
            return context_result

        routes = []
        for route in self._routes.values():
            if route.user_id != user_id or route.workspace_id != workspace_id:
                continue
            if enabled_only and not route.enabled:
                continue
            routes.append(route.to_dict(include_handler=False))

        routes.sort(key=lambda item: item.get("priority", 100))

        return self._safe_result(
            message="Webhook routes listed successfully.",
            data={"routes": routes, "count": len(routes)},
        )

    # ------------------------------------------------------------------
    # Public Inbound Processing Methods
    # ------------------------------------------------------------------

    def receive_webhook(
        self,
        *,
        body: Union[str, bytes, bytearray, Dict[str, Any], None],
        headers: Optional[Mapping[str, Any]] = None,
        endpoint_path: Optional[str] = None,
        webhook_id: Optional[str] = None,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        secret: Optional[str] = None,
        token: Optional[str] = None,
        route: bool = True,
        skip_auth_for_internal: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Main API entry point for FastAPI/dashboard/Workflow Agent.

        This method:
            1. Resolves webhook config.
            2. Parses and validates payload.
            3. Verifies auth/signature/token unless intentionally skipped.
            4. Builds normalized envelope.
            5. Applies idempotency.
            6. Routes payload if requested.
            7. Prepares verification and memory payloads.
        """
        try:
            config = self._resolve_webhook(webhook_id=webhook_id, endpoint_path=endpoint_path)
            if not config:
                return self._error_result(
                    message="Webhook not found.",
                    error="webhook_not_found",
                    metadata={"webhook_id": webhook_id, "endpoint_path": endpoint_path},
                )

            isolation = self._validate_resource_isolation(
                resource_user_id=config.user_id,
                resource_workspace_id=config.workspace_id,
                user_id=user_id,
                workspace_id=workspace_id,
            )
            if not isolation["success"]:
                return isolation

            if config.status != WebhookStatus.ACTIVE:
                return self._error_result(
                    message="Webhook is not active.",
                    error="webhook_not_active",
                    metadata={"webhook_id": config.webhook_id, "status": config.status.value},
                )

            parsed_body, raw_size_bytes = parse_json_body(body)
            normalized_headers = normalize_headers(headers)

            validation = self.validate_payload(
                payload=parsed_body,
                headers=normalized_headers,
                webhook_id=config.webhook_id,
                source_ip=source_ip,
                raw_size_bytes=raw_size_bytes,
                secret=secret,
                token=token,
                skip_auth_for_internal=skip_auth_for_internal,
            )
            if not validation["success"]:
                self._log_audit_event(
                    event_type="webhook.validation_failed",
                    user_id=config.user_id,
                    workspace_id=config.workspace_id,
                    data={
                        "webhook_id": config.webhook_id,
                        "endpoint_path": config.endpoint_path,
                        "error": validation.get("error"),
                        "source_ip": source_ip,
                    },
                )
                return validation

            envelope_result = self.create_payload_envelope(
                webhook_id=config.webhook_id,
                payload=parsed_body,
                headers=normalized_headers,
                user_id=config.user_id,
                workspace_id=config.workspace_id,
                source_ip=source_ip,
                raw_size_bytes=raw_size_bytes,
                metadata=metadata,
            )
            if not envelope_result["success"]:
                return envelope_result

            envelope_data = envelope_result["data"]["envelope"]
            idempotency_key = self._build_idempotency_key(envelope_data)

            if self.idempotency_store.seen(idempotency_key):
                self._log_audit_event(
                    event_type="webhook.duplicate_ignored",
                    user_id=config.user_id,
                    workspace_id=config.workspace_id,
                    data={
                        "webhook_id": config.webhook_id,
                        "event_id": envelope_data.get("event_id"),
                        "event_type": envelope_data.get("event_type"),
                    },
                )
                return self._safe_result(
                    message="Duplicate webhook event ignored.",
                    data={
                        "envelope": envelope_data,
                        "duplicate": True,
                        "routes": [],
                    },
                    metadata={"idempotency_key": idempotency_key},
                )

            self.idempotency_store.mark(idempotency_key)

            route_result: Dict[str, Any]
            if route:
                route_result = self.route_payload(envelope=envelope_data)
            else:
                route_result = self._safe_result(
                    message="Webhook accepted without routing.",
                    data={"routes": [], "routed": False},
                )

            verification_payload = self._prepare_verification_payload(
                action="webhook.receive",
                user_id=config.user_id,
                workspace_id=config.workspace_id,
                data={
                    "webhook_id": config.webhook_id,
                    "event_id": envelope_data.get("event_id"),
                    "event_type": envelope_data.get("event_type"),
                    "route_success": route_result.get("success", False),
                    "route_count": len(route_result.get("data", {}).get("routes", [])),
                },
            )

            memory_payload = self._prepare_memory_payload(
                action="webhook.receive",
                user_id=config.user_id,
                workspace_id=config.workspace_id,
                data={
                    "webhook_id": config.webhook_id,
                    "event_id": envelope_data.get("event_id"),
                    "event_type": envelope_data.get("event_type"),
                    "payload_summary": self._summarize_payload(envelope_data.get("payload", {})),
                },
            )

            self._emit_agent_event(
                event_type="workflow.webhook.received",
                user_id=config.user_id,
                workspace_id=config.workspace_id,
                data={
                    "webhook_id": config.webhook_id,
                    "event_id": envelope_data.get("event_id"),
                    "event_type": envelope_data.get("event_type"),
                    "routed": route_result.get("success", False),
                },
            )

            self._log_audit_event(
                event_type="webhook.received",
                user_id=config.user_id,
                workspace_id=config.workspace_id,
                data={
                    "webhook_id": config.webhook_id,
                    "event_id": envelope_data.get("event_id"),
                    "event_type": envelope_data.get("event_type"),
                    "source_ip": source_ip,
                    "raw_size_bytes": raw_size_bytes,
                    "route_success": route_result.get("success", False),
                },
            )

            return self._safe_result(
                message="Webhook received and processed.",
                data={
                    "envelope": envelope_data,
                    "route_result": route_result,
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                    "duplicate": False,
                },
                metadata={
                    "agent_id": self.agent_id,
                    "idempotency_key": idempotency_key,
                    "processed_at": utc_now_iso(),
                },
            )

        except Exception as exc:
            self.logger.exception("Webhook receive failed.")
            return self._error_result(
                message="Webhook receive failed.",
                error=str(exc),
                metadata={"operation": "receive_webhook"},
            )

    def validate_payload(
        self,
        *,
        payload: Dict[str, Any],
        headers: Optional[Mapping[str, Any]],
        webhook_id: str,
        source_ip: Optional[str] = None,
        raw_size_bytes: Optional[int] = None,
        secret: Optional[str] = None,
        token: Optional[str] = None,
        skip_auth_for_internal: bool = False,
    ) -> Dict[str, Any]:
        """
        Validate inbound webhook payload against webhook config.

        This method is safe to call independently from receive_webhook().
        """
        try:
            config = self._webhooks.get(webhook_id)
            if not config:
                return self._error_result(
                    message="Webhook not found.",
                    error="webhook_not_found",
                    metadata={"webhook_id": webhook_id},
                )

            normalized_headers = normalize_headers(headers)

            if not isinstance(payload, dict):
                return self._error_result(
                    message="Webhook payload must be a JSON object.",
                    error="invalid_payload_type",
                )

            size = raw_size_bytes
            if size is None:
                size = len(safe_json_dumps(payload).encode("utf-8"))

            if size > config.max_payload_bytes:
                return self._error_result(
                    message="Webhook payload exceeds maximum allowed size.",
                    error="payload_too_large",
                    metadata={
                        "size_bytes": size,
                        "max_payload_bytes": config.max_payload_bytes,
                    },
                )

            event_type = self._extract_event_type(payload, normalized_headers)
            if config.event_types and event_type not in config.event_types:
                return self._error_result(
                    message="Webhook event type is not allowed for this webhook.",
                    error="event_type_not_allowed",
                    metadata={
                        "event_type": event_type,
                        "allowed_event_types": config.event_types,
                    },
                )

            if config.allowed_sources and source_ip:
                if source_ip not in config.allowed_sources:
                    return self._error_result(
                        message="Webhook source IP is not allowed.",
                        error="source_not_allowed",
                        metadata={"source_ip": source_ip},
                    )

            if config.require_timestamp:
                timestamp_validation = self._validate_timestamp(
                    headers=normalized_headers,
                    tolerance_seconds=config.timestamp_tolerance_seconds,
                )
                if not timestamp_validation["success"]:
                    return timestamp_validation

            if skip_auth_for_internal:
                return self._safe_result(
                    message="Webhook payload validated. Auth skipped for trusted internal caller.",
                    data={"event_type": event_type, "auth_skipped": True},
                )

            auth_result = self._validate_auth(
                config=config,
                payload=payload,
                headers=normalized_headers,
                secret=secret,
                token=token,
            )
            if not auth_result["success"]:
                return auth_result

            return self._safe_result(
                message="Webhook payload validated successfully.",
                data={
                    "event_type": event_type,
                    "auth_mode": config.auth_mode.value,
                    "size_bytes": size,
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Webhook payload validation failed.",
                error=str(exc),
                metadata={"operation": "validate_payload"},
            )

    def create_payload_envelope(
        self,
        *,
        webhook_id: str,
        payload: Dict[str, Any],
        headers: Optional[Mapping[str, Any]],
        user_id: str,
        workspace_id: str,
        source_ip: Optional[str] = None,
        raw_size_bytes: int = 0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create a normalized webhook payload envelope."""
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            operation="create_payload_envelope",
        )
        if not context_result["success"]:
            return context_result

        try:
            normalized_headers = normalize_headers(headers)
            event_type = self._extract_event_type(payload, normalized_headers)
            event_id = self._extract_event_id(payload, normalized_headers)
            correlation_id = (
                normalized_headers.get("x-correlation-id")
                or payload.get("correlation_id")
                or payload.get("correlationId")
                or str(uuid.uuid4())
            )

            envelope = WebhookPayloadEnvelope(
                event_id=event_id,
                webhook_id=webhook_id,
                event_type=event_type,
                user_id=user_id,
                workspace_id=workspace_id,
                payload=payload,
                headers=self._safe_headers_for_storage(normalized_headers),
                source_ip=source_ip,
                correlation_id=str(correlation_id),
                raw_size_bytes=raw_size_bytes,
                metadata=metadata or {},
            )

            return self._safe_result(
                message="Webhook payload envelope created.",
                data={"envelope": envelope.to_dict(redact=True)},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to create webhook payload envelope.",
                error=str(exc),
                metadata={"operation": "create_payload_envelope"},
            )

    def route_payload(self, *, envelope: Dict[str, Any]) -> Dict[str, Any]:
        """
        Route a normalized webhook envelope to matching routes.

        For HANDLER routes with a registered callable, the callable receives a
        safe envelope dict and must return a structured result. For all other
        target types, this method prepares a route dispatch payload but does not
        execute external side effects.
        """
        try:
            user_id = str(envelope.get("user_id") or "")
            workspace_id = str(envelope.get("workspace_id") or "")
            event_type = str(envelope.get("event_type") or "")

            context_result = self._validate_task_context(
                user_id=user_id,
                workspace_id=workspace_id,
                operation="route_payload",
            )
            if not context_result["success"]:
                return context_result

            matching_routes = self._match_routes(
                user_id=user_id,
                workspace_id=workspace_id,
                webhook_id=str(envelope.get("webhook_id") or ""),
                event_type=event_type,
            )

            route_outputs: List[Dict[str, Any]] = []
            overall_success = True

            for route in matching_routes:
                route_output = self._dispatch_to_route(route=route, envelope=envelope)
                route_outputs.append(route_output)

                if not route_output.get("success", False):
                    overall_success = False

            if not matching_routes:
                self._log_audit_event(
                    event_type="webhook.no_route_matched",
                    user_id=user_id,
                    workspace_id=workspace_id,
                    data={
                        "webhook_id": envelope.get("webhook_id"),
                        "event_id": envelope.get("event_id"),
                        "event_type": event_type,
                    },
                )

            return self._safe_result(
                success=overall_success,
                message=(
                    "Webhook payload routed."
                    if matching_routes
                    else "Webhook payload accepted but no route matched."
                ),
                data={
                    "routed": bool(matching_routes),
                    "routes": route_outputs,
                    "route_count": len(route_outputs),
                },
                metadata={
                    "event_type": event_type,
                    "processed_at": utc_now_iso(),
                },
            )

        except Exception as exc:
            self.logger.exception("Webhook routing failed.")
            return self._error_result(
                message="Webhook routing failed.",
                error=str(exc),
                metadata={"operation": "route_payload"},
            )

    # ------------------------------------------------------------------
    # Signature / Auth Methods
    # ------------------------------------------------------------------

    def verify_signature(
        self,
        *,
        payload: Union[str, bytes, Dict[str, Any]],
        signature: str,
        secret: str,
        algorithm: str = "sha256",
    ) -> Dict[str, Any]:
        """Verify HMAC webhook signature."""
        try:
            if not signature:
                return self._error_result(
                    message="Missing webhook signature.",
                    error="missing_signature",
                )

            if not secret:
                return self._error_result(
                    message="Missing webhook secret.",
                    error="missing_webhook_secret",
                )

            algorithm = algorithm.lower().strip()
            if algorithm not in SUPPORTED_SIGNATURE_ALGORITHMS:
                return self._error_result(
                    message="Unsupported signature algorithm.",
                    error="unsupported_signature_algorithm",
                    metadata={"algorithm": algorithm},
                )

            prefix, received_digest = extract_signature_parts(signature)
            expected_plain = build_hmac_signature(
                secret=secret,
                body=payload,
                algorithm=algorithm,
            )
            expected_prefixed = build_hmac_signature(
                secret=secret,
                body=payload,
                algorithm=algorithm,
                prefix=f"{algorithm}=",
            )

            valid = (
                constant_time_equals(received_digest, expected_plain)
                or constant_time_equals(signature, expected_plain)
                or constant_time_equals(signature, expected_prefixed)
            )

            return self._safe_result(
                success=valid,
                message="Webhook signature verified." if valid else "Invalid webhook signature.",
                data={
                    "valid": valid,
                    "algorithm": algorithm,
                    "signature_format": prefix or "plain",
                },
                error=None if valid else "invalid_signature",
            )

        except Exception as exc:
            return self._error_result(
                message="Webhook signature verification failed.",
                error=str(exc),
                metadata={"operation": "verify_signature"},
            )

    # ------------------------------------------------------------------
    # Compatibility Hooks Required by William/Jarvis Architecture
    # ------------------------------------------------------------------

    def _validate_task_context(
        self,
        *,
        user_id: Optional[str],
        workspace_id: Optional[str],
        operation: str = "unknown",
        allow_system: bool = False,
    ) -> Dict[str, Any]:
        """
        Validate SaaS context.

        Every user-specific execution must include user_id and workspace_id to
        prevent cross-user or cross-workspace mixing.
        """
        if allow_system and user_id == "system" and workspace_id == "system":
            return self._safe_result(
                message="System context validated.",
                data={"operation": operation},
            )

        if not user_id or not str(user_id).strip():
            return self._error_result(
                message="Missing user_id for workflow webhook operation.",
                error="missing_user_id",
                metadata={"operation": operation},
            )

        if not workspace_id or not str(workspace_id).strip():
            return self._error_result(
                message="Missing workspace_id for workflow webhook operation.",
                error="missing_workspace_id",
                metadata={"operation": operation},
            )

        return self._safe_result(
            message="Task context validated.",
            data={
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
                "operation": operation,
            },
        )

    def _requires_security_check(
        self,
        *,
        action: str,
        payload: Optional[Mapping[str, Any]] = None,
        route: Optional[WebhookRoute] = None,
    ) -> bool:
        """
        Decide if a webhook action needs Security Agent approval.

        Sensitive routes/actions include messaging, calls, payments, destructive
        operations, permission changes, external browser/API operations, and any
        route explicitly marked requires_security=True.
        """
        if route and route.requires_security:
            return True

        action_l = str(action or "").lower()
        if any(keyword in action_l for keyword in SENSITIVE_EVENT_KEYWORDS):
            return True

        if payload:
            event_type = str(payload.get("event_type") or payload.get("type") or "").lower()
            target = str(payload.get("target") or payload.get("action") or "").lower()
            combined = f"{event_type} {target}"
            if any(keyword in combined for keyword in SENSITIVE_EVENT_KEYWORDS):
                return True

        return False

    def _request_security_approval(
        self,
        *,
        action: str,
        user_id: str,
        workspace_id: str,
        payload: Dict[str, Any],
        route: Optional[WebhookRoute] = None,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        If no Security Agent is attached, safe default is to block sensitive
        actions and allow non-sensitive actions.
        """
        requires = self._requires_security_check(action=action, payload=payload, route=route)
        if not requires:
            return self._safe_result(
                message="Security approval not required.",
                data={"approved": True, "required": False},
            )

        approval_request = {
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "payload": redact_sensitive(payload),
            "route": route.to_dict(include_handler=False) if route else None,
            "requested_by": self.agent_id,
            "requested_at": utc_now_iso(),
        }

        if not self.security_agent:
            return self._error_result(
                message="Sensitive webhook action blocked because Security Agent is unavailable.",
                error="security_agent_unavailable",
                data={"approved": False, "required": True},
                metadata={"action": action},
            )

        try:
            if hasattr(self.security_agent, "approve_action"):
                response = self.security_agent.approve_action(approval_request)
            elif hasattr(self.security_agent, "request_approval"):
                response = self.security_agent.request_approval(approval_request)
            else:
                return self._error_result(
                    message="Security Agent does not expose an approval method.",
                    error="security_agent_approval_method_missing",
                    data={"approved": False, "required": True},
                )

            if isinstance(response, dict):
                approved = bool(
                    response.get("approved")
                    or response.get("success")
                    or response.get("data", {}).get("approved")
                )
                if approved:
                    return self._safe_result(
                        message="Security Agent approved webhook action.",
                        data={"approved": True, "required": True, "response": response},
                    )

                return self._error_result(
                    message="Security Agent rejected webhook action.",
                    error="security_rejected",
                    data={"approved": False, "required": True, "response": response},
                )

            if bool(response):
                return self._safe_result(
                    message="Security Agent approved webhook action.",
                    data={"approved": True, "required": True},
                )

            return self._error_result(
                message="Security Agent rejected webhook action.",
                error="security_rejected",
                data={"approved": False, "required": True},
            )

        except Exception as exc:
            self.logger.exception("Security approval request failed.")
            return self._error_result(
                message="Security approval request failed.",
                error=str(exc),
                data={"approved": False, "required": True},
            )

    def _prepare_verification_payload(
        self,
        *,
        action: str,
        user_id: str,
        workspace_id: str,
        data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare a Verification Agent compatible payload.

        The payload can be sent to Verification Agent by the caller or future
        event bus. This method does not force external execution.
        """
        return {
            "success": True,
            "message": "Verification payload prepared.",
            "data": {
                "verification_type": "workflow_webhook_action",
                "action": action,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "source_agent": self.agent_id,
                "payload": redact_sensitive(data),
                "created_at": utc_now_iso(),
            },
            "error": None,
            "metadata": {
                "agent": self.agent_name,
                "compatible_with": "VerificationAgent",
            },
        }

    def _prepare_memory_payload(
        self,
        *,
        action: str,
        user_id: str,
        workspace_id: str,
        data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare a Memory Agent compatible payload.

        This does not store memory directly unless a memory_agent with a known
        method is attached.
        """
        memory_payload = {
            "memory_type": "workflow_webhook_context",
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "source_agent": self.agent_id,
            "content": redact_sensitive(data),
            "created_at": utc_now_iso(),
            "tags": ["workflow", "webhook", "automation"],
        }

        if self.memory_agent:
            try:
                if hasattr(self.memory_agent, "prepare_memory_payload"):
                    prepared = self.memory_agent.prepare_memory_payload(memory_payload)
                    if isinstance(prepared, dict):
                        return prepared
                elif hasattr(self.memory_agent, "store"):
                    self.memory_agent.store(memory_payload)
            except Exception as exc:
                self.logger.warning("Memory Agent integration failed: %s", exc)

        return {
            "success": True,
            "message": "Memory payload prepared.",
            "data": memory_payload,
            "error": None,
            "metadata": {
                "agent": self.agent_name,
                "compatible_with": "MemoryAgent",
            },
        }

    def _emit_agent_event(
        self,
        *,
        event_type: str,
        user_id: str,
        workspace_id: str,
        data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Emit an agent event for dashboard/API/event-bus integrations.

        Uses injected event_emitter when available. Otherwise logs safely.
        """
        event = {
            "event_id": f"agent_evt_{uuid.uuid4().hex}",
            "event_type": event_type,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "source_agent": self.agent_id,
            "data": redact_sensitive(data),
            "created_at": utc_now_iso(),
        }

        try:
            if self.event_emitter:
                self.event_emitter(event)
            else:
                self.logger.info("Agent event: %s", safe_json_dumps(event))

            return self._safe_result(
                message="Agent event emitted.",
                data={"event": event},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to emit agent event.",
                error=str(exc),
                data={"event": event},
            )

    def _log_audit_event(
        self,
        *,
        event_type: str,
        user_id: str,
        workspace_id: str,
        data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Log an audit event.

        Dashboard/API can inject audit_logger to persist these in a database.
        """
        audit_event = {
            "audit_id": f"audit_{uuid.uuid4().hex}",
            "event_type": event_type,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "source_agent": self.agent_id,
            "data": redact_sensitive(data),
            "created_at": utc_now_iso(),
        }

        try:
            if self.audit_logger:
                self.audit_logger(audit_event)
            else:
                self.logger.info("Audit event: %s", safe_json_dumps(audit_event))

            return self._safe_result(
                message="Audit event logged.",
                data={"audit_event": audit_event},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to log audit event.",
                error=str(exc),
                data={"audit_event": audit_event},
            )

    def _safe_result(
        self,
        *,
        success: bool = True,
        message: str = "OK",
        data: Optional[Dict[str, Any]] = None,
        error: Optional[Union[str, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standardized William/Jarvis result shape."""
        return {
            "success": success,
            "message": message,
            "data": data or {},
            "error": error,
            "metadata": {
                "agent": self.agent_name,
                "agent_id": self.agent_id,
                "timestamp": utc_now_iso(),
                **(metadata or {}),
            },
        }

    def _error_result(
        self,
        *,
        message: str,
        error: Union[str, Dict[str, Any], Exception],
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standardized William/Jarvis error result shape."""
        return self._safe_result(
            success=False,
            message=message,
            data=data or {},
            error=str(error),
            metadata=metadata or {},
        )

    # ------------------------------------------------------------------
    # Internal Helpers
    # ------------------------------------------------------------------

    def _resolve_webhook(
        self,
        *,
        webhook_id: Optional[str] = None,
        endpoint_path: Optional[str] = None,
    ) -> Optional[WebhookConfig]:
        if webhook_id and webhook_id in self._webhooks:
            return self._webhooks[webhook_id]

        if endpoint_path:
            clean_path = slugify_path(endpoint_path)
            resolved_id = self._webhooks_by_path.get(clean_path)
            if resolved_id:
                return self._webhooks.get(resolved_id)

        return None

    def _validate_resource_isolation(
        self,
        *,
        resource_user_id: str,
        resource_workspace_id: str,
        user_id: Optional[str],
        workspace_id: Optional[str],
    ) -> Dict[str, Any]:
        """
        Prevent cross-user/workspace access.

        If user_id/workspace_id are omitted by an inbound public webhook, the
        webhook config context is treated as the source of truth. If provided,
        they must match.
        """
        if not self.strict_workspace_isolation:
            return self._safe_result(message="Resource isolation check skipped by configuration.")

        if user_id is not None and str(user_id) != str(resource_user_id):
            return self._error_result(
                message="Webhook user context mismatch.",
                error="user_context_mismatch",
                metadata={
                    "expected_user_id": resource_user_id,
                    "received_user_id": user_id,
                },
            )

        if workspace_id is not None and str(workspace_id) != str(resource_workspace_id):
            return self._error_result(
                message="Webhook workspace context mismatch.",
                error="workspace_context_mismatch",
                metadata={
                    "expected_workspace_id": resource_workspace_id,
                    "received_workspace_id": workspace_id,
                },
            )

        return self._safe_result(
            message="Resource isolation validated.",
            data={
                "user_id": resource_user_id,
                "workspace_id": resource_workspace_id,
            },
        )

    def _validate_auth(
        self,
        *,
        config: WebhookConfig,
        payload: Dict[str, Any],
        headers: Dict[str, str],
        secret: Optional[str] = None,
        token: Optional[str] = None,
    ) -> Dict[str, Any]:
        if config.auth_mode == WebhookAuthMode.NONE:
            return self._safe_result(
                message="Webhook auth not required.",
                data={"auth_mode": WebhookAuthMode.NONE.value},
            )

        if config.auth_mode == WebhookAuthMode.HMAC:
            resolved_secret = secret or self._resolve_secret(config.secret_ref)
            signature = headers.get(normalize_header_key(config.signature_header), "")

            return self.verify_signature(
                payload=payload,
                signature=signature,
                secret=resolved_secret or "",
                algorithm=config.signature_algorithm,
            )

        if config.auth_mode == WebhookAuthMode.TOKEN:
            resolved_token = token or self._resolve_token(config.token_ref)
            received_token = (
                headers.get("authorization", "").replace("Bearer ", "").strip()
                or headers.get("x-webhook-token", "").strip()
                or headers.get("x-api-key", "").strip()
            )

            if not resolved_token:
                return self._error_result(
                    message="Webhook token is unavailable.",
                    error="missing_webhook_token",
                )

            valid = constant_time_equals(received_token, resolved_token)
            return self._safe_result(
                success=valid,
                message="Webhook token verified." if valid else "Invalid webhook token.",
                data={"valid": valid, "auth_mode": WebhookAuthMode.TOKEN.value},
                error=None if valid else "invalid_token",
            )

        return self._error_result(
            message="Unsupported webhook auth mode.",
            error="unsupported_auth_mode",
            metadata={"auth_mode": config.auth_mode.value},
        )

    def _resolve_secret(self, secret_ref: Optional[str]) -> Optional[str]:
        """
        Resolve secret by reference.

        Production should inject secret_resolver connected to a vault.
        For generated_once refs, the actual secret cannot be recovered by design.
        """
        if not secret_ref:
            return None

        if self.secret_resolver:
            try:
                return self.secret_resolver(secret_ref)
            except Exception as exc:
                self.logger.warning("Secret resolver failed: %s", exc)
                return None

        return None

    def _resolve_token(self, token_ref: Optional[str]) -> Optional[str]:
        """
        Resolve token by reference.

        Production should inject token_resolver connected to a vault.
        """
        if not token_ref:
            return None

        if self.token_resolver:
            try:
                return self.token_resolver(token_ref)
            except Exception as exc:
                self.logger.warning("Token resolver failed: %s", exc)
                return None

        return None

    def _validate_timestamp(
        self,
        *,
        headers: Dict[str, str],
        tolerance_seconds: int,
    ) -> Dict[str, Any]:
        raw_timestamp = headers.get("x-timestamp") or headers.get("x-webhook-timestamp")
        if not raw_timestamp:
            return self._error_result(
                message="Missing webhook timestamp.",
                error="missing_timestamp",
            )

        try:
            timestamp_float = float(raw_timestamp)
            now = time.time()
            drift = abs(now - timestamp_float)

            if drift > tolerance_seconds:
                return self._error_result(
                    message="Webhook timestamp is outside allowed tolerance.",
                    error="timestamp_outside_tolerance",
                    metadata={
                        "drift_seconds": drift,
                        "tolerance_seconds": tolerance_seconds,
                    },
                )

            return self._safe_result(
                message="Webhook timestamp validated.",
                data={"drift_seconds": drift},
            )

        except Exception as exc:
            return self._error_result(
                message="Invalid webhook timestamp.",
                error=str(exc),
            )

    def _extract_event_type(self, payload: Mapping[str, Any], headers: Mapping[str, str]) -> str:
        event_type = (
            headers.get("x-event-type")
            or payload.get("event_type")
            or payload.get("event")
            or payload.get("type")
            or payload.get("action")
            or "unknown"
        )
        return str(event_type).strip().lower() or "unknown"

    def _extract_event_id(self, payload: Mapping[str, Any], headers: Mapping[str, str]) -> str:
        event_id = (
            headers.get("x-event-id")
            or headers.get("x-request-id")
            or payload.get("event_id")
            or payload.get("id")
            or payload.get("request_id")
            or payload.get("uuid")
        )

        if event_id:
            return str(event_id)

        event_type = self._extract_event_type(payload, headers)
        digest = hashlib.sha256(safe_json_dumps(payload).encode("utf-8")).hexdigest()[:24]
        return f"evt_{event_type}_{digest}"

    def _safe_headers_for_storage(self, headers: Mapping[str, str]) -> Dict[str, str]:
        safe: Dict[str, str] = {}
        for key, value in headers.items():
            key_l = normalize_header_key(key)
            if key_l in SAFE_HEADER_ALLOWLIST:
                safe[key_l] = value
        return redact_sensitive(safe)

    def _build_idempotency_key(self, envelope: Mapping[str, Any]) -> str:
        workspace_id = str(envelope.get("workspace_id") or "")
        webhook_id = str(envelope.get("webhook_id") or "")
        event_id = str(envelope.get("event_id") or "")
        event_type = str(envelope.get("event_type") or "")
        return hashlib.sha256(
            f"{workspace_id}:{webhook_id}:{event_type}:{event_id}".encode("utf-8")
        ).hexdigest()

    def _match_routes(
        self,
        *,
        user_id: str,
        workspace_id: str,
        webhook_id: str,
        event_type: str,
    ) -> List[WebhookRoute]:
        routes: List[WebhookRoute] = []

        for route in self._routes.values():
            if not route.enabled:
                continue
            if route.user_id != user_id or route.workspace_id != workspace_id:
                continue
            if route.allowed_webhook_ids and webhook_id not in route.allowed_webhook_ids:
                continue
            if self._event_matches_route(event_type=event_type, route=route):
                routes.append(route)

        routes.sort(key=lambda item: item.priority)
        return routes

    def _event_matches_route(self, *, event_type: str, route: WebhookRoute) -> bool:
        pattern = route.event_pattern or "*"

        if route.mode == WebhookRouteMode.ANY or pattern == "*":
            return True

        if route.mode == WebhookRouteMode.EXACT:
            return event_type == pattern.lower()

        if route.mode == WebhookRouteMode.PREFIX:
            return event_type.startswith(pattern.lower())

        if route.mode == WebhookRouteMode.REGEX:
            try:
                return re.search(pattern, event_type) is not None
            except re.error:
                return False

        return False

    def _dispatch_to_route(
        self,
        *,
        route: WebhookRoute,
        envelope: Dict[str, Any],
    ) -> Dict[str, Any]:
        user_id = str(envelope.get("user_id") or "")
        workspace_id = str(envelope.get("workspace_id") or "")

        security_result = self._request_security_approval(
            action=f"webhook.route.{route.target_type.value}.{route.target_name}",
            user_id=user_id,
            workspace_id=workspace_id,
            payload=envelope,
            route=route,
        )

        if not security_result["success"]:
            self._log_audit_event(
                event_type="webhook.route.blocked_by_security",
                user_id=user_id,
                workspace_id=workspace_id,
                data={
                    "route_id": route.route_id,
                    "target_type": route.target_type.value,
                    "target_name": route.target_name,
                    "event_id": envelope.get("event_id"),
                    "event_type": envelope.get("event_type"),
                    "security_result": security_result,
                },
            )
            return {
                "success": False,
                "message": "Webhook route blocked by security policy.",
                "route": route.to_dict(include_handler=False),
                "error": security_result.get("error"),
                "data": {
                    "security_result": security_result,
                },
            }

        dispatch_payload = {
            "dispatch_id": f"dispatch_{uuid.uuid4().hex}",
            "route_id": route.route_id,
            "route_name": route.name,
            "target_type": route.target_type.value,
            "target_name": route.target_name,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "envelope": envelope,
            "created_at": utc_now_iso(),
        }

        if route.target_type == RouteTargetType.LOG_ONLY:
            self._log_audit_event(
                event_type="webhook.route.log_only",
                user_id=user_id,
                workspace_id=workspace_id,
                data=dispatch_payload,
            )
            return {
                "success": True,
                "message": "Webhook route logged only.",
                "route": route.to_dict(include_handler=False),
                "data": dispatch_payload,
                "error": None,
            }

        if route.target_type == RouteTargetType.HANDLER and route.handler:
            try:
                handler_result = route.handler(dispatch_payload)
                if not isinstance(handler_result, dict):
                    handler_result = {
                        "success": bool(handler_result),
                        "message": "Handler returned non-dict response.",
                        "data": {"raw_response": repr(handler_result)},
                        "error": None,
                    }

                self._log_audit_event(
                    event_type="webhook.route.handler_executed",
                    user_id=user_id,
                    workspace_id=workspace_id,
                    data={
                        "route_id": route.route_id,
                        "event_id": envelope.get("event_id"),
                        "handler_success": handler_result.get("success"),
                    },
                )

                return {
                    "success": bool(handler_result.get("success", False)),
                    "message": "Webhook handler route executed.",
                    "route": route.to_dict(include_handler=False),
                    "data": {
                        "dispatch_payload": dispatch_payload,
                        "handler_result": handler_result,
                    },
                    "error": handler_result.get("error"),
                }

            except Exception as exc:
                self.logger.exception("Webhook handler execution failed.")
                return {
                    "success": False,
                    "message": "Webhook handler execution failed.",
                    "route": route.to_dict(include_handler=False),
                    "data": {"dispatch_payload": dispatch_payload},
                    "error": str(exc),
                }

        # Safe default for agent/connector/workflow/queue:
        # prepare dispatch payload but do not execute real side effects here.
        self._emit_agent_event(
            event_type="workflow.webhook.route_dispatch_prepared",
            user_id=user_id,
            workspace_id=workspace_id,
            data=dispatch_payload,
        )

        return {
            "success": True,
            "message": "Webhook route dispatch payload prepared.",
            "route": route.to_dict(include_handler=False),
            "data": dispatch_payload,
            "error": None,
            "metadata": {
                "note": (
                    "Prepared for Master Agent, Workflow Agent, Action Router, "
                    "queue worker, or connector execution."
                )
            },
        }

    def _summarize_payload(self, payload: Mapping[str, Any], max_keys: int = 20) -> Dict[str, Any]:
        """
        Create a compact payload summary for Memory Agent and dashboard context.
        """
        summary: Dict[str, Any] = {}
        for index, (key, value) in enumerate(payload.items()):
            if index >= max_keys:
                summary["_truncated"] = True
                break

            if isinstance(value, Mapping):
                summary[str(key)] = {
                    "type": "object",
                    "keys": list(value.keys())[:10],
                }
            elif isinstance(value, list):
                summary[str(key)] = {
                    "type": "list",
                    "length": len(value),
                }
            else:
                text = str(value)
                summary[str(key)] = text[:250] + ("..." if len(text) > 250 else "")

        return redact_sensitive(summary)

    # ------------------------------------------------------------------
    # Export / Import Helpers for Dashboard/API Persistence
    # ------------------------------------------------------------------

    def export_state(self, *, include_handlers: bool = False) -> Dict[str, Any]:
        """
        Export in-memory configs/routes for tests or dashboard persistence.

        Handler callables cannot be serialized safely. include_handlers only
        includes repr(handler), not executable objects.
        """
        return self._safe_result(
            message="Webhook manager state exported.",
            data={
                "webhooks": [
                    config.to_dict(include_sensitive=False)
                    for config in self._webhooks.values()
                ],
                "routes": [
                    route.to_dict(include_handler=include_handlers)
                    for route in self._routes.values()
                ],
                "version": DEFAULT_WEBHOOK_VERSION,
            },
        )

    def load_webhook_config(self, config_data: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Load one webhook config from persisted data.

        This is useful for FastAPI startup, tests, or dashboard-driven config
        restore. Secrets should remain in a vault and be referenced by secret_ref.
        """
        try:
            webhook_id = str(config_data.get("webhook_id") or generate_webhook_id())
            endpoint_path = slugify_path(str(config_data.get("endpoint_path") or f"/webhooks/{webhook_id}"))

            config = WebhookConfig(
                webhook_id=webhook_id,
                name=str(config_data.get("name") or webhook_id),
                user_id=str(config_data.get("user_id") or ""),
                workspace_id=str(config_data.get("workspace_id") or ""),
                endpoint_path=endpoint_path,
                status=WebhookStatus(str(config_data.get("status") or WebhookStatus.ACTIVE.value).lower()),
                auth_mode=WebhookAuthMode(str(config_data.get("auth_mode") or WebhookAuthMode.HMAC.value).lower()),
                signature_header=normalize_header_key(str(config_data.get("signature_header") or "x-william-signature")),
                signature_algorithm=str(config_data.get("signature_algorithm") or "sha256").lower(),
                secret_ref=config_data.get("secret_ref"),
                token_ref=config_data.get("token_ref"),
                event_types=list(config_data.get("event_types") or []),
                allowed_sources=list(config_data.get("allowed_sources") or []),
                max_payload_bytes=int(config_data.get("max_payload_bytes") or DEFAULT_MAX_PAYLOAD_BYTES),
                require_timestamp=bool(config_data.get("require_timestamp", False)),
                timestamp_tolerance_seconds=int(config_data.get("timestamp_tolerance_seconds") or 300),
                metadata=dict(config_data.get("metadata") or {}),
                created_at=str(config_data.get("created_at") or utc_now_iso()),
                updated_at=str(config_data.get("updated_at") or utc_now_iso()),
            )

            context_result = self._validate_task_context(
                user_id=config.user_id,
                workspace_id=config.workspace_id,
                operation="load_webhook_config",
            )
            if not context_result["success"]:
                return context_result

            self._webhooks[webhook_id] = config
            self._webhooks_by_path[endpoint_path] = webhook_id

            return self._safe_result(
                message="Webhook config loaded.",
                data={"webhook": config.to_dict(include_sensitive=False)},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to load webhook config.",
                error=str(exc),
                metadata={"operation": "load_webhook_config"},
            )


# ---------------------------------------------------------------------------
# Module-level convenience exports
# ---------------------------------------------------------------------------

__all__ = [
    "WebhookManager",
    "WebhookConfig",
    "WebhookRoute",
    "WebhookPayloadEnvelope",
    "WebhookStatus",
    "WebhookAuthMode",
    "RouteTargetType",
    "WebhookRouteMode",
    "TTLIdempotencyStore",
    "build_hmac_signature",
    "generate_webhook_secret",
    "generate_webhook_id",
    "generate_event_id",
    "redact_sensitive",
]


# ---------------------------------------------------------------------------
# Minimal self-test helper
# ---------------------------------------------------------------------------

def _self_test() -> Dict[str, Any]:
    """
    Lightweight local test.

    This does not run automatically on import. Developers may call:
        python -c "from agents.workflow_agent.webhook_manager import _self_test; print(_self_test())"
    """
    manager = WebhookManager()

    create_result = manager.create_webhook(
        name="Lead Form Webhook",
        user_id="user_test",
        workspace_id="workspace_test",
        endpoint_path="/webhooks/test-lead",
        auth_mode=WebhookAuthMode.HMAC,
        event_types=["lead.created"],
    )

    if not create_result["success"]:
        return create_result

    webhook = create_result["data"]["webhook"]
    secret = create_result["data"]["generated_secret_once"]

    route_result = manager.register_route(
        name="Log Lead",
        user_id="user_test",
        workspace_id="workspace_test",
        target_type=RouteTargetType.LOG_ONLY,
        target_name="audit_log",
        event_pattern="lead.created",
        mode=WebhookRouteMode.EXACT,
    )

    if not route_result["success"]:
        return route_result

    payload = {
        "event_type": "lead.created",
        "event_id": "lead_evt_001",
        "lead": {
            "name": "Test User",
            "phone": "+15555550123",
            "service": "Website Design",
        },
    }

    signature = build_hmac_signature(secret=secret, body=payload, algorithm="sha256")

    receive_result = manager.receive_webhook(
        body=payload,
        headers={
            "x-william-signature": signature,
            "x-event-type": "lead.created",
        },
        endpoint_path=webhook["endpoint_path"],
        source_ip="127.0.0.1",
        secret=secret,
    )

    return receive_result


"""
Where to place:
    agents/workflow_agent/webhook_manager.py

Required dependencies:
    - Python 3.10+
    - Standard library only for this file:
        dataclasses, enum, typing, json, hmac, hashlib, uuid, time, logging, datetime,
        collections, re, secrets, base64

How to test:
    1. Save this file at:
        agents/workflow_agent/webhook_manager.py

    2. Run import test:
        python -m py_compile agents/workflow_agent/webhook_manager.py

    3. Run lightweight self-test:
        python -c "from agents.workflow_agent.webhook_manager import _self_test; import json; print(json.dumps(_self_test(), indent=2))"

    4. Expected:
        - success: true
        - message: Webhook received and processed.
        - route_result shows log_only route processed.

Agent/module completion percentage after this file:
    33.3%

Next file to generate:
    agents/workflow_agent/form_pipeline.py

Agent/Module: Workflow Agent
File Completed: webhook_manager.py
Completion: 33.3%
Completed Files: ['workflow_agent.py', 'n8n_connector.py', 'workflow_builder.py', 'trigger_engine.py', 'action_router.py', 'app_connector.py', 'webhook_manager.py']
Remaining Files: ['form_pipeline.py', 'crm_connector.py', 'sheet_connector.py', 'whatsapp_connector.py', 'email_connector.py', 'notification_engine.py', 'condition_engine.py', 'scheduler.py', 'workflow_monitor.py', 'retry_handler.py', 'workflow_templates.py', 'workflow_memory.py', 'approval_gate.py', 'config.py']
Next Recommended File: agents/workflow_agent/form_pipeline.py
FILE COMPLETE
"""