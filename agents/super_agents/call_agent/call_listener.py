"""
agents/super_agents/call_agent/call_listener.py

William / Jarvis Multi-Agent AI SaaS System - Call Agent Listener
Digital Promotix

Purpose:
    Detects incoming/outgoing calls and permissions.

This module is designed to be:
    - Import-safe even if future William/Jarvis files are not created yet.
    - Compatible with BaseAgent, Agent Registry, Agent Loader, Agent Router, and Master Agent routing.
    - SaaS-safe with strict user_id and workspace_id isolation.
    - Security-aware before any sensitive call handling.
    - Verification-ready for completed call-detection events.
    - Memory-compatible for useful non-sensitive call context.
    - Dashboard/API-ready with structured dict/JSON results.

Important Safety Rule:
    This file does NOT answer calls, place calls, record calls, forward calls,
    transcribe calls, or perform destructive actions directly. It only detects,
    normalizes, validates, permission-checks, and emits safe call events that
    future Call Agent modules can consume.
"""

from __future__ import annotations

import dataclasses
import enum
import hashlib
import json
import logging
import os
import re
import time
import traceback
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple, Union


# =============================================================================
# Import-safe BaseAgent fallback
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for early project generation
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        Keeps this file safe to import before the real William/Jarvis BaseAgent
        exists. The real BaseAgent should provide richer lifecycle, registry,
        routing, telemetry, and permission behavior.
        """

        agent_name: str = "base_agent"
        agent_type: str = "generic"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_id = kwargs.get("agent_id", self.agent_name)
            self.logger = logging.getLogger(self.agent_id)

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback emit_event: %s %s", event_name, payload)


# =============================================================================
# Logging
# =============================================================================

LOGGER = logging.getLogger(__name__)
if not LOGGER.handlers:
    logging.basicConfig(level=os.getenv("WILLIAM_LOG_LEVEL", "INFO"))


# =============================================================================
# Enums and constants
# =============================================================================

class CallDirection(str, enum.Enum):
    """Supported call direction values."""

    INCOMING = "incoming"
    OUTGOING = "outgoing"
    UNKNOWN = "unknown"


class CallProvider(str, enum.Enum):
    """Supported provider/source identifiers."""

    GENERIC = "generic"
    TWILIO = "twilio"
    PLIVO = "plivo"
    VONAGE = "vonage"
    TELNYX = "telnyx"
    AIRCALL = "aircall"
    HUBSPOT = "hubspot"
    CUSTOM_WEBHOOK = "custom_webhook"
    MOBILE_DEVICE = "mobile_device"
    VOIP = "voip"


class CallState(str, enum.Enum):
    """Normalized call state values."""

    RINGING = "ringing"
    INITIATED = "initiated"
    QUEUED = "queued"
    CONNECTED = "connected"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    MISSED = "missed"
    FAILED = "failed"
    BUSY = "busy"
    NO_ANSWER = "no_answer"
    CANCELED = "canceled"
    UNKNOWN = "unknown"


class CallPermission(str, enum.Enum):
    """Permission flags used by Call Agent."""

    DETECT_CALLS = "call.detect"
    VIEW_CALL_METADATA = "call.metadata.view"
    HANDLE_INCOMING = "call.incoming.handle"
    HANDLE_OUTGOING = "call.outgoing.handle"
    ROUTE_CALLS = "call.route"
    RECORD_CALLS = "call.record"
    TRANSCRIBE_CALLS = "call.transcribe"
    SUMMARIZE_CALLS = "call.summarize"
    BOOK_APPOINTMENTS = "call.appointment.book"
    QUALIFY_LEADS = "call.lead.qualify"


class PermissionDecision(str, enum.Enum):
    """Permission/security decision values."""

    ALLOWED = "allowed"
    DENIED = "denied"
    REQUIRES_APPROVAL = "requires_approval"
    NOT_REQUIRED = "not_required"
    UNAVAILABLE = "unavailable"


class DetectionStatus(str, enum.Enum):
    """Call detection processing status."""

    DETECTED = "detected"
    IGNORED = "ignored"
    BLOCKED = "blocked"
    FAILED = "failed"
    REQUIRES_APPROVAL = "requires_approval"


SENSITIVE_CALL_ACTIONS = {
    CallPermission.HANDLE_INCOMING.value,
    CallPermission.HANDLE_OUTGOING.value,
    CallPermission.ROUTE_CALLS.value,
    CallPermission.RECORD_CALLS.value,
    CallPermission.TRANSCRIBE_CALLS.value,
    CallPermission.BOOK_APPOINTMENTS.value,
    CallPermission.QUALIFY_LEADS.value,
}

DEFAULT_ALLOWED_DIRECTIONS = {
    CallDirection.INCOMING.value,
    CallDirection.OUTGOING.value,
}

DEFAULT_REQUIRED_PERMISSIONS = {
    CallDirection.INCOMING.value: [
        CallPermission.DETECT_CALLS.value,
        CallPermission.VIEW_CALL_METADATA.value,
        CallPermission.HANDLE_INCOMING.value,
    ],
    CallDirection.OUTGOING.value: [
        CallPermission.DETECT_CALLS.value,
        CallPermission.VIEW_CALL_METADATA.value,
        CallPermission.HANDLE_OUTGOING.value,
    ],
    CallDirection.UNKNOWN.value: [
        CallPermission.DETECT_CALLS.value,
        CallPermission.VIEW_CALL_METADATA.value,
    ],
}

MAX_PROVIDER_PAYLOAD_BYTES = 128_000
MAX_EVENT_METADATA_KEYS = 80
MAX_PHONE_DISPLAY_LENGTH = 64


# =============================================================================
# Utility helpers
# =============================================================================

def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def parse_bool(value: Optional[str], default: bool = False) -> bool:
    """Parse bool-ish env/config values."""
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def parse_int(value: Optional[str], default: int) -> int:
    """Parse integer safely."""
    try:
        if value is None:
            return default
        return int(value)
    except Exception:
        return default


def stable_hash(value: str) -> str:
    """Create stable short hash for trace-safe IDs."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def mask_phone(value: Optional[str]) -> Optional[str]:
    """Mask phone number or contact identifier for logs/events."""
    if value is None:
        return None
    raw = str(value).strip()
    if not raw:
        return raw
    digits = "".join(ch for ch in raw if ch.isdigit())
    if len(digits) >= 7:
        return f"***{digits[-4:]}"
    if len(raw) <= 4:
        return "***"
    return f"{raw[:2]}***{raw[-2:]}"


def normalize_phone(value: Optional[str]) -> Optional[str]:
    """
    Normalize phone-like value.

    This does not force a specific country format because providers may pass
    SIP IDs, masked phone numbers, or internal extension IDs.
    """
    if value is None:
        return None
    raw = str(value).strip()
    if not raw:
        return None

    if raw.startswith("sip:"):
        return raw[:MAX_PHONE_DISPLAY_LENGTH]

    cleaned = re.sub(r"[^\d+]", "", raw)
    if cleaned.startswith("00"):
        cleaned = "+" + cleaned[2:]
    if cleaned.count("+") > 1:
        cleaned = cleaned.replace("+", "")
    if cleaned and not cleaned.startswith("+") and len(cleaned) >= 10:
        return cleaned[:MAX_PHONE_DISPLAY_LENGTH]
    return cleaned[:MAX_PHONE_DISPLAY_LENGTH] if cleaned else raw[:MAX_PHONE_DISPLAY_LENGTH]


def normalize_direction(value: Optional[str]) -> str:
    """Normalize provider call direction."""
    raw = str(value or "").strip().lower()

    incoming_values = {
        "incoming",
        "inbound",
        "received",
        "receive",
        "ringing_in",
        "from_customer",
        "customer_to_agent",
    }
    outgoing_values = {
        "outgoing",
        "outbound",
        "sent",
        "dialed",
        "initiated",
        "agent_to_customer",
        "from_agent",
    }

    if raw in incoming_values:
        return CallDirection.INCOMING.value
    if raw in outgoing_values:
        return CallDirection.OUTGOING.value
    return CallDirection.UNKNOWN.value


def normalize_state(value: Optional[str]) -> str:
    """Normalize provider call state/status."""
    raw = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")

    state_map = {
        "ringing": CallState.RINGING.value,
        "initiated": CallState.INITIATED.value,
        "queued": CallState.QUEUED.value,
        "connected": CallState.CONNECTED.value,
        "answered": CallState.CONNECTED.value,
        "in_progress": CallState.IN_PROGRESS.value,
        "progress": CallState.IN_PROGRESS.value,
        "completed": CallState.COMPLETED.value,
        "complete": CallState.COMPLETED.value,
        "missed": CallState.MISSED.value,
        "failed": CallState.FAILED.value,
        "busy": CallState.BUSY.value,
        "no_answer": CallState.NO_ANSWER.value,
        "noanswer": CallState.NO_ANSWER.value,
        "canceled": CallState.CANCELED.value,
        "cancelled": CallState.CANCELED.value,
    }
    return state_map.get(raw, CallState.UNKNOWN.value)


def normalize_provider(value: Optional[str]) -> str:
    """Normalize provider/source name."""
    raw = str(value or CallProvider.GENERIC.value).strip().lower()
    allowed = {item.value for item in CallProvider}
    return raw if raw in allowed else CallProvider.GENERIC.value


def truncate_text(value: str, limit: int = 300) -> str:
    """Truncate long text safely."""
    if len(value) <= limit:
        return value
    return value[: max(0, limit - 3)] + "..."


def safe_json_size(payload: Mapping[str, Any]) -> int:
    """Return JSON payload byte size safely."""
    try:
        return len(json.dumps(payload, default=str).encode("utf-8"))
    except Exception:
        return MAX_PROVIDER_PAYLOAD_BYTES + 1


def safe_metadata(metadata: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    """Redact secrets and sensitive contact fields from metadata."""
    if not metadata:
        return {}

    secret_terms = {
        "token",
        "secret",
        "password",
        "api_key",
        "apikey",
        "authorization",
        "auth",
        "bearer",
        "cookie",
        "session",
        "private_key",
        "recording_url",
        "recording",
    }

    phone_terms = {
        "phone",
        "number",
        "caller",
        "callee",
        "from",
        "to",
        "ani",
        "dnis",
    }

    safe: Dict[str, Any] = {}
    count = 0
    for key, value in metadata.items():
        count += 1
        if count > MAX_EVENT_METADATA_KEYS:
            safe["_truncated"] = True
            safe["_truncated_reason"] = "too_many_metadata_keys"
            break

        key_str = str(key)
        key_lower = key_str.lower()

        if any(term in key_lower for term in secret_terms):
            safe[key_str] = "***REDACTED***"
        elif any(term == key_lower or key_lower.endswith(term) for term in phone_terms):
            safe[key_str] = mask_phone(str(value)) if value is not None else None
        elif isinstance(value, Mapping):
            safe[key_str] = safe_metadata(value)
        elif isinstance(value, list):
            safe[key_str] = [
                safe_metadata(item) if isinstance(item, Mapping) else item
                for item in value[:25]
            ]
            if len(value) > 25:
                safe[key_str].append(f"... {len(value) - 25} more items")
        else:
            safe[key_str] = value
    return safe


def coerce_str(value: Any, default: str = "") -> str:
    """Return safe string."""
    if value is None:
        return default
    return str(value)


# =============================================================================
# Data structures
# =============================================================================

@dataclasses.dataclass
class CallListenerConfig:
    """
    Runtime configuration for CallListener.

    No secrets are hardcoded. Permission/security behavior should be injected by
    callbacks or configured from environment.
    """

    detection_enabled: bool = True
    allowed_directions: Sequence[str] = dataclasses.field(
        default_factory=lambda: sorted(DEFAULT_ALLOWED_DIRECTIONS)
    )
    require_security_for_sensitive_actions: bool = True
    require_security_for_unknown_direction: bool = True
    allow_unknown_provider: bool = True
    allow_unknown_direction_detection: bool = True
    max_provider_payload_bytes: int = MAX_PROVIDER_PAYLOAD_BYTES

    # If false, listener detects only and does not emit dashboard-style call events.
    emit_detection_events: bool = True

    # If true, raw provider payload is never returned in public results.
    redact_provider_payload: bool = True

    # Future system can use this to avoid duplicate provider events.
    dedupe_window_seconds: int = 300

    @classmethod
    def from_env(cls) -> "CallListenerConfig":
        """Build config from environment variables."""
        return cls(
            detection_enabled=parse_bool(os.getenv("WILLIAM_CALL_DETECTION_ENABLED"), True),
            require_security_for_sensitive_actions=parse_bool(
                os.getenv("WILLIAM_CALL_REQUIRE_SECURITY_SENSITIVE"), True
            ),
            require_security_for_unknown_direction=parse_bool(
                os.getenv("WILLIAM_CALL_REQUIRE_SECURITY_UNKNOWN_DIRECTION"), True
            ),
            allow_unknown_provider=parse_bool(os.getenv("WILLIAM_CALL_ALLOW_UNKNOWN_PROVIDER"), True),
            allow_unknown_direction_detection=parse_bool(
                os.getenv("WILLIAM_CALL_ALLOW_UNKNOWN_DIRECTION"), True
            ),
            max_provider_payload_bytes=parse_int(
                os.getenv("WILLIAM_CALL_MAX_PAYLOAD_BYTES"),
                MAX_PROVIDER_PAYLOAD_BYTES,
            ),
            emit_detection_events=parse_bool(os.getenv("WILLIAM_CALL_EMIT_EVENTS"), True),
            redact_provider_payload=parse_bool(os.getenv("WILLIAM_CALL_REDACT_PROVIDER_PAYLOAD"), True),
            dedupe_window_seconds=parse_int(
                os.getenv("WILLIAM_CALL_DEDUPE_WINDOW_SECONDS"),
                300,
            ),
        )


@dataclasses.dataclass(frozen=True)
class CallParty:
    """Represents caller/callee/agent/customer party metadata."""

    phone: Optional[str] = None
    name: Optional[str] = None
    user_id: Optional[str] = None
    contact_id: Optional[str] = None
    role: Optional[str] = None
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def safe_dict(self) -> Dict[str, Any]:
        return {
            "phone": mask_phone(self.phone),
            "name": self.name,
            "user_id": self.user_id,
            "contact_id": self.contact_id,
            "role": self.role,
            "metadata": safe_metadata(self.metadata),
        }


@dataclasses.dataclass(frozen=True)
class CallEvent:
    """
    Normalized call detection event.

    provider_payload is kept optional and should not be exposed publicly unless
    explicitly needed for internal debugging and redaction is disabled.
    """

    user_id: str
    workspace_id: str
    call_id: str
    provider: str
    direction: str
    state: str
    from_party: CallParty
    to_party: CallParty
    detected_at: str
    provider_event_id: Optional[str] = None
    provider_call_id: Optional[str] = None
    line_id: Optional[str] = None
    device_id: Optional[str] = None
    workflow_id: Optional[str] = None
    task_id: Optional[str] = None
    correlation_id: Optional[str] = None
    requested_actions: Tuple[str, ...] = dataclasses.field(default_factory=tuple)
    provider_payload: Dict[str, Any] = dataclasses.field(default_factory=dict)
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def safe_dict(self, include_provider_payload: bool = False) -> Dict[str, Any]:
        data = {
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "call_id": self.call_id,
            "provider": self.provider,
            "direction": self.direction,
            "state": self.state,
            "from_party": self.from_party.safe_dict(),
            "to_party": self.to_party.safe_dict(),
            "detected_at": self.detected_at,
            "provider_event_id": self.provider_event_id,
            "provider_call_id": self.provider_call_id,
            "line_id": self.line_id,
            "device_id": self.device_id,
            "workflow_id": self.workflow_id,
            "task_id": self.task_id,
            "correlation_id": self.correlation_id,
            "requested_actions": list(self.requested_actions),
            "metadata": safe_metadata(self.metadata),
        }
        if include_provider_payload:
            data["provider_payload"] = safe_metadata(self.provider_payload)
        else:
            data["provider_payload_redacted"] = True
        return data


# =============================================================================
# CallListener
# =============================================================================

class CallListener(BaseAgent):
    """
    Call Agent helper that detects incoming/outgoing calls and validates permissions.

    Master Agent:
        Can route call event detection tasks to this class via public methods:
        - detect_call_event()
        - detect_provider_event()
        - validate_call_permissions()
        - get_supported_providers()
        - get_recent_detected_calls()

    Security Agent:
        Sensitive call actions pass through _requires_security_check() and
        _request_security_approval() before being allowed.

    Memory Agent:
        Useful call metadata can be prepared through _prepare_memory_payload()
        without storing raw private provider payloads.

    Verification Agent:
        Every completed detection prepares a verification payload using
        _prepare_verification_payload().

    Dashboard/API:
        Results are structured and safe for API responses.
    """

    agent_name = "call_listener"
    agent_type = "call_agent"
    public_methods = (
        "detect_call_event",
        "detect_provider_event",
        "validate_call_permissions",
        "get_supported_providers",
        "get_recent_detected_calls",
        "clear_recent_detected_calls",
    )

    def __init__(
        self,
        config: Optional[CallListenerConfig] = None,
        permission_callback: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        security_approval_callback: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        audit_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        event_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        memory_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        verification_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        logger: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self.config = config or CallListenerConfig.from_env()
        self.permission_callback = permission_callback
        self.security_approval_callback = security_approval_callback
        self.audit_callback = audit_callback
        self.event_callback = event_callback
        self.memory_callback = memory_callback
        self.verification_callback = verification_callback
        self.logger = logger or getattr(self, "logger", LOGGER)

        # In-memory recent event cache. Future workflow_monitor/call_memory can
        # replace this with persistent per-workspace storage.
        self._recent_calls: List[Dict[str, Any]] = []
        self._dedupe_cache: Dict[str, float] = {}

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    def get_supported_providers(self) -> Dict[str, Any]:
        """Return supported provider/source identifiers."""
        return self._safe_result(
            message="Supported call providers loaded.",
            data={
                "providers": [provider.value for provider in CallProvider],
                "directions": [direction.value for direction in CallDirection],
                "states": [state.value for state in CallState],
                "permissions": [permission.value for permission in CallPermission],
                "detection_enabled": self.config.detection_enabled,
                "allowed_directions": list(self.config.allowed_directions),
            },
            metadata={"agent": self.agent_name},
        )

    def detect_call_event(
        self,
        *,
        user_id: str,
        workspace_id: str,
        direction: str,
        from_number: Optional[str] = None,
        to_number: Optional[str] = None,
        state: str = CallState.UNKNOWN.value,
        provider: str = CallProvider.GENERIC.value,
        provider_event_id: Optional[str] = None,
        provider_call_id: Optional[str] = None,
        line_id: Optional[str] = None,
        device_id: Optional[str] = None,
        caller_name: Optional[str] = None,
        callee_name: Optional[str] = None,
        requested_actions: Optional[Sequence[str]] = None,
        workflow_id: Optional[str] = None,
        task_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        provider_payload: Optional[Mapping[str, Any]] = None,
        require_approval: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Detect and validate a normalized incoming/outgoing call event.

        This method does not answer/place/record/route a call. It only detects,
        validates, checks permissions, emits events, and returns routing-ready
        payloads for future Call Agent modules.
        """
        started = time.time()
        correlation_id = correlation_id or self._new_correlation_id()

        try:
            if not self.config.detection_enabled:
                return self._error_result(
                    message="Call detection is disabled by configuration.",
                    error="call_detection_disabled",
                    metadata={"agent": self.agent_name, "correlation_id": correlation_id},
                )

            call_event = self._build_call_event(
                user_id=user_id,
                workspace_id=workspace_id,
                direction=direction,
                from_number=from_number,
                to_number=to_number,
                state=state,
                provider=provider,
                provider_event_id=provider_event_id,
                provider_call_id=provider_call_id,
                line_id=line_id,
                device_id=device_id,
                caller_name=caller_name,
                callee_name=callee_name,
                requested_actions=requested_actions,
                workflow_id=workflow_id,
                task_id=task_id,
                correlation_id=correlation_id,
                metadata=metadata,
                provider_payload=provider_payload,
            )

            context_result = self._validate_task_context(
                user_id=call_event.user_id,
                workspace_id=call_event.workspace_id,
                task_id=call_event.task_id,
                workflow_id=call_event.workflow_id,
                metadata=call_event.metadata,
            )
            if not context_result["success"]:
                return context_result

            validation_result = self._validate_call_event(call_event)
            if not validation_result["success"]:
                self._log_audit_event(
                    action="call_listener.validation_failed",
                    user_id=call_event.user_id,
                    workspace_id=call_event.workspace_id,
                    data={
                        "call_event": call_event.safe_dict(
                            include_provider_payload=not self.config.redact_provider_payload
                        ),
                        "error": validation_result.get("error"),
                    },
                    correlation_id=call_event.correlation_id,
                )
                return validation_result

            if self._is_duplicate_event(call_event):
                duplicate_result = self._safe_result(
                    message="Duplicate call event ignored.",
                    data={
                        "status": DetectionStatus.IGNORED.value,
                        "reason": "duplicate_event",
                        "call_event": call_event.safe_dict(
                            include_provider_payload=not self.config.redact_provider_payload
                        ),
                    },
                    metadata={"agent": self.agent_name, "correlation_id": call_event.correlation_id},
                )
                self._emit_agent_event("call_listener.duplicate_ignored", duplicate_result["data"])
                return duplicate_result

            permission_result = self.validate_call_permissions(
                user_id=call_event.user_id,
                workspace_id=call_event.workspace_id,
                direction=call_event.direction,
                requested_actions=list(call_event.requested_actions),
                call_event=call_event.safe_dict(include_provider_payload=False),
                correlation_id=call_event.correlation_id,
                require_approval=require_approval,
            )

            if not permission_result["success"]:
                self._log_audit_event(
                    action="call_listener.permission_denied",
                    user_id=call_event.user_id,
                    workspace_id=call_event.workspace_id,
                    data={
                        "call_event": call_event.safe_dict(include_provider_payload=False),
                        "permission_result": permission_result,
                    },
                    correlation_id=call_event.correlation_id,
                )
                return permission_result

            permission_status = permission_result.get("data", {}).get("decision")
            if permission_status == PermissionDecision.REQUIRES_APPROVAL.value:
                self._log_audit_event(
                    action="call_listener.requires_security_approval",
                    user_id=call_event.user_id,
                    workspace_id=call_event.workspace_id,
                    data={
                        "call_event": call_event.safe_dict(include_provider_payload=False),
                        "permission_result": permission_result,
                    },
                    correlation_id=call_event.correlation_id,
                )
                return permission_result

            self._mark_event_seen(call_event)

            duration_ms = int((time.time() - started) * 1000)

            verification_payload = self._prepare_verification_payload(
                call_event=call_event,
                permission_result=permission_result,
                duration_ms=duration_ms,
            )
            memory_payload = self._prepare_memory_payload(
                call_event=call_event,
                permission_result=permission_result,
            )

            self._send_optional_callback(self.verification_callback, verification_payload)
            self._send_optional_callback(self.memory_callback, memory_payload)

            event_data = {
                "status": DetectionStatus.DETECTED.value,
                "call_event": call_event.safe_dict(
                    include_provider_payload=not self.config.redact_provider_payload
                ),
                "permission_result": permission_result.get("data", {}),
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
                "next_suggested_modules": self._suggest_next_modules(call_event),
            }

            self._recent_calls.append(
                {
                    "detected_at": utc_now_iso(),
                    "user_id": call_event.user_id,
                    "workspace_id": call_event.workspace_id,
                    "call_id": call_event.call_id,
                    "correlation_id": call_event.correlation_id,
                    "event": call_event.safe_dict(include_provider_payload=False),
                }
            )
            self._trim_recent_calls()

            self._emit_agent_event("call_listener.call_detected", event_data)

            self._log_audit_event(
                action="call_listener.call_detected",
                user_id=call_event.user_id,
                workspace_id=call_event.workspace_id,
                data={
                    "call_event": call_event.safe_dict(include_provider_payload=False),
                    "permission_result": permission_result.get("data", {}),
                    "duration_ms": duration_ms,
                },
                correlation_id=call_event.correlation_id,
            )

            return self._safe_result(
                message=f"{call_event.direction.title()} call detected and permission-checked.",
                data=event_data,
                metadata={
                    "agent": self.agent_name,
                    "correlation_id": call_event.correlation_id,
                    "duration_ms": duration_ms,
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Call detection failed.",
                error=exc,
                metadata={
                    "agent": self.agent_name,
                    "correlation_id": correlation_id,
                    "duration_ms": int((time.time() - started) * 1000),
                },
            )

    def detect_provider_event(
        self,
        *,
        user_id: str,
        workspace_id: str,
        provider: str,
        provider_payload: Mapping[str, Any],
        workflow_id: Optional[str] = None,
        task_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        require_approval: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Detect call event from a provider webhook-style payload.

        Supports common fields from Twilio/Plivo/Vonage/Telnyx/Aircall/custom
        sources while staying provider-neutral.
        """
        correlation_id = correlation_id or self._new_correlation_id()

        if not isinstance(provider_payload, Mapping):
            return self._error_result(
                message="provider_payload must be a dictionary.",
                error="invalid_provider_payload",
                metadata={"agent": self.agent_name, "correlation_id": correlation_id},
            )

        if safe_json_size(provider_payload) > self.config.max_provider_payload_bytes:
            return self._error_result(
                message="Provider payload is too large.",
                error="provider_payload_too_large",
                metadata={
                    "agent": self.agent_name,
                    "correlation_id": correlation_id,
                    "max_bytes": self.config.max_provider_payload_bytes,
                },
            )

        parsed = self._parse_provider_payload(provider, provider_payload)

        return self.detect_call_event(
            user_id=user_id,
            workspace_id=workspace_id,
            direction=parsed.get("direction", CallDirection.UNKNOWN.value),
            from_number=parsed.get("from_number"),
            to_number=parsed.get("to_number"),
            state=parsed.get("state", CallState.UNKNOWN.value),
            provider=provider,
            provider_event_id=parsed.get("provider_event_id"),
            provider_call_id=parsed.get("provider_call_id"),
            line_id=parsed.get("line_id"),
            device_id=parsed.get("device_id"),
            caller_name=parsed.get("caller_name"),
            callee_name=parsed.get("callee_name"),
            requested_actions=parsed.get("requested_actions") or [],
            workflow_id=workflow_id,
            task_id=task_id,
            correlation_id=correlation_id,
            metadata=parsed.get("metadata") or {},
            provider_payload=dict(provider_payload),
            require_approval=require_approval,
        )

    def validate_call_permissions(
        self,
        *,
        user_id: str,
        workspace_id: str,
        direction: str,
        requested_actions: Optional[Sequence[str]] = None,
        call_event: Optional[Mapping[str, Any]] = None,
        correlation_id: Optional[str] = None,
        require_approval: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Validate permissions for detected call handling.

        Uses permission_callback if provided. Without a callback, only safe
        detection-level permissions are allowed and sensitive handling requires
        approval or is blocked.
        """
        correlation_id = correlation_id or self._new_correlation_id()
        normalized_direction = normalize_direction(direction)
        actions = self._required_permissions_for_direction(
            normalized_direction,
            requested_actions=requested_actions,
        )

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            metadata={},
        )
        if not context_result["success"]:
            return context_result

        permission_request = {
            "agent": self.agent_name,
            "action": "validate_call_permissions",
            "user_id": user_id,
            "workspace_id": workspace_id,
            "direction": normalized_direction,
            "permissions": actions,
            "call_event": safe_metadata(dict(call_event or {})),
            "correlation_id": correlation_id,
            "created_at": utc_now_iso(),
        }

        callback_decision = self._check_permission_callback(permission_request)
        if callback_decision.get("decision") == PermissionDecision.DENIED.value:
            return self._error_result(
                message="Call permission denied.",
                error="call_permission_denied",
                data=callback_decision,
                metadata={"agent": self.agent_name, "correlation_id": correlation_id},
            )

        security_result = self._handle_security(
            permission_request=permission_request,
            direction=normalized_direction,
            requested_actions=actions,
            require_approval=require_approval,
        )
        if not security_result["success"]:
            return security_result

        if security_result.get("data", {}).get("decision") == PermissionDecision.REQUIRES_APPROVAL.value:
            return security_result

        return self._safe_result(
            message="Call permissions validated.",
            data={
                "decision": PermissionDecision.ALLOWED.value,
                "direction": normalized_direction,
                "permissions": actions,
                "permission_callback": callback_decision,
                "security": security_result.get("data", {}),
            },
            metadata={"agent": self.agent_name, "correlation_id": correlation_id},
        )

    def get_recent_detected_calls(
        self,
        *,
        user_id: str,
        workspace_id: str,
        limit: int = 25,
    ) -> Dict[str, Any]:
        """Return recent detected call events for one SaaS user/workspace only."""
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
        )
        if not context_result["success"]:
            return context_result

        safe_limit = max(1, min(int(limit or 25), 100))
        filtered = [
            item
            for item in reversed(self._recent_calls)
            if item.get("user_id") == user_id and item.get("workspace_id") == workspace_id
        ][:safe_limit]

        return self._safe_result(
            message="Recent detected calls loaded.",
            data={
                "calls": filtered,
                "count": len(filtered),
                "limit": safe_limit,
            },
            metadata={"agent": self.agent_name},
        )

    def clear_recent_detected_calls(
        self,
        *,
        user_id: str,
        workspace_id: str,
    ) -> Dict[str, Any]:
        """Clear recent in-memory call events for one SaaS user/workspace only."""
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
        )
        if not context_result["success"]:
            return context_result

        before = len(self._recent_calls)
        self._recent_calls = [
            item
            for item in self._recent_calls
            if not (
                item.get("user_id") == user_id
                and item.get("workspace_id") == workspace_id
            )
        ]
        removed = before - len(self._recent_calls)

        self._log_audit_event(
            action="call_listener.recent_calls_cleared",
            user_id=user_id,
            workspace_id=workspace_id,
            data={"removed": removed},
            correlation_id=None,
        )

        return self._safe_result(
            message="Recent detected calls cleared for this workspace.",
            data={"removed": removed},
            metadata={"agent": self.agent_name},
        )

    # -------------------------------------------------------------------------
    # Compatibility hooks
    # -------------------------------------------------------------------------

    def _validate_task_context(
        self,
        *,
        user_id: str,
        workspace_id: str,
        task_id: Optional[str] = None,
        workflow_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Validate SaaS isolation.

        All user-specific call detection must include both user_id and workspace_id.
        """
        if not user_id or not str(user_id).strip():
            return self._error_result(
                message="Missing user_id. Call detection requires SaaS user isolation.",
                error="missing_user_id",
                metadata={"task_id": task_id, "workflow_id": workflow_id},
            )

        if not workspace_id or not str(workspace_id).strip():
            return self._error_result(
                message="Missing workspace_id. Call detection requires workspace isolation.",
                error="missing_workspace_id",
                metadata={"task_id": task_id, "workflow_id": workflow_id},
            )

        if metadata:
            meta_user = metadata.get("user_id")
            meta_workspace = metadata.get("workspace_id")
            if meta_user and str(meta_user) != str(user_id):
                return self._error_result(
                    message="Context mismatch: metadata user_id does not match call user_id.",
                    error="user_context_mismatch",
                    metadata={"task_id": task_id, "workflow_id": workflow_id},
                )
            if meta_workspace and str(meta_workspace) != str(workspace_id):
                return self._error_result(
                    message="Context mismatch: metadata workspace_id does not match call workspace_id.",
                    error="workspace_context_mismatch",
                    metadata={"task_id": task_id, "workflow_id": workflow_id},
                )

        return self._safe_result(
            message="Task context validated.",
            data={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "task_id": task_id,
                "workflow_id": workflow_id,
            },
            metadata={"agent": self.agent_name},
        )

    def _requires_security_check(
        self,
        *,
        direction: str,
        requested_actions: Sequence[str],
        require_approval: Optional[bool] = None,
    ) -> bool:
        """
        Determine if Security Agent approval is required.

        Unknown direction and sensitive actions require security by default.
        """
        if require_approval is not None:
            return bool(require_approval)

        if (
            direction == CallDirection.UNKNOWN.value
            and self.config.require_security_for_unknown_direction
        ):
            return True

        if self.config.require_security_for_sensitive_actions:
            return any(action in SENSITIVE_CALL_ACTIONS for action in requested_actions)

        return False

    def _request_security_approval(self, permission_request: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Ask Security Agent/callback for call permission approval.

        If no callback exists and approval is required, this returns requires_approval
        instead of allowing sensitive call handling.
        """
        approval_request = {
            "agent": self.agent_name,
            "risk_type": "call_permission",
            "action": "call_listener_permission_check",
            "request": safe_metadata(dict(permission_request)),
            "created_at": utc_now_iso(),
        }

        self._emit_agent_event("call_listener.security_approval_requested", approval_request)

        if not self.security_approval_callback:
            return self._safe_result(
                message="Security approval is required but Security Agent callback is unavailable.",
                data={
                    "decision": PermissionDecision.REQUIRES_APPROVAL.value,
                    "approval_request": approval_request,
                },
                metadata={
                    "agent": self.agent_name,
                    "correlation_id": permission_request.get("correlation_id"),
                },
            )

        try:
            response = self.security_approval_callback(approval_request)
            decision = str(response.get("decision") or response.get("status") or "").lower()

            if decision in {"approved", "allow", "allowed", "ok"}:
                return self._safe_result(
                    message="Security approval granted.",
                    data={
                        "decision": PermissionDecision.ALLOWED.value,
                        "approval_response": safe_metadata(response),
                    },
                    metadata={
                        "agent": self.agent_name,
                        "correlation_id": permission_request.get("correlation_id"),
                    },
                )

            if decision in {"denied", "deny", "blocked", "rejected"}:
                return self._error_result(
                    message="Security approval denied.",
                    error="security_denied",
                    data={
                        "decision": PermissionDecision.DENIED.value,
                        "approval_response": safe_metadata(response),
                    },
                    metadata={
                        "agent": self.agent_name,
                        "correlation_id": permission_request.get("correlation_id"),
                    },
                )

            return self._safe_result(
                message="Security approval did not return a final approval decision.",
                data={
                    "decision": PermissionDecision.REQUIRES_APPROVAL.value,
                    "approval_response": safe_metadata(response),
                },
                metadata={
                    "agent": self.agent_name,
                    "correlation_id": permission_request.get("correlation_id"),
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Security approval request failed.",
                error=exc,
                metadata={
                    "agent": self.agent_name,
                    "correlation_id": permission_request.get("correlation_id"),
                },
            )

    def _prepare_verification_payload(
        self,
        *,
        call_event: CallEvent,
        permission_result: Mapping[str, Any],
        duration_ms: int,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        Verification Agent can later confirm call event integrity, permission
        decision, provider call ID, and routing readiness.
        """
        safe_event = call_event.safe_dict(include_provider_payload=False)
        return {
            "verification_type": "call_detection",
            "agent": self.agent_name,
            "user_id": call_event.user_id,
            "workspace_id": call_event.workspace_id,
            "workflow_id": call_event.workflow_id,
            "task_id": call_event.task_id,
            "correlation_id": call_event.correlation_id,
            "call_id": call_event.call_id,
            "provider": call_event.provider,
            "provider_event_id": call_event.provider_event_id,
            "provider_call_id": call_event.provider_call_id,
            "direction": call_event.direction,
            "state": call_event.state,
            "permission_decision": permission_result.get("data", {}).get("decision"),
            "safe_event_hash": stable_hash(json.dumps(safe_event, sort_keys=True, default=str)),
            "duration_ms": duration_ms,
            "created_at": utc_now_iso(),
            "metadata": {
                "requested_actions": list(call_event.requested_actions),
                "next_suggested_modules": self._suggest_next_modules(call_event),
            },
        }

    def _prepare_memory_payload(
        self,
        *,
        call_event: CallEvent,
        permission_result: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent payload.

        This summary avoids raw call payloads and masks phone numbers.
        """
        return {
            "memory_type": "call_detection_event",
            "agent": self.agent_name,
            "user_id": call_event.user_id,
            "workspace_id": call_event.workspace_id,
            "workflow_id": call_event.workflow_id,
            "task_id": call_event.task_id,
            "correlation_id": call_event.correlation_id,
            "summary": (
                f"{call_event.direction.title()} call detected via "
                f"{call_event.provider} with state {call_event.state}."
            ),
            "data": {
                "call_id": call_event.call_id,
                "provider": call_event.provider,
                "direction": call_event.direction,
                "state": call_event.state,
                "from_phone": mask_phone(call_event.from_party.phone),
                "to_phone": mask_phone(call_event.to_party.phone),
                "permission_decision": permission_result.get("data", {}).get("decision"),
                "requested_actions": list(call_event.requested_actions),
            },
            "created_at": utc_now_iso(),
        }

    def _emit_agent_event(self, event_name: str, payload: Dict[str, Any]) -> None:
        """
        Emit agent event for Master Agent, Dashboard/API, Registry, or event bus.

        Safe even when no event bus exists.
        """
        safe_payload = safe_metadata(payload)
        try:
            if self.event_callback:
                self.event_callback(event_name, safe_payload)
            elif hasattr(super(), "emit_event"):
                try:
                    super().emit_event(event_name, safe_payload)  # type: ignore[misc]
                except Exception:
                    self.logger.debug("BaseAgent emit_event failed.", exc_info=True)
            else:
                self.logger.debug("Agent event: %s %s", event_name, safe_payload)
        except Exception:
            self.logger.warning("Failed to emit agent event: %s", event_name, exc_info=True)

    def _log_audit_event(
        self,
        *,
        action: str,
        user_id: str,
        workspace_id: str,
        data: Optional[Mapping[str, Any]] = None,
        correlation_id: Optional[str] = None,
    ) -> None:
        """
        Log audit event.

        Audit events always include user_id/workspace_id for SaaS isolation.
        """
        event = {
            "audit_id": f"audit_{uuid.uuid4().hex}",
            "agent": self.agent_name,
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "correlation_id": correlation_id,
            "data": safe_metadata(dict(data or {})),
            "created_at": utc_now_iso(),
        }

        try:
            if self.audit_callback:
                self.audit_callback(event)
            else:
                self.logger.info("AUDIT %s", json.dumps(event, default=str))
        except Exception:
            self.logger.warning("Audit logging failed for action=%s", action, exc_info=True)

    def _safe_result(
        self,
        *,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard success result."""
        return {
            "success": True,
            "message": message,
            "data": dict(data or {}),
            "error": None,
            "metadata": {
                "timestamp": utc_now_iso(),
                **dict(metadata or {}),
            },
        }

    def _error_result(
        self,
        *,
        message: str,
        error: Union[str, Exception, Mapping[str, Any]],
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard error result."""
        if isinstance(error, Exception):
            error_payload: Union[str, Dict[str, Any], Mapping[str, Any]] = {
                "type": error.__class__.__name__,
                "message": str(error),
            }
            self.logger.debug("Exception detail: %s", traceback.format_exc())
        elif isinstance(error, Mapping):
            error_payload = dict(error)
        else:
            error_payload = str(error)

        return {
            "success": False,
            "message": message,
            "data": dict(data or {}),
            "error": error_payload,
            "metadata": {
                "timestamp": utc_now_iso(),
                **dict(metadata or {}),
            },
        }

    # -------------------------------------------------------------------------
    # Internal builders and validators
    # -------------------------------------------------------------------------

    def _build_call_event(
        self,
        *,
        user_id: str,
        workspace_id: str,
        direction: str,
        from_number: Optional[str],
        to_number: Optional[str],
        state: str,
        provider: str,
        provider_event_id: Optional[str],
        provider_call_id: Optional[str],
        line_id: Optional[str],
        device_id: Optional[str],
        caller_name: Optional[str],
        callee_name: Optional[str],
        requested_actions: Optional[Sequence[str]],
        workflow_id: Optional[str],
        task_id: Optional[str],
        correlation_id: str,
        metadata: Optional[Mapping[str, Any]],
        provider_payload: Optional[Mapping[str, Any]],
    ) -> CallEvent:
        """Build normalized CallEvent object."""
        normalized_direction = normalize_direction(direction)
        normalized_provider = normalize_provider(provider)
        normalized_state = normalize_state(state)
        normalized_from = normalize_phone(from_number)
        normalized_to = normalize_phone(to_number)

        action_tuple = tuple(
            self._normalize_requested_actions(
                normalized_direction,
                requested_actions=requested_actions,
            )
        )

        raw_identity = "|".join(
            [
                coerce_str(user_id),
                coerce_str(workspace_id),
                coerce_str(normalized_provider),
                coerce_str(provider_event_id),
                coerce_str(provider_call_id),
                coerce_str(normalized_direction),
                coerce_str(normalized_from),
                coerce_str(normalized_to),
                coerce_str(correlation_id),
            ]
        )
        call_id = provider_call_id or f"call_{stable_hash(raw_identity)}"

        return CallEvent(
            user_id=str(user_id or "").strip(),
            workspace_id=str(workspace_id or "").strip(),
            call_id=call_id,
            provider=normalized_provider,
            direction=normalized_direction,
            state=normalized_state,
            from_party=CallParty(
                phone=normalized_from,
                name=caller_name,
                role="caller",
            ),
            to_party=CallParty(
                phone=normalized_to,
                name=callee_name,
                role="callee",
            ),
            detected_at=utc_now_iso(),
            provider_event_id=provider_event_id,
            provider_call_id=provider_call_id,
            line_id=line_id,
            device_id=device_id,
            workflow_id=workflow_id,
            task_id=task_id,
            correlation_id=correlation_id,
            requested_actions=action_tuple,
            provider_payload=dict(provider_payload or {}),
            metadata=dict(metadata or {}),
        )

    def _validate_call_event(self, call_event: CallEvent) -> Dict[str, Any]:
        """Validate normalized CallEvent."""
        if not call_event.call_id:
            return self._error_result(
                message="Call ID could not be generated.",
                error="missing_call_id",
                metadata={"agent": self.agent_name, "correlation_id": call_event.correlation_id},
            )

        if call_event.provider == CallProvider.GENERIC.value and not self.config.allow_unknown_provider:
            return self._error_result(
                message="Unknown/generic call provider is not allowed.",
                error="unknown_provider_not_allowed",
                metadata={"agent": self.agent_name, "correlation_id": call_event.correlation_id},
            )

        if call_event.direction == CallDirection.UNKNOWN.value and not self.config.allow_unknown_direction_detection:
            return self._error_result(
                message="Unknown call direction is not allowed.",
                error="unknown_direction_not_allowed",
                metadata={"agent": self.agent_name, "correlation_id": call_event.correlation_id},
            )

        if (
            call_event.direction != CallDirection.UNKNOWN.value
            and call_event.direction not in set(self.config.allowed_directions)
        ):
            return self._error_result(
                message=f"Call direction is disabled by configuration: {call_event.direction}",
                error="direction_disabled",
                data={"allowed_directions": list(self.config.allowed_directions)},
                metadata={"agent": self.agent_name, "correlation_id": call_event.correlation_id},
            )

        if not call_event.from_party.phone and not call_event.to_party.phone:
            return self._error_result(
                message="At least one call party phone/contact identifier is required.",
                error="missing_call_parties",
                metadata={"agent": self.agent_name, "correlation_id": call_event.correlation_id},
            )

        if safe_json_size(call_event.provider_payload) > self.config.max_provider_payload_bytes:
            return self._error_result(
                message="Provider payload is too large.",
                error="provider_payload_too_large",
                metadata={
                    "agent": self.agent_name,
                    "correlation_id": call_event.correlation_id,
                    "max_bytes": self.config.max_provider_payload_bytes,
                },
            )

        return self._safe_result(
            message="Call event validation passed.",
            data={"call_event": call_event.safe_dict(include_provider_payload=False)},
            metadata={"agent": self.agent_name, "correlation_id": call_event.correlation_id},
        )

    def _normalize_requested_actions(
        self,
        direction: str,
        *,
        requested_actions: Optional[Sequence[str]],
    ) -> List[str]:
        """
        Normalize requested permissions/actions.

        Always includes baseline required permissions for direction.
        """
        required = list(DEFAULT_REQUIRED_PERMISSIONS.get(direction, DEFAULT_REQUIRED_PERMISSIONS[CallDirection.UNKNOWN.value]))
        extras = [str(action).strip().lower() for action in (requested_actions or []) if str(action).strip()]
        allowed = {permission.value for permission in CallPermission}

        normalized: List[str] = []
        for action in required + extras:
            if action in allowed and action not in normalized:
                normalized.append(action)
        return normalized

    def _required_permissions_for_direction(
        self,
        direction: str,
        *,
        requested_actions: Optional[Sequence[str]],
    ) -> List[str]:
        """Return permission list for direction plus requested actions."""
        return self._normalize_requested_actions(direction, requested_actions=requested_actions)

    def _check_permission_callback(self, permission_request: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Check permission callback if available.

        Without a callback, detection-level permissions are allowed but sensitive
        actions move to Security Agent approval path.
        """
        if not self.permission_callback:
            return {
                "decision": PermissionDecision.UNAVAILABLE.value,
                "reason": "permission_callback_unavailable",
                "fallback": "security_gate_for_sensitive_actions",
            }

        try:
            response = self.permission_callback(dict(permission_request))
            decision = str(response.get("decision") or response.get("status") or "").lower()

            if decision in {"allowed", "approved", "allow", "ok"}:
                return {
                    "decision": PermissionDecision.ALLOWED.value,
                    "response": safe_metadata(response),
                }

            if decision in {"denied", "deny", "blocked", "rejected"}:
                return {
                    "decision": PermissionDecision.DENIED.value,
                    "response": safe_metadata(response),
                }

            if decision in {"requires_approval", "pending", "approval_required"}:
                return {
                    "decision": PermissionDecision.REQUIRES_APPROVAL.value,
                    "response": safe_metadata(response),
                }

            return {
                "decision": PermissionDecision.UNAVAILABLE.value,
                "response": safe_metadata(response),
            }

        except Exception as exc:
            self.logger.warning("Permission callback failed.", exc_info=True)
            return {
                "decision": PermissionDecision.UNAVAILABLE.value,
                "error": {
                    "type": exc.__class__.__name__,
                    "message": str(exc),
                },
            }

    def _handle_security(
        self,
        *,
        permission_request: Mapping[str, Any],
        direction: str,
        requested_actions: Sequence[str],
        require_approval: Optional[bool],
    ) -> Dict[str, Any]:
        """Run Security Agent approval path when needed."""
        if not self._requires_security_check(
            direction=direction,
            requested_actions=requested_actions,
            require_approval=require_approval,
        ):
            return self._safe_result(
                message="Security approval not required for call detection.",
                data={
                    "decision": PermissionDecision.NOT_REQUIRED.value,
                    "permissions": list(requested_actions),
                },
                metadata={
                    "agent": self.agent_name,
                    "correlation_id": permission_request.get("correlation_id"),
                },
            )

        return self._request_security_approval(permission_request)

    def _parse_provider_payload(
        self,
        provider: str,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Parse provider payload into normalized fields.

        This parser intentionally supports common aliases while remaining safe
        and provider-neutral.
        """
        provider_name = normalize_provider(provider)

        def first(*keys: str) -> Optional[Any]:
            for key in keys:
                if key in payload and payload[key] not in (None, ""):
                    return payload[key]
            return None

        direction_value = first(
            "direction",
            "Direction",
            "call_direction",
            "CallDirection",
            "type",
            "event_type",
        )

        state_value = first(
            "state",
            "status",
            "Status",
            "call_status",
            "CallStatus",
            "event",
            "event_name",
        )

        from_number = first(
            "from",
            "From",
            "caller",
            "Caller",
            "caller_number",
            "from_number",
            "ani",
            "ANI",
        )

        to_number = first(
            "to",
            "To",
            "callee",
            "Callee",
            "called",
            "called_number",
            "to_number",
            "dnis",
            "DNIS",
        )

        provider_event_id = first(
            "event_id",
            "EventId",
            "eventId",
            "webhook_id",
            "id",
            "uuid",
        )

        provider_call_id = first(
            "call_id",
            "CallSid",
            "callSid",
            "CallUUID",
            "call_uuid",
            "uuid",
            "call_control_id",
            "provider_call_id",
        )

        # Provider-specific light adjustments
        if provider_name == CallProvider.TWILIO.value:
            direction_value = first("Direction", "direction") or direction_value
            state_value = first("CallStatus", "Status", "status") or state_value
            provider_call_id = first("CallSid", "ParentCallSid", "call_sid") or provider_call_id

        elif provider_name == CallProvider.PLIVO.value:
            direction_value = first("Direction", "direction") or direction_value
            state_value = first("CallStatus", "call_status", "status") or state_value
            provider_call_id = first("CallUUID", "call_uuid") or provider_call_id

        elif provider_name == CallProvider.TELNYX.value:
            data = payload.get("data")
            if isinstance(data, Mapping):
                inner_payload = data.get("payload")
                if isinstance(inner_payload, Mapping):
                    from_number = from_number or inner_payload.get("from")
                    to_number = to_number or inner_payload.get("to")
                    provider_call_id = provider_call_id or inner_payload.get("call_control_id")
                    state_value = state_value or data.get("event_type")
                    provider_event_id = provider_event_id or data.get("id")

        metadata = {
            "provider": provider_name,
            "raw_direction": direction_value,
            "raw_state": state_value,
            "line_id": first("line_id", "LineId", "phone_number_id"),
            "device_id": first("device_id", "DeviceId", "device"),
            "parsed_by": self.agent_name,
        }

        return {
            "direction": normalize_direction(str(direction_value or "")),
            "state": normalize_state(str(state_value or "")),
            "from_number": normalize_phone(coerce_str(from_number)) if from_number is not None else None,
            "to_number": normalize_phone(coerce_str(to_number)) if to_number is not None else None,
            "provider_event_id": coerce_str(provider_event_id) if provider_event_id is not None else None,
            "provider_call_id": coerce_str(provider_call_id) if provider_call_id is not None else None,
            "line_id": coerce_str(metadata.get("line_id")) if metadata.get("line_id") else None,
            "device_id": coerce_str(metadata.get("device_id")) if metadata.get("device_id") else None,
            "caller_name": first("caller_name", "CallerName", "from_name"),
            "callee_name": first("callee_name", "CalleeName", "to_name"),
            "requested_actions": [],
            "metadata": metadata,
        }

    def _suggest_next_modules(self, call_event: CallEvent) -> List[str]:
        """
        Suggest next Call Agent modules based on state/direction.

        This does not invoke modules. It only prepares Master Agent routing hints.
        """
        suggestions: List[str] = []

        if call_event.direction == CallDirection.INCOMING.value:
            suggestions.append("receptionist_mode.py")
            suggestions.append("contact_router.py")

        if call_event.direction == CallDirection.OUTGOING.value:
            suggestions.append("call_scripts.py")
            suggestions.append("lead_qualifier.py")

        if call_event.state in {
            CallState.CONNECTED.value,
            CallState.IN_PROGRESS.value,
            CallState.COMPLETED.value,
        }:
            suggestions.append("call_transcriber.py")
            suggestions.append("call_summarizer.py")

        if call_event.state in {
            CallState.MISSED.value,
            CallState.NO_ANSWER.value,
            CallState.BUSY.value,
        }:
            suggestions.append("voicemail_handler.py")

        if CallPermission.BOOK_APPOINTMENTS.value in call_event.requested_actions:
            suggestions.append("appointment_booker.py")

        # Keep stable order and no duplicates.
        seen = set()
        unique: List[str] = []
        for item in suggestions:
            if item not in seen:
                seen.add(item)
                unique.append(item)
        return unique

    def _is_duplicate_event(self, call_event: CallEvent) -> bool:
        """Detect duplicate provider events within configured dedupe window."""
        key = self._dedupe_key(call_event)
        now = time.time()

        self._cleanup_dedupe_cache(now)

        last_seen = self._dedupe_cache.get(key)
        if last_seen and now - last_seen <= self.config.dedupe_window_seconds:
            return True
        return False

    def _mark_event_seen(self, call_event: CallEvent) -> None:
        """Mark event as seen for duplicate prevention."""
        self._dedupe_cache[self._dedupe_key(call_event)] = time.time()

    def _dedupe_key(self, call_event: CallEvent) -> str:
        """Build dedupe key."""
        raw = "|".join(
            [
                call_event.user_id,
                call_event.workspace_id,
                call_event.provider,
                coerce_str(call_event.provider_event_id),
                coerce_str(call_event.provider_call_id),
                call_event.direction,
                call_event.state,
                coerce_str(call_event.from_party.phone),
                coerce_str(call_event.to_party.phone),
            ]
        )
        return stable_hash(raw)

    def _cleanup_dedupe_cache(self, now: Optional[float] = None) -> None:
        """Remove old dedupe entries."""
        now = now or time.time()
        expired = [
            key for key, timestamp in self._dedupe_cache.items()
            if now - timestamp > self.config.dedupe_window_seconds
        ]
        for key in expired:
            self._dedupe_cache.pop(key, None)

    def _trim_recent_calls(self, max_items: int = 500) -> None:
        """Keep recent in-memory cache bounded."""
        if len(self._recent_calls) > max_items:
            self._recent_calls = self._recent_calls[-max_items:]

    def _send_optional_callback(
        self,
        callback: Optional[Callable[[Dict[str, Any]], Any]],
        payload: Dict[str, Any],
    ) -> None:
        """Safely call optional integration callback."""
        if not callback:
            return
        try:
            callback(payload)
        except Exception:
            self.logger.warning("Optional callback failed.", exc_info=True)

    def _new_correlation_id(self) -> str:
        """Create trace id for Master/Security/Verification routing."""
        return f"call_evt_{uuid.uuid4().hex}"


# =============================================================================
# Registry-friendly module exports
# =============================================================================

def create_call_listener(
    config: Optional[CallListenerConfig] = None,
    **kwargs: Any,
) -> CallListener:
    """Factory used by future Agent Loader / Agent Registry."""
    return CallListener(config=config, **kwargs)


def get_agent_metadata() -> Dict[str, Any]:
    """Return metadata for Agent Registry / Agent Loader."""
    return {
        "agent_name": CallListener.agent_name,
        "agent_type": CallListener.agent_type,
        "class_name": "CallListener",
        "module": "agents.super_agents.call_agent.call_listener",
        "public_methods": list(CallListener.public_methods),
        "supported_providers": [provider.value for provider in CallProvider],
        "supported_directions": [direction.value for direction in CallDirection],
        "supported_states": [state.value for state in CallState],
        "permissions": [permission.value for permission in CallPermission],
        "safe_to_import": True,
        "requires_user_id": True,
        "requires_workspace_id": True,
        "security_aware": True,
        "verification_ready": True,
        "memory_compatible": True,
        "dashboard_ready": True,
        "does_not_place_calls": True,
        "does_not_answer_calls": True,
        "does_not_record_calls": True,
    }


__all__ = [
    "CallListener",
    "CallListenerConfig",
    "CallEvent",
    "CallParty",
    "CallDirection",
    "CallProvider",
    "CallState",
    "CallPermission",
    "PermissionDecision",
    "DetectionStatus",
    "create_call_listener",
    "get_agent_metadata",
]


# =============================================================================
# Lightweight manual test
# =============================================================================

if __name__ == "__main__":
    listener = CallListener()

    result = listener.detect_call_event(
        user_id="demo_user",
        workspace_id="demo_workspace",
        direction="incoming",
        from_number="+15551234567",
        to_number="+15559876543",
        state="ringing",
        provider="generic",
        requested_actions=["call.detect", "call.metadata.view"],
        workflow_id="wf_demo",
        task_id="task_demo",
        metadata={"source": "manual_test"},
        require_approval=False,
    )

    print(json.dumps(result, indent=2, default=str))