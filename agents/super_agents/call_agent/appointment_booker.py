"""
agents/super_agents/call_agent/appointment_booker.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
Call Agent - Appointment Booker

Purpose:
    Books meetings with calendar integration and confirmations.

This file is designed for the Call Agent module and is safe to import even when
other William/Jarvis files are not created yet.

Core responsibilities:
    - Validate SaaS user/workspace context.
    - Validate appointment booking details collected during calls.
    - Check calendar availability through a protected calendar adapter.
    - Create booking requests and booking records.
    - Prepare confirmation payloads for email/SMS/WhatsApp/call follow-up.
    - Prepare Verification Agent payloads after completed actions.
    - Prepare Memory Agent payloads for useful appointment context.
    - Emit agent events and audit logs.
    - Avoid direct real-world calendar/message actions unless protected by
      permission/security hooks and adapter interfaces.

Important:
    This file does not hardcode secrets.
    This file does not call Google Calendar, Outlook, Twilio, WhatsApp, email, or
    external APIs directly. Real integrations should be injected through adapters.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import re
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Protocol, Tuple, Union


# =============================================================================
# Safe optional BaseAgent import
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Minimal fallback BaseAgent stub.

        The real William/Jarvis BaseAgent can replace this automatically when
        available. This fallback keeps the file import-safe.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())
            self.logger = logging.getLogger(self.agent_name)

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback emit_event: %s | %s", event_name, payload)

        def log_audit_event(self, payload: Dict[str, Any]) -> None:
            self.logger.info("Fallback audit_event: %s", payload)


# =============================================================================
# Constants
# =============================================================================

AGENT_NAME = "AppointmentBooker"
AGENT_MODULE = "Call Agent"
MODULE_NAME = "appointment_booker"
DEFAULT_SCHEMA_VERSION = "1.0.0"

DEFAULT_MEETING_DURATION_MINUTES = 30
DEFAULT_BOOKING_TIMEZONE = "UTC"
DEFAULT_MAX_ATTENDEES = 25
DEFAULT_MAX_NOTES_LENGTH = 5000
DEFAULT_MAX_TITLE_LENGTH = 160

BOOKING_STATUSES = {
    "draft",
    "pending_approval",
    "confirmed",
    "cancelled",
    "failed",
}

CONFIRMATION_CHANNELS = {
    "email",
    "sms",
    "whatsapp",
    "call",
    "dashboard",
    "none",
}

SENSITIVE_KEYWORDS = {
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "client_secret",
    "access_token",
    "refresh_token",
    "bearer",
    "credential",
    "credentials",
    "auth",
    "cookie",
    "session",
}


# =============================================================================
# Utility helpers
# =============================================================================

def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def safe_json_dumps(data: Any) -> str:
    """Safely serialize any data for hashing/logging."""
    try:
        return json.dumps(data, sort_keys=True, default=str, ensure_ascii=False)
    except Exception:
        return str(data)


def stable_hash(data: Any) -> str:
    """Create a stable SHA-256 hash for structured data."""
    return hashlib.sha256(safe_json_dumps(data).encode("utf-8", errors="ignore")).hexdigest()


def normalize_text(value: Any) -> str:
    """Normalize arbitrary text."""
    return str(value or "").strip()


def normalize_key(value: Any) -> str:
    """Normalize keys/action names/channel names."""
    value = normalize_text(value).lower()
    value = re.sub(r"[^a-z0-9_\-]+", "_", value)
    value = re.sub(r"_+", "_", value).strip("_")
    return value


def is_sensitive_key(key: str) -> bool:
    """Return True when key appears to contain sensitive material."""
    key_l = str(key or "").lower()
    return any(word in key_l for word in SENSITIVE_KEYWORDS)


def parse_datetime(value: Union[str, datetime]) -> datetime:
    """
    Parse datetime from ISO string or datetime object.

    Naive datetime values are treated as UTC for safe deterministic behavior.
    Production adapters may apply workspace/user timezone rules.
    """
    if isinstance(value, datetime):
        dt = value
    else:
        raw = normalize_text(value)
        if not raw:
            raise ValueError("datetime value is required.")

        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"

        dt = datetime.fromisoformat(raw)

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt


def to_iso(dt: datetime) -> str:
    """Convert datetime to ISO-8601 string."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def redact_sensitive(data: Any) -> Any:
    """Recursively redact sensitive values."""
    if isinstance(data, Mapping):
        redacted: Dict[str, Any] = {}
        for key, value in data.items():
            if is_sensitive_key(str(key)):
                redacted[str(key)] = "***REDACTED***"
            else:
                redacted[str(key)] = redact_sensitive(value)
        return redacted

    if isinstance(data, list):
        return [redact_sensitive(item) for item in data]

    if isinstance(data, tuple):
        return tuple(redact_sensitive(item) for item in data)

    return data


def remove_sensitive_for_storage(data: Any) -> Any:
    """Remove sensitive fields before storing local booking metadata."""
    if isinstance(data, Mapping):
        cleaned: Dict[str, Any] = {}
        for key, value in data.items():
            if is_sensitive_key(str(key)):
                continue
            cleaned[str(key)] = remove_sensitive_for_storage(value)
        return cleaned

    if isinstance(data, list):
        return [remove_sensitive_for_storage(item) for item in data]

    if isinstance(data, tuple):
        return tuple(remove_sensitive_for_storage(item) for item in data)

    return data


# =============================================================================
# Adapter protocols
# =============================================================================

class CalendarAdapter(Protocol):
    """
    Calendar integration protocol.

    Real Google Calendar, Outlook, Cal.com, Calendly, or internal calendar
    connectors should implement this interface.

    The AppointmentBooker does not directly call external APIs. It delegates to
    this adapter only after context validation and security approval.
    """

    def check_availability(
        self,
        *,
        context: Mapping[str, Any],
        calendar_id: str,
        start_time: str,
        end_time: str,
        timezone_name: str,
        attendees: List[Dict[str, Any]],
        metadata: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Return structured availability result."""
        ...

    def create_event(
        self,
        *,
        context: Mapping[str, Any],
        calendar_id: str,
        title: str,
        start_time: str,
        end_time: str,
        timezone_name: str,
        attendees: List[Dict[str, Any]],
        location: Optional[str],
        description: Optional[str],
        metadata: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Create a calendar event and return structured result."""
        ...

    def cancel_event(
        self,
        *,
        context: Mapping[str, Any],
        calendar_id: str,
        external_event_id: str,
        reason: Optional[str],
        metadata: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Cancel a calendar event and return structured result."""
        ...


class ConfirmationAdapter(Protocol):
    """
    Confirmation delivery protocol.

    Real email, SMS, WhatsApp, dashboard notification, or call confirmation
    connectors should implement this interface.
    """

    def send_confirmation(
        self,
        *,
        context: Mapping[str, Any],
        booking: Mapping[str, Any],
        channel: str,
        recipient: Mapping[str, Any],
        message: Mapping[str, Any],
        metadata: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Send confirmation and return structured result."""
        ...


# =============================================================================
# Safe fallback adapters
# =============================================================================

class SafeNoopCalendarAdapter:
    """
    Safe calendar adapter used when no real calendar integration is injected.

    It never calls external systems. It simulates availability and returns a
    local external_event_id for testing/dev usage.
    """

    def check_availability(
        self,
        *,
        context: Mapping[str, Any],
        calendar_id: str,
        start_time: str,
        end_time: str,
        timezone_name: str,
        attendees: List[Dict[str, Any]],
        metadata: Dict[str, Any],
    ) -> Dict[str, Any]:
        return {
            "success": True,
            "message": "Availability checked using safe noop calendar adapter.",
            "data": {
                "available": True,
                "calendar_id": calendar_id,
                "start_time": start_time,
                "end_time": end_time,
                "timezone": timezone_name,
                "adapter": "SafeNoopCalendarAdapter",
                "external_action_executed": False,
            },
            "error": None,
            "metadata": {
                "safe_noop": True,
                "timestamp": utc_now_iso(),
            },
        }

    def create_event(
        self,
        *,
        context: Mapping[str, Any],
        calendar_id: str,
        title: str,
        start_time: str,
        end_time: str,
        timezone_name: str,
        attendees: List[Dict[str, Any]],
        location: Optional[str],
        description: Optional[str],
        metadata: Dict[str, Any],
    ) -> Dict[str, Any]:
        return {
            "success": True,
            "message": "Calendar event simulated using safe noop calendar adapter.",
            "data": {
                "external_event_id": f"noop_evt_{uuid.uuid4().hex}",
                "calendar_id": calendar_id,
                "title": title,
                "start_time": start_time,
                "end_time": end_time,
                "timezone": timezone_name,
                "location": location,
                "adapter": "SafeNoopCalendarAdapter",
                "external_action_executed": False,
            },
            "error": None,
            "metadata": {
                "safe_noop": True,
                "timestamp": utc_now_iso(),
            },
        }

    def cancel_event(
        self,
        *,
        context: Mapping[str, Any],
        calendar_id: str,
        external_event_id: str,
        reason: Optional[str],
        metadata: Dict[str, Any],
    ) -> Dict[str, Any]:
        return {
            "success": True,
            "message": "Calendar cancellation simulated using safe noop calendar adapter.",
            "data": {
                "external_event_id": external_event_id,
                "calendar_id": calendar_id,
                "cancelled": True,
                "reason": reason,
                "adapter": "SafeNoopCalendarAdapter",
                "external_action_executed": False,
            },
            "error": None,
            "metadata": {
                "safe_noop": True,
                "timestamp": utc_now_iso(),
            },
        }


class SafeNoopConfirmationAdapter:
    """
    Safe confirmation adapter used when no real message integration is injected.

    It prepares and returns confirmation payloads without sending real messages.
    """

    def send_confirmation(
        self,
        *,
        context: Mapping[str, Any],
        booking: Mapping[str, Any],
        channel: str,
        recipient: Mapping[str, Any],
        message: Mapping[str, Any],
        metadata: Dict[str, Any],
    ) -> Dict[str, Any]:
        return {
            "success": True,
            "message": "Confirmation prepared using safe noop confirmation adapter.",
            "data": {
                "channel": channel,
                "recipient": redact_sensitive(dict(recipient)),
                "message": redact_sensitive(dict(message)),
                "sent": False,
                "adapter": "SafeNoopConfirmationAdapter",
                "external_action_executed": False,
            },
            "error": None,
            "metadata": {
                "safe_noop": True,
                "timestamp": utc_now_iso(),
            },
        }


# =============================================================================
# Data structures
# =============================================================================

@dataclass
class AppointmentAttendee:
    """Represents an appointment attendee."""

    name: str
    email: Optional[str] = None
    phone: Optional[str] = None
    role: str = "guest"
    is_required: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return redact_sensitive(asdict(self))


@dataclass
class AppointmentRequest:
    """Normalized booking request."""

    appointment_id: str
    user_id: str
    workspace_id: str
    caller_name: str
    caller_phone: Optional[str]
    caller_email: Optional[str]
    title: str
    start_time: str
    end_time: str
    timezone: str
    calendar_id: str
    attendees: List[Dict[str, Any]]
    location: Optional[str] = None
    description: Optional[str] = None
    notes: Optional[str] = None
    source: str = "call_agent"
    status: str = "draft"
    confirmation_channels: List[str] = field(default_factory=list)
    lead_id: Optional[str] = None
    call_id: Optional[str] = None
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return redact_sensitive(asdict(self))


@dataclass
class AppointmentRecord:
    """Stored booking record."""

    appointment_id: str
    user_id: str
    workspace_id: str
    status: str
    request: Dict[str, Any]
    calendar_result: Dict[str, Any] = field(default_factory=dict)
    confirmation_results: List[Dict[str, Any]] = field(default_factory=list)
    external_event_id: Optional[str] = None
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)
    created_by: Optional[str] = None
    updated_by: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return redact_sensitive(asdict(self))


# =============================================================================
# Local appointment store
# =============================================================================

class AppointmentStore:
    """
    Thread-safe local appointment store.

    This is a lightweight fallback store for import-safe operation. Production
    systems can replace this with database-backed storage later.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._records: Dict[str, Dict[str, AppointmentRecord]] = {}

    @staticmethod
    def tenant_key(user_id: str, workspace_id: str) -> str:
        return stable_hash({"user_id": user_id, "workspace_id": workspace_id})

    def upsert(self, record: AppointmentRecord) -> AppointmentRecord:
        with self._lock:
            tenant_key = self.tenant_key(record.user_id, record.workspace_id)
            self._records.setdefault(tenant_key, {})
            self._records[tenant_key][record.appointment_id] = copy.deepcopy(record)
            return copy.deepcopy(record)

    def get(self, user_id: str, workspace_id: str, appointment_id: str) -> Optional[AppointmentRecord]:
        with self._lock:
            tenant_key = self.tenant_key(user_id, workspace_id)
            record = self._records.get(tenant_key, {}).get(appointment_id)
            return copy.deepcopy(record) if record else None

    def list(
        self,
        user_id: str,
        workspace_id: str,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> List[AppointmentRecord]:
        with self._lock:
            tenant_key = self.tenant_key(user_id, workspace_id)
            records = list(self._records.get(tenant_key, {}).values())

            if status:
                status_n = normalize_key(status)
                records = [record for record in records if normalize_key(record.status) == status_n]

            records.sort(key=lambda record: record.updated_at, reverse=True)
            return [copy.deepcopy(record) for record in records[: max(1, min(limit, 500))]]

    def delete(self, user_id: str, workspace_id: str, appointment_id: str) -> bool:
        with self._lock:
            tenant_key = self.tenant_key(user_id, workspace_id)
            if appointment_id in self._records.get(tenant_key, {}):
                del self._records[tenant_key][appointment_id]
                return True
            return False


# =============================================================================
# AppointmentBooker
# =============================================================================

class AppointmentBooker(BaseAgent):
    """
    Books meetings with calendar integration and confirmations.

    Master Agent:
        Routes call booking tasks here after caller intent is identified.

    Security Agent:
        Calendar creation/cancellation and confirmation delivery are sensitive
        actions and require approval through the security hook.

    Memory Agent:
        Useful booking preferences and appointment context are prepared in a
        Memory Agent compatible payload.

    Verification Agent:
        Every completed booking/cancellation/check creates a verification payload.

    Dashboard/API:
        All public methods return structured dicts ready for FastAPI/dashboard use.

    Agent Registry/Loader:
        The class is import-safe and exposes a manifest through get_agent_manifest().
    """

    agent_name = AGENT_NAME
    agent_module = AGENT_MODULE
    module_name = MODULE_NAME
    version = DEFAULT_SCHEMA_VERSION

    def __init__(
        self,
        calendar_adapter: Optional[CalendarAdapter] = None,
        confirmation_adapter: Optional[ConfirmationAdapter] = None,
        security_approval_callback: Optional[Callable[[Dict[str, Any]], bool]] = None,
        event_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        audit_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        logger: Optional[logging.Logger] = None,
        strict_security: bool = False,
        default_calendar_id: str = "primary",
        default_timezone: str = DEFAULT_BOOKING_TIMEZONE,
        default_duration_minutes: int = DEFAULT_MEETING_DURATION_MINUTES,
    ) -> None:
        try:
            super().__init__(agent_name=AGENT_NAME, agent_id=MODULE_NAME)
        except TypeError:
            super().__init__()

        self.logger = logger or getattr(self, "logger", logging.getLogger(AGENT_NAME))
        self.calendar_adapter = calendar_adapter or SafeNoopCalendarAdapter()
        self.confirmation_adapter = confirmation_adapter or SafeNoopConfirmationAdapter()
        self.security_approval_callback = security_approval_callback
        self.event_callback = event_callback
        self.audit_callback = audit_callback
        self.strict_security = strict_security
        self.default_calendar_id = normalize_text(default_calendar_id) or "primary"
        self.default_timezone = normalize_text(default_timezone) or DEFAULT_BOOKING_TIMEZONE
        self.default_duration_minutes = max(5, int(default_duration_minutes or DEFAULT_MEETING_DURATION_MINUTES))
        self.store = AppointmentStore()

    # -------------------------------------------------------------------------
    # Manifest / registry
    # -------------------------------------------------------------------------

    def get_agent_manifest(self) -> Dict[str, Any]:
        """Return Agent Registry / Agent Loader compatible manifest."""
        return self._safe_result(
            message="AppointmentBooker manifest loaded.",
            data={
                "agent_name": self.agent_name,
                "agent_module": self.agent_module,
                "module_name": self.module_name,
                "class_name": self.__class__.__name__,
                "version": self.version,
                "capabilities": [
                    "validate_appointment_request",
                    "check_calendar_availability",
                    "book_appointment",
                    "prepare_confirmation_payload",
                    "send_booking_confirmation",
                    "cancel_appointment",
                    "list_appointments",
                    "get_appointment",
                    "route_action",
                ],
                "requires_user_id": True,
                "requires_workspace_id": True,
                "saas_isolation_required": True,
                "external_actions_directly_executed": False,
                "external_integrations": [
                    "calendar_adapter",
                    "confirmation_adapter",
                ],
                "sensitive_actions": [
                    "book_appointment",
                    "send_booking_confirmation",
                    "cancel_appointment",
                ],
            },
            metadata=self._result_metadata(action="get_agent_manifest"),
        )

    def get_supported_actions(self) -> Dict[str, Any]:
        """Return supported public actions for Master Agent / Router."""
        return self._safe_result(
            message="Supported AppointmentBooker actions loaded.",
            data={
                "actions": [
                    "validate_appointment_request",
                    "check_availability",
                    "book_appointment",
                    "prepare_confirmation_payload",
                    "send_booking_confirmation",
                    "cancel_appointment",
                    "get_appointment",
                    "list_appointments",
                    "route_action",
                ]
            },
            metadata=self._result_metadata(action="get_supported_actions"),
        )

    # -------------------------------------------------------------------------
    # Required compatibility hooks
    # -------------------------------------------------------------------------

    def _validate_task_context(self, context: Mapping[str, Any]) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """
        Validate SaaS context.

        Every booking belongs to one user_id and workspace_id. This prevents
        calendar data, call history, audit logs, and confirmations from mixing
        across SaaS tenants.
        """
        if not isinstance(context, Mapping):
            return False, "context must be a mapping/dict.", {}

        user_id = normalize_text(context.get("user_id"))
        workspace_id = normalize_text(context.get("workspace_id"))

        if not user_id:
            return False, "user_id is required.", {}

        if not workspace_id:
            return False, "workspace_id is required.", {}

        normalized = dict(context)
        normalized["user_id"] = user_id
        normalized["workspace_id"] = workspace_id
        normalized.setdefault("actor_id", context.get("actor_id") or user_id)
        normalized.setdefault("request_id", str(uuid.uuid4()))

        return True, None, normalized

    def _requires_security_check(self, action: str, payload: Optional[Mapping[str, Any]] = None) -> bool:
        """
        Decide whether action requires Security Agent approval.

        Calendar writes/cancellations and confirmation delivery are sensitive.
        """
        action_n = normalize_key(action)

        if action_n in {
            "book_appointment",
            "create_calendar_event",
            "send_booking_confirmation",
            "cancel_appointment",
        }:
            return True

        if self._contains_sensitive_keys(payload or {}):
            return True

        return False

    def _request_security_approval(
        self,
        action: str,
        context: Mapping[str, Any],
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        Production should connect this to the real Security Agent. The fallback
        allows approval by context flag or callback. In strict_security mode,
        sensitive actions fail without approval.
        """
        approval_payload = {
            "agent": self.agent_name,
            "module": self.module_name,
            "action": action,
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "actor_id": context.get("actor_id"),
            "request_id": context.get("request_id"),
            "timestamp": utc_now_iso(),
            "payload_hash": stable_hash(redact_sensitive(payload or {})),
            "redacted_payload": redact_sensitive(payload or {}),
            "reason": "Appointment booking action requires permission/security approval.",
        }

        approved = False
        approval_source = "none"

        try:
            if context.get("security_approved") is True:
                approved = True
                approval_source = "context.security_approved"
            elif callable(self.security_approval_callback):
                approved = bool(self.security_approval_callback(approval_payload))
                approval_source = "security_approval_callback"
            elif not self.strict_security:
                approved = True
                approval_source = "safe_fallback_non_strict_mode"
            else:
                approved = False
                approval_source = "strict_security_requires_callback"
        except Exception as exc:
            self.logger.exception("Security approval callback failed: %s", exc)
            approved = False
            approval_source = "callback_error"

        approval_payload["approved"] = approved
        approval_payload["approval_source"] = approval_source

        self._log_audit_event(
            {
                "event": "security_approval_requested",
                "action": action,
                "approved": approved,
                "approval_source": approval_source,
                "user_id": context.get("user_id"),
                "workspace_id": context.get("workspace_id"),
                "request_id": context.get("request_id"),
                "timestamp": utc_now_iso(),
            }
        )

        if approved:
            return self._safe_result(
                message="Security approval granted.",
                data=approval_payload,
                metadata=self._result_metadata(action="_request_security_approval", context=context),
            )

        return self._error_result(
            message="Security approval denied.",
            error="SECURITY_APPROVAL_DENIED",
            data=approval_payload,
            metadata=self._result_metadata(action="_request_security_approval", context=context),
        )

    def _prepare_verification_payload(
        self,
        action: str,
        context: Mapping[str, Any],
        result_data: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Prepare Verification Agent compatible payload."""
        redacted_data = redact_sensitive(dict(result_data or {}))
        return {
            "verification_type": "call_agent_appointment_operation",
            "agent": self.agent_name,
            "module": self.module_name,
            "action": action,
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "actor_id": context.get("actor_id"),
            "request_id": context.get("request_id"),
            "timestamp": utc_now_iso(),
            "data_hash": stable_hash(redacted_data),
            "redacted_data": redacted_data,
            "checks": {
                "saas_context_present": bool(context.get("user_id") and context.get("workspace_id")),
                "calendar_adapter_used": True,
                "confirmation_adapter_used": action == "send_booking_confirmation",
                "secrets_redacted": True,
                "permission_checked": self._requires_security_check(action, result_data or {}),
            },
        }

    def _prepare_memory_payload(
        self,
        action: str,
        context: Mapping[str, Any],
        appointment: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        This can be consumed by Memory Agent to remember useful appointment
        context, such as preferred calendar, caller follow-up preferences, and
        booking outcome.
        """
        return {
            "memory_event_type": "call_appointment_context",
            "agent": self.agent_name,
            "module": self.module_name,
            "action": action,
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "actor_id": context.get("actor_id"),
            "request_id": context.get("request_id"),
            "timestamp": utc_now_iso(),
            "appointment": redact_sensitive(dict(appointment)),
            "metadata": {
                "source": MODULE_NAME,
                "safe_for_long_term_memory": True,
                "contains_raw_secret": False,
            },
        }

    def _emit_agent_event(self, event_name: str, payload: Dict[str, Any]) -> None:
        """Emit dashboard/API/event-bus compatible event safely."""
        safe_payload = redact_sensitive(payload)

        try:
            if callable(self.event_callback):
                self.event_callback(event_name, safe_payload)
                return

            emit = getattr(super(), "emit_event", None)
            if callable(emit):
                emit(event_name, safe_payload)
                return
        except Exception as exc:
            self.logger.debug("Failed to emit event: %s", exc)

        self.logger.debug("AppointmentBooker event: %s | %s", event_name, safe_payload)

    def _log_audit_event(self, payload: Dict[str, Any]) -> None:
        """Log audit event safely."""
        safe_payload = redact_sensitive(payload)

        try:
            if callable(self.audit_callback):
                self.audit_callback(safe_payload)
                return

            log_audit = getattr(super(), "log_audit_event", None)
            if callable(log_audit):
                log_audit(safe_payload)
                return
        except Exception as exc:
            self.logger.debug("Failed to log audit event: %s", exc)

        self.logger.info("AppointmentBooker audit: %s", safe_payload)

    def _safe_result(
        self,
        message: str,
        data: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard success result."""
        return {
            "success": True,
            "message": message,
            "data": redact_sensitive(data if data is not None else {}),
            "error": None,
            "metadata": metadata or self._result_metadata(),
        }

    def _error_result(
        self,
        message: str,
        error: Union[str, Exception, Dict[str, Any]],
        data: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard error result."""
        if isinstance(error, Exception):
            error_value: Union[str, Dict[str, Any]] = {
                "type": error.__class__.__name__,
                "detail": str(error),
            }
        else:
            error_value = error

        return {
            "success": False,
            "message": message,
            "data": redact_sensitive(data if data is not None else {}),
            "error": redact_sensitive(error_value),
            "metadata": metadata or self._result_metadata(),
        }

    # -------------------------------------------------------------------------
    # Public booking methods
    # -------------------------------------------------------------------------

    def validate_appointment_request(
        self,
        context: Mapping[str, Any],
        caller_name: str,
        start_time: Union[str, datetime],
        end_time: Optional[Union[str, datetime]] = None,
        caller_phone: Optional[str] = None,
        caller_email: Optional[str] = None,
        title: Optional[str] = None,
        duration_minutes: Optional[int] = None,
        timezone_name: Optional[str] = None,
        calendar_id: Optional[str] = None,
        attendees: Optional[List[Mapping[str, Any]]] = None,
        location: Optional[str] = None,
        description: Optional[str] = None,
        notes: Optional[str] = None,
        confirmation_channels: Optional[List[str]] = None,
        lead_id: Optional[str] = None,
        call_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Validate and normalize appointment details.

        This method does not check calendar availability and does not create an
        event. It only prepares a safe AppointmentRequest.
        """
        valid, error, ctx = self._validate_task_context(context)
        if not valid:
            return self._error_result("Invalid task context.", error or "INVALID_CONTEXT")

        try:
            appointment_request = self._build_appointment_request(
                context=ctx,
                caller_name=caller_name,
                caller_phone=caller_phone,
                caller_email=caller_email,
                title=title,
                start_time=start_time,
                end_time=end_time,
                duration_minutes=duration_minutes,
                timezone_name=timezone_name,
                calendar_id=calendar_id,
                attendees=attendees,
                location=location,
                description=description,
                notes=notes,
                confirmation_channels=confirmation_channels,
                lead_id=lead_id,
                call_id=call_id,
                metadata=metadata,
            )

            data = {
                "appointment_request": appointment_request.to_dict(),
                "valid": True,
            }
            data["verification_payload"] = self._prepare_verification_payload(
                "validate_appointment_request",
                ctx,
                data,
            )

            return self._safe_result(
                message="Appointment request validated.",
                data=data,
                metadata=self._result_metadata(action="validate_appointment_request", context=ctx),
            )

        except Exception as exc:
            return self._error_result(
                message="Appointment request validation failed.",
                error=exc,
                metadata=self._result_metadata(action="validate_appointment_request", context=ctx),
            )

    def check_availability(
        self,
        context: Mapping[str, Any],
        start_time: Union[str, datetime],
        end_time: Optional[Union[str, datetime]] = None,
        duration_minutes: Optional[int] = None,
        calendar_id: Optional[str] = None,
        timezone_name: Optional[str] = None,
        attendees: Optional[List[Mapping[str, Any]]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Check calendar availability through the calendar adapter.

        This is a read/check operation. It does not create an appointment.
        """
        valid, error, ctx = self._validate_task_context(context)
        if not valid:
            return self._error_result("Invalid task context.", error or "INVALID_CONTEXT")

        try:
            start_dt, end_dt = self._normalize_time_range(start_time, end_time, duration_minutes)
            calendar_id_n = normalize_text(calendar_id) or self.default_calendar_id
            timezone_n = normalize_text(timezone_name) or self.default_timezone
            safe_attendees = self._normalize_attendees(attendees or [])
            safe_metadata = self._validate_metadata(metadata or {})

            adapter_result = self.calendar_adapter.check_availability(
                context=ctx,
                calendar_id=calendar_id_n,
                start_time=to_iso(start_dt),
                end_time=to_iso(end_dt),
                timezone_name=timezone_n,
                attendees=safe_attendees,
                metadata=safe_metadata,
            )

            data = {
                "availability": redact_sensitive(adapter_result),
                "start_time": to_iso(start_dt),
                "end_time": to_iso(end_dt),
                "calendar_id": calendar_id_n,
                "timezone": timezone_n,
            }
            data["verification_payload"] = self._prepare_verification_payload(
                "check_availability",
                ctx,
                data,
            )

            self._emit_agent_event("call_agent.appointment.availability_checked", data)

            return self._safe_result(
                message="Calendar availability checked.",
                data=data,
                metadata=self._result_metadata(action="check_availability", context=ctx),
            )

        except Exception as exc:
            self.logger.exception("Availability check failed.")
            return self._error_result(
                message="Calendar availability check failed.",
                error=exc,
                metadata=self._result_metadata(action="check_availability", context=ctx),
            )

    def book_appointment(
        self,
        context: Mapping[str, Any],
        caller_name: str,
        start_time: Union[str, datetime],
        end_time: Optional[Union[str, datetime]] = None,
        caller_phone: Optional[str] = None,
        caller_email: Optional[str] = None,
        title: Optional[str] = None,
        duration_minutes: Optional[int] = None,
        timezone_name: Optional[str] = None,
        calendar_id: Optional[str] = None,
        attendees: Optional[List[Mapping[str, Any]]] = None,
        location: Optional[str] = None,
        description: Optional[str] = None,
        notes: Optional[str] = None,
        confirmation_channels: Optional[List[str]] = None,
        lead_id: Optional[str] = None,
        call_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        send_confirmation: bool = True,
    ) -> Dict[str, Any]:
        """
        Book an appointment through the calendar adapter.

        This method:
            1. Validates SaaS context.
            2. Normalizes booking details.
            3. Requests security approval.
            4. Checks availability.
            5. Creates calendar event through adapter.
            6. Stores local booking record.
            7. Optionally prepares/sends confirmation through adapter.
            8. Prepares Memory Agent and Verification Agent payloads.
        """
        valid, error, ctx = self._validate_task_context(context)
        if not valid:
            return self._error_result("Invalid task context.", error or "INVALID_CONTEXT")

        try:
            appointment_request = self._build_appointment_request(
                context=ctx,
                caller_name=caller_name,
                caller_phone=caller_phone,
                caller_email=caller_email,
                title=title,
                start_time=start_time,
                end_time=end_time,
                duration_minutes=duration_minutes,
                timezone_name=timezone_name,
                calendar_id=calendar_id,
                attendees=attendees,
                location=location,
                description=description,
                notes=notes,
                confirmation_channels=confirmation_channels,
                lead_id=lead_id,
                call_id=call_id,
                metadata=metadata,
            )

            request_payload = appointment_request.to_dict()

            if self._requires_security_check("book_appointment", request_payload):
                approval = self._request_security_approval("book_appointment", ctx, request_payload)
                if not approval["success"]:
                    return approval

            availability = self.calendar_adapter.check_availability(
                context=ctx,
                calendar_id=appointment_request.calendar_id,
                start_time=appointment_request.start_time,
                end_time=appointment_request.end_time,
                timezone_name=appointment_request.timezone,
                attendees=appointment_request.attendees,
                metadata=appointment_request.metadata,
            )

            available = bool(
                availability.get("success")
                and availability.get("data", {}).get("available", False)
            )

            if not available:
                record = AppointmentRecord(
                    appointment_id=appointment_request.appointment_id,
                    user_id=ctx["user_id"],
                    workspace_id=ctx["workspace_id"],
                    status="failed",
                    request=appointment_request.to_dict(),
                    calendar_result=availability,
                    created_by=ctx.get("actor_id"),
                    updated_by=ctx.get("actor_id"),
                    metadata={
                        "failure_reason": "calendar_slot_unavailable",
                    },
                )
                self.store.upsert(record)

                return self._error_result(
                    message="Requested appointment slot is not available.",
                    error="SLOT_UNAVAILABLE",
                    data={
                        "appointment": record.to_dict(),
                        "availability": availability,
                    },
                    metadata=self._result_metadata(action="book_appointment", context=ctx),
                )

            calendar_result = self.calendar_adapter.create_event(
                context=ctx,
                calendar_id=appointment_request.calendar_id,
                title=appointment_request.title,
                start_time=appointment_request.start_time,
                end_time=appointment_request.end_time,
                timezone_name=appointment_request.timezone,
                attendees=appointment_request.attendees,
                location=appointment_request.location,
                description=appointment_request.description,
                metadata=appointment_request.metadata,
            )

            calendar_success = bool(calendar_result.get("success"))
            external_event_id = calendar_result.get("data", {}).get("external_event_id")

            status = "confirmed" if calendar_success else "failed"

            record = AppointmentRecord(
                appointment_id=appointment_request.appointment_id,
                user_id=ctx["user_id"],
                workspace_id=ctx["workspace_id"],
                status=status,
                request=appointment_request.to_dict(),
                calendar_result=calendar_result,
                external_event_id=external_event_id,
                created_by=ctx.get("actor_id"),
                updated_by=ctx.get("actor_id"),
                metadata={
                    "lead_id": appointment_request.lead_id,
                    "call_id": appointment_request.call_id,
                    "source": appointment_request.source,
                },
            )

            confirmation_results: List[Dict[str, Any]] = []
            if calendar_success and send_confirmation:
                for channel in appointment_request.confirmation_channels:
                    if channel == "none":
                        continue

                    confirmation = self.send_booking_confirmation(
                        context=ctx,
                        appointment_id=appointment_request.appointment_id,
                        channel=channel,
                        booking_record=record.to_dict(),
                    )
                    confirmation_results.append(confirmation)

            record.confirmation_results = confirmation_results
            record.updated_at = utc_now_iso()
            self.store.upsert(record)

            output = {
                "appointment": record.to_dict(),
                "availability": availability,
                "calendar_result": calendar_result,
                "confirmation_results": confirmation_results,
                "memory_payload": self._prepare_memory_payload(
                    "book_appointment",
                    ctx,
                    record.to_dict(),
                ),
            }
            output["verification_payload"] = self._prepare_verification_payload(
                "book_appointment",
                ctx,
                output,
            )

            self._emit_agent_event("call_agent.appointment.booked", output)
            self._log_audit_event(
                {
                    "event": "call_agent.appointment.booked",
                    "user_id": ctx["user_id"],
                    "workspace_id": ctx["workspace_id"],
                    "actor_id": ctx.get("actor_id"),
                    "appointment_id": appointment_request.appointment_id,
                    "status": status,
                    "calendar_id": appointment_request.calendar_id,
                    "external_event_id": external_event_id,
                    "request_id": ctx.get("request_id"),
                    "timestamp": utc_now_iso(),
                }
            )

            if not calendar_success:
                return self._error_result(
                    message="Calendar event creation failed.",
                    error=calendar_result.get("error") or "CALENDAR_EVENT_CREATION_FAILED",
                    data=output,
                    metadata=self._result_metadata(action="book_appointment", context=ctx),
                )

            return self._safe_result(
                message="Appointment booked successfully.",
                data=output,
                metadata=self._result_metadata(action="book_appointment", context=ctx),
            )

        except Exception as exc:
            self.logger.exception("Appointment booking failed.")
            return self._error_result(
                message="Appointment booking failed.",
                error=exc,
                metadata=self._result_metadata(action="book_appointment", context=ctx),
            )

    def prepare_confirmation_payload(
        self,
        context: Mapping[str, Any],
        appointment: Mapping[str, Any],
        channel: str = "email",
    ) -> Dict[str, Any]:
        """
        Prepare confirmation payload.

        This method does not send a message. It creates a structured payload that
        Email Connector, WhatsApp Connector, Notification Engine, or Dashboard can
        use later.
        """
        valid, error, ctx = self._validate_task_context(context)
        if not valid:
            return self._error_result("Invalid task context.", error or "INVALID_CONTEXT")

        try:
            channel_n = self._normalize_confirmation_channel(channel)
            booking = dict(appointment or {})
            request = booking.get("request", booking)

            caller_name = normalize_text(request.get("caller_name")) or "there"
            title = normalize_text(request.get("title")) or "your appointment"
            start_time = normalize_text(request.get("start_time"))
            end_time = normalize_text(request.get("end_time"))
            timezone_name = normalize_text(request.get("timezone")) or self.default_timezone
            location = normalize_text(request.get("location"))
            appointment_id = normalize_text(request.get("appointment_id") or booking.get("appointment_id"))

            subject = f"Appointment confirmed: {title}"
            body = (
                f"Hi {caller_name},\n\n"
                f"Your appointment is confirmed.\n\n"
                f"Title: {title}\n"
                f"Time: {start_time} to {end_time}\n"
                f"Timezone: {timezone_name}\n"
            )

            if location:
                body += f"Location: {location}\n"

            body += f"Appointment ID: {appointment_id}\n\n"
            body += "Thank you."

            recipient = {
                "name": caller_name,
                "email": request.get("caller_email"),
                "phone": request.get("caller_phone"),
            }

            message = {
                "subject": subject,
                "body": body,
                "channel": channel_n,
                "appointment_id": appointment_id,
            }

            data = {
                "channel": channel_n,
                "recipient": recipient,
                "message": message,
                "appointment_id": appointment_id,
            }
            data["verification_payload"] = self._prepare_verification_payload(
                "prepare_confirmation_payload",
                ctx,
                data,
            )

            return self._safe_result(
                message="Confirmation payload prepared.",
                data=data,
                metadata=self._result_metadata(action="prepare_confirmation_payload", context=ctx),
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to prepare confirmation payload.",
                error=exc,
                metadata=self._result_metadata(action="prepare_confirmation_payload", context=ctx),
            )

    def send_booking_confirmation(
        self,
        context: Mapping[str, Any],
        appointment_id: str,
        channel: str = "email",
        booking_record: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Send or prepare booking confirmation through the confirmation adapter.

        With the default safe adapter, this does not send anything externally.
        """
        valid, error, ctx = self._validate_task_context(context)
        if not valid:
            return self._error_result("Invalid task context.", error or "INVALID_CONTEXT")

        appointment_id_n = normalize_text(appointment_id)
        if not appointment_id_n:
            return self._error_result("appointment_id is required.", "INVALID_APPOINTMENT_ID")

        try:
            record = dict(booking_record or {})

            if not record:
                stored = self.store.get(ctx["user_id"], ctx["workspace_id"], appointment_id_n)
                if not stored:
                    return self._error_result(
                        message="Appointment not found.",
                        error="APPOINTMENT_NOT_FOUND",
                        metadata=self._result_metadata(action="send_booking_confirmation", context=ctx),
                    )
                record = stored.to_dict()

            channel_n = self._normalize_confirmation_channel(channel)

            confirmation_payload_result = self.prepare_confirmation_payload(
                context=ctx,
                appointment=record,
                channel=channel_n,
            )

            if not confirmation_payload_result["success"]:
                return confirmation_payload_result

            payload_data = confirmation_payload_result["data"]
            approval_payload = {
                "appointment_id": appointment_id_n,
                "channel": channel_n,
                "recipient": payload_data.get("recipient"),
                "message_hash": stable_hash(payload_data.get("message")),
            }

            if self._requires_security_check("send_booking_confirmation", approval_payload):
                approval = self._request_security_approval("send_booking_confirmation", ctx, approval_payload)
                if not approval["success"]:
                    return approval

            adapter_result = self.confirmation_adapter.send_confirmation(
                context=ctx,
                booking=record,
                channel=channel_n,
                recipient=payload_data.get("recipient", {}),
                message=payload_data.get("message", {}),
                metadata={
                    "appointment_id": appointment_id_n,
                    "request_id": ctx.get("request_id"),
                },
            )

            output = {
                "appointment_id": appointment_id_n,
                "channel": channel_n,
                "confirmation_payload": payload_data,
                "confirmation_result": adapter_result,
            }
            output["verification_payload"] = self._prepare_verification_payload(
                "send_booking_confirmation",
                ctx,
                output,
            )

            self._emit_agent_event("call_agent.appointment.confirmation_sent", output)
            self._log_audit_event(
                {
                    "event": "call_agent.appointment.confirmation_sent",
                    "user_id": ctx["user_id"],
                    "workspace_id": ctx["workspace_id"],
                    "actor_id": ctx.get("actor_id"),
                    "appointment_id": appointment_id_n,
                    "channel": channel_n,
                    "request_id": ctx.get("request_id"),
                    "timestamp": utc_now_iso(),
                    "adapter_success": adapter_result.get("success"),
                }
            )

            return self._safe_result(
                message="Booking confirmation processed.",
                data=output,
                metadata=self._result_metadata(action="send_booking_confirmation", context=ctx),
            )

        except Exception as exc:
            self.logger.exception("Failed to send booking confirmation.")
            return self._error_result(
                message="Failed to send booking confirmation.",
                error=exc,
                metadata=self._result_metadata(action="send_booking_confirmation", context=ctx),
            )

    def cancel_appointment(
        self,
        context: Mapping[str, Any],
        appointment_id: str,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Cancel appointment through calendar adapter.

        This is sensitive and requires Security Agent compatible approval.
        """
        valid, error, ctx = self._validate_task_context(context)
        if not valid:
            return self._error_result("Invalid task context.", error or "INVALID_CONTEXT")

        appointment_id_n = normalize_text(appointment_id)
        if not appointment_id_n:
            return self._error_result("appointment_id is required.", "INVALID_APPOINTMENT_ID")

        record = self.store.get(ctx["user_id"], ctx["workspace_id"], appointment_id_n)
        if not record:
            return self._error_result(
                message="Appointment not found.",
                error="APPOINTMENT_NOT_FOUND",
                metadata=self._result_metadata(action="cancel_appointment", context=ctx),
            )

        approval_payload = {
            "appointment_id": appointment_id_n,
            "reason": reason,
            "external_event_id": record.external_event_id,
            "calendar_id": record.request.get("calendar_id"),
        }

        if self._requires_security_check("cancel_appointment", approval_payload):
            approval = self._request_security_approval("cancel_appointment", ctx, approval_payload)
            if not approval["success"]:
                return approval

        try:
            calendar_result = self.calendar_adapter.cancel_event(
                context=ctx,
                calendar_id=record.request.get("calendar_id", self.default_calendar_id),
                external_event_id=record.external_event_id or appointment_id_n,
                reason=reason,
                metadata={
                    "appointment_id": appointment_id_n,
                    "request_id": ctx.get("request_id"),
                },
            )

            record.status = "cancelled" if calendar_result.get("success") else "failed"
            record.updated_at = utc_now_iso()
            record.updated_by = ctx.get("actor_id")
            record.metadata["cancel_reason"] = reason
            record.metadata["cancel_result"] = calendar_result
            self.store.upsert(record)

            output = {
                "appointment": record.to_dict(),
                "calendar_result": calendar_result,
                "memory_payload": self._prepare_memory_payload(
                    "cancel_appointment",
                    ctx,
                    record.to_dict(),
                ),
            }
            output["verification_payload"] = self._prepare_verification_payload(
                "cancel_appointment",
                ctx,
                output,
            )

            self._emit_agent_event("call_agent.appointment.cancelled", output)
            self._log_audit_event(
                {
                    "event": "call_agent.appointment.cancelled",
                    "user_id": ctx["user_id"],
                    "workspace_id": ctx["workspace_id"],
                    "actor_id": ctx.get("actor_id"),
                    "appointment_id": appointment_id_n,
                    "request_id": ctx.get("request_id"),
                    "timestamp": utc_now_iso(),
                    "status": record.status,
                }
            )

            if not calendar_result.get("success"):
                return self._error_result(
                    message="Appointment cancellation failed.",
                    error=calendar_result.get("error") or "CANCELLATION_FAILED",
                    data=output,
                    metadata=self._result_metadata(action="cancel_appointment", context=ctx),
                )

            return self._safe_result(
                message="Appointment cancelled.",
                data=output,
                metadata=self._result_metadata(action="cancel_appointment", context=ctx),
            )

        except Exception as exc:
            self.logger.exception("Appointment cancellation failed.")
            return self._error_result(
                message="Appointment cancellation failed.",
                error=exc,
                metadata=self._result_metadata(action="cancel_appointment", context=ctx),
            )

    def get_appointment(
        self,
        context: Mapping[str, Any],
        appointment_id: str,
    ) -> Dict[str, Any]:
        """Get one appointment record for the current user/workspace."""
        valid, error, ctx = self._validate_task_context(context)
        if not valid:
            return self._error_result("Invalid task context.", error or "INVALID_CONTEXT")

        appointment_id_n = normalize_text(appointment_id)
        if not appointment_id_n:
            return self._error_result("appointment_id is required.", "INVALID_APPOINTMENT_ID")

        record = self.store.get(ctx["user_id"], ctx["workspace_id"], appointment_id_n)

        if not record:
            return self._safe_result(
                message="Appointment not found.",
                data={"found": False, "appointment_id": appointment_id_n},
                metadata=self._result_metadata(action="get_appointment", context=ctx),
            )

        return self._safe_result(
            message="Appointment loaded.",
            data={"found": True, "appointment": record.to_dict()},
            metadata=self._result_metadata(action="get_appointment", context=ctx),
        )

    def list_appointments(
        self,
        context: Mapping[str, Any],
        status: Optional[str] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """List appointment records for the current user/workspace."""
        valid, error, ctx = self._validate_task_context(context)
        if not valid:
            return self._error_result("Invalid task context.", error or "INVALID_CONTEXT")

        records = self.store.list(
            user_id=ctx["user_id"],
            workspace_id=ctx["workspace_id"],
            status=status,
            limit=limit,
        )

        return self._safe_result(
            message="Appointments loaded.",
            data={
                "items": [record.to_dict() for record in records],
                "count": len(records),
                "status": status,
            },
            metadata=self._result_metadata(action="list_appointments", context=ctx),
        )

    # -------------------------------------------------------------------------
    # Master Agent / Router compatibility
    # -------------------------------------------------------------------------

    def route_action(
        self,
        action: str,
        context: Mapping[str, Any],
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Route generic actions from Master Agent, Agent Router, or dashboard API.

        This keeps the public surface stable for future registry/loader systems.
        """
        action_n = normalize_key(action)
        payload = dict(payload or {})

        routes: Dict[str, Callable[..., Dict[str, Any]]] = {
            "validate_appointment_request": self.validate_appointment_request,
            "check_availability": self.check_availability,
            "book_appointment": self.book_appointment,
            "prepare_confirmation_payload": self.prepare_confirmation_payload,
            "send_booking_confirmation": self.send_booking_confirmation,
            "cancel_appointment": self.cancel_appointment,
            "get_appointment": self.get_appointment,
            "list_appointments": self.list_appointments,
        }

        method = routes.get(action_n)
        if not method:
            return self._error_result(
                message=f"Unsupported AppointmentBooker action: {action}",
                error="UNSUPPORTED_ACTION",
                metadata=self._result_metadata(action="route_action"),
            )

        try:
            return method(context=context, **payload)
        except TypeError as exc:
            return self._error_result(
                message="Invalid payload for AppointmentBooker action.",
                error={
                    "code": "INVALID_ACTION_PAYLOAD",
                    "detail": str(exc),
                    "action": action_n,
                },
                metadata=self._result_metadata(action="route_action"),
            )
        except Exception as exc:
            self.logger.exception("AppointmentBooker route_action failed.")
            return self._error_result(
                message="AppointmentBooker action failed.",
                error=exc,
                metadata=self._result_metadata(action="route_action"),
            )

    # -------------------------------------------------------------------------
    # Internal validation/build helpers
    # -------------------------------------------------------------------------

    def _build_appointment_request(
        self,
        context: Mapping[str, Any],
        caller_name: str,
        start_time: Union[str, datetime],
        end_time: Optional[Union[str, datetime]] = None,
        caller_phone: Optional[str] = None,
        caller_email: Optional[str] = None,
        title: Optional[str] = None,
        duration_minutes: Optional[int] = None,
        timezone_name: Optional[str] = None,
        calendar_id: Optional[str] = None,
        attendees: Optional[List[Mapping[str, Any]]] = None,
        location: Optional[str] = None,
        description: Optional[str] = None,
        notes: Optional[str] = None,
        confirmation_channels: Optional[List[str]] = None,
        lead_id: Optional[str] = None,
        call_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> AppointmentRequest:
        """Build normalized AppointmentRequest dataclass."""
        caller_name_n = normalize_text(caller_name)
        if not caller_name_n:
            raise ValueError("caller_name is required.")

        caller_phone_n = self._normalize_phone(caller_phone)
        caller_email_n = self._normalize_email(caller_email)

        if not caller_phone_n and not caller_email_n:
            raise ValueError("At least one caller contact method is required: caller_phone or caller_email.")

        title_n = normalize_text(title) or f"Appointment with {caller_name_n}"
        if len(title_n) > DEFAULT_MAX_TITLE_LENGTH:
            raise ValueError(f"title is too long. Max length: {DEFAULT_MAX_TITLE_LENGTH}")

        start_dt, end_dt = self._normalize_time_range(start_time, end_time, duration_minutes)

        if start_dt <= datetime.now(timezone.utc) - timedelta(minutes=1):
            raise ValueError("start_time must be in the future.")

        notes_n = normalize_text(notes)
        if len(notes_n) > DEFAULT_MAX_NOTES_LENGTH:
            raise ValueError(f"notes are too long. Max length: {DEFAULT_MAX_NOTES_LENGTH}")

        timezone_n = normalize_text(timezone_name) or self.default_timezone
        calendar_id_n = normalize_text(calendar_id) or self.default_calendar_id
        safe_metadata = self._validate_metadata(metadata or {})

        attendee_list = self._normalize_attendees(attendees or [])

        caller_attendee = AppointmentAttendee(
            name=caller_name_n,
            email=caller_email_n,
            phone=caller_phone_n,
            role="caller",
            is_required=True,
        ).to_dict()

        attendee_list = self._merge_attendees([caller_attendee] + attendee_list)

        channels = self._normalize_confirmation_channels(confirmation_channels)
        if not channels:
            channels = self._default_confirmation_channels(caller_email_n, caller_phone_n)

        appointment_id = f"appt_{uuid.uuid4().hex}"

        return AppointmentRequest(
            appointment_id=appointment_id,
            user_id=context["user_id"],
            workspace_id=context["workspace_id"],
            caller_name=caller_name_n,
            caller_phone=caller_phone_n,
            caller_email=caller_email_n,
            title=title_n,
            start_time=to_iso(start_dt),
            end_time=to_iso(end_dt),
            timezone=timezone_n,
            calendar_id=calendar_id_n,
            attendees=attendee_list,
            location=normalize_text(location) or None,
            description=normalize_text(description) or None,
            notes=notes_n or None,
            source="call_agent",
            status="draft",
            confirmation_channels=channels,
            lead_id=normalize_text(lead_id) or None,
            call_id=normalize_text(call_id) or None,
            metadata=safe_metadata,
        )

    def _normalize_time_range(
        self,
        start_time: Union[str, datetime],
        end_time: Optional[Union[str, datetime]] = None,
        duration_minutes: Optional[int] = None,
    ) -> Tuple[datetime, datetime]:
        """Normalize appointment start/end datetimes."""
        start_dt = parse_datetime(start_time)

        if end_time is not None:
            end_dt = parse_datetime(end_time)
        else:
            duration = int(duration_minutes or self.default_duration_minutes)
            duration = max(5, min(duration, 24 * 60))
            end_dt = start_dt + timedelta(minutes=duration)

        if end_dt <= start_dt:
            raise ValueError("end_time must be after start_time.")

        if (end_dt - start_dt) > timedelta(hours=24):
            raise ValueError("Appointment duration cannot exceed 24 hours.")

        return start_dt, end_dt

    def _normalize_attendees(self, attendees: Iterable[Mapping[str, Any]]) -> List[Dict[str, Any]]:
        """Normalize attendee list."""
        normalized: List[Dict[str, Any]] = []

        for attendee in attendees:
            if not isinstance(attendee, Mapping):
                continue

            name = normalize_text(attendee.get("name"))
            email = self._normalize_email(attendee.get("email"))
            phone = self._normalize_phone(attendee.get("phone"))

            if not name and email:
                name = email
            if not name and phone:
                name = phone
            if not name:
                continue

            normalized.append(
                AppointmentAttendee(
                    name=name,
                    email=email,
                    phone=phone,
                    role=normalize_key(attendee.get("role") or "guest") or "guest",
                    is_required=bool(attendee.get("is_required", True)),
                    metadata=self._validate_metadata(attendee.get("metadata") or {}),
                ).to_dict()
            )

            if len(normalized) >= DEFAULT_MAX_ATTENDEES:
                break

        return normalized

    def _merge_attendees(self, attendees: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Deduplicate attendees by email, phone, or name."""
        merged: List[Dict[str, Any]] = []
        seen = set()

        for attendee in attendees:
            email = normalize_text(attendee.get("email")).lower()
            phone = normalize_text(attendee.get("phone"))
            name = normalize_text(attendee.get("name")).lower()
            key = email or phone or name

            if not key or key in seen:
                continue

            seen.add(key)
            merged.append(attendee)

        return merged[:DEFAULT_MAX_ATTENDEES]

    def _normalize_phone(self, phone: Optional[Any]) -> Optional[str]:
        """Normalize phone number while preserving international plus prefix."""
        raw = normalize_text(phone)
        if not raw:
            return None

        cleaned = re.sub(r"[^\d+]", "", raw)

        if cleaned.count("+") > 1:
            cleaned = cleaned.replace("+", "")
        if "+" in cleaned and not cleaned.startswith("+"):
            cleaned = cleaned.replace("+", "")

        digits = re.sub(r"\D", "", cleaned)
        if len(digits) < 7 or len(digits) > 16:
            raise ValueError("caller_phone must contain 7 to 16 digits.")

        return cleaned

    def _normalize_email(self, email: Optional[Any]) -> Optional[str]:
        """Normalize and lightly validate email."""
        raw = normalize_text(email).lower()
        if not raw:
            return None

        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", raw):
            raise ValueError("Invalid email address.")

        return raw

    def _normalize_confirmation_channel(self, channel: str) -> str:
        """Normalize one confirmation channel."""
        channel_n = normalize_key(channel or "none")
        if channel_n not in CONFIRMATION_CHANNELS:
            raise ValueError(f"Unsupported confirmation channel: {channel}")
        return channel_n

    def _normalize_confirmation_channels(self, channels: Optional[Iterable[str]]) -> List[str]:
        """Normalize confirmation channel list."""
        output: List[str] = []
        seen = set()

        for channel in channels or []:
            channel_n = self._normalize_confirmation_channel(channel)
            if channel_n not in seen:
                seen.add(channel_n)
                output.append(channel_n)

        return output

    def _default_confirmation_channels(
        self,
        caller_email: Optional[str],
        caller_phone: Optional[str],
    ) -> List[str]:
        """Choose safe default confirmation channels based on available contact data."""
        if caller_email:
            return ["email"]
        if caller_phone:
            return ["sms"]
        return ["dashboard"]

    def _validate_metadata(self, metadata: Mapping[str, Any]) -> Dict[str, Any]:
        """Clean metadata and remove sensitive fields."""
        if not isinstance(metadata, Mapping):
            raise ValueError("metadata must be a mapping/dict.")

        cleaned = remove_sensitive_for_storage(dict(metadata))
        serialized = safe_json_dumps(cleaned)

        if len(serialized) > 10000:
            raise ValueError("metadata is too large.")

        return cleaned

    def _contains_sensitive_keys(self, payload: Any) -> bool:
        """Recursively detect sensitive fields."""
        if isinstance(payload, Mapping):
            for key, value in payload.items():
                if is_sensitive_key(str(key)):
                    return True
                if self._contains_sensitive_keys(value):
                    return True

        if isinstance(payload, list):
            return any(self._contains_sensitive_keys(item) for item in payload)

        return False

    def _result_metadata(
        self,
        action: Optional[str] = None,
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Build standard metadata for structured results."""
        context = context or {}

        return {
            "agent": self.agent_name,
            "module": self.module_name,
            "agent_module": self.agent_module,
            "version": self.version,
            "action": action,
            "timestamp": utc_now_iso(),
            "request_id": context.get("request_id"),
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "external_action_executed_directly_by_this_file": False,
            "safe_to_import": True,
        }


# =============================================================================
# Factory helper for Agent Loader / Registry
# =============================================================================

def create_appointment_booker(
    calendar_adapter: Optional[CalendarAdapter] = None,
    confirmation_adapter: Optional[ConfirmationAdapter] = None,
    **kwargs: Any,
) -> AppointmentBooker:
    """
    Create AppointmentBooker instance.

    Agent Loader / Registry can use this factory without needing to know the
    constructor details.
    """
    return AppointmentBooker(
        calendar_adapter=calendar_adapter,
        confirmation_adapter=confirmation_adapter,
        **kwargs,
    )


# =============================================================================
# Self-test helper
# =============================================================================

def _self_test() -> Dict[str, Any]:
    """
    Lightweight self-test.

    This does not run on import. It can be called manually from unit tests.
    """
    booker = AppointmentBooker()
    context = {
        "user_id": "test_user",
        "workspace_id": "test_workspace",
        "actor_id": "tester",
        "security_approved": True,
    }

    start = datetime.now(timezone.utc) + timedelta(days=1)
    end = start + timedelta(minutes=30)

    result = booker.book_appointment(
        context=context,
        caller_name="John Doe",
        caller_phone="+15551234567",
        caller_email="john@example.com",
        title="Discovery Call",
        start_time=start,
        end_time=end,
        timezone_name="UTC",
        calendar_id="primary",
        attendees=[
            {
                "name": "Sales Specialist",
                "email": "sales@example.com",
                "role": "host",
            }
        ],
        location="Google Meet",
        description="Discovery call booked by Call Agent.",
        notes="Caller requested pricing details.",
        confirmation_channels=["email"],
        lead_id="lead_123",
        call_id="call_123",
    )

    return {
        "manifest": booker.get_agent_manifest(),
        "booking_result": result,
        "appointments": booker.list_appointments(context),
    }


__all__ = [
    "AppointmentBooker",
    "AppointmentStore",
    "AppointmentRequest",
    "AppointmentRecord",
    "AppointmentAttendee",
    "CalendarAdapter",
    "ConfirmationAdapter",
    "SafeNoopCalendarAdapter",
    "SafeNoopConfirmationAdapter",
    "create_appointment_booker",
]