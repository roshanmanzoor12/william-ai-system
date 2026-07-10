"""
agents/system_agent/call_controller.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Detect, answer, reject, mute, dial, and log calls with strict approval.

Safety Rules:
    - Every user-specific action requires user_id and workspace_id.
    - Never mix call logs, approvals, events, analytics, or memory between users/workspaces.
    - Real call actions must never execute unless approved.
    - Dialing, answering, rejecting, muting, unmuting, and ending calls are sensitive.
    - All sensitive actions go through Security Agent approval flow first.
    - This file is safe to import and safe to run locally.
    - Default provider is safe in-memory simulation only.

Compatibility:
    - BaseAgent compatible.
    - Agent Registry compatible.
    - Agent Loader compatible.
    - Master Agent routing compatible.
    - Security Agent approval compatible.
    - Verification Agent payload compatible.
    - Memory Agent payload compatible.
    - Dashboard/API ready.
"""

from __future__ import annotations

import copy
import logging
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Optional, Protocol, Union


# ---------------------------------------------------------------------------
# Safe optional BaseAgent import
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover

    class BaseAgent:  # type: ignore
        """
        Safe fallback BaseAgent.

        This lets the file import before the full William/Jarvis framework exists.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())
            self.logger = logging.getLogger(self.agent_name)

        def emit_event(self, *args: Any, **kwargs: Any) -> None:
            return None


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger("William.SystemAgent.CallController")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class CallProviderType(str, Enum):
    """Supported provider categories."""

    IN_MEMORY = "in_memory"
    ANDROID = "android"
    IOS = "ios"
    DESKTOP = "desktop"
    VOIP = "voip"
    TWILIO = "twilio"
    SIP = "sip"
    WHATSAPP = "whatsapp"
    SLACK = "slack"
    TEAMS = "teams"
    INTERNAL = "internal"


class CallDirection(str, Enum):
    """Call direction."""

    INBOUND = "inbound"
    OUTBOUND = "outbound"
    UNKNOWN = "unknown"


class CallState(str, Enum):
    """Call lifecycle state."""

    IDLE = "idle"
    RINGING = "ringing"
    DIALING = "dialing"
    CONNECTING = "connecting"
    ACTIVE = "active"
    ON_HOLD = "on_hold"
    MUTED = "muted"
    ENDED = "ended"
    MISSED = "missed"
    REJECTED = "rejected"
    FAILED = "failed"
    BLOCKED = "blocked"
    UNKNOWN = "unknown"


class CallAction(str, Enum):
    """Actions supported by CallController."""

    DETECT = "detect"
    LOG = "log"
    LIST_CALLS = "list_calls"
    GET_CALL = "get_call"

    REQUEST_APPROVAL = "request_approval"
    APPROVE_ACTION = "approve_action"
    DENY_ACTION = "deny_action"
    LIST_PENDING_APPROVALS = "list_pending_approvals"

    ANSWER = "answer"
    REJECT = "reject"
    MUTE = "mute"
    UNMUTE = "unmute"
    DIAL = "dial"
    END = "end"


class ApprovalStatus(str, Enum):
    """Approval status for call actions."""

    NOT_REQUIRED = "not_required"
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    FAILED = "failed"


class SensitivityLevel(str, Enum):
    """Sensitivity level."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CallRiskLevel(str, Enum):
    """Call risk level."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# Provider Protocol
# ---------------------------------------------------------------------------

class CallProvider(Protocol):
    """
    Provider protocol for phone/VoIP/device call integrations.

    Real Android, iOS, SIP, VoIP, WhatsApp, or Twilio adapters can implement
    this interface and be registered in CallController.

    Default implementation is safe in-memory only.
    """

    provider_name: str

    def detect_calls(
        self,
        *,
        user_id: str,
        workspace_id: str,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """Detect or list current/recent calls."""

    def answer_call(
        self,
        *,
        user_id: str,
        workspace_id: str,
        call_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Answer an inbound call."""

    def reject_call(
        self,
        *,
        user_id: str,
        workspace_id: str,
        call_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Reject an inbound call."""

    def mute_call(
        self,
        *,
        user_id: str,
        workspace_id: str,
        call_id: str,
        muted: bool,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Mute or unmute an active call."""

    def dial_call(
        self,
        *,
        user_id: str,
        workspace_id: str,
        phone_number: str,
        display_name: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Dial an outbound call."""

    def end_call(
        self,
        *,
        user_id: str,
        workspace_id: str,
        call_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """End an active call."""


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

@dataclass
class CallContext:
    """
    SaaS context for all call actions.

    user_id and workspace_id are mandatory for isolation.
    """

    user_id: str
    workspace_id: str
    actor_id: Optional[str] = None
    role: Optional[str] = None
    subscription_plan: Optional[str] = None
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source: str = "system_agent"
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    device_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CallRecord:
    """Call record for logs, detection, and dashboard."""

    call_id: str
    user_id: str
    workspace_id: str
    provider: str
    direction: str
    state: str
    phone_number: Optional[str] = None
    display_name: Optional[str] = None
    started_at: Optional[str] = None
    ended_at: Optional[str] = None
    duration_seconds: Optional[int] = None
    muted: bool = False
    answered: bool = False
    rejected: bool = False
    missed: bool = False
    provider_call_id: Optional[str] = None
    sensitivity: str = SensitivityLevel.MEDIUM.value
    risk_level: str = CallRiskLevel.MEDIUM.value
    created_at: str = field(default_factory=lambda: _utc_now())
    updated_at: str = field(default_factory=lambda: _utc_now())
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CallApprovalRequest:
    """Approval request for sensitive call actions."""

    approval_id: str
    user_id: str
    workspace_id: str
    action: str
    provider: str
    status: str = ApprovalStatus.PENDING.value
    call_id: Optional[str] = None
    phone_number: Optional[str] = None
    display_name: Optional[str] = None
    reason: str = ""
    requested_by: Optional[str] = None
    approved_by: Optional[str] = None
    denied_by: Optional[str] = None
    created_at: str = field(default_factory=lambda: _utc_now())
    updated_at: str = field(default_factory=lambda: _utc_now())
    expires_at: Optional[str] = None
    security_payload: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CallAuditEvent:
    """Audit event for call actions."""

    event_id: str
    user_id: str
    workspace_id: str
    action: str
    success: bool
    message: str
    created_at: str = field(default_factory=lambda: _utc_now())
    request_id: Optional[str] = None
    actor_id: Optional[str] = None
    provider: Optional[str] = None
    call_id: Optional[str] = None
    approval_id: Optional[str] = None
    phone_number_masked: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    """Return current UTC timestamp."""

    return datetime.now(timezone.utc).isoformat()


def _safe_copy(value: Any) -> Any:
    """Return defensive deep copy when possible."""

    try:
        return copy.deepcopy(value)
    except Exception:
        return value


def _normalize_id(value: Any) -> str:
    """Normalize IDs."""

    if value is None:
        return ""
    return str(value).strip()


def _is_non_empty_string(value: Any) -> bool:
    """Check if value is a non-empty string."""

    return isinstance(value, str) and bool(value.strip())


def _truncate_text(text: Optional[str], limit: int = 300) -> str:
    """Truncate text safely."""

    if text is None:
        return ""
    clean = str(text).replace("\n", " ").strip()
    if len(clean) <= limit:
        return clean
    return clean[: limit - 3] + "..."


def _mask_phone_number(phone_number: Optional[str]) -> Optional[str]:
    """Mask phone number for audit logs."""

    if not phone_number:
        return None

    digits = re.sub(r"\D+", "", str(phone_number))
    if len(digits) <= 4:
        return "*" * len(digits)

    return f"{'*' * max(0, len(digits) - 4)}{digits[-4:]}"


def _normalize_phone_number(phone_number: str) -> str:
    """
    Normalize phone number while keeping + when provided.

    This is intentionally conservative. Real E.164 validation can be added in
    future provider adapters.
    """

    raw = str(phone_number or "").strip()
    has_plus = raw.startswith("+")
    digits = re.sub(r"\D+", "", raw)

    if has_plus:
        return f"+{digits}"
    return digits


def _safe_int(value: Any, default: int = 0) -> int:
    """Safely convert to int."""

    try:
        return int(value)
    except Exception:
        return default


# ---------------------------------------------------------------------------
# Safe In-Memory Provider
# ---------------------------------------------------------------------------

class InMemoryCallProvider:
    """
    Safe provider for local tests.

    It does not interact with a real phone, operating system, browser, VoIP,
    WhatsApp, Slack, Teams, Twilio, or SIP service.
    """

    provider_name = "in_memory"

    def __init__(self) -> None:
        self._calls: Dict[str, Dict[str, Any]] = {}

    def seed_call(self, call: Dict[str, Any]) -> str:
        """Seed a call for local testing."""

        call_id = str(call.get("call_id") or f"call_{uuid.uuid4().hex}")
        record = {
            "call_id": call_id,
            "user_id": call.get("user_id"),
            "workspace_id": call.get("workspace_id"),
            "provider": self.provider_name,
            "direction": call.get("direction", CallDirection.INBOUND.value),
            "state": call.get("state", CallState.RINGING.value),
            "phone_number": call.get("phone_number"),
            "display_name": call.get("display_name"),
            "started_at": call.get("started_at"),
            "ended_at": call.get("ended_at"),
            "duration_seconds": call.get("duration_seconds"),
            "muted": bool(call.get("muted", False)),
            "answered": bool(call.get("answered", False)),
            "rejected": bool(call.get("rejected", False)),
            "missed": bool(call.get("missed", False)),
            "provider_call_id": call.get("provider_call_id") or call_id,
            "metadata": call.get("metadata") or {},
            "created_at": call.get("created_at") or _utc_now(),
            "updated_at": call.get("updated_at") or _utc_now(),
        }
        self._calls[call_id] = record
        return call_id

    def detect_calls(
        self,
        *,
        user_id: str,
        workspace_id: str,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """Return calls for the current user/workspace."""

        filters = filters or {}
        results: List[Dict[str, Any]] = []

        for call in self._calls.values():
            if str(call.get("user_id")) != str(user_id):
                continue
            if str(call.get("workspace_id")) != str(workspace_id):
                continue

            state_filter = filters.get("state")
            if state_filter and str(call.get("state")) != str(state_filter):
                continue

            direction_filter = filters.get("direction")
            if direction_filter and str(call.get("direction")) != str(direction_filter):
                continue

            phone_query = filters.get("phone_number")
            if phone_query:
                normalized_query = _normalize_phone_number(str(phone_query))
                normalized_call = _normalize_phone_number(str(call.get("phone_number") or ""))
                if normalized_query not in normalized_call:
                    continue

            results.append(_safe_copy(call))

            if len(results) >= max(1, int(limit)):
                break

        return results

    def answer_call(
        self,
        *,
        user_id: str,
        workspace_id: str,
        call_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Safely simulate answering a call."""

        call = self._get_owned_call(user_id, workspace_id, call_id)
        if not call:
            return {
                "success": False,
                "message": "Call not found in in-memory provider.",
                "error_code": "CALL_NOT_FOUND",
            }

        call["state"] = CallState.ACTIVE.value
        call["answered"] = True
        call["rejected"] = False
        call["missed"] = False
        call["started_at"] = call.get("started_at") or _utc_now()
        call["updated_at"] = _utc_now()
        call["metadata"] = {**(call.get("metadata") or {}), **(metadata or {})}
        self._calls[call_id] = call

        return {
            "success": True,
            "message": "Call answered through safe in-memory provider.",
            "provider": self.provider_name,
            "data": _safe_copy(call),
        }

    def reject_call(
        self,
        *,
        user_id: str,
        workspace_id: str,
        call_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Safely simulate rejecting a call."""

        call = self._get_owned_call(user_id, workspace_id, call_id)
        if not call:
            return {
                "success": False,
                "message": "Call not found in in-memory provider.",
                "error_code": "CALL_NOT_FOUND",
            }

        call["state"] = CallState.REJECTED.value
        call["rejected"] = True
        call["answered"] = False
        call["ended_at"] = _utc_now()
        call["updated_at"] = _utc_now()
        call["metadata"] = {**(call.get("metadata") or {}), **(metadata or {})}
        self._calls[call_id] = call

        return {
            "success": True,
            "message": "Call rejected through safe in-memory provider.",
            "provider": self.provider_name,
            "data": _safe_copy(call),
        }

    def mute_call(
        self,
        *,
        user_id: str,
        workspace_id: str,
        call_id: str,
        muted: bool,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Safely simulate mute/unmute."""

        call = self._get_owned_call(user_id, workspace_id, call_id)
        if not call:
            return {
                "success": False,
                "message": "Call not found in in-memory provider.",
                "error_code": "CALL_NOT_FOUND",
            }

        call["muted"] = bool(muted)
        call["state"] = CallState.MUTED.value if muted else CallState.ACTIVE.value
        call["updated_at"] = _utc_now()
        call["metadata"] = {**(call.get("metadata") or {}), **(metadata or {})}
        self._calls[call_id] = call

        return {
            "success": True,
            "message": "Call muted." if muted else "Call unmuted.",
            "provider": self.provider_name,
            "data": _safe_copy(call),
        }

    def dial_call(
        self,
        *,
        user_id: str,
        workspace_id: str,
        phone_number: str,
        display_name: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Safely simulate dialing an outbound call."""

        call_id = f"call_{uuid.uuid4().hex}"
        call = {
            "call_id": call_id,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "provider": self.provider_name,
            "direction": CallDirection.OUTBOUND.value,
            "state": CallState.DIALING.value,
            "phone_number": phone_number,
            "display_name": display_name,
            "started_at": _utc_now(),
            "ended_at": None,
            "duration_seconds": None,
            "muted": False,
            "answered": False,
            "rejected": False,
            "missed": False,
            "provider_call_id": f"mem_{uuid.uuid4().hex}",
            "metadata": metadata or {},
            "created_at": _utc_now(),
            "updated_at": _utc_now(),
        }
        self._calls[call_id] = call

        return {
            "success": True,
            "message": "Outbound call dialed through safe in-memory provider.",
            "provider": self.provider_name,
            "provider_call_id": call["provider_call_id"],
            "data": _safe_copy(call),
        }

    def end_call(
        self,
        *,
        user_id: str,
        workspace_id: str,
        call_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Safely simulate ending a call."""

        call = self._get_owned_call(user_id, workspace_id, call_id)
        if not call:
            return {
                "success": False,
                "message": "Call not found in in-memory provider.",
                "error_code": "CALL_NOT_FOUND",
            }

        ended_at = _utc_now()
        call["state"] = CallState.ENDED.value
        call["ended_at"] = ended_at
        call["updated_at"] = ended_at

        if call.get("started_at"):
            call["duration_seconds"] = _calculate_duration_seconds(call.get("started_at"), ended_at)

        call["metadata"] = {**(call.get("metadata") or {}), **(metadata or {})}
        self._calls[call_id] = call

        return {
            "success": True,
            "message": "Call ended through safe in-memory provider.",
            "provider": self.provider_name,
            "data": _safe_copy(call),
        }

    def _get_owned_call(
        self,
        user_id: str,
        workspace_id: str,
        call_id: str,
    ) -> Optional[Dict[str, Any]]:
        """Return owned call from memory."""

        call = self._calls.get(call_id)
        if not call:
            return None

        if str(call.get("user_id")) != str(user_id):
            return None

        if str(call.get("workspace_id")) != str(workspace_id):
            return None

        return _safe_copy(call)


def _calculate_duration_seconds(started_at: Optional[str], ended_at: Optional[str]) -> Optional[int]:
    """Calculate duration safely."""

    if not started_at or not ended_at:
        return None

    try:
        start = datetime.fromisoformat(started_at)
        end = datetime.fromisoformat(ended_at)

        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)

        if end.tzinfo is None:
            end = end.replace(tzinfo=timezone.utc)

        return max(0, int((end - start).total_seconds()))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# CallController
# ---------------------------------------------------------------------------

class CallController(BaseAgent):
    """
    System Agent call controller.

    Responsibilities:
        - Detect active/recent calls.
        - Log inbound/outbound calls.
        - Request strict approval for sensitive call actions.
        - Approve or deny call actions.
        - Answer approved inbound calls.
        - Reject approved inbound calls.
        - Mute/unmute approved active calls.
        - Dial approved outbound calls.
        - End approved active calls.
        - Maintain SaaS isolation.
        - Prepare Verification Agent payloads.
        - Prepare Memory Agent payloads.
        - Emit events and audit logs.

    Master Agent:
        Can route call tasks to this class through public methods.

    Security Agent:
        All real call-control actions require approval.

    Verification Agent:
        Every completed action prepares a verification payload.

    Memory Agent:
        Useful safe call context can be stored per user/workspace.

    Dashboard/API:
        Results are structured dict/JSON style.
    """

    DEFAULT_APPROVAL_TTL_SECONDS = 60 * 30
    DEFAULT_DETECT_LIMIT = 20
    MAX_DETECT_LIMIT = 100
    MIN_PHONE_DIGITS = 5
    MAX_PHONE_DIGITS = 16

    SENSITIVE_ACTIONS = {
        CallAction.ANSWER.value,
        CallAction.REJECT.value,
        CallAction.MUTE.value,
        CallAction.UNMUTE.value,
        CallAction.DIAL.value,
        CallAction.END.value,
    }

    def __init__(
        self,
        *,
        agent_name: str = "SystemCallController",
        agent_id: str = "system_agent.call_controller",
        providers: Optional[Dict[str, CallProvider]] = None,
        security_approval_callback: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        audit_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        enable_in_memory_provider: bool = True,
        strict_provider_mode: bool = False,
        default_provider_name: str = "in_memory",
    ) -> None:
        """
        Initialize CallController.

        Args:
            agent_name:
                Human-readable name.
            agent_id:
                Registry/router ID.
            providers:
                Optional provider registry.
            security_approval_callback:
                External Security Agent approval callback.
            event_callback:
                Event bus/dashboard callback.
            audit_callback:
                Persistent audit callback.
            enable_in_memory_provider:
                Register safe in-memory provider.
            strict_provider_mode:
                If True, default in-memory provider cannot execute real actions.
            default_provider_name:
                Default provider key.
        """

        super().__init__(agent_name=agent_name, agent_id=agent_id)

        self.agent_name = agent_name
        self.agent_id = agent_id
        self.logger = logging.getLogger(agent_name)

        self.security_approval_callback = security_approval_callback
        self.event_callback = event_callback
        self.audit_callback = audit_callback
        self.strict_provider_mode = strict_provider_mode
        self.default_provider_name = default_provider_name

        self.providers: Dict[str, CallProvider] = {}
        self.provider_type_map: Dict[str, str] = {}

        self._calls: Dict[str, CallRecord] = {}
        self._approvals: Dict[str, CallApprovalRequest] = {}
        self._audit_events: List[CallAuditEvent] = []
        self._task_history: List[Dict[str, Any]] = []

        if enable_in_memory_provider:
            self.register_provider(default_provider_name, InMemoryCallProvider())

        if providers:
            for name, provider in providers.items():
                self.register_provider(name, provider)

        self._emit_agent_event(
            event_type="call_controller.initialized",
            payload={
                "agent_id": self.agent_id,
                "providers": list(self.providers.keys()),
                "strict_provider_mode": self.strict_provider_mode,
            },
        )

    # -----------------------------------------------------------------------
    # Provider management
    # -----------------------------------------------------------------------

    def register_provider(
        self,
        provider_name: str,
        provider: CallProvider,
        *,
        provider_types: Optional[Iterable[Union[str, CallProviderType]]] = None,
    ) -> Dict[str, Any]:
        """Register a call provider."""

        if not _is_non_empty_string(provider_name):
            return self._error_result(
                message="Provider name is required.",
                error_code="INVALID_PROVIDER_NAME",
            )

        required_methods = (
            "detect_calls",
            "answer_call",
            "reject_call",
            "mute_call",
            "dial_call",
            "end_call",
        )

        for method_name in required_methods:
            if not callable(getattr(provider, method_name, None)):
                return self._error_result(
                    message=f"Provider '{provider_name}' is missing method '{method_name}'.",
                    error_code="INVALID_PROVIDER_INTERFACE",
                    data={"provider_name": provider_name},
                )

        normalized_name = provider_name.strip()
        self.providers[normalized_name] = provider

        mapped_types: List[str] = []

        if provider_types:
            for provider_type in provider_types:
                normalized_type = self._normalize_provider_type(provider_type)
                self.provider_type_map[normalized_type] = normalized_name
                mapped_types.append(normalized_type)

        self._emit_agent_event(
            event_type="call_provider.registered",
            payload={
                "provider_name": normalized_name,
                "provider_types": mapped_types,
            },
        )

        return self._safe_result(
            message=f"Provider '{normalized_name}' registered successfully.",
            data={
                "provider_name": normalized_name,
                "provider_types": mapped_types,
            },
        )

    def map_provider_type(
        self,
        provider_type: Union[str, CallProviderType],
        provider_name: str,
    ) -> Dict[str, Any]:
        """Map a provider type to a registered provider."""

        normalized_type = self._normalize_provider_type(provider_type)
        normalized_provider = str(provider_name).strip()

        if normalized_provider not in self.providers:
            return self._error_result(
                message=f"Provider '{normalized_provider}' is not registered.",
                error_code="PROVIDER_NOT_REGISTERED",
                data={
                    "provider_type": normalized_type,
                    "provider_name": normalized_provider,
                },
            )

        self.provider_type_map[normalized_type] = normalized_provider

        return self._safe_result(
            message=f"Provider type '{normalized_type}' mapped to provider '{normalized_provider}'.",
            data={
                "provider_type": normalized_type,
                "provider_name": normalized_provider,
            },
        )

    def get_registered_providers(self) -> Dict[str, Any]:
        """Return registered providers and mappings."""

        return self._safe_result(
            message="Registered providers fetched successfully.",
            data={
                "providers": list(self.providers.keys()),
                "provider_type_map": _safe_copy(self.provider_type_map),
                "default_provider_name": self.default_provider_name,
                "strict_provider_mode": self.strict_provider_mode,
            },
        )

    # -----------------------------------------------------------------------
    # Public call methods
    # -----------------------------------------------------------------------

    def detect_calls(
        self,
        *,
        context: Union[CallContext, Dict[str, Any]],
        provider_type: Union[str, CallProviderType] = CallProviderType.IN_MEMORY,
        provider_name: Optional[str] = None,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = DEFAULT_DETECT_LIMIT,
    ) -> Dict[str, Any]:
        """
        Detect active/recent calls.

        Detecting is read-only and does not require approval, but it still
        enforces user/workspace isolation.
        """

        started_at = time.time()
        action = CallAction.DETECT.value

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        ctx = ctx_result["data"]["context"]
        normalized_provider_type = self._normalize_provider_type(provider_type)
        normalized_limit = min(max(1, int(limit)), self.MAX_DETECT_LIMIT)

        provider_result = self._resolve_provider(normalized_provider_type, provider_name)
        if not provider_result["success"]:
            self._log_audit_event(
                context=ctx,
                action=action,
                success=False,
                message=provider_result["message"],
                provider=provider_name,
                metadata={"filters": self._sanitize_filters(filters)},
            )
            return provider_result

        provider = provider_result["data"]["provider"]
        provider_key = provider_result["data"]["provider_name"]

        try:
            raw_calls = provider.detect_calls(
                user_id=ctx.user_id,
                workspace_id=ctx.workspace_id,
                filters=filters or {},
                limit=normalized_limit,
            )

            calls: List[Dict[str, Any]] = []

            for raw_call in raw_calls:
                if str(raw_call.get("user_id")) != str(ctx.user_id):
                    continue
                if str(raw_call.get("workspace_id")) != str(ctx.workspace_id):
                    continue

                record = self._call_record_from_provider(raw_call, ctx=ctx, provider=provider_key)
                self._calls[record.call_id] = record
                calls.append(self._public_call_dict(record))

            verification_payload = self._prepare_verification_payload(
                context=ctx,
                action=action,
                success=True,
                message="Calls detected successfully.",
                data={
                    "provider": provider_key,
                    "provider_type": normalized_provider_type,
                    "count": len(calls),
                },
            )

            memory_payload = self._prepare_memory_payload(
                context=ctx,
                action=action,
                data={
                    "provider": provider_key,
                    "provider_type": normalized_provider_type,
                    "call_count": len(calls),
                    "filters": self._sanitize_filters(filters),
                },
            )

            self._log_audit_event(
                context=ctx,
                action=action,
                success=True,
                message="Calls detected successfully.",
                provider=provider_key,
                metadata={
                    "provider_type": normalized_provider_type,
                    "count": len(calls),
                    "duration_ms": int((time.time() - started_at) * 1000),
                },
            )

            self._record_task_history(
                context=ctx,
                action=action,
                success=True,
                data={
                    "provider": provider_key,
                    "provider_type": normalized_provider_type,
                    "count": len(calls),
                },
            )

            return self._safe_result(
                message="Calls detected successfully.",
                data={
                    "calls": calls,
                    "count": len(calls),
                    "provider": provider_key,
                    "provider_type": normalized_provider_type,
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                metadata={
                    "request_id": ctx.request_id,
                    "user_id": ctx.user_id,
                    "workspace_id": ctx.workspace_id,
                    "duration_ms": int((time.time() - started_at) * 1000),
                },
            )

        except Exception as exc:
            self.logger.exception("Failed to detect calls.")

            self._log_audit_event(
                context=ctx,
                action=action,
                success=False,
                message="Failed to detect calls.",
                provider=provider_key,
                metadata={"error": str(exc)},
            )

            return self._error_result(
                message="Failed to detect calls.",
                error_code="CALL_DETECTION_FAILED",
                error=str(exc),
                data={
                    "provider": provider_key,
                    "provider_type": normalized_provider_type,
                },
                metadata={
                    "request_id": ctx.request_id,
                    "user_id": ctx.user_id,
                    "workspace_id": ctx.workspace_id,
                },
            )

    def log_call(
        self,
        *,
        context: Union[CallContext, Dict[str, Any]],
        provider: str = "manual",
        direction: Union[str, CallDirection] = CallDirection.UNKNOWN,
        state: Union[str, CallState] = CallState.UNKNOWN,
        phone_number: Optional[str] = None,
        display_name: Optional[str] = None,
        started_at: Optional[str] = None,
        ended_at: Optional[str] = None,
        duration_seconds: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
        sensitivity: Union[str, SensitivityLevel] = SensitivityLevel.MEDIUM,
        risk_level: Union[str, CallRiskLevel] = CallRiskLevel.MEDIUM,
    ) -> Dict[str, Any]:
        """
        Log a call manually or from external provider callback.

        Logging is not a real call-control action, but it is audited and isolated.
        """

        started_timer = time.time()
        action = CallAction.LOG.value

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        ctx = ctx_result["data"]["context"]

        normalized_direction = self._normalize_direction(direction)
        normalized_state = self._normalize_state(state)
        normalized_phone = _normalize_phone_number(phone_number) if phone_number else None

        if normalized_phone:
            phone_result = self._validate_phone_number(normalized_phone)
            if not phone_result["success"]:
                return phone_result

        call_id = f"call_{uuid.uuid4().hex}"

        record = CallRecord(
            call_id=call_id,
            user_id=ctx.user_id,
            workspace_id=ctx.workspace_id,
            provider=str(provider or "manual").strip(),
            direction=normalized_direction,
            state=normalized_state,
            phone_number=normalized_phone,
            display_name=display_name,
            started_at=started_at,
            ended_at=ended_at,
            duration_seconds=duration_seconds if duration_seconds is not None else _calculate_duration_seconds(started_at, ended_at),
            muted=False,
            answered=normalized_state == CallState.ACTIVE.value,
            rejected=normalized_state == CallState.REJECTED.value,
            missed=normalized_state == CallState.MISSED.value,
            provider_call_id=None,
            sensitivity=self._normalize_sensitivity(sensitivity),
            risk_level=self._normalize_risk_level(risk_level),
            metadata={
                **(metadata or {}),
                "request_id": ctx.request_id,
                "actor_id": ctx.actor_id,
                "source": ctx.source,
            },
        )

        self._calls[call_id] = record

        verification_payload = self._prepare_verification_payload(
            context=ctx,
            action=action,
            success=True,
            message="Call logged successfully.",
            data={
                "call_id": call_id,
                "provider": record.provider,
                "direction": record.direction,
                "state": record.state,
            },
        )

        memory_payload = self._prepare_memory_payload(
            context=ctx,
            action=action,
            data={
                "call_id": call_id,
                "provider": record.provider,
                "direction": record.direction,
                "state": record.state,
                "phone_number_masked": _mask_phone_number(record.phone_number),
                "display_name": record.display_name,
            },
        )

        self._log_audit_event(
            context=ctx,
            action=action,
            success=True,
            message="Call logged successfully.",
            provider=record.provider,
            call_id=call_id,
            phone_number=record.phone_number,
            metadata={
                "direction": record.direction,
                "state": record.state,
                "duration_ms": int((time.time() - started_timer) * 1000),
            },
        )

        self._emit_agent_event(
            event_type="call.logged",
            payload={
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
                "call_id": call_id,
                "provider": record.provider,
                "direction": record.direction,
                "state": record.state,
            },
        )

        self._record_task_history(
            context=ctx,
            action=action,
            success=True,
            data={"call_id": call_id},
        )

        return self._safe_result(
            message="Call logged successfully.",
            data={
                "call": self._public_call_dict(record),
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                "request_id": ctx.request_id,
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
                "duration_ms": int((time.time() - started_timer) * 1000),
            },
        )

    def request_action_approval(
        self,
        *,
        context: Union[CallContext, Dict[str, Any]],
        action: Union[str, CallAction],
        call_id: Optional[str] = None,
        phone_number: Optional[str] = None,
        display_name: Optional[str] = None,
        provider_type: Union[str, CallProviderType] = CallProviderType.IN_MEMORY,
        provider_name: Optional[str] = None,
        reason: str = "",
        expires_in_seconds: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request strict approval for a call-control action.

        Required before:
            - answer
            - reject
            - mute
            - unmute
            - dial
            - end
        """

        started_at = time.time()
        request_action = CallAction.REQUEST_APPROVAL.value

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        ctx = ctx_result["data"]["context"]
        normalized_action = self._normalize_action(action)
        normalized_provider_type = self._normalize_provider_type(provider_type)

        if normalized_action not in self.SENSITIVE_ACTIONS:
            return self._error_result(
                message=f"Action '{normalized_action}' does not require call approval or is unsupported.",
                error_code="UNSUPPORTED_APPROVAL_ACTION",
                data={"action": normalized_action},
            )

        provider_result = self._resolve_provider(normalized_provider_type, provider_name)
        if not provider_result["success"]:
            return provider_result

        provider_key = provider_result["data"]["provider_name"]

        call: Optional[CallRecord] = None
        if normalized_action != CallAction.DIAL.value:
            call_result = self._get_owned_call(ctx, call_id)
            if not call_result["success"]:
                return call_result
            call = call_result["data"]["call"]

        normalized_phone: Optional[str] = None
        if normalized_action == CallAction.DIAL.value:
            if not phone_number:
                return self._error_result(
                    message="phone_number is required for dial approval.",
                    error_code="MISSING_PHONE_NUMBER",
                )
            normalized_phone = _normalize_phone_number(phone_number)
            phone_result = self._validate_phone_number(normalized_phone)
            if not phone_result["success"]:
                return phone_result
        elif call:
            normalized_phone = call.phone_number

        synthetic_call = call or CallRecord(
            call_id=f"pending_dial_{uuid.uuid4().hex}",
            user_id=ctx.user_id,
            workspace_id=ctx.workspace_id,
            provider=provider_key,
            direction=CallDirection.OUTBOUND.value,
            state=CallState.DIALING.value,
            phone_number=normalized_phone,
            display_name=display_name,
            sensitivity=SensitivityLevel.HIGH.value,
            risk_level=CallRiskLevel.HIGH.value,
        )

        if self._requires_security_check(action=normalized_action, call=synthetic_call):
            security_result = self._request_security_approval(
                context=ctx,
                action=normalized_action,
                call=synthetic_call,
                reason=reason,
                metadata=metadata or {},
            )
            if not security_result["success"]:
                self._log_audit_event(
                    context=ctx,
                    action=request_action,
                    success=False,
                    message=security_result["message"],
                    provider=provider_key,
                    call_id=call.call_id if call else None,
                    phone_number=normalized_phone,
                    metadata={"reason": reason},
                )
                return security_result

            security_payload = security_result["data"]
        else:
            security_payload = {
                "approval_required": False,
                "status": ApprovalStatus.NOT_REQUIRED.value,
            }

        approval_id = f"call_approval_{uuid.uuid4().hex}"
        ttl = expires_in_seconds or self.DEFAULT_APPROVAL_TTL_SECONDS
        expires_at = datetime.fromtimestamp(time.time() + ttl, tz=timezone.utc).isoformat()

        approval = CallApprovalRequest(
            approval_id=approval_id,
            user_id=ctx.user_id,
            workspace_id=ctx.workspace_id,
            action=normalized_action,
            provider=provider_key,
            status=ApprovalStatus.PENDING.value,
            call_id=call.call_id if call else None,
            phone_number=normalized_phone,
            display_name=display_name or (call.display_name if call else None),
            reason=reason,
            requested_by=ctx.actor_id or ctx.user_id,
            expires_at=expires_at,
            security_payload=security_payload,
            metadata={
                **(metadata or {}),
                "request_id": ctx.request_id,
                "provider_type": normalized_provider_type,
                "phone_number_masked": _mask_phone_number(normalized_phone),
                "call_state": call.state if call else CallState.DIALING.value,
            },
        )

        self._approvals[approval_id] = approval

        verification_payload = self._prepare_verification_payload(
            context=ctx,
            action=request_action,
            success=True,
            message="Call action approval requested successfully.",
            data={
                "approval_id": approval_id,
                "action": normalized_action,
                "call_id": approval.call_id,
                "provider": provider_key,
                "status": approval.status,
            },
        )

        memory_payload = self._prepare_memory_payload(
            context=ctx,
            action=request_action,
            data={
                "approval_id": approval_id,
                "action": normalized_action,
                "call_id": approval.call_id,
                "provider": provider_key,
                "phone_number_masked": _mask_phone_number(normalized_phone),
                "reason": reason,
            },
        )

        self._log_audit_event(
            context=ctx,
            action=request_action,
            success=True,
            message="Call action approval requested successfully.",
            provider=provider_key,
            call_id=approval.call_id,
            approval_id=approval_id,
            phone_number=normalized_phone,
            metadata={
                "requested_action": normalized_action,
                "reason": reason,
                "expires_at": expires_at,
                "duration_ms": int((time.time() - started_at) * 1000),
            },
        )

        self._emit_agent_event(
            event_type="call.approval_requested",
            payload={
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
                "approval_id": approval_id,
                "action": normalized_action,
                "call_id": approval.call_id,
                "provider": provider_key,
            },
        )

        self._record_task_history(
            context=ctx,
            action=request_action,
            success=True,
            data={
                "approval_id": approval_id,
                "requested_action": normalized_action,
                "call_id": approval.call_id,
            },
        )

        return self._safe_result(
            message="Call action approval requested successfully.",
            data={
                "approval": asdict(approval),
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                "request_id": ctx.request_id,
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
                "duration_ms": int((time.time() - started_at) * 1000),
            },
        )

    def approve_action(
        self,
        *,
        context: Union[CallContext, Dict[str, Any]],
        approval_id: str,
        approved_by: Optional[str] = None,
        note: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Approve a pending call action."""

        return self._set_approval_status(
            context=context,
            approval_id=approval_id,
            status=ApprovalStatus.APPROVED,
            actor=approved_by,
            note=note,
        )

    def deny_action(
        self,
        *,
        context: Union[CallContext, Dict[str, Any]],
        approval_id: str,
        denied_by: Optional[str] = None,
        note: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Deny a pending call action."""

        return self._set_approval_status(
            context=context,
            approval_id=approval_id,
            status=ApprovalStatus.DENIED,
            actor=denied_by,
            note=note,
        )

    def answer_call(
        self,
        *,
        context: Union[CallContext, Dict[str, Any]],
        call_id: str,
        approval_id: str,
        provider_type: Union[str, CallProviderType] = CallProviderType.IN_MEMORY,
        provider_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Answer an approved inbound call."""

        return self._execute_call_action(
            context=context,
            action=CallAction.ANSWER,
            approval_id=approval_id,
            call_id=call_id,
            provider_type=provider_type,
            provider_name=provider_name,
        )

    def reject_call(
        self,
        *,
        context: Union[CallContext, Dict[str, Any]],
        call_id: str,
        approval_id: str,
        provider_type: Union[str, CallProviderType] = CallProviderType.IN_MEMORY,
        provider_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Reject an approved inbound call."""

        return self._execute_call_action(
            context=context,
            action=CallAction.REJECT,
            approval_id=approval_id,
            call_id=call_id,
            provider_type=provider_type,
            provider_name=provider_name,
        )

    def mute_call(
        self,
        *,
        context: Union[CallContext, Dict[str, Any]],
        call_id: str,
        approval_id: str,
        provider_type: Union[str, CallProviderType] = CallProviderType.IN_MEMORY,
        provider_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Mute an approved active call."""

        return self._execute_call_action(
            context=context,
            action=CallAction.MUTE,
            approval_id=approval_id,
            call_id=call_id,
            provider_type=provider_type,
            provider_name=provider_name,
        )

    def unmute_call(
        self,
        *,
        context: Union[CallContext, Dict[str, Any]],
        call_id: str,
        approval_id: str,
        provider_type: Union[str, CallProviderType] = CallProviderType.IN_MEMORY,
        provider_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Unmute an approved active call."""

        return self._execute_call_action(
            context=context,
            action=CallAction.UNMUTE,
            approval_id=approval_id,
            call_id=call_id,
            provider_type=provider_type,
            provider_name=provider_name,
        )

    def dial_call(
        self,
        *,
        context: Union[CallContext, Dict[str, Any]],
        phone_number: str,
        approval_id: str,
        display_name: Optional[str] = None,
        provider_type: Union[str, CallProviderType] = CallProviderType.IN_MEMORY,
        provider_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Dial an approved outbound call."""

        return self._execute_call_action(
            context=context,
            action=CallAction.DIAL,
            approval_id=approval_id,
            call_id=None,
            phone_number=phone_number,
            display_name=display_name,
            provider_type=provider_type,
            provider_name=provider_name,
        )

    def end_call(
        self,
        *,
        context: Union[CallContext, Dict[str, Any]],
        call_id: str,
        approval_id: str,
        provider_type: Union[str, CallProviderType] = CallProviderType.IN_MEMORY,
        provider_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """End an approved active call."""

        return self._execute_call_action(
            context=context,
            action=CallAction.END,
            approval_id=approval_id,
            call_id=call_id,
            provider_type=provider_type,
            provider_name=provider_name,
        )

    def list_calls(
        self,
        *,
        context: Union[CallContext, Dict[str, Any]],
        state: Optional[Union[str, CallState]] = None,
        direction: Optional[Union[str, CallDirection]] = None,
        provider: Optional[str] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """List stored calls for current user/workspace."""

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        ctx = ctx_result["data"]["context"]
        normalized_state = self._normalize_state(state) if state else None
        normalized_direction = self._normalize_direction(direction) if direction else None
        normalized_limit = min(max(1, int(limit)), 500)

        calls: List[Dict[str, Any]] = []

        for call in self._calls.values():
            if call.user_id != ctx.user_id:
                continue
            if call.workspace_id != ctx.workspace_id:
                continue
            if normalized_state and call.state != normalized_state:
                continue
            if normalized_direction and call.direction != normalized_direction:
                continue
            if provider and call.provider != provider:
                continue

            calls.append(self._public_call_dict(call))

        calls = calls[-normalized_limit:]

        return self._safe_result(
            message="Calls fetched successfully.",
            data={
                "calls": calls,
                "count": len(calls),
                "filters": {
                    "state": normalized_state,
                    "direction": normalized_direction,
                    "provider": provider,
                },
            },
            metadata={
                "request_id": ctx.request_id,
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
            },
        )

    def get_call(
        self,
        *,
        context: Union[CallContext, Dict[str, Any]],
        call_id: str,
    ) -> Dict[str, Any]:
        """Get one owned call."""

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        ctx = ctx_result["data"]["context"]
        call_result = self._get_owned_call(ctx, call_id)
        if not call_result["success"]:
            return call_result

        return self._safe_result(
            message="Call fetched successfully.",
            data={"call": self._public_call_dict(call_result["data"]["call"])},
            metadata={
                "request_id": ctx.request_id,
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
            },
        )

    def get_approval(
        self,
        *,
        context: Union[CallContext, Dict[str, Any]],
        approval_id: str,
    ) -> Dict[str, Any]:
        """Get one owned approval."""

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        ctx = ctx_result["data"]["context"]
        approval_result = self._get_owned_approval(ctx, approval_id)
        if not approval_result["success"]:
            return approval_result

        approval = approval_result["data"]["approval"]
        self._expire_approval_if_needed(approval)

        return self._safe_result(
            message="Approval fetched successfully.",
            data={"approval": asdict(approval)},
            metadata={
                "request_id": ctx.request_id,
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
            },
        )

    def list_pending_approvals(
        self,
        *,
        context: Union[CallContext, Dict[str, Any]],
        action: Optional[Union[str, CallAction]] = None,
        provider: Optional[str] = None,
    ) -> Dict[str, Any]:
        """List pending approvals for current user/workspace."""

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        ctx = ctx_result["data"]["context"]
        normalized_action = self._normalize_action(action) if action else None

        approvals: List[Dict[str, Any]] = []

        for approval in self._approvals.values():
            if approval.user_id != ctx.user_id:
                continue
            if approval.workspace_id != ctx.workspace_id:
                continue
            if approval.status != ApprovalStatus.PENDING.value:
                continue
            if normalized_action and approval.action != normalized_action:
                continue
            if provider and approval.provider != provider:
                continue

            self._expire_approval_if_needed(approval)

            if approval.status == ApprovalStatus.PENDING.value:
                approvals.append(asdict(approval))

        return self._safe_result(
            message="Pending approvals fetched successfully.",
            data={
                "approvals": approvals,
                "count": len(approvals),
                "filters": {
                    "action": normalized_action,
                    "provider": provider,
                },
            },
            metadata={
                "request_id": ctx.request_id,
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
            },
        )

    def get_audit_events(
        self,
        *,
        context: Union[CallContext, Dict[str, Any]],
        limit: int = 50,
    ) -> Dict[str, Any]:
        """Get audit events for current user/workspace."""

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        ctx = ctx_result["data"]["context"]
        normalized_limit = min(max(1, int(limit)), 500)

        events = [
            asdict(event)
            for event in self._audit_events
            if event.user_id == ctx.user_id and event.workspace_id == ctx.workspace_id
        ]

        events = events[-normalized_limit:]

        return self._safe_result(
            message="Audit events fetched successfully.",
            data={
                "events": events,
                "count": len(events),
            },
            metadata={
                "request_id": ctx.request_id,
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
            },
        )

    def get_task_history(
        self,
        *,
        context: Union[CallContext, Dict[str, Any]],
        limit: int = 50,
    ) -> Dict[str, Any]:
        """Get task history for current user/workspace."""

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        ctx = ctx_result["data"]["context"]
        normalized_limit = min(max(1, int(limit)), 500)

        history = [
            item
            for item in self._task_history
            if item.get("user_id") == ctx.user_id and item.get("workspace_id") == ctx.workspace_id
        ]

        history = history[-normalized_limit:]

        return self._safe_result(
            message="Task history fetched successfully.",
            data={
                "history": history,
                "count": len(history),
            },
            metadata={
                "request_id": ctx.request_id,
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
            },
        )

    # -----------------------------------------------------------------------
    # Required compatibility hooks
    # -----------------------------------------------------------------------

    def _validate_task_context(
        self,
        context: Union[CallContext, Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Validate user/workspace context.

        Required for SaaS isolation:
            - user_id
            - workspace_id
        """

        if isinstance(context, CallContext):
            ctx = context
        elif isinstance(context, dict):
            ctx = CallContext(
                user_id=_normalize_id(context.get("user_id")),
                workspace_id=_normalize_id(context.get("workspace_id")),
                actor_id=_normalize_id(context.get("actor_id")) or None,
                role=context.get("role"),
                subscription_plan=context.get("subscription_plan"),
                request_id=_normalize_id(context.get("request_id")) or str(uuid.uuid4()),
                source=context.get("source", "system_agent"),
                ip_address=context.get("ip_address"),
                user_agent=context.get("user_agent"),
                device_id=context.get("device_id"),
                metadata=context.get("metadata") or {},
            )
        else:
            return self._error_result(
                message="Invalid task context type.",
                error_code="INVALID_CONTEXT_TYPE",
            )

        if not _is_non_empty_string(ctx.user_id):
            return self._error_result(
                message="user_id is required for call operations.",
                error_code="MISSING_USER_ID",
            )

        if not _is_non_empty_string(ctx.workspace_id):
            return self._error_result(
                message="workspace_id is required for call operations.",
                error_code="MISSING_WORKSPACE_ID",
            )

        ctx.user_id = _normalize_id(ctx.user_id)
        ctx.workspace_id = _normalize_id(ctx.workspace_id)
        ctx.actor_id = _normalize_id(ctx.actor_id) or ctx.user_id
        ctx.request_id = _normalize_id(ctx.request_id) or str(uuid.uuid4())

        return self._safe_result(
            message="Task context validated successfully.",
            data={"context": ctx},
        )

    def _requires_security_check(
        self,
        *,
        action: Union[str, CallAction],
        call: Optional[CallRecord] = None,
    ) -> bool:
        """
        Determine whether Security Agent approval is required.

        All call-control actions are sensitive.
        """

        normalized_action = self._normalize_action(action)

        if normalized_action in self.SENSITIVE_ACTIONS:
            return True

        if call and call.risk_level in {
            CallRiskLevel.HIGH.value,
            CallRiskLevel.CRITICAL.value,
        }:
            return True

        if call and call.sensitivity in {
            SensitivityLevel.HIGH.value,
            SensitivityLevel.CRITICAL.value,
        }:
            return True

        return False

    def _request_security_approval(
        self,
        *,
        context: CallContext,
        action: Union[str, CallAction],
        call: CallRecord,
        reason: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Security Agent approval payload.

        If external callback exists, it is called.
        Otherwise, a safe pending approval payload is returned.
        """

        normalized_action = self._normalize_action(action)

        payload = {
            "approval_type": "call_action",
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "actor_id": context.actor_id,
            "request_id": context.request_id,
            "device_id": context.device_id,
            "action": normalized_action,
            "resource_type": "call",
            "resource_id": call.call_id,
            "provider": call.provider,
            "direction": call.direction,
            "state": call.state,
            "phone_number_masked": _mask_phone_number(call.phone_number),
            "display_name": call.display_name,
            "risk_level": call.risk_level,
            "sensitivity": call.sensitivity,
            "reason": reason,
            "metadata": metadata or {},
            "created_at": _utc_now(),
        }

        if self.security_approval_callback:
            try:
                response = self.security_approval_callback(payload)

                if not isinstance(response, dict):
                    return self._error_result(
                        message="Security approval callback returned invalid response.",
                        error_code="INVALID_SECURITY_CALLBACK_RESPONSE",
                    )

                if response.get("success") is False:
                    return self._error_result(
                        message=response.get("message", "Security approval rejected."),
                        error_code=response.get("error_code", "SECURITY_APPROVAL_FAILED"),
                        data=response,
                    )

                return self._safe_result(
                    message="Security approval payload processed successfully.",
                    data={
                        "approval_required": True,
                        "status": response.get("status", ApprovalStatus.PENDING.value),
                        "security_response": response,
                        "security_payload": payload,
                    },
                )

            except Exception as exc:
                self.logger.exception("Security approval callback failed.")
                return self._error_result(
                    message="Security approval callback failed.",
                    error_code="SECURITY_CALLBACK_FAILED",
                    error=str(exc),
                    data={"security_payload": payload},
                )

        return self._safe_result(
            message="Security approval required.",
            data={
                "approval_required": True,
                "status": ApprovalStatus.PENDING.value,
                "security_payload": payload,
            },
        )

    def _prepare_verification_payload(
        self,
        *,
        context: CallContext,
        action: str,
        success: bool,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        Verification Agent can confirm call action status, approval state,
        provider result, and user/workspace scope.
        """

        return {
            "verification_type": "call_action",
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "actor_id": context.actor_id,
            "request_id": context.request_id,
            "device_id": context.device_id,
            "action": action,
            "success": bool(success),
            "message": message,
            "data": data or {},
            "error": error,
            "created_at": _utc_now(),
        }

    def _prepare_memory_payload(
        self,
        *,
        context: CallContext,
        action: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent-compatible payload.

        Uses masked phone numbers only by default.
        """

        return {
            "memory_type": "call_context",
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "actor_id": context.actor_id,
            "request_id": context.request_id,
            "device_id": context.device_id,
            "action": action,
            "data": data or {},
            "safe_to_store": True,
            "contains_full_phone_number": False,
            "created_at": _utc_now(),
        }

    def _emit_agent_event(
        self,
        *,
        event_type: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Emit event for Master Agent, dashboard, WebSocket stream, or registry.
        """

        event = {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "payload": payload or {},
            "created_at": _utc_now(),
        }

        if self.event_callback:
            try:
                self.event_callback(event)
            except Exception:
                self.logger.exception("Event callback failed.")

        try:
            emit_event = getattr(super(), "emit_event", None)
            if callable(emit_event):
                emit_event(event_type, event)
        except Exception:
            pass

    def _log_audit_event(
        self,
        *,
        context: CallContext,
        action: str,
        success: bool,
        message: str,
        provider: Optional[str] = None,
        call_id: Optional[str] = None,
        approval_id: Optional[str] = None,
        phone_number: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Store audit event.

        Phone numbers are masked in audit events.
        """

        event = CallAuditEvent(
            event_id=f"audit_{uuid.uuid4().hex}",
            user_id=context.user_id,
            workspace_id=context.workspace_id,
            action=action,
            success=bool(success),
            message=message,
            request_id=context.request_id,
            actor_id=context.actor_id,
            provider=provider,
            call_id=call_id,
            approval_id=approval_id,
            phone_number_masked=_mask_phone_number(phone_number),
            metadata=metadata or {},
        )

        self._audit_events.append(event)

        event_dict = asdict(event)

        if self.audit_callback:
            try:
                self.audit_callback(event_dict)
            except Exception:
                self.logger.exception("Audit callback failed.")

        return event_dict

    def _safe_result(
        self,
        *,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Standard success response."""

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
        error_code: str = "ERROR",
        error: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Standard error response."""

        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": {
                "code": error_code,
                "detail": error or message,
            },
            "metadata": metadata or {},
        }

    # -----------------------------------------------------------------------
    # Internal execution helpers
    # -----------------------------------------------------------------------

    def _execute_call_action(
        self,
        *,
        context: Union[CallContext, Dict[str, Any]],
        action: Union[str, CallAction],
        approval_id: str,
        call_id: Optional[str] = None,
        phone_number: Optional[str] = None,
        display_name: Optional[str] = None,
        provider_type: Union[str, CallProviderType] = CallProviderType.IN_MEMORY,
        provider_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Execute approved sensitive call action."""

        started_at = time.time()

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        ctx = ctx_result["data"]["context"]
        normalized_action = self._normalize_action(action)
        normalized_provider_type = self._normalize_provider_type(provider_type)

        if normalized_action not in self.SENSITIVE_ACTIONS:
            return self._error_result(
                message=f"Unsupported call action '{normalized_action}'.",
                error_code="UNSUPPORTED_CALL_ACTION",
                data={"action": normalized_action},
            )

        approval_result = self._get_owned_approval(ctx, approval_id)
        if not approval_result["success"]:
            return approval_result

        approval = approval_result["data"]["approval"]

        approval_check = self._ensure_approval_is_valid(approval, expected_action=normalized_action)
        if not approval_check["success"]:
            self._log_audit_event(
                context=ctx,
                action=normalized_action,
                success=False,
                message=approval_check["message"],
                provider=approval.provider,
                call_id=call_id or approval.call_id,
                approval_id=approval_id,
                phone_number=phone_number or approval.phone_number,
            )
            return approval_check

        provider_result = self._resolve_provider(normalized_provider_type, provider_name or approval.provider)
        if not provider_result["success"]:
            return provider_result

        provider = provider_result["data"]["provider"]
        provider_key = provider_result["data"]["provider_name"]

        target_call: Optional[CallRecord] = None
        normalized_phone: Optional[str] = None

        if normalized_action == CallAction.DIAL.value:
            normalized_phone = _normalize_phone_number(phone_number or approval.phone_number or "")
            phone_result = self._validate_phone_number(normalized_phone)
            if not phone_result["success"]:
                return phone_result
        else:
            target_call_id = call_id or approval.call_id
            call_result = self._get_owned_call(ctx, target_call_id)
            if not call_result["success"]:
                return call_result
            target_call = call_result["data"]["call"]
            normalized_phone = target_call.phone_number

            if approval.call_id and target_call.call_id != approval.call_id:
                return self._error_result(
                    message="Approval request does not match this call.",
                    error_code="APPROVAL_CALL_MISMATCH",
                    data={
                        "approval_id": approval_id,
                        "approval_call_id": approval.call_id,
                        "requested_call_id": target_call.call_id,
                    },
                )

        try:
            provider_response: Dict[str, Any]

            if normalized_action == CallAction.ANSWER.value:
                provider_response = provider.answer_call(
                    user_id=ctx.user_id,
                    workspace_id=ctx.workspace_id,
                    call_id=target_call.call_id if target_call else "",
                    metadata={"approval_id": approval_id, "request_id": ctx.request_id},
                )
            elif normalized_action == CallAction.REJECT.value:
                provider_response = provider.reject_call(
                    user_id=ctx.user_id,
                    workspace_id=ctx.workspace_id,
                    call_id=target_call.call_id if target_call else "",
                    metadata={"approval_id": approval_id, "request_id": ctx.request_id},
                )
            elif normalized_action == CallAction.MUTE.value:
                provider_response = provider.mute_call(
                    user_id=ctx.user_id,
                    workspace_id=ctx.workspace_id,
                    call_id=target_call.call_id if target_call else "",
                    muted=True,
                    metadata={"approval_id": approval_id, "request_id": ctx.request_id},
                )
            elif normalized_action == CallAction.UNMUTE.value:
                provider_response = provider.mute_call(
                    user_id=ctx.user_id,
                    workspace_id=ctx.workspace_id,
                    call_id=target_call.call_id if target_call else "",
                    muted=False,
                    metadata={"approval_id": approval_id, "request_id": ctx.request_id},
                )
            elif normalized_action == CallAction.DIAL.value:
                provider_response = provider.dial_call(
                    user_id=ctx.user_id,
                    workspace_id=ctx.workspace_id,
                    phone_number=normalized_phone or "",
                    display_name=display_name or approval.display_name,
                    metadata={"approval_id": approval_id, "request_id": ctx.request_id},
                )
            elif normalized_action == CallAction.END.value:
                provider_response = provider.end_call(
                    user_id=ctx.user_id,
                    workspace_id=ctx.workspace_id,
                    call_id=target_call.call_id if target_call else "",
                    metadata={"approval_id": approval_id, "request_id": ctx.request_id},
                )
            else:
                return self._error_result(
                    message=f"Unsupported action '{normalized_action}'.",
                    error_code="UNSUPPORTED_CALL_ACTION",
                )

            if not provider_response.get("success", False):
                return self._error_result(
                    message=provider_response.get("message", "Provider failed to execute call action."),
                    error_code=provider_response.get("error_code", "PROVIDER_CALL_ACTION_FAILED"),
                    data={
                        "provider": provider_key,
                        "provider_response": provider_response,
                    },
                )

            raw_call = provider_response.get("data") or {}

            if normalized_action == CallAction.DIAL.value:
                updated_call = self._call_record_from_provider(raw_call, ctx=ctx, provider=provider_key)
            else:
                updated_call = self._merge_provider_call_update(
                    target_call,
                    raw_call,
                    provider=provider_key,
                )

            self._calls[updated_call.call_id] = updated_call

            verification_payload = self._prepare_verification_payload(
                context=ctx,
                action=normalized_action,
                success=True,
                message=f"Call action '{normalized_action}' completed successfully.",
                data={
                    "call_id": updated_call.call_id,
                    "approval_id": approval_id,
                    "provider": provider_key,
                    "state": updated_call.state,
                    "phone_number_masked": _mask_phone_number(updated_call.phone_number),
                },
            )

            memory_payload = self._prepare_memory_payload(
                context=ctx,
                action=normalized_action,
                data={
                    "call_id": updated_call.call_id,
                    "approval_id": approval_id,
                    "provider": provider_key,
                    "state": updated_call.state,
                    "phone_number_masked": _mask_phone_number(updated_call.phone_number),
                    "display_name": updated_call.display_name,
                },
            )

            self._log_audit_event(
                context=ctx,
                action=normalized_action,
                success=True,
                message=f"Call action '{normalized_action}' completed successfully.",
                provider=provider_key,
                call_id=updated_call.call_id,
                approval_id=approval_id,
                phone_number=updated_call.phone_number,
                metadata={
                    "provider_response": self._safe_provider_response_summary(provider_response),
                    "duration_ms": int((time.time() - started_at) * 1000),
                },
            )

            self._emit_agent_event(
                event_type=f"call.{normalized_action}",
                payload={
                    "user_id": ctx.user_id,
                    "workspace_id": ctx.workspace_id,
                    "call_id": updated_call.call_id,
                    "approval_id": approval_id,
                    "provider": provider_key,
                    "state": updated_call.state,
                },
            )

            self._record_task_history(
                context=ctx,
                action=normalized_action,
                success=True,
                data={
                    "call_id": updated_call.call_id,
                    "approval_id": approval_id,
                    "provider": provider_key,
                    "state": updated_call.state,
                },
            )

            return self._safe_result(
                message=f"Call action '{normalized_action}' completed successfully.",
                data={
                    "call": self._public_call_dict(updated_call),
                    "provider_response": provider_response,
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                metadata={
                    "request_id": ctx.request_id,
                    "user_id": ctx.user_id,
                    "workspace_id": ctx.workspace_id,
                    "duration_ms": int((time.time() - started_at) * 1000),
                },
            )

        except Exception as exc:
            self.logger.exception("Failed to execute call action.")

            self._log_audit_event(
                context=ctx,
                action=normalized_action,
                success=False,
                message="Failed to execute call action.",
                provider=provider_key,
                call_id=call_id or approval.call_id,
                approval_id=approval_id,
                phone_number=normalized_phone,
                metadata={"error": str(exc)},
            )

            return self._error_result(
                message="Failed to execute call action.",
                error_code="CALL_ACTION_FAILED",
                error=str(exc),
                data={
                    "action": normalized_action,
                    "approval_id": approval_id,
                    "call_id": call_id or approval.call_id,
                    "provider": provider_key,
                },
                metadata={
                    "request_id": ctx.request_id,
                    "user_id": ctx.user_id,
                    "workspace_id": ctx.workspace_id,
                },
            )

    def _set_approval_status(
        self,
        *,
        context: Union[CallContext, Dict[str, Any]],
        approval_id: str,
        status: ApprovalStatus,
        actor: Optional[str] = None,
        note: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Approve or deny a pending approval."""

        action = (
            CallAction.APPROVE_ACTION.value
            if status == ApprovalStatus.APPROVED
            else CallAction.DENY_ACTION.value
        )

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        ctx = ctx_result["data"]["context"]

        approval_result = self._get_owned_approval(ctx, approval_id)
        if not approval_result["success"]:
            return approval_result

        approval = approval_result["data"]["approval"]
        self._expire_approval_if_needed(approval)

        if approval.status == ApprovalStatus.EXPIRED.value:
            return self._error_result(
                message="Approval request has expired.",
                error_code="APPROVAL_EXPIRED",
                data={"approval_id": approval_id},
            )

        if approval.status != ApprovalStatus.PENDING.value:
            return self._error_result(
                message=f"Approval request is already '{approval.status}'.",
                error_code="APPROVAL_NOT_PENDING",
                data={
                    "approval_id": approval_id,
                    "status": approval.status,
                },
            )

        approval.status = status.value
        approval.updated_at = _utc_now()
        approval.metadata["note"] = note

        if status == ApprovalStatus.APPROVED:
            approval.approved_by = actor or ctx.actor_id or ctx.user_id
            result_message = "Call action approved successfully."
            event_type = "call.action_approved"
        else:
            approval.denied_by = actor or ctx.actor_id or ctx.user_id
            result_message = "Call action denied successfully."
            event_type = "call.action_denied"

        self._approvals[approval.approval_id] = approval

        verification_payload = self._prepare_verification_payload(
            context=ctx,
            action=action,
            success=True,
            message=result_message,
            data={
                "approval_id": approval.approval_id,
                "requested_action": approval.action,
                "status": approval.status,
                "note": note,
            },
        )

        memory_payload = self._prepare_memory_payload(
            context=ctx,
            action=action,
            data={
                "approval_id": approval.approval_id,
                "requested_action": approval.action,
                "status": approval.status,
                "note": note,
                "phone_number_masked": _mask_phone_number(approval.phone_number),
            },
        )

        self._log_audit_event(
            context=ctx,
            action=action,
            success=True,
            message=result_message,
            provider=approval.provider,
            call_id=approval.call_id,
            approval_id=approval.approval_id,
            phone_number=approval.phone_number,
            metadata={
                "status": approval.status,
                "actor": actor or ctx.actor_id or ctx.user_id,
                "note": note,
            },
        )

        self._emit_agent_event(
            event_type=event_type,
            payload={
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
                "approval_id": approval.approval_id,
                "requested_action": approval.action,
                "status": approval.status,
            },
        )

        self._record_task_history(
            context=ctx,
            action=action,
            success=True,
            data={
                "approval_id": approval.approval_id,
                "requested_action": approval.action,
                "status": approval.status,
            },
        )

        return self._safe_result(
            message=result_message,
            data={
                "approval": asdict(approval),
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                "request_id": ctx.request_id,
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
            },
        )

    def _ensure_approval_is_valid(
        self,
        approval: CallApprovalRequest,
        *,
        expected_action: str,
    ) -> Dict[str, Any]:
        """Validate approval before executing sensitive action."""

        self._expire_approval_if_needed(approval)

        if approval.status == ApprovalStatus.EXPIRED.value:
            return self._error_result(
                message="Approval request has expired.",
                error_code="APPROVAL_EXPIRED",
                data={"approval_id": approval.approval_id},
            )

        if approval.status == ApprovalStatus.DENIED.value:
            return self._error_result(
                message="Approval request was denied.",
                error_code="APPROVAL_DENIED",
                data={"approval_id": approval.approval_id},
            )

        if approval.status != ApprovalStatus.APPROVED.value:
            return self._error_result(
                message="Call action cannot execute without approved approval request.",
                error_code="APPROVAL_REQUIRED",
                data={
                    "approval_id": approval.approval_id,
                    "status": approval.status,
                },
            )

        if approval.action != expected_action:
            return self._error_result(
                message="Approval action does not match requested action.",
                error_code="APPROVAL_ACTION_MISMATCH",
                data={
                    "approval_id": approval.approval_id,
                    "approval_action": approval.action,
                    "expected_action": expected_action,
                },
            )

        return self._safe_result(
            message="Approval is valid.",
            data={"approval_id": approval.approval_id},
        )

    def _expire_approval_if_needed(self, approval: CallApprovalRequest) -> None:
        """Expire approval if its TTL passed."""

        if approval.status != ApprovalStatus.PENDING.value:
            return

        if not approval.expires_at:
            return

        try:
            expires_at = datetime.fromisoformat(approval.expires_at)
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)

            now = datetime.now(timezone.utc)
            if now > expires_at:
                approval.status = ApprovalStatus.EXPIRED.value
                approval.updated_at = _utc_now()
                self._approvals[approval.approval_id] = approval
        except Exception:
            self.logger.exception("Failed to evaluate approval expiry.")

    # -----------------------------------------------------------------------
    # Internal object helpers
    # -----------------------------------------------------------------------

    def _call_record_from_provider(
        self,
        raw: Dict[str, Any],
        *,
        ctx: CallContext,
        provider: str,
    ) -> CallRecord:
        """Create CallRecord from provider response."""

        call_id = str(raw.get("call_id") or raw.get("id") or f"call_{uuid.uuid4().hex}")
        started_at = raw.get("started_at")
        ended_at = raw.get("ended_at")

        return CallRecord(
            call_id=call_id,
            user_id=ctx.user_id,
            workspace_id=ctx.workspace_id,
            provider=str(raw.get("provider") or provider),
            direction=self._normalize_direction(raw.get("direction") or CallDirection.UNKNOWN.value),
            state=self._normalize_state(raw.get("state") or CallState.UNKNOWN.value),
            phone_number=_normalize_phone_number(raw.get("phone_number")) if raw.get("phone_number") else None,
            display_name=raw.get("display_name"),
            started_at=started_at,
            ended_at=ended_at,
            duration_seconds=(
                _safe_int(raw.get("duration_seconds"))
                if raw.get("duration_seconds") is not None
                else _calculate_duration_seconds(started_at, ended_at)
            ),
            muted=bool(raw.get("muted", False)),
            answered=bool(raw.get("answered", False)),
            rejected=bool(raw.get("rejected", False)),
            missed=bool(raw.get("missed", False)),
            provider_call_id=raw.get("provider_call_id"),
            sensitivity=self._normalize_sensitivity(raw.get("sensitivity") or SensitivityLevel.MEDIUM.value),
            risk_level=self._normalize_risk_level(raw.get("risk_level") or CallRiskLevel.MEDIUM.value),
            created_at=str(raw.get("created_at") or _utc_now()),
            updated_at=str(raw.get("updated_at") or _utc_now()),
            metadata=raw.get("metadata") or {},
        )

    def _merge_provider_call_update(
        self,
        existing: Optional[CallRecord],
        raw: Dict[str, Any],
        *,
        provider: str,
    ) -> CallRecord:
        """Merge provider response into existing CallRecord."""

        if existing is None:
            fallback_ctx = CallContext(
                user_id=str(raw.get("user_id") or ""),
                workspace_id=str(raw.get("workspace_id") or ""),
            )
            return self._call_record_from_provider(raw, ctx=fallback_ctx, provider=provider)

        updated = copy.deepcopy(existing)

        updated.provider = str(raw.get("provider") or provider or updated.provider)
        updated.direction = self._normalize_direction(raw.get("direction") or updated.direction)
        updated.state = self._normalize_state(raw.get("state") or updated.state)
        updated.phone_number = (
            _normalize_phone_number(raw.get("phone_number"))
            if raw.get("phone_number")
            else updated.phone_number
        )
        updated.display_name = raw.get("display_name", updated.display_name)
        updated.started_at = raw.get("started_at", updated.started_at)
        updated.ended_at = raw.get("ended_at", updated.ended_at)
        updated.duration_seconds = (
            _safe_int(raw.get("duration_seconds"))
            if raw.get("duration_seconds") is not None
            else _calculate_duration_seconds(updated.started_at, updated.ended_at)
        )
        updated.muted = bool(raw.get("muted", updated.muted))
        updated.answered = bool(raw.get("answered", updated.answered))
        updated.rejected = bool(raw.get("rejected", updated.rejected))
        updated.missed = bool(raw.get("missed", updated.missed))
        updated.provider_call_id = raw.get("provider_call_id", updated.provider_call_id)
        updated.sensitivity = self._normalize_sensitivity(raw.get("sensitivity") or updated.sensitivity)
        updated.risk_level = self._normalize_risk_level(raw.get("risk_level") or updated.risk_level)
        updated.updated_at = str(raw.get("updated_at") or _utc_now())
        updated.metadata = {
            **(updated.metadata or {}),
            **(raw.get("metadata") or {}),
        }

        return updated

    def _get_owned_call(
        self,
        ctx: CallContext,
        call_id: Optional[str],
    ) -> Dict[str, Any]:
        """Get call and enforce user/workspace ownership."""

        if not _is_non_empty_string(call_id):
            return self._error_result(
                message="call_id is required.",
                error_code="MISSING_CALL_ID",
            )

        call = self._calls.get(str(call_id))
        if not call:
            return self._error_result(
                message="Call not found.",
                error_code="CALL_NOT_FOUND",
                data={"call_id": call_id},
            )

        if call.user_id != ctx.user_id or call.workspace_id != ctx.workspace_id:
            return self._error_result(
                message="Call does not belong to this user/workspace.",
                error_code="CALL_ACCESS_DENIED",
                data={"call_id": call_id},
            )

        return self._safe_result(
            message="Call fetched successfully.",
            data={"call": call},
        )

    def _get_owned_approval(
        self,
        ctx: CallContext,
        approval_id: str,
    ) -> Dict[str, Any]:
        """Get approval and enforce user/workspace ownership."""

        if not _is_non_empty_string(approval_id):
            return self._error_result(
                message="approval_id is required.",
                error_code="MISSING_APPROVAL_ID",
            )

        approval = self._approvals.get(approval_id)
        if not approval:
            return self._error_result(
                message="Approval request not found.",
                error_code="APPROVAL_NOT_FOUND",
                data={"approval_id": approval_id},
            )

        if approval.user_id != ctx.user_id or approval.workspace_id != ctx.workspace_id:
            return self._error_result(
                message="Approval request does not belong to this user/workspace.",
                error_code="APPROVAL_ACCESS_DENIED",
                data={"approval_id": approval_id},
            )

        return self._safe_result(
            message="Approval fetched successfully.",
            data={"approval": approval},
        )

    def _public_call_dict(self, call: CallRecord) -> Dict[str, Any]:
        """Return public call dictionary."""

        return {
            "call_id": call.call_id,
            "user_id": call.user_id,
            "workspace_id": call.workspace_id,
            "provider": call.provider,
            "direction": call.direction,
            "state": call.state,
            "phone_number": call.phone_number,
            "phone_number_masked": _mask_phone_number(call.phone_number),
            "display_name": call.display_name,
            "started_at": call.started_at,
            "ended_at": call.ended_at,
            "duration_seconds": call.duration_seconds,
            "muted": call.muted,
            "answered": call.answered,
            "rejected": call.rejected,
            "missed": call.missed,
            "provider_call_id": call.provider_call_id,
            "sensitivity": call.sensitivity,
            "risk_level": call.risk_level,
            "created_at": call.created_at,
            "updated_at": call.updated_at,
            "metadata": _safe_copy(call.metadata),
        }

    def _validate_phone_number(self, phone_number: str) -> Dict[str, Any]:
        """Validate normalized phone number."""

        normalized = _normalize_phone_number(phone_number)
        digits = re.sub(r"\D+", "", normalized)

        if len(digits) < self.MIN_PHONE_DIGITS:
            return self._error_result(
                message="Phone number is too short.",
                error_code="PHONE_NUMBER_TOO_SHORT",
                data={
                    "min_digits": self.MIN_PHONE_DIGITS,
                    "actual_digits": len(digits),
                },
            )

        if len(digits) > self.MAX_PHONE_DIGITS:
            return self._error_result(
                message="Phone number is too long.",
                error_code="PHONE_NUMBER_TOO_LONG",
                data={
                    "max_digits": self.MAX_PHONE_DIGITS,
                    "actual_digits": len(digits),
                },
            )

        return self._safe_result(
            message="Phone number validated successfully.",
            data={
                "phone_number": normalized,
                "phone_number_masked": _mask_phone_number(normalized),
            },
        )

    def _resolve_provider(
        self,
        provider_type: str,
        provider_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Resolve provider."""

        selected_name: Optional[str] = None

        if provider_name:
            selected_name = str(provider_name).strip()
        elif provider_type in self.provider_type_map:
            selected_name = self.provider_type_map[provider_type]
        elif self.default_provider_name in self.providers:
            selected_name = self.default_provider_name

        if not selected_name:
            return self._error_result(
                message=f"No provider configured for provider type '{provider_type}'.",
                error_code="NO_PROVIDER_CONFIGURED",
                data={"provider_type": provider_type},
            )

        provider = self.providers.get(selected_name)
        if not provider:
            return self._error_result(
                message=f"Provider '{selected_name}' is not registered.",
                error_code="PROVIDER_NOT_REGISTERED",
                data={
                    "provider_type": provider_type,
                    "provider_name": selected_name,
                },
            )

        if self.strict_provider_mode and selected_name == self.default_provider_name:
            return self._error_result(
                message=(
                    f"Strict provider mode is enabled. Configure a real approved "
                    f"provider for provider type '{provider_type}'."
                ),
                error_code="STRICT_PROVIDER_REQUIRED",
                data={
                    "provider_type": provider_type,
                    "provider_name": selected_name,
                },
            )

        return self._safe_result(
            message="Provider resolved successfully.",
            data={
                "provider": provider,
                "provider_name": selected_name,
                "provider_type": provider_type,
            },
        )

    def _record_task_history(
        self,
        *,
        context: CallContext,
        action: str,
        success: bool,
        data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Record task history."""

        self._task_history.append(
            {
                "task_id": f"task_{uuid.uuid4().hex}",
                "agent_id": self.agent_id,
                "agent_name": self.agent_name,
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
                "actor_id": context.actor_id,
                "request_id": context.request_id,
                "device_id": context.device_id,
                "action": action,
                "success": bool(success),
                "data": data or {},
                "created_at": _utc_now(),
            }
        )

    # -----------------------------------------------------------------------
    # Normalization helpers
    # -----------------------------------------------------------------------

    def _normalize_provider_type(
        self,
        provider_type: Union[str, CallProviderType],
    ) -> str:
        """Normalize provider type."""

        if isinstance(provider_type, CallProviderType):
            return provider_type.value

        raw = str(provider_type or "").strip().lower()
        if not raw:
            return CallProviderType.IN_MEMORY.value

        aliases = {
            "memory": CallProviderType.IN_MEMORY.value,
            "inmemory": CallProviderType.IN_MEMORY.value,
            "in_memory": CallProviderType.IN_MEMORY.value,
            "android": CallProviderType.ANDROID.value,
            "ios": CallProviderType.IOS.value,
            "desktop": CallProviderType.DESKTOP.value,
            "voip": CallProviderType.VOIP.value,
            "twilio": CallProviderType.TWILIO.value,
            "sip": CallProviderType.SIP.value,
            "whatsapp": CallProviderType.WHATSAPP.value,
            "slack": CallProviderType.SLACK.value,
            "teams": CallProviderType.TEAMS.value,
            "internal": CallProviderType.INTERNAL.value,
        }

        return aliases.get(raw, raw)

    def _normalize_direction(
        self,
        direction: Union[str, CallDirection],
    ) -> str:
        """Normalize call direction."""

        if isinstance(direction, CallDirection):
            return direction.value

        raw = str(direction or "").strip().lower()

        if raw in {"in", "incoming", "inbound"}:
            return CallDirection.INBOUND.value

        if raw in {"out", "outgoing", "outbound"}:
            return CallDirection.OUTBOUND.value

        return CallDirection.UNKNOWN.value

    def _normalize_state(
        self,
        state: Union[str, CallState],
    ) -> str:
        """Normalize call state."""

        if isinstance(state, CallState):
            return state.value

        raw = str(state or "").strip().lower()

        aliases = {
            "idle": CallState.IDLE.value,
            "ring": CallState.RINGING.value,
            "ringing": CallState.RINGING.value,
            "dial": CallState.DIALING.value,
            "dialing": CallState.DIALING.value,
            "connecting": CallState.CONNECTING.value,
            "active": CallState.ACTIVE.value,
            "hold": CallState.ON_HOLD.value,
            "on_hold": CallState.ON_HOLD.value,
            "muted": CallState.MUTED.value,
            "ended": CallState.ENDED.value,
            "end": CallState.ENDED.value,
            "missed": CallState.MISSED.value,
            "rejected": CallState.REJECTED.value,
            "failed": CallState.FAILED.value,
            "blocked": CallState.BLOCKED.value,
        }

        return aliases.get(raw, CallState.UNKNOWN.value)

    def _normalize_action(
        self,
        action: Union[str, CallAction, None],
    ) -> str:
        """Normalize call action."""

        if isinstance(action, CallAction):
            return action.value

        raw = str(action or "").strip().lower()

        aliases = {
            "detect": CallAction.DETECT.value,
            "log": CallAction.LOG.value,
            "list": CallAction.LIST_CALLS.value,
            "list_calls": CallAction.LIST_CALLS.value,
            "get": CallAction.GET_CALL.value,
            "get_call": CallAction.GET_CALL.value,
            "request": CallAction.REQUEST_APPROVAL.value,
            "request_approval": CallAction.REQUEST_APPROVAL.value,
            "approve": CallAction.APPROVE_ACTION.value,
            "approve_action": CallAction.APPROVE_ACTION.value,
            "deny": CallAction.DENY_ACTION.value,
            "deny_action": CallAction.DENY_ACTION.value,
            "answer": CallAction.ANSWER.value,
            "reject": CallAction.REJECT.value,
            "mute": CallAction.MUTE.value,
            "unmute": CallAction.UNMUTE.value,
            "dial": CallAction.DIAL.value,
            "call": CallAction.DIAL.value,
            "end": CallAction.END.value,
            "hangup": CallAction.END.value,
            "hang_up": CallAction.END.value,
        }

        return aliases.get(raw, raw)

    def _normalize_sensitivity(
        self,
        sensitivity: Union[str, SensitivityLevel],
    ) -> str:
        """Normalize sensitivity."""

        if isinstance(sensitivity, SensitivityLevel):
            return sensitivity.value

        raw = str(sensitivity or SensitivityLevel.MEDIUM.value).strip().lower()
        valid = {item.value for item in SensitivityLevel}
        return raw if raw in valid else SensitivityLevel.MEDIUM.value

    def _normalize_risk_level(
        self,
        risk_level: Union[str, CallRiskLevel],
    ) -> str:
        """Normalize risk level."""

        if isinstance(risk_level, CallRiskLevel):
            return risk_level.value

        raw = str(risk_level or CallRiskLevel.MEDIUM.value).strip().lower()
        valid = {item.value for item in CallRiskLevel}
        return raw if raw in valid else CallRiskLevel.MEDIUM.value

    def _sanitize_filters(
        self,
        filters: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Sanitize filter values for audit logs."""

        if not filters:
            return {}

        safe: Dict[str, Any] = {}

        for key, value in filters.items():
            key_lower = str(key).lower()
            if key_lower in {"phone", "phone_number", "number"}:
                safe[key] = _mask_phone_number(str(value))
            elif key_lower in {"password", "token", "secret", "api_key"}:
                safe[key] = "***redacted***"
            else:
                safe[key] = _truncate_text(str(value), 120)

        return safe

    def _safe_provider_response_summary(
        self,
        response: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Return safe provider response summary for audit."""

        return {
            "success": bool(response.get("success")),
            "message": response.get("message"),
            "provider": response.get("provider"),
            "provider_call_id": response.get("provider_call_id"),
        }


# ---------------------------------------------------------------------------
# Module-level factory
# ---------------------------------------------------------------------------

def build_call_controller(**kwargs: Any) -> CallController:
    """
    Factory for Agent Loader / Registry.

    Example:
        controller = build_call_controller()
    """

    return CallController(**kwargs)


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    controller = CallController()

    test_context = {
        "user_id": "user_demo_1",
        "workspace_id": "workspace_demo_1",
        "actor_id": "admin_demo_1",
        "role": "owner",
        "device_id": "device_demo_1",
    }

    log_result = controller.log_call(
        context=test_context,
        provider="in_memory",
        direction="inbound",
        state="ringing",
        phone_number="+1 555 123 4567",
        display_name="Demo Caller",
    )

    print("LOG:", log_result)

    if log_result["success"]:
        call_id = log_result["data"]["call"]["call_id"]

        approval = controller.request_action_approval(
            context=test_context,
            action="answer",
            call_id=call_id,
            provider_type="in_memory",
            reason="User approved answering this demo inbound call.",
        )

        print("APPROVAL REQUEST:", approval)

        if approval["success"]:
            approved = controller.approve_action(
                context=test_context,
                approval_id=approval["data"]["approval"]["approval_id"],
                approved_by="admin_demo_1",
                note="Approved in local smoke test.",
            )

            print("APPROVED:", approved)

            answered = controller.answer_call(
                context=test_context,
                call_id=call_id,
                approval_id=approval["data"]["approval"]["approval_id"],
                provider_type="in_memory",
            )

            print("ANSWERED:", answered)

    dial_approval = controller.request_action_approval(
        context=test_context,
        action="dial",
        phone_number="+1 555 888 9999",
        display_name="Outbound Demo",
        provider_type="in_memory",
        reason="User approved outbound demo call.",
    )

    print("DIAL APPROVAL:", dial_approval)

    if dial_approval["success"]:
        dial_approved = controller.approve_action(
            context=test_context,
            approval_id=dial_approval["data"]["approval"]["approval_id"],
            approved_by="admin_demo_1",
            note="Outbound call approved in local smoke test.",
        )

        print("DIAL APPROVED:", dial_approved)

        dialed = controller.dial_call(
            context=test_context,
            phone_number="+1 555 888 9999",
            display_name="Outbound Demo",
            approval_id=dial_approval["data"]["approval"]["approval_id"],
            provider_type="in_memory",
        )

        print("DIALED:", dialed)


"""
Agent/Module: System Agent
File Completed: call_controller.py
Completion: 52.9%
Completed Files: ['system_agent.py', 'app_controller.py', 'file_manager.py', 'os_commands.py', 'device_controls.py', 'automation.py', 'notification_reader.py', 'message_controller.py', 'call_controller.py']
Remaining Files: ['permission_guard.py', 'app_profiles.py', 'device_sync.py', 'gesture_control.py', 'desktop_vision.py', 'task_recorder.py', 'system_memory.py', 'config.py']
Next Recommended File: agents/system_agent/permission_guard.py
FILE COMPLETE
"""