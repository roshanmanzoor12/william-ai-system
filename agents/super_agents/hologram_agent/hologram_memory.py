"""
agents/super_agents/hologram_agent/hologram_memory.py

Purpose:
    Stores AR layout preferences, safe zones, recurring overlays, and hologram UI
    memory for the William / Jarvis Hologram Agent.

Project:
    William / Jarvis Multi-Agent AI SaaS System by Digital Promotix.

Architecture:
    This module is designed for the Hologram Agent and supports:
        - SaaS-safe user_id/workspace_id isolation.
        - AR layout preference storage.
        - Safe zone storage and validation.
        - Recurring overlay storage.
        - Device/context-aware hologram layout memory.
        - Import-safe fallback BaseAgent compatibility.
        - Security Agent approval hooks.
        - Verification Agent payload hooks.
        - Memory Agent payload hooks.
        - Audit/dashboard event hooks.
        - Master Agent / Agent Registry manifest compatibility.

Where to place:
    agents/super_agents/hologram_agent/hologram_memory.py

Required dependencies:
    Python standard library only.

Optional future integrations:
    - Redis
    - PostgreSQL
    - Vector memory store
    - Cloud object storage
    - User preference service
    - AR device SDK bridge

How to test:
    python -m py_compile agents/super_agents/hologram_agent/hologram_memory.py

Example:
    from agents.super_agents.hologram_agent.hologram_memory import HologramMemory

    memory = HologramMemory()
    context = {"user_id": "user_1", "workspace_id": "workspace_1"}

    result = memory.save_layout_preference(
        context=context,
        layout_name="default_dashboard",
        preferences={
            "anchor": "front_center",
            "opacity": 0.92,
            "scale": 1.0,
            "theme": "dark"
        }
    )
    print(result)

Agent/Module: Hologram Agent
File Completed: hologram_memory.py
Completion: 90.9%
Completed Files: ['hologram_agent.py', 'ar_overlay.py', 'spatial_mapper.py', 'gesture_bridge.py', 'real_world_context.py', 'object_recognizer.py', 'navigation_overlay.py', 'notification_overlay.py', 'device_bridge.py', 'hologram_memory.py']
Remaining Files: ['config.py']
Next Recommended File: agents/super_agents/hologram_agent/config.py

FILE COMPLETE
"""

from __future__ import annotations

import copy
import json
import logging
import os
import re
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# =============================================================================
# Safe BaseAgent import
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    try:
        from agents.base import BaseAgent  # type: ignore
    except Exception:  # pragma: no cover

        class BaseAgent:  # type: ignore
            """
            Import-safe BaseAgent fallback.

            This fallback allows this file to be imported even before the full
            William/Jarvis agent framework has been created.
            """

            def __init__(self, *args: Any, **kwargs: Any) -> None:
                self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
                self.agent_type = kwargs.get("agent_type", "hologram_agent")
                self.agent_id = kwargs.get("agent_id", self.agent_name.lower())


# =============================================================================
# Constants
# =============================================================================

SUPPORTED_MEMORY_TYPES = {
    "layout_preference",
    "safe_zone",
    "recurring_overlay",
    "device_profile",
    "session_preference",
}

SENSITIVE_OPERATIONS = {
    "delete_layout_preference",
    "delete_safe_zone",
    "delete_recurring_overlay",
    "clear_user_memory",
    "clear_workspace_memory",
    "import_memory_snapshot",
}

DEFAULT_MAX_SAFE_ZONES = 250
DEFAULT_MAX_RECURRING_OVERLAYS = 500
DEFAULT_MAX_LAYOUTS = 250
DEFAULT_STORAGE_ROOT = "storage/hologram_memory"

VALID_ANCHORS = {
    "front_center",
    "front_left",
    "front_right",
    "top_left",
    "top_right",
    "bottom_left",
    "bottom_right",
    "world_locked",
    "object_locked",
    "hand_locked",
    "head_locked",
    "custom",
}

VALID_OVERLAY_PRIORITIES = {
    "low",
    "normal",
    "high",
    "critical",
}

VALID_SAFE_ZONE_TYPES = {
    "no_overlay",
    "reduced_opacity",
    "collision_avoidance",
    "privacy_sensitive",
    "walkway",
    "vehicle_area",
    "restricted_area",
    "custom",
}

VALID_RECURRENCE_TYPES = {
    "always",
    "daily",
    "weekly",
    "monthly",
    "session_start",
    "context_triggered",
    "manual",
}

SAFE_ID_PATTERN = re.compile(r"^[a-zA-Z0-9._:-]{1,160}$")


# =============================================================================
# Helpers
# =============================================================================

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def _safe_slug(value: Any, fallback: str = "unknown") -> str:
    text = str(value or fallback).strip()
    text = re.sub(r"[^a-zA-Z0-9._-]+", "_", text)
    return text[:120] or fallback


def _deepcopy_json_safe(value: Any) -> Any:
    try:
        return json.loads(json.dumps(value, default=str))
    except Exception:
        return copy.deepcopy(value)


def _normalize_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    return bool(value)


def _ensure_dict(value: Any, field_name: str) -> Dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError(f"{field_name} must be a dictionary.")
    return dict(value)


def _ensure_list(value: Any, field_name: str) -> List[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{field_name} must be a list.")
    return list(value)


def _validate_public_id(value: str, field_name: str) -> None:
    if not value:
        raise ValueError(f"{field_name} is required.")
    if not SAFE_ID_PATTERN.match(str(value)):
        raise ValueError(
            f"{field_name} may only contain letters, numbers, dash, underscore, dot, or colon."
        )


def _safe_float(
    value: Any,
    field_name: str,
    minimum: Optional[float] = None,
    maximum: Optional[float] = None,
    default: Optional[float] = None,
) -> float:
    if value is None and default is not None:
        parsed = float(default)
    else:
        try:
            parsed = float(value)
        except Exception as exc:
            raise ValueError(f"{field_name} must be numeric.") from exc

    if minimum is not None and parsed < minimum:
        raise ValueError(f"{field_name} must be >= {minimum}.")
    if maximum is not None and parsed > maximum:
        raise ValueError(f"{field_name} must be <= {maximum}.")
    return parsed


def _safe_int(
    value: Any,
    field_name: str,
    minimum: Optional[int] = None,
    maximum: Optional[int] = None,
    default: Optional[int] = None,
) -> int:
    if value is None and default is not None:
        parsed = int(default)
    else:
        try:
            parsed = int(value)
        except Exception as exc:
            raise ValueError(f"{field_name} must be an integer.") from exc

    if minimum is not None and parsed < minimum:
        raise ValueError(f"{field_name} must be >= {minimum}.")
    if maximum is not None and parsed > maximum:
        raise ValueError(f"{field_name} must be <= {maximum}.")
    return parsed


def _redact_sensitive(data: Any) -> Any:
    """
    Redact fields that may contain personal/sensitive data before audit logs.
    """

    sensitive_tokens = {
        "token",
        "secret",
        "password",
        "api_key",
        "apikey",
        "credential",
        "private",
        "face",
        "biometric",
        "precise_location",
    }

    if isinstance(data, Mapping):
        clean: Dict[str, Any] = {}
        for key, value in data.items():
            key_text = str(key).lower()
            if any(token in key_text for token in sensitive_tokens):
                clean[str(key)] = "***REDACTED***"
            else:
                clean[str(key)] = _redact_sensitive(value)
        return clean

    if isinstance(data, list):
        return [_redact_sensitive(item) for item in data]

    return data


# =============================================================================
# Data structures
# =============================================================================

@dataclass
class HologramMemoryConfig:
    """
    Configuration for HologramMemory.

    The default storage backend is local JSON for import-safety and easy testing.
    Production systems can inject a custom storage_backend object later.
    """

    storage_root: str = DEFAULT_STORAGE_ROOT
    use_local_json_storage: bool = True
    auto_create_storage_dirs: bool = True

    max_layouts_per_user_workspace: int = DEFAULT_MAX_LAYOUTS
    max_safe_zones_per_user_workspace: int = DEFAULT_MAX_SAFE_ZONES
    max_recurring_overlays_per_user_workspace: int = DEFAULT_MAX_RECURRING_OVERLAYS

    require_security_for_delete: bool = True
    require_security_for_import: bool = True
    require_security_for_workspace_clear: bool = True

    audit_enabled: bool = True
    events_enabled: bool = True
    memory_payload_enabled: bool = True
    verification_payload_enabled: bool = True

    default_layout_name: str = "default"
    default_device_profile_name: str = "default_device"

    allow_custom_anchor: bool = True
    allow_custom_safe_zone_type: bool = True
    allow_custom_overlay_payload: bool = True

    redact_sensitive_audit_values: bool = True


@dataclass
class LayoutPreference:
    """
    AR layout preference record.

    This stores how a user prefers overlays positioned, scaled, and styled.
    It is user/workspace scoped and can optionally be device/context scoped.
    """

    layout_id: str
    layout_name: str
    user_id: str
    workspace_id: str
    anchor: str = "front_center"
    position: Dict[str, float] = field(default_factory=lambda: {"x": 0.0, "y": 0.0, "z": 1.5})
    rotation: Dict[str, float] = field(default_factory=lambda: {"pitch": 0.0, "yaw": 0.0, "roll": 0.0})
    scale: float = 1.0
    opacity: float = 1.0
    theme: str = "system"
    pinned: bool = False
    device_profile: Optional[str] = None
    context_tags: List[str] = field(default_factory=list)
    preferences: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    created_at: str = field(default_factory=_utc_now_iso)
    updated_at: str = field(default_factory=_utc_now_iso)


@dataclass
class SafeZone:
    """
    Safe zone record.

    Safe zones tell AR overlays where not to render, where to reduce opacity,
    or where to avoid blocking real-world view.
    """

    zone_id: str
    zone_name: str
    user_id: str
    workspace_id: str
    zone_type: str = "no_overlay"
    shape: str = "box"
    coordinates: Dict[str, Any] = field(default_factory=dict)
    radius_meters: Optional[float] = None
    priority: int = 50
    device_profile: Optional[str] = None
    context_tags: List[str] = field(default_factory=list)
    rules: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    created_at: str = field(default_factory=_utc_now_iso)
    updated_at: str = field(default_factory=_utc_now_iso)


@dataclass
class RecurringOverlay:
    """
    Recurring overlay record.

    Recurring overlays are reusable AR cards, reminders, dashboards, widgets,
    visual hints, or workflow summaries that appear based on recurrence rules.
    """

    overlay_id: str
    overlay_name: str
    user_id: str
    workspace_id: str
    overlay_type: str = "card"
    recurrence_type: str = "manual"
    schedule: Dict[str, Any] = field(default_factory=dict)
    trigger_context: Dict[str, Any] = field(default_factory=dict)
    anchor: str = "front_center"
    layout_name: Optional[str] = None
    priority: str = "normal"
    payload: Dict[str, Any] = field(default_factory=dict)
    device_profile: Optional[str] = None
    context_tags: List[str] = field(default_factory=list)
    enabled: bool = True
    last_rendered_at: Optional[str] = None
    created_at: str = field(default_factory=_utc_now_iso)
    updated_at: str = field(default_factory=_utc_now_iso)


@dataclass
class DeviceProfile:
    """
    AR device profile memory.

    Stores safe display defaults for glasses/headset/mobile AR devices without
    storing sensitive biometric data.
    """

    profile_id: str
    profile_name: str
    user_id: str
    workspace_id: str
    device_type: str = "unknown"
    device_vendor: Optional[str] = None
    device_model: Optional[str] = None
    field_of_view: Dict[str, float] = field(default_factory=dict)
    comfort_limits: Dict[str, Any] = field(default_factory=dict)
    display_preferences: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    created_at: str = field(default_factory=_utc_now_iso)
    updated_at: str = field(default_factory=_utc_now_iso)


# =============================================================================
# Main class
# =============================================================================

class HologramMemory(BaseAgent):
    """
    Memory helper for the William / Jarvis Hologram Agent.

    Core responsibilities:
        - Store AR layout preferences.
        - Store safe zones.
        - Store recurring overlays.
        - Store basic AR device profiles.
        - Provide context-aware retrieval for the Hologram Agent.
        - Protect SaaS isolation by requiring user_id and workspace_id.
        - Prepare structured payloads for Security, Verification, Memory,
          Dashboard/API, Agent Registry, and Master Agent routing.

    This class is intentionally import-safe and uses a simple JSON-backed local
    store by default. In production, a database or Memory Agent backend can be
    injected through storage_backend.
    """

    def __init__(
        self,
        config: Optional[Union[HologramMemoryConfig, Mapping[str, Any]]] = None,
        storage_backend: Optional[Any] = None,
        security_client: Optional[Any] = None,
        memory_client: Optional[Any] = None,
        verification_client: Optional[Any] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], None]] = None,
        event_emitter: Optional[Callable[[Dict[str, Any]], None]] = None,
        logger: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            agent_name=kwargs.pop("agent_name", "HologramMemory"),
            agent_type=kwargs.pop("agent_type", "hologram_agent"),
            agent_id=kwargs.pop("agent_id", "super_agents.hologram_agent.hologram_memory"),
            **kwargs,
        )

        if config is None:
            self.config = HologramMemoryConfig()
        elif isinstance(config, HologramMemoryConfig):
            self.config = config
        elif isinstance(config, Mapping):
            self.config = HologramMemoryConfig(**dict(config))
        else:
            raise TypeError("config must be HologramMemoryConfig, mapping, or None.")

        self.storage_backend = storage_backend
        self.security_client = security_client
        self.memory_client = memory_client
        self.verification_client = verification_client
        self.audit_logger = audit_logger
        self.event_emitter = event_emitter
        self.logger = logger or logging.getLogger(__name__)
        self._lock = threading.RLock()

        if self.config.auto_create_storage_dirs and self.config.use_local_json_storage:
            Path(self.config.storage_root).mkdir(parents=True, exist_ok=True)

    # -------------------------------------------------------------------------
    # Required compatibility hooks
    # -------------------------------------------------------------------------

    def _validate_task_context(self, context: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Validate SaaS task context.

        Every user-specific hologram memory operation must include user_id and
        workspace_id to prevent cross-tenant memory mixing.
        """

        if not isinstance(context, Mapping):
            return self._error_result(
                message="Invalid task context.",
                code="invalid_context",
                details={"reason": "context must be a dictionary"},
            )

        user_id = context.get("user_id")
        workspace_id = context.get("workspace_id")

        if not user_id or not workspace_id:
            return self._error_result(
                message="Missing required SaaS isolation context.",
                code="missing_context",
                details={
                    "required": ["user_id", "workspace_id"],
                    "received": list(context.keys()),
                },
            )

        return self._safe_result(
            message="Task context validated.",
            data={
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
                "actor_id": str(context.get("actor_id") or user_id),
                "request_id": str(context.get("request_id") or uuid.uuid4()),
                "role": context.get("role"),
                "source": context.get("source", "hologram_agent"),
                "security_approved": bool(context.get("security_approved", False)),
            },
        )

    def _requires_security_check(
        self,
        operation: str,
        context: Optional[Mapping[str, Any]] = None,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Decide if Security Agent approval is required.

        Deletes, workspace clears, and memory snapshot imports are sensitive
        because they can remove or overwrite user AR preferences.
        """

        operation = str(operation or "").lower()
        context = context or {}

        if context.get("security_approved") is True:
            return False

        if operation in {
            "delete_layout_preference",
            "delete_safe_zone",
            "delete_recurring_overlay",
            "delete_device_profile",
            "clear_user_memory",
        }:
            return self.config.require_security_for_delete

        if operation == "clear_workspace_memory":
            return self.config.require_security_for_workspace_clear

        if operation == "import_memory_snapshot":
            return self.config.require_security_for_import

        return operation in SENSITIVE_OPERATIONS

    def _request_security_approval(
        self,
        context: Mapping[str, Any],
        operation: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        If no Security Agent is connected, sensitive operations are blocked
        instead of silently executing.
        """

        approval_payload = {
            "event_type": "security_approval_request",
            "agent": "HologramMemory",
            "operation": operation,
            "context": {
                "user_id": context.get("user_id"),
                "workspace_id": context.get("workspace_id"),
                "actor_id": context.get("actor_id"),
                "request_id": context.get("request_id"),
            },
            "payload": _redact_sensitive(dict(payload or {})),
            "created_at": _utc_now_iso(),
        }

        if self.security_client is None:
            return self._error_result(
                message="Security approval is required before this hologram memory operation can run.",
                code="security_approval_required",
                details=approval_payload,
                metadata={"requires_security_approval": True},
            )

        try:
            if hasattr(self.security_client, "approve_action"):
                approval = self.security_client.approve_action(approval_payload)
            elif hasattr(self.security_client, "request_approval"):
                approval = self.security_client.request_approval(approval_payload)
            elif callable(self.security_client):
                approval = self.security_client(approval_payload)
            else:
                return self._error_result(
                    message="Invalid Security Agent client.",
                    code="invalid_security_client",
                    details={"approval_payload": approval_payload},
                    metadata={"requires_security_approval": True},
                )

            if isinstance(approval, Mapping) and approval.get("approved") is True:
                return self._safe_result(
                    message="Security approval granted.",
                    data={"approval": dict(approval)},
                    metadata={"requires_security_approval": False},
                )

            return self._error_result(
                message="Security approval denied or unavailable.",
                code="security_approval_denied",
                details={
                    "approval": approval,
                    "approval_payload": approval_payload,
                },
                metadata={"requires_security_approval": True},
            )

        except Exception as exc:
            return self._error_result(
                message="Security approval request failed.",
                code="security_approval_failed",
                details={
                    "exception": str(exc),
                    "approval_payload": approval_payload,
                },
                metadata={"requires_security_approval": True},
            )

    def _prepare_verification_payload(
        self,
        context: Mapping[str, Any],
        operation: str,
        result: Mapping[str, Any],
        memory_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Prepare payload for Verification Agent.

        Verification Agent can confirm that memory was written, updated, deleted,
        or retrieved with correct user/workspace isolation.
        """

        data = result.get("data") if isinstance(result.get("data"), Mapping) else {}

        return {
            "verification_type": "hologram_memory_operation",
            "agent": "HologramMemory",
            "operation": operation,
            "memory_type": memory_type,
            "success": bool(result.get("success")),
            "message": result.get("message"),
            "context": {
                "user_id": context.get("user_id"),
                "workspace_id": context.get("workspace_id"),
                "actor_id": context.get("actor_id"),
                "request_id": context.get("request_id"),
            },
            "data_summary": {
                "layout_id": data.get("layout_id"),
                "zone_id": data.get("zone_id"),
                "overlay_id": data.get("overlay_id"),
                "profile_id": data.get("profile_id"),
                "count": data.get("count"),
                "memory_type": data.get("memory_type"),
            },
            "created_at": _utc_now_iso(),
        }

    def _prepare_memory_payload(
        self,
        context: Mapping[str, Any],
        operation: str,
        result: Mapping[str, Any],
        memory_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent-compatible payload.

        This payload summarizes useful AR preference context without exposing
        unnecessary raw device or location-sensitive information.
        """

        data = result.get("data") if isinstance(result.get("data"), Mapping) else {}

        return {
            "memory_type": "hologram_agent_memory_event",
            "agent": "HologramMemory",
            "operation": operation,
            "hologram_memory_type": memory_type,
            "context": {
                "user_id": context.get("user_id"),
                "workspace_id": context.get("workspace_id"),
                "request_id": context.get("request_id"),
            },
            "summary": {
                "success": bool(result.get("success")),
                "message": result.get("message"),
                "layout_name": data.get("layout_name"),
                "zone_name": data.get("zone_name"),
                "overlay_name": data.get("overlay_name"),
                "profile_name": data.get("profile_name"),
                "count": data.get("count"),
            },
            "created_at": _utc_now_iso(),
        }

    def _emit_agent_event(self, event: Mapping[str, Any]) -> None:
        """
        Emit Hologram Agent event for dashboard/API or internal bus.

        Safe no-op if no event emitter is attached.
        """

        if not self.config.events_enabled:
            return

        payload = dict(event)
        payload.setdefault("agent", "HologramMemory")
        payload.setdefault("created_at", _utc_now_iso())

        if self.config.redact_sensitive_audit_values:
            payload = _redact_sensitive(payload)

        try:
            if self.event_emitter:
                self.event_emitter(payload)
            else:
                self.logger.debug("HologramMemory event: %s", payload)
        except Exception as exc:
            self.logger.warning("Failed to emit HologramMemory event: %s", exc)

    def _log_audit_event(self, event: Mapping[str, Any]) -> None:
        """
        Write audit event.

        Audit events are scoped with user_id/workspace_id and can be connected
        later to dashboard analytics or compliance logs.
        """

        if not self.config.audit_enabled:
            return

        payload = dict(event)
        payload.setdefault("agent", "HologramMemory")
        payload.setdefault("created_at", _utc_now_iso())

        if self.config.redact_sensitive_audit_values:
            payload = _redact_sensitive(payload)

        try:
            if self.audit_logger:
                self.audit_logger(payload)
            else:
                self.logger.info("HologramMemory audit: %s", payload)
        except Exception as exc:
            self.logger.warning("Failed to log HologramMemory audit event: %s", exc)

    def _safe_result(
        self,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard structured success response.
        """

        return {
            "success": True,
            "message": message,
            "data": dict(data or {}),
            "error": None,
            "metadata": {
                "agent": "HologramMemory",
                "timestamp": _utc_now_iso(),
                **dict(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str,
        code: str = "hologram_memory_error",
        details: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard structured error response.
        """

        return {
            "success": False,
            "message": message,
            "data": {},
            "error": {
                "code": code,
                "details": dict(details or {}),
            },
            "metadata": {
                "agent": "HologramMemory",
                "timestamp": _utc_now_iso(),
                **dict(metadata or {}),
            },
        }

    # -------------------------------------------------------------------------
    # Agent Registry / Master Agent compatibility
    # -------------------------------------------------------------------------

    def get_capabilities(self) -> Dict[str, Any]:
        """
        Return capability manifest for Master Agent, Agent Router, and Registry.
        """

        return self._safe_result(
            message="HologramMemory capabilities loaded.",
            data={
                "agent": "HologramMemory",
                "module": "hologram_agent",
                "file": "hologram_memory.py",
                "purpose": "Stores AR layout preferences, safe zones, recurring overlays.",
                "memory_types": sorted(SUPPORTED_MEMORY_TYPES),
                "public_methods": [
                    "save_layout_preference",
                    "get_layout_preference",
                    "list_layout_preferences",
                    "delete_layout_preference",
                    "save_safe_zone",
                    "get_safe_zone",
                    "list_safe_zones",
                    "delete_safe_zone",
                    "save_recurring_overlay",
                    "get_recurring_overlay",
                    "list_recurring_overlays",
                    "delete_recurring_overlay",
                    "save_device_profile",
                    "get_device_profile",
                    "list_device_profiles",
                    "delete_device_profile",
                    "get_context_memory",
                    "export_memory_snapshot",
                    "import_memory_snapshot",
                    "clear_user_memory",
                    "health_check",
                ],
                "supports_user_workspace_isolation": True,
                "supports_security_approval": True,
                "supports_memory_payload": True,
                "supports_verification_payload": True,
                "safe_to_import": True,
            },
        )

    def health_check(self) -> Dict[str, Any]:
        """
        Health check for dashboard/API and agent loader.
        """

        local_storage_ok = True
        storage_path = Path(self.config.storage_root)

        if self.config.use_local_json_storage:
            try:
                storage_path.mkdir(parents=True, exist_ok=True)
                test_path = storage_path / ".health_check"
                test_path.write_text("ok", encoding="utf-8")
                test_path.unlink(missing_ok=True)
            except Exception:
                local_storage_ok = False

        return self._safe_result(
            message="HologramMemory health check completed.",
            data={
                "status": "ok" if local_storage_ok else "degraded",
                "local_json_storage": self.config.use_local_json_storage,
                "storage_root": str(storage_path),
                "storage_backend_attached": self.storage_backend is not None,
                "supported_memory_types": sorted(SUPPORTED_MEMORY_TYPES),
            },
        )

    # -------------------------------------------------------------------------
    # Layout preferences
    # -------------------------------------------------------------------------

    def save_layout_preference(
        self,
        context: Mapping[str, Any],
        layout_name: str,
        preferences: Optional[Mapping[str, Any]] = None,
        layout_id: Optional[str] = None,
        anchor: str = "front_center",
        position: Optional[Mapping[str, Any]] = None,
        rotation: Optional[Mapping[str, Any]] = None,
        scale: float = 1.0,
        opacity: float = 1.0,
        theme: str = "system",
        pinned: bool = False,
        device_profile: Optional[str] = None,
        context_tags: Optional[Sequence[str]] = None,
        enabled: bool = True,
    ) -> Dict[str, Any]:
        """
        Save or update an AR layout preference.

        The Hologram Agent can use this to restore user-specific overlay
        placement, size, opacity, theme, and anchoring.
        """

        operation = "save_layout_preference"
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx = ctx_result["data"]

        try:
            record = self._build_layout_preference(
                ctx=ctx,
                layout_name=layout_name,
                preferences=preferences,
                layout_id=layout_id,
                anchor=anchor,
                position=position,
                rotation=rotation,
                scale=scale,
                opacity=opacity,
                theme=theme,
                pinned=pinned,
                device_profile=device_profile,
                context_tags=context_tags,
                enabled=enabled,
            )

            with self._lock:
                store = self._load_store(ctx)
                layouts = store.setdefault("layout_preferences", {})

                if record.layout_id not in layouts and len(layouts) >= self.config.max_layouts_per_user_workspace:
                    return self._error_result(
                        message="Layout preference limit reached for this user/workspace.",
                        code="layout_limit_reached",
                        details={"max": self.config.max_layouts_per_user_workspace},
                    )

                existing = layouts.get(record.layout_id)
                if existing:
                    record.created_at = existing.get("created_at", record.created_at)
                    record.updated_at = _utc_now_iso()

                layouts[record.layout_id] = asdict(record)
                self._save_store(ctx, store)

            result = self._safe_result(
                message="Layout preference saved successfully.",
                data={
                    "memory_type": "layout_preference",
                    "layout_id": record.layout_id,
                    "layout_name": record.layout_name,
                    "record": asdict(record),
                },
                metadata={"operation": operation},
            )

            self._after_operation(ctx, operation, result, "layout_preference")
            return result

        except Exception as exc:
            result = self._error_result(
                message="Failed to save layout preference.",
                code="save_layout_preference_failed",
                details={"exception": str(exc)},
                metadata={"operation": operation},
            )
            self._after_operation(ctx, operation, result, "layout_preference")
            return result

    def get_layout_preference(
        self,
        context: Mapping[str, Any],
        layout_id: Optional[str] = None,
        layout_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Retrieve one layout preference by layout_id or layout_name.
        """

        operation = "get_layout_preference"
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx = ctx_result["data"]

        if not layout_id and not layout_name:
            layout_name = self.config.default_layout_name

        try:
            store = self._load_store(ctx)
            layouts = store.get("layout_preferences", {})

            record = None
            if layout_id:
                record = layouts.get(layout_id)
            else:
                for item in layouts.values():
                    if item.get("layout_name") == layout_name:
                        record = item
                        break

            if not record:
                return self._error_result(
                    message="Layout preference not found.",
                    code="layout_preference_not_found",
                    details={"layout_id": layout_id, "layout_name": layout_name},
                    metadata={"operation": operation},
                )

            result = self._safe_result(
                message="Layout preference retrieved successfully.",
                data={
                    "memory_type": "layout_preference",
                    "layout_id": record.get("layout_id"),
                    "layout_name": record.get("layout_name"),
                    "record": _deepcopy_json_safe(record),
                },
                metadata={"operation": operation},
            )

            self._after_operation(ctx, operation, result, "layout_preference")
            return result

        except Exception as exc:
            return self._error_result(
                message="Failed to retrieve layout preference.",
                code="get_layout_preference_failed",
                details={"exception": str(exc)},
                metadata={"operation": operation},
            )

    def list_layout_preferences(
        self,
        context: Mapping[str, Any],
        enabled_only: bool = False,
        device_profile: Optional[str] = None,
        context_tags: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        """
        List layout preferences for current user/workspace.
        """

        operation = "list_layout_preferences"
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx = ctx_result["data"]

        try:
            store = self._load_store(ctx)
            records = list(store.get("layout_preferences", {}).values())
            records = self._filter_records(
                records,
                enabled_only=enabled_only,
                device_profile=device_profile,
                context_tags=context_tags,
            )

            return self._safe_result(
                message="Layout preferences listed successfully.",
                data={
                    "memory_type": "layout_preference",
                    "count": len(records),
                    "records": records,
                },
                metadata={"operation": operation},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to list layout preferences.",
                code="list_layout_preferences_failed",
                details={"exception": str(exc)},
                metadata={"operation": operation},
            )

    def delete_layout_preference(
        self,
        context: Mapping[str, Any],
        layout_id: str,
    ) -> Dict[str, Any]:
        """
        Delete a layout preference.

        This is sensitive and can require Security Agent approval.
        """

        operation = "delete_layout_preference"
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx = ctx_result["data"]

        if self._requires_security_check(operation, ctx, {"layout_id": layout_id}):
            approval = self._request_security_approval(ctx, operation, {"layout_id": layout_id})
            if not approval["success"]:
                return approval

        try:
            _validate_public_id(layout_id, "layout_id")

            with self._lock:
                store = self._load_store(ctx)
                layouts = store.setdefault("layout_preferences", {})

                if layout_id not in layouts:
                    return self._error_result(
                        message="Layout preference not found.",
                        code="layout_preference_not_found",
                        details={"layout_id": layout_id},
                        metadata={"operation": operation},
                    )

                deleted = layouts.pop(layout_id)
                self._save_store(ctx, store)

            result = self._safe_result(
                message="Layout preference deleted successfully.",
                data={
                    "memory_type": "layout_preference",
                    "layout_id": layout_id,
                    "deleted_record": deleted,
                },
                metadata={"operation": operation},
            )

            self._after_operation(ctx, operation, result, "layout_preference")
            return result

        except Exception as exc:
            return self._error_result(
                message="Failed to delete layout preference.",
                code="delete_layout_preference_failed",
                details={"exception": str(exc)},
                metadata={"operation": operation},
            )

    # -------------------------------------------------------------------------
    # Safe zones
    # -------------------------------------------------------------------------

    def save_safe_zone(
        self,
        context: Mapping[str, Any],
        zone_name: str,
        coordinates: Mapping[str, Any],
        zone_id: Optional[str] = None,
        zone_type: str = "no_overlay",
        shape: str = "box",
        radius_meters: Optional[float] = None,
        priority: int = 50,
        device_profile: Optional[str] = None,
        context_tags: Optional[Sequence[str]] = None,
        rules: Optional[Mapping[str, Any]] = None,
        enabled: bool = True,
    ) -> Dict[str, Any]:
        """
        Save or update a safe zone.

        Safe zones prevent AR overlays from blocking real-world objects,
        walkways, privacy areas, vehicle zones, or restricted areas.
        """

        operation = "save_safe_zone"
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx = ctx_result["data"]

        try:
            record = self._build_safe_zone(
                ctx=ctx,
                zone_name=zone_name,
                coordinates=coordinates,
                zone_id=zone_id,
                zone_type=zone_type,
                shape=shape,
                radius_meters=radius_meters,
                priority=priority,
                device_profile=device_profile,
                context_tags=context_tags,
                rules=rules,
                enabled=enabled,
            )

            with self._lock:
                store = self._load_store(ctx)
                zones = store.setdefault("safe_zones", {})

                if record.zone_id not in zones and len(zones) >= self.config.max_safe_zones_per_user_workspace:
                    return self._error_result(
                        message="Safe zone limit reached for this user/workspace.",
                        code="safe_zone_limit_reached",
                        details={"max": self.config.max_safe_zones_per_user_workspace},
                    )

                existing = zones.get(record.zone_id)
                if existing:
                    record.created_at = existing.get("created_at", record.created_at)
                    record.updated_at = _utc_now_iso()

                zones[record.zone_id] = asdict(record)
                self._save_store(ctx, store)

            result = self._safe_result(
                message="Safe zone saved successfully.",
                data={
                    "memory_type": "safe_zone",
                    "zone_id": record.zone_id,
                    "zone_name": record.zone_name,
                    "record": asdict(record),
                },
                metadata={"operation": operation},
            )

            self._after_operation(ctx, operation, result, "safe_zone")
            return result

        except Exception as exc:
            result = self._error_result(
                message="Failed to save safe zone.",
                code="save_safe_zone_failed",
                details={"exception": str(exc)},
                metadata={"operation": operation},
            )
            self._after_operation(ctx, operation, result, "safe_zone")
            return result

    def get_safe_zone(
        self,
        context: Mapping[str, Any],
        zone_id: Optional[str] = None,
        zone_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Retrieve one safe zone by zone_id or zone_name.
        """

        operation = "get_safe_zone"
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx = ctx_result["data"]

        if not zone_id and not zone_name:
            return self._error_result(
                message="zone_id or zone_name is required.",
                code="missing_safe_zone_identifier",
                metadata={"operation": operation},
            )

        try:
            store = self._load_store(ctx)
            zones = store.get("safe_zones", {})

            record = None
            if zone_id:
                record = zones.get(zone_id)
            else:
                for item in zones.values():
                    if item.get("zone_name") == zone_name:
                        record = item
                        break

            if not record:
                return self._error_result(
                    message="Safe zone not found.",
                    code="safe_zone_not_found",
                    details={"zone_id": zone_id, "zone_name": zone_name},
                    metadata={"operation": operation},
                )

            result = self._safe_result(
                message="Safe zone retrieved successfully.",
                data={
                    "memory_type": "safe_zone",
                    "zone_id": record.get("zone_id"),
                    "zone_name": record.get("zone_name"),
                    "record": _deepcopy_json_safe(record),
                },
                metadata={"operation": operation},
            )

            self._after_operation(ctx, operation, result, "safe_zone")
            return result

        except Exception as exc:
            return self._error_result(
                message="Failed to retrieve safe zone.",
                code="get_safe_zone_failed",
                details={"exception": str(exc)},
                metadata={"operation": operation},
            )

    def list_safe_zones(
        self,
        context: Mapping[str, Any],
        enabled_only: bool = False,
        zone_type: Optional[str] = None,
        device_profile: Optional[str] = None,
        context_tags: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        """
        List safe zones for current user/workspace.
        """

        operation = "list_safe_zones"
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx = ctx_result["data"]

        try:
            store = self._load_store(ctx)
            records = list(store.get("safe_zones", {}).values())

            if zone_type:
                records = [record for record in records if record.get("zone_type") == zone_type]

            records = self._filter_records(
                records,
                enabled_only=enabled_only,
                device_profile=device_profile,
                context_tags=context_tags,
            )

            return self._safe_result(
                message="Safe zones listed successfully.",
                data={
                    "memory_type": "safe_zone",
                    "count": len(records),
                    "records": records,
                },
                metadata={"operation": operation},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to list safe zones.",
                code="list_safe_zones_failed",
                details={"exception": str(exc)},
                metadata={"operation": operation},
            )

    def delete_safe_zone(
        self,
        context: Mapping[str, Any],
        zone_id: str,
    ) -> Dict[str, Any]:
        """
        Delete a safe zone.

        This is sensitive because it may remove AR safety rules.
        """

        operation = "delete_safe_zone"
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx = ctx_result["data"]

        if self._requires_security_check(operation, ctx, {"zone_id": zone_id}):
            approval = self._request_security_approval(ctx, operation, {"zone_id": zone_id})
            if not approval["success"]:
                return approval

        try:
            _validate_public_id(zone_id, "zone_id")

            with self._lock:
                store = self._load_store(ctx)
                zones = store.setdefault("safe_zones", {})

                if zone_id not in zones:
                    return self._error_result(
                        message="Safe zone not found.",
                        code="safe_zone_not_found",
                        details={"zone_id": zone_id},
                        metadata={"operation": operation},
                    )

                deleted = zones.pop(zone_id)
                self._save_store(ctx, store)

            result = self._safe_result(
                message="Safe zone deleted successfully.",
                data={
                    "memory_type": "safe_zone",
                    "zone_id": zone_id,
                    "deleted_record": deleted,
                },
                metadata={"operation": operation},
            )

            self._after_operation(ctx, operation, result, "safe_zone")
            return result

        except Exception as exc:
            return self._error_result(
                message="Failed to delete safe zone.",
                code="delete_safe_zone_failed",
                details={"exception": str(exc)},
                metadata={"operation": operation},
            )

    # -------------------------------------------------------------------------
    # Recurring overlays
    # -------------------------------------------------------------------------

    def save_recurring_overlay(
        self,
        context: Mapping[str, Any],
        overlay_name: str,
        payload: Mapping[str, Any],
        overlay_id: Optional[str] = None,
        overlay_type: str = "card",
        recurrence_type: str = "manual",
        schedule: Optional[Mapping[str, Any]] = None,
        trigger_context: Optional[Mapping[str, Any]] = None,
        anchor: str = "front_center",
        layout_name: Optional[str] = None,
        priority: str = "normal",
        device_profile: Optional[str] = None,
        context_tags: Optional[Sequence[str]] = None,
        enabled: bool = True,
    ) -> Dict[str, Any]:
        """
        Save or update a recurring overlay.

        Recurring overlays can represent dashboards, reminders, persistent AR
        cards, workflow alerts, or contextual visual helpers.
        """

        operation = "save_recurring_overlay"
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx = ctx_result["data"]

        try:
            record = self._build_recurring_overlay(
                ctx=ctx,
                overlay_name=overlay_name,
                payload=payload,
                overlay_id=overlay_id,
                overlay_type=overlay_type,
                recurrence_type=recurrence_type,
                schedule=schedule,
                trigger_context=trigger_context,
                anchor=anchor,
                layout_name=layout_name,
                priority=priority,
                device_profile=device_profile,
                context_tags=context_tags,
                enabled=enabled,
            )

            with self._lock:
                store = self._load_store(ctx)
                overlays = store.setdefault("recurring_overlays", {})

                if record.overlay_id not in overlays and len(overlays) >= self.config.max_recurring_overlays_per_user_workspace:
                    return self._error_result(
                        message="Recurring overlay limit reached for this user/workspace.",
                        code="recurring_overlay_limit_reached",
                        details={"max": self.config.max_recurring_overlays_per_user_workspace},
                    )

                existing = overlays.get(record.overlay_id)
                if existing:
                    record.created_at = existing.get("created_at", record.created_at)
                    record.last_rendered_at = existing.get("last_rendered_at")
                    record.updated_at = _utc_now_iso()

                overlays[record.overlay_id] = asdict(record)
                self._save_store(ctx, store)

            result = self._safe_result(
                message="Recurring overlay saved successfully.",
                data={
                    "memory_type": "recurring_overlay",
                    "overlay_id": record.overlay_id,
                    "overlay_name": record.overlay_name,
                    "record": asdict(record),
                },
                metadata={"operation": operation},
            )

            self._after_operation(ctx, operation, result, "recurring_overlay")
            return result

        except Exception as exc:
            result = self._error_result(
                message="Failed to save recurring overlay.",
                code="save_recurring_overlay_failed",
                details={"exception": str(exc)},
                metadata={"operation": operation},
            )
            self._after_operation(ctx, operation, result, "recurring_overlay")
            return result

    def get_recurring_overlay(
        self,
        context: Mapping[str, Any],
        overlay_id: Optional[str] = None,
        overlay_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Retrieve one recurring overlay by overlay_id or overlay_name.
        """

        operation = "get_recurring_overlay"
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx = ctx_result["data"]

        if not overlay_id and not overlay_name:
            return self._error_result(
                message="overlay_id or overlay_name is required.",
                code="missing_overlay_identifier",
                metadata={"operation": operation},
            )

        try:
            store = self._load_store(ctx)
            overlays = store.get("recurring_overlays", {})

            record = None
            if overlay_id:
                record = overlays.get(overlay_id)
            else:
                for item in overlays.values():
                    if item.get("overlay_name") == overlay_name:
                        record = item
                        break

            if not record:
                return self._error_result(
                    message="Recurring overlay not found.",
                    code="recurring_overlay_not_found",
                    details={"overlay_id": overlay_id, "overlay_name": overlay_name},
                    metadata={"operation": operation},
                )

            result = self._safe_result(
                message="Recurring overlay retrieved successfully.",
                data={
                    "memory_type": "recurring_overlay",
                    "overlay_id": record.get("overlay_id"),
                    "overlay_name": record.get("overlay_name"),
                    "record": _deepcopy_json_safe(record),
                },
                metadata={"operation": operation},
            )

            self._after_operation(ctx, operation, result, "recurring_overlay")
            return result

        except Exception as exc:
            return self._error_result(
                message="Failed to retrieve recurring overlay.",
                code="get_recurring_overlay_failed",
                details={"exception": str(exc)},
                metadata={"operation": operation},
            )

    def list_recurring_overlays(
        self,
        context: Mapping[str, Any],
        enabled_only: bool = False,
        recurrence_type: Optional[str] = None,
        priority: Optional[str] = None,
        device_profile: Optional[str] = None,
        context_tags: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        """
        List recurring overlays for current user/workspace.
        """

        operation = "list_recurring_overlays"
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx = ctx_result["data"]

        try:
            store = self._load_store(ctx)
            records = list(store.get("recurring_overlays", {}).values())

            if recurrence_type:
                records = [
                    record for record in records
                    if record.get("recurrence_type") == recurrence_type
                ]

            if priority:
                records = [
                    record for record in records
                    if record.get("priority") == priority
                ]

            records = self._filter_records(
                records,
                enabled_only=enabled_only,
                device_profile=device_profile,
                context_tags=context_tags,
            )

            return self._safe_result(
                message="Recurring overlays listed successfully.",
                data={
                    "memory_type": "recurring_overlay",
                    "count": len(records),
                    "records": records,
                },
                metadata={"operation": operation},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to list recurring overlays.",
                code="list_recurring_overlays_failed",
                details={"exception": str(exc)},
                metadata={"operation": operation},
            )

    def delete_recurring_overlay(
        self,
        context: Mapping[str, Any],
        overlay_id: str,
    ) -> Dict[str, Any]:
        """
        Delete a recurring overlay.
        """

        operation = "delete_recurring_overlay"
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx = ctx_result["data"]

        if self._requires_security_check(operation, ctx, {"overlay_id": overlay_id}):
            approval = self._request_security_approval(ctx, operation, {"overlay_id": overlay_id})
            if not approval["success"]:
                return approval

        try:
            _validate_public_id(overlay_id, "overlay_id")

            with self._lock:
                store = self._load_store(ctx)
                overlays = store.setdefault("recurring_overlays", {})

                if overlay_id not in overlays:
                    return self._error_result(
                        message="Recurring overlay not found.",
                        code="recurring_overlay_not_found",
                        details={"overlay_id": overlay_id},
                        metadata={"operation": operation},
                    )

                deleted = overlays.pop(overlay_id)
                self._save_store(ctx, store)

            result = self._safe_result(
                message="Recurring overlay deleted successfully.",
                data={
                    "memory_type": "recurring_overlay",
                    "overlay_id": overlay_id,
                    "deleted_record": deleted,
                },
                metadata={"operation": operation},
            )

            self._after_operation(ctx, operation, result, "recurring_overlay")
            return result

        except Exception as exc:
            return self._error_result(
                message="Failed to delete recurring overlay.",
                code="delete_recurring_overlay_failed",
                details={"exception": str(exc)},
                metadata={"operation": operation},
            )

    def mark_overlay_rendered(
        self,
        context: Mapping[str, Any],
        overlay_id: str,
        rendered_at: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Mark recurring overlay as rendered.

        Hologram Agent can call this after showing an overlay to maintain
        recurrence state.
        """

        operation = "mark_overlay_rendered"
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx = ctx_result["data"]

        try:
            _validate_public_id(overlay_id, "overlay_id")

            with self._lock:
                store = self._load_store(ctx)
                overlays = store.setdefault("recurring_overlays", {})

                if overlay_id not in overlays:
                    return self._error_result(
                        message="Recurring overlay not found.",
                        code="recurring_overlay_not_found",
                        details={"overlay_id": overlay_id},
                        metadata={"operation": operation},
                    )

                overlays[overlay_id]["last_rendered_at"] = rendered_at or _utc_now_iso()
                overlays[overlay_id]["updated_at"] = _utc_now_iso()
                self._save_store(ctx, store)

            result = self._safe_result(
                message="Recurring overlay render state updated.",
                data={
                    "memory_type": "recurring_overlay",
                    "overlay_id": overlay_id,
                    "last_rendered_at": overlays[overlay_id]["last_rendered_at"],
                    "record": overlays[overlay_id],
                },
                metadata={"operation": operation},
            )

            self._after_operation(ctx, operation, result, "recurring_overlay")
            return result

        except Exception as exc:
            return self._error_result(
                message="Failed to update recurring overlay render state.",
                code="mark_overlay_rendered_failed",
                details={"exception": str(exc)},
                metadata={"operation": operation},
            )

    # -------------------------------------------------------------------------
    # Device profiles
    # -------------------------------------------------------------------------

    def save_device_profile(
        self,
        context: Mapping[str, Any],
        profile_name: str,
        device_type: str = "unknown",
        profile_id: Optional[str] = None,
        device_vendor: Optional[str] = None,
        device_model: Optional[str] = None,
        field_of_view: Optional[Mapping[str, Any]] = None,
        comfort_limits: Optional[Mapping[str, Any]] = None,
        display_preferences: Optional[Mapping[str, Any]] = None,
        enabled: bool = True,
    ) -> Dict[str, Any]:
        """
        Save AR device profile.

        This avoids storing biometric details and keeps only display and comfort
        preferences needed for safe overlay rendering.
        """

        operation = "save_device_profile"
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx = ctx_result["data"]

        try:
            profile_name = str(profile_name or "").strip()
            if not profile_name:
                raise ValueError("profile_name is required.")

            if profile_id:
                _validate_public_id(profile_id, "profile_id")
            else:
                profile_id = _new_id("device_profile")

            fov = _ensure_dict(field_of_view, "field_of_view")
            comfort = _ensure_dict(comfort_limits, "comfort_limits")
            display = _ensure_dict(display_preferences, "display_preferences")

            record = DeviceProfile(
                profile_id=profile_id,
                profile_name=profile_name,
                user_id=ctx["user_id"],
                workspace_id=ctx["workspace_id"],
                device_type=str(device_type or "unknown"),
                device_vendor=device_vendor,
                device_model=device_model,
                field_of_view={
                    key: _safe_float(value, f"field_of_view.{key}", minimum=0.0, maximum=360.0)
                    for key, value in fov.items()
                },
                comfort_limits=comfort,
                display_preferences=display,
                enabled=_normalize_bool(enabled, True),
            )

            with self._lock:
                store = self._load_store(ctx)
                profiles = store.setdefault("device_profiles", {})
                existing = profiles.get(record.profile_id)
                if existing:
                    record.created_at = existing.get("created_at", record.created_at)
                    record.updated_at = _utc_now_iso()

                profiles[record.profile_id] = asdict(record)
                self._save_store(ctx, store)

            result = self._safe_result(
                message="Device profile saved successfully.",
                data={
                    "memory_type": "device_profile",
                    "profile_id": record.profile_id,
                    "profile_name": record.profile_name,
                    "record": asdict(record),
                },
                metadata={"operation": operation},
            )

            self._after_operation(ctx, operation, result, "device_profile")
            return result

        except Exception as exc:
            result = self._error_result(
                message="Failed to save device profile.",
                code="save_device_profile_failed",
                details={"exception": str(exc)},
                metadata={"operation": operation},
            )
            self._after_operation(ctx, operation, result, "device_profile")
            return result

    def get_device_profile(
        self,
        context: Mapping[str, Any],
        profile_id: Optional[str] = None,
        profile_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Retrieve one device profile.
        """

        operation = "get_device_profile"
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx = ctx_result["data"]

        if not profile_id and not profile_name:
            profile_name = self.config.default_device_profile_name

        try:
            store = self._load_store(ctx)
            profiles = store.get("device_profiles", {})

            record = None
            if profile_id:
                record = profiles.get(profile_id)
            else:
                for item in profiles.values():
                    if item.get("profile_name") == profile_name:
                        record = item
                        break

            if not record:
                return self._error_result(
                    message="Device profile not found.",
                    code="device_profile_not_found",
                    details={"profile_id": profile_id, "profile_name": profile_name},
                    metadata={"operation": operation},
                )

            return self._safe_result(
                message="Device profile retrieved successfully.",
                data={
                    "memory_type": "device_profile",
                    "profile_id": record.get("profile_id"),
                    "profile_name": record.get("profile_name"),
                    "record": _deepcopy_json_safe(record),
                },
                metadata={"operation": operation},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to retrieve device profile.",
                code="get_device_profile_failed",
                details={"exception": str(exc)},
                metadata={"operation": operation},
            )

    def list_device_profiles(
        self,
        context: Mapping[str, Any],
        enabled_only: bool = False,
    ) -> Dict[str, Any]:
        """
        List device profiles for current user/workspace.
        """

        operation = "list_device_profiles"
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx = ctx_result["data"]

        try:
            store = self._load_store(ctx)
            records = list(store.get("device_profiles", {}).values())

            if enabled_only:
                records = [record for record in records if record.get("enabled") is True]

            return self._safe_result(
                message="Device profiles listed successfully.",
                data={
                    "memory_type": "device_profile",
                    "count": len(records),
                    "records": records,
                },
                metadata={"operation": operation},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to list device profiles.",
                code="list_device_profiles_failed",
                details={"exception": str(exc)},
                metadata={"operation": operation},
            )

    def delete_device_profile(
        self,
        context: Mapping[str, Any],
        profile_id: str,
    ) -> Dict[str, Any]:
        """
        Delete a device profile.
        """

        operation = "delete_device_profile"
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx = ctx_result["data"]

        if self._requires_security_check(operation, ctx, {"profile_id": profile_id}):
            approval = self._request_security_approval(ctx, operation, {"profile_id": profile_id})
            if not approval["success"]:
                return approval

        try:
            _validate_public_id(profile_id, "profile_id")

            with self._lock:
                store = self._load_store(ctx)
                profiles = store.setdefault("device_profiles", {})

                if profile_id not in profiles:
                    return self._error_result(
                        message="Device profile not found.",
                        code="device_profile_not_found",
                        details={"profile_id": profile_id},
                        metadata={"operation": operation},
                    )

                deleted = profiles.pop(profile_id)
                self._save_store(ctx, store)

            result = self._safe_result(
                message="Device profile deleted successfully.",
                data={
                    "memory_type": "device_profile",
                    "profile_id": profile_id,
                    "deleted_record": deleted,
                },
                metadata={"operation": operation},
            )

            self._after_operation(ctx, operation, result, "device_profile")
            return result

        except Exception as exc:
            return self._error_result(
                message="Failed to delete device profile.",
                code="delete_device_profile_failed",
                details={"exception": str(exc)},
                metadata={"operation": operation},
            )

    # -------------------------------------------------------------------------
    # Context-aware memory retrieval
    # -------------------------------------------------------------------------

    def get_context_memory(
        self,
        context: Mapping[str, Any],
        device_profile: Optional[str] = None,
        context_tags: Optional[Sequence[str]] = None,
        include_disabled: bool = False,
    ) -> Dict[str, Any]:
        """
        Return all relevant hologram memory for a current AR session.

        Hologram Agent can call this at session start to restore:
            - Layout preferences
            - Safe zones
            - Recurring overlays
            - Device profile defaults
        """

        operation = "get_context_memory"
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx = ctx_result["data"]

        try:
            store = self._load_store(ctx)

            enabled_only = not include_disabled

            layouts = self._filter_records(
                list(store.get("layout_preferences", {}).values()),
                enabled_only=enabled_only,
                device_profile=device_profile,
                context_tags=context_tags,
            )

            zones = self._filter_records(
                list(store.get("safe_zones", {}).values()),
                enabled_only=enabled_only,
                device_profile=device_profile,
                context_tags=context_tags,
            )

            overlays = self._filter_records(
                list(store.get("recurring_overlays", {}).values()),
                enabled_only=enabled_only,
                device_profile=device_profile,
                context_tags=context_tags,
            )

            profiles = list(store.get("device_profiles", {}).values())
            if device_profile:
                profiles = [
                    profile for profile in profiles
                    if profile.get("profile_id") == device_profile
                    or profile.get("profile_name") == device_profile
                ]
            if enabled_only:
                profiles = [profile for profile in profiles if profile.get("enabled") is True]

            result = self._safe_result(
                message="Context hologram memory loaded successfully.",
                data={
                    "memory_type": "context_memory",
                    "layout_preferences": layouts,
                    "safe_zones": zones,
                    "recurring_overlays": overlays,
                    "device_profiles": profiles,
                    "counts": {
                        "layout_preferences": len(layouts),
                        "safe_zones": len(zones),
                        "recurring_overlays": len(overlays),
                        "device_profiles": len(profiles),
                    },
                },
                metadata={"operation": operation},
            )

            self._after_operation(ctx, operation, result, "context_memory")
            return result

        except Exception as exc:
            return self._error_result(
                message="Failed to load context hologram memory.",
                code="get_context_memory_failed",
                details={"exception": str(exc)},
                metadata={"operation": operation},
            )

    # -------------------------------------------------------------------------
    # Snapshot import/export
    # -------------------------------------------------------------------------

    def export_memory_snapshot(
        self,
        context: Mapping[str, Any],
        include_disabled: bool = True,
    ) -> Dict[str, Any]:
        """
        Export user/workspace-scoped hologram memory snapshot.

        This does not export memories from any other user or workspace.
        """

        operation = "export_memory_snapshot"
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx = ctx_result["data"]

        try:
            store = self._load_store(ctx)
            snapshot = _deepcopy_json_safe(store)

            if not include_disabled:
                for key in ["layout_preferences", "safe_zones", "recurring_overlays", "device_profiles"]:
                    snapshot[key] = {
                        record_id: record
                        for record_id, record in snapshot.get(key, {}).items()
                        if record.get("enabled") is True
                    }

            snapshot["snapshot_metadata"] = {
                "agent": "HologramMemory",
                "user_id": ctx["user_id"],
                "workspace_id": ctx["workspace_id"],
                "exported_at": _utc_now_iso(),
                "include_disabled": include_disabled,
            }

            result = self._safe_result(
                message="Hologram memory snapshot exported successfully.",
                data={
                    "memory_type": "memory_snapshot",
                    "snapshot": snapshot,
                    "counts": self._store_counts(snapshot),
                },
                metadata={"operation": operation},
            )

            self._after_operation(ctx, operation, result, "memory_snapshot")
            return result

        except Exception as exc:
            return self._error_result(
                message="Failed to export hologram memory snapshot.",
                code="export_memory_snapshot_failed",
                details={"exception": str(exc)},
                metadata={"operation": operation},
            )

    def import_memory_snapshot(
        self,
        context: Mapping[str, Any],
        snapshot: Mapping[str, Any],
        merge: bool = True,
        overwrite_existing: bool = False,
    ) -> Dict[str, Any]:
        """
        Import user/workspace-scoped hologram memory snapshot.

        Security Agent approval may be required because this can overwrite AR
        safety settings and recurring overlays.
        """

        operation = "import_memory_snapshot"
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx = ctx_result["data"]

        if self._requires_security_check(operation, ctx, {"merge": merge, "overwrite_existing": overwrite_existing}):
            approval = self._request_security_approval(
                ctx,
                operation,
                {
                    "merge": merge,
                    "overwrite_existing": overwrite_existing,
                    "snapshot_counts": self._store_counts(snapshot),
                },
            )
            if not approval["success"]:
                return approval

        try:
            incoming = _ensure_dict(snapshot, "snapshot")
            self._validate_snapshot_for_current_context(ctx, incoming)

            with self._lock:
                current = self._load_store(ctx)

                if not merge:
                    new_store = self._empty_store(ctx)
                else:
                    new_store = current

                for section in ["layout_preferences", "safe_zones", "recurring_overlays", "device_profiles"]:
                    incoming_section = incoming.get(section, {})
                    if not isinstance(incoming_section, Mapping):
                        continue

                    target_section = new_store.setdefault(section, {})
                    for record_id, record in incoming_section.items():
                        if not isinstance(record, Mapping):
                            continue
                        if record_id in target_section and not overwrite_existing:
                            continue

                        safe_record = dict(record)
                        safe_record["user_id"] = ctx["user_id"]
                        safe_record["workspace_id"] = ctx["workspace_id"]
                        safe_record["updated_at"] = _utc_now_iso()
                        target_section[str(record_id)] = safe_record

                self._save_store(ctx, new_store)

            result = self._safe_result(
                message="Hologram memory snapshot imported successfully.",
                data={
                    "memory_type": "memory_snapshot",
                    "counts": self._store_counts(new_store),
                    "merge": merge,
                    "overwrite_existing": overwrite_existing,
                },
                metadata={"operation": operation},
            )

            self._after_operation(ctx, operation, result, "memory_snapshot")
            return result

        except Exception as exc:
            return self._error_result(
                message="Failed to import hologram memory snapshot.",
                code="import_memory_snapshot_failed",
                details={"exception": str(exc)},
                metadata={"operation": operation},
            )

    # -------------------------------------------------------------------------
    # Clear memory
    # -------------------------------------------------------------------------

    def clear_user_memory(
        self,
        context: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Clear all hologram memory for the current user/workspace only.
        """

        operation = "clear_user_memory"
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx = ctx_result["data"]

        if self._requires_security_check(operation, ctx):
            approval = self._request_security_approval(ctx, operation, {"scope": "current_user_workspace"})
            if not approval["success"]:
                return approval

        try:
            with self._lock:
                old_store = self._load_store(ctx)
                new_store = self._empty_store(ctx)
                self._save_store(ctx, new_store)

            result = self._safe_result(
                message="User hologram memory cleared successfully for this workspace.",
                data={
                    "memory_type": "clear_memory",
                    "scope": "current_user_workspace",
                    "previous_counts": self._store_counts(old_store),
                    "current_counts": self._store_counts(new_store),
                },
                metadata={"operation": operation},
            )

            self._after_operation(ctx, operation, result, "clear_memory")
            return result

        except Exception as exc:
            return self._error_result(
                message="Failed to clear user hologram memory.",
                code="clear_user_memory_failed",
                details={"exception": str(exc)},
                metadata={"operation": operation},
            )

    def clear_workspace_memory(
        self,
        context: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Clear all hologram memory for current workspace/user storage file.

        This method remains scoped to the current context. It does not scan or
        delete unrelated users unless the production storage backend implements
        a broader workspace-level method with Security Agent approval.
        """

        operation = "clear_workspace_memory"
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx = ctx_result["data"]

        if self._requires_security_check(operation, ctx):
            approval = self._request_security_approval(ctx, operation, {"scope": "workspace_context"})
            if not approval["success"]:
                return approval

        return self.clear_user_memory({**ctx, "security_approved": True})

    # -------------------------------------------------------------------------
    # Builders and validators
    # -------------------------------------------------------------------------

    def _build_layout_preference(
        self,
        ctx: Mapping[str, Any],
        layout_name: str,
        preferences: Optional[Mapping[str, Any]],
        layout_id: Optional[str],
        anchor: str,
        position: Optional[Mapping[str, Any]],
        rotation: Optional[Mapping[str, Any]],
        scale: float,
        opacity: float,
        theme: str,
        pinned: bool,
        device_profile: Optional[str],
        context_tags: Optional[Sequence[str]],
        enabled: bool,
    ) -> LayoutPreference:
        layout_name = str(layout_name or "").strip()
        if not layout_name:
            raise ValueError("layout_name is required.")

        if layout_id:
            _validate_public_id(layout_id, "layout_id")
        else:
            layout_id = _new_id("layout")

        anchor = self._validate_anchor(anchor)
        position_dict = self._validate_vector(position or {"x": 0.0, "y": 0.0, "z": 1.5}, "position")
        rotation_dict = self._validate_rotation(rotation or {"pitch": 0.0, "yaw": 0.0, "roll": 0.0})

        return LayoutPreference(
            layout_id=layout_id,
            layout_name=layout_name,
            user_id=ctx["user_id"],
            workspace_id=ctx["workspace_id"],
            anchor=anchor,
            position=position_dict,
            rotation=rotation_dict,
            scale=_safe_float(scale, "scale", minimum=0.05, maximum=10.0, default=1.0),
            opacity=_safe_float(opacity, "opacity", minimum=0.0, maximum=1.0, default=1.0),
            theme=str(theme or "system"),
            pinned=_normalize_bool(pinned, False),
            device_profile=device_profile,
            context_tags=self._normalize_tags(context_tags),
            preferences=_ensure_dict(preferences, "preferences"),
            enabled=_normalize_bool(enabled, True),
        )

    def _build_safe_zone(
        self,
        ctx: Mapping[str, Any],
        zone_name: str,
        coordinates: Mapping[str, Any],
        zone_id: Optional[str],
        zone_type: str,
        shape: str,
        radius_meters: Optional[float],
        priority: int,
        device_profile: Optional[str],
        context_tags: Optional[Sequence[str]],
        rules: Optional[Mapping[str, Any]],
        enabled: bool,
    ) -> SafeZone:
        zone_name = str(zone_name or "").strip()
        if not zone_name:
            raise ValueError("zone_name is required.")

        if zone_id:
            _validate_public_id(zone_id, "zone_id")
        else:
            zone_id = _new_id("safe_zone")

        zone_type = self._validate_safe_zone_type(zone_type)
        coordinates_dict = _ensure_dict(coordinates, "coordinates")

        if not coordinates_dict:
            raise ValueError("coordinates are required for safe zones.")

        radius_value = None
        if radius_meters is not None:
            radius_value = _safe_float(radius_meters, "radius_meters", minimum=0.0, maximum=100000.0)

        return SafeZone(
            zone_id=zone_id,
            zone_name=zone_name,
            user_id=ctx["user_id"],
            workspace_id=ctx["workspace_id"],
            zone_type=zone_type,
            shape=str(shape or "box"),
            coordinates=_deepcopy_json_safe(coordinates_dict),
            radius_meters=radius_value,
            priority=_safe_int(priority, "priority", minimum=0, maximum=100, default=50),
            device_profile=device_profile,
            context_tags=self._normalize_tags(context_tags),
            rules=_ensure_dict(rules, "rules"),
            enabled=_normalize_bool(enabled, True),
        )

    def _build_recurring_overlay(
        self,
        ctx: Mapping[str, Any],
        overlay_name: str,
        payload: Mapping[str, Any],
        overlay_id: Optional[str],
        overlay_type: str,
        recurrence_type: str,
        schedule: Optional[Mapping[str, Any]],
        trigger_context: Optional[Mapping[str, Any]],
        anchor: str,
        layout_name: Optional[str],
        priority: str,
        device_profile: Optional[str],
        context_tags: Optional[Sequence[str]],
        enabled: bool,
    ) -> RecurringOverlay:
        overlay_name = str(overlay_name or "").strip()
        if not overlay_name:
            raise ValueError("overlay_name is required.")

        if overlay_id:
            _validate_public_id(overlay_id, "overlay_id")
        else:
            overlay_id = _new_id("overlay")

        recurrence_type = str(recurrence_type or "manual").strip().lower()
        if recurrence_type not in VALID_RECURRENCE_TYPES:
            raise ValueError(f"Invalid recurrence_type. Valid values: {sorted(VALID_RECURRENCE_TYPES)}")

        priority = str(priority or "normal").strip().lower()
        if priority not in VALID_OVERLAY_PRIORITIES:
            raise ValueError(f"Invalid priority. Valid values: {sorted(VALID_OVERLAY_PRIORITIES)}")

        overlay_payload = _ensure_dict(payload, "payload")
        if not self.config.allow_custom_overlay_payload:
            overlay_payload = self._sanitize_overlay_payload(overlay_payload)

        return RecurringOverlay(
            overlay_id=overlay_id,
            overlay_name=overlay_name,
            user_id=ctx["user_id"],
            workspace_id=ctx["workspace_id"],
            overlay_type=str(overlay_type or "card"),
            recurrence_type=recurrence_type,
            schedule=_ensure_dict(schedule, "schedule"),
            trigger_context=_ensure_dict(trigger_context, "trigger_context"),
            anchor=self._validate_anchor(anchor),
            layout_name=layout_name,
            priority=priority,
            payload=_deepcopy_json_safe(overlay_payload),
            device_profile=device_profile,
            context_tags=self._normalize_tags(context_tags),
            enabled=_normalize_bool(enabled, True),
        )

    def _validate_anchor(self, anchor: str) -> str:
        anchor = str(anchor or "front_center").strip().lower()
        if anchor not in VALID_ANCHORS:
            if self.config.allow_custom_anchor:
                return "custom"
            raise ValueError(f"Invalid anchor. Valid values: {sorted(VALID_ANCHORS)}")
        return anchor

    def _validate_safe_zone_type(self, zone_type: str) -> str:
        zone_type = str(zone_type or "no_overlay").strip().lower()
        if zone_type not in VALID_SAFE_ZONE_TYPES:
            if self.config.allow_custom_safe_zone_type:
                return "custom"
            raise ValueError(f"Invalid zone_type. Valid values: {sorted(VALID_SAFE_ZONE_TYPES)}")
        return zone_type

    def _validate_vector(
        self,
        vector: Mapping[str, Any],
        field_name: str,
    ) -> Dict[str, float]:
        vector = _ensure_dict(vector, field_name)

        return {
            "x": _safe_float(vector.get("x", 0.0), f"{field_name}.x", minimum=-100000.0, maximum=100000.0),
            "y": _safe_float(vector.get("y", 0.0), f"{field_name}.y", minimum=-100000.0, maximum=100000.0),
            "z": _safe_float(vector.get("z", 0.0), f"{field_name}.z", minimum=-100000.0, maximum=100000.0),
        }

    def _validate_rotation(
        self,
        rotation: Mapping[str, Any],
    ) -> Dict[str, float]:
        rotation = _ensure_dict(rotation, "rotation")

        return {
            "pitch": _safe_float(rotation.get("pitch", 0.0), "rotation.pitch", minimum=-360.0, maximum=360.0),
            "yaw": _safe_float(rotation.get("yaw", 0.0), "rotation.yaw", minimum=-360.0, maximum=360.0),
            "roll": _safe_float(rotation.get("roll", 0.0), "rotation.roll", minimum=-360.0, maximum=360.0),
        }

    def _normalize_tags(self, tags: Optional[Sequence[str]]) -> List[str]:
        if tags is None:
            return []

        if not isinstance(tags, Sequence) or isinstance(tags, (str, bytes)):
            raise ValueError("context_tags must be a sequence of strings.")

        clean_tags: List[str] = []
        seen = set()

        for tag in tags:
            clean = str(tag).strip().lower()
            if not clean:
                continue
            clean = re.sub(r"[^a-zA-Z0-9._:-]+", "_", clean)[:80]
            if clean and clean not in seen:
                clean_tags.append(clean)
                seen.add(clean)

        return clean_tags

    def _sanitize_overlay_payload(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        allowed_keys = {
            "title",
            "message",
            "icon",
            "color",
            "cta",
            "route",
            "metadata",
        }
        return {key: value for key, value in payload.items() if key in allowed_keys}

    # -------------------------------------------------------------------------
    # Storage backend
    # -------------------------------------------------------------------------

    def _empty_store(self, ctx: Mapping[str, Any]) -> Dict[str, Any]:
        return {
            "store_metadata": {
                "agent": "HologramMemory",
                "user_id": ctx["user_id"],
                "workspace_id": ctx["workspace_id"],
                "created_at": _utc_now_iso(),
                "updated_at": _utc_now_iso(),
                "schema_version": "1.0",
            },
            "layout_preferences": {},
            "safe_zones": {},
            "recurring_overlays": {},
            "device_profiles": {},
        }

    def _load_store(self, ctx: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Load current user/workspace memory store.

        Supports custom storage_backend methods:
            - load_hologram_memory(context)
            - load(context)
        """

        if self.storage_backend is not None:
            if hasattr(self.storage_backend, "load_hologram_memory"):
                loaded = self.storage_backend.load_hologram_memory(dict(ctx))
                return self._normalize_store(ctx, loaded)
            if hasattr(self.storage_backend, "load"):
                loaded = self.storage_backend.load(dict(ctx))
                return self._normalize_store(ctx, loaded)
            if callable(self.storage_backend):
                loaded = self.storage_backend("load", dict(ctx), None)
                return self._normalize_store(ctx, loaded)

        if not self.config.use_local_json_storage:
            return self._empty_store(ctx)

        path = self._store_path(ctx)
        if not path.exists():
            return self._empty_store(ctx)

        try:
            with path.open("r", encoding="utf-8") as handle:
                loaded = json.load(handle)
            return self._normalize_store(ctx, loaded)
        except Exception:
            self.logger.exception("Failed to load hologram memory store. Rebuilding empty store.")
            return self._empty_store(ctx)

    def _save_store(self, ctx: Mapping[str, Any], store: Mapping[str, Any]) -> None:
        """
        Save current user/workspace memory store.
        """

        normalized = self._normalize_store(ctx, store)
        normalized["store_metadata"]["updated_at"] = _utc_now_iso()

        if self.storage_backend is not None:
            if hasattr(self.storage_backend, "save_hologram_memory"):
                self.storage_backend.save_hologram_memory(dict(ctx), normalized)
                return
            if hasattr(self.storage_backend, "save"):
                self.storage_backend.save(dict(ctx), normalized)
                return
            if callable(self.storage_backend):
                self.storage_backend("save", dict(ctx), normalized)
                return

        if not self.config.use_local_json_storage:
            return

        path = self._store_path(ctx)
        path.parent.mkdir(parents=True, exist_ok=True)

        temp_path = path.with_suffix(".tmp")
        with temp_path.open("w", encoding="utf-8") as handle:
            json.dump(normalized, handle, ensure_ascii=False, indent=2, default=str)
        temp_path.replace(path)

    def _store_path(self, ctx: Mapping[str, Any]) -> Path:
        root = Path(self.config.storage_root).resolve()
        workspace_id = _safe_slug(ctx.get("workspace_id"), "workspace")
        user_id = _safe_slug(ctx.get("user_id"), "user")
        return root / workspace_id / f"{user_id}.json"

    def _normalize_store(
        self,
        ctx: Mapping[str, Any],
        store: Optional[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        if not isinstance(store, Mapping):
            return self._empty_store(ctx)

        clean = dict(store)

        metadata = dict(clean.get("store_metadata") or {})
        metadata["agent"] = "HologramMemory"
        metadata["user_id"] = ctx["user_id"]
        metadata["workspace_id"] = ctx["workspace_id"]
        metadata.setdefault("created_at", _utc_now_iso())
        metadata.setdefault("updated_at", _utc_now_iso())
        metadata.setdefault("schema_version", "1.0")

        clean["store_metadata"] = metadata

        for section in ["layout_preferences", "safe_zones", "recurring_overlays", "device_profiles"]:
            if not isinstance(clean.get(section), Mapping):
                clean[section] = {}
            else:
                clean[section] = dict(clean[section])

        return clean

    def _validate_snapshot_for_current_context(
        self,
        ctx: Mapping[str, Any],
        snapshot: Mapping[str, Any],
    ) -> None:
        """
        Ensure imported records cannot claim another user/workspace.
        """

        for section in ["layout_preferences", "safe_zones", "recurring_overlays", "device_profiles"]:
            records = snapshot.get(section, {})
            if not isinstance(records, Mapping):
                continue

            for record_id, record in records.items():
                if not isinstance(record, Mapping):
                    continue

                record_user = record.get("user_id")
                record_workspace = record.get("workspace_id")

                if record_user and str(record_user) != str(ctx["user_id"]):
                    raise ValueError(
                        f"Snapshot record {record_id} in {section} belongs to another user."
                    )

                if record_workspace and str(record_workspace) != str(ctx["workspace_id"]):
                    raise ValueError(
                        f"Snapshot record {record_id} in {section} belongs to another workspace."
                    )

    # -------------------------------------------------------------------------
    # Filtering and summaries
    # -------------------------------------------------------------------------

    def _filter_records(
        self,
        records: Sequence[Mapping[str, Any]],
        enabled_only: bool = False,
        device_profile: Optional[str] = None,
        context_tags: Optional[Sequence[str]] = None,
    ) -> List[Dict[str, Any]]:
        filtered: List[Dict[str, Any]] = []

        requested_tags = set(self._normalize_tags(context_tags))

        for record in records:
            item = dict(record)

            if enabled_only and item.get("enabled") is not True:
                continue

            if device_profile:
                record_device = item.get("device_profile") or item.get("profile_name") or item.get("profile_id")
                if record_device and record_device != device_profile:
                    continue

            if requested_tags:
                record_tags = set(self._normalize_tags(item.get("context_tags") or []))
                if record_tags and not requested_tags.intersection(record_tags):
                    continue

            filtered.append(_deepcopy_json_safe(item))

        return filtered

    def _store_counts(self, store: Mapping[str, Any]) -> Dict[str, int]:
        return {
            "layout_preferences": len(store.get("layout_preferences", {}) or {}),
            "safe_zones": len(store.get("safe_zones", {}) or {}),
            "recurring_overlays": len(store.get("recurring_overlays", {}) or {}),
            "device_profiles": len(store.get("device_profiles", {}) or {}),
        }

    # -------------------------------------------------------------------------
    # Operation finalization
    # -------------------------------------------------------------------------

    def _after_operation(
        self,
        ctx: Mapping[str, Any],
        operation: str,
        result: Mapping[str, Any],
        memory_type: Optional[str] = None,
    ) -> None:
        """
        Send audit, dashboard event, verification payload, and memory payload.
        """

        event = {
            "event_type": "hologram_memory_operation_completed",
            "operation": operation,
            "memory_type": memory_type,
            "success": bool(result.get("success")),
            "message": result.get("message"),
            "context": {
                "user_id": ctx.get("user_id"),
                "workspace_id": ctx.get("workspace_id"),
                "actor_id": ctx.get("actor_id"),
                "request_id": ctx.get("request_id"),
            },
            "result_summary": self._result_summary(result),
            "error": result.get("error"),
            "created_at": _utc_now_iso(),
        }

        self._log_audit_event(event)
        self._emit_agent_event(event)

        if self.config.verification_payload_enabled:
            verification_payload = self._prepare_verification_payload(
                context=ctx,
                operation=operation,
                result=result,
                memory_type=memory_type,
            )
            self._send_optional_payload(self.verification_client, verification_payload, "verification")

        if self.config.memory_payload_enabled:
            memory_payload = self._prepare_memory_payload(
                context=ctx,
                operation=operation,
                result=result,
                memory_type=memory_type,
            )
            self._send_optional_payload(self.memory_client, memory_payload, "memory")

    def _result_summary(self, result: Mapping[str, Any]) -> Dict[str, Any]:
        data = result.get("data") if isinstance(result.get("data"), Mapping) else {}

        keys = [
            "memory_type",
            "layout_id",
            "layout_name",
            "zone_id",
            "zone_name",
            "overlay_id",
            "overlay_name",
            "profile_id",
            "profile_name",
            "count",
            "counts",
            "scope",
        ]

        return {key: data.get(key) for key in keys if key in data}

    def _send_optional_payload(
        self,
        client: Optional[Any],
        payload: Mapping[str, Any],
        client_name: str,
    ) -> None:
        if client is None:
            return

        try:
            if hasattr(client, "record"):
                client.record(dict(payload))
            elif hasattr(client, "store"):
                client.store(dict(payload))
            elif hasattr(client, "submit"):
                client.submit(dict(payload))
            elif callable(client):
                client(dict(payload))
        except Exception as exc:
            self.logger.warning("Failed to send %s payload: %s", client_name, exc)


# =============================================================================
# Agent Loader / Registry helpers
# =============================================================================

def create_hologram_memory(
    config: Optional[Union[HologramMemoryConfig, Mapping[str, Any]]] = None,
    **kwargs: Any,
) -> HologramMemory:
    """
    Factory for Agent Loader / Agent Registry.
    """

    return HologramMemory(config=config, **kwargs)


def get_agent_manifest() -> Dict[str, Any]:
    """
    Static manifest for Master Agent, Agent Router, Agent Loader, and Registry.
    """

    return {
        "agent": "HologramMemory",
        "module": "hologram_agent",
        "file_path": "agents/super_agents/hologram_agent/hologram_memory.py",
        "class_name": "HologramMemory",
        "factory": "create_hologram_memory",
        "purpose": "Stores AR layout preferences, safe zones, recurring overlays.",
        "supported_memory_types": sorted(SUPPORTED_MEMORY_TYPES),
        "requires_context": ["user_id", "workspace_id"],
        "safe_to_import": True,
        "public_methods": [
            "health_check",
            "get_capabilities",
            "save_layout_preference",
            "get_layout_preference",
            "list_layout_preferences",
            "delete_layout_preference",
            "save_safe_zone",
            "get_safe_zone",
            "list_safe_zones",
            "delete_safe_zone",
            "save_recurring_overlay",
            "get_recurring_overlay",
            "list_recurring_overlays",
            "delete_recurring_overlay",
            "mark_overlay_rendered",
            "save_device_profile",
            "get_device_profile",
            "list_device_profiles",
            "delete_device_profile",
            "get_context_memory",
            "export_memory_snapshot",
            "import_memory_snapshot",
            "clear_user_memory",
            "clear_workspace_memory",
        ],
        "compatibility_hooks": [
            "_validate_task_context",
            "_requires_security_check",
            "_request_security_approval",
            "_prepare_verification_payload",
            "_prepare_memory_payload",
            "_emit_agent_event",
            "_log_audit_event",
            "_safe_result",
            "_error_result",
        ],
        "completion": {
            "agent_module": "Hologram Agent",
            "file_completed": "hologram_memory.py",
            "completion_percent": "90.9%",
            "next_recommended_file": "agents/super_agents/hologram_agent/config.py",
        },
    }


__all__ = [
    "HologramMemory",
    "HologramMemoryConfig",
    "LayoutPreference",
    "SafeZone",
    "RecurringOverlay",
    "DeviceProfile",
    "create_hologram_memory",
    "get_agent_manifest",
]


# =============================================================================
# Completion tracking
# =============================================================================
#
# Agent/Module: Hologram Agent
# File Completed: hologram_memory.py
# Completion: 90.9%
# Completed Files: ['hologram_agent.py', 'ar_overlay.py', 'spatial_mapper.py', 'gesture_bridge.py', 'real_world_context.py', 'object_recognizer.py', 'navigation_overlay.py', 'notification_overlay.py', 'device_bridge.py', 'hologram_memory.py']
# Remaining Files: ['config.py']
# Next Recommended File: agents/super_agents/hologram_agent/config.py
# FILE COMPLETE