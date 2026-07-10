"""
agents/security_agent/emergency_lock.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
Security Agent - Emergency Lock

Purpose:
    Kill switch to stop all agents, freeze automation, and lock sensitive apps.

Security model:
    - Emergency activation fails closed.
    - Unlock/deactivation requires stronger authorization than activation.
    - Every operation is tenant-scoped using user_id and workspace_id.
    - Platform-wide locks are restricted to explicitly authorized system roles.
    - This helper coordinates registered agents and adapters; it does not kill
      operating-system processes directly.
    - Emergency state is persisted atomically so application restarts do not
      silently bypass an active lock.
    - Unavailable components are recorded as failures instead of being assumed
      safe.
    - New task admission can be checked synchronously through guard_action().

Architecture connections:
    - Master Agent:
        Calls activate(), deactivate(), get_status(), or guard_action().
    - Agent Router:
        Calls guard_action() before dispatching any task.
    - Agent Registry:
        Registers stoppable agents through register_agent().
    - Workflow Agent:
        Registers automation controllers through register_automation_controller().
    - App Lock / System Agent:
        Registers sensitive application lock adapters through register_sensitive_app().
    - Security Agent:
        Provides approval, permission, biometric, policy, and risk decisions.
    - Verification Agent:
        Receives verification payloads for every completed transition.
    - Memory Agent:
        Receives safe event summaries without storing secrets.
    - Dashboard / FastAPI:
        Uses structured dict/JSON-style responses from all public methods.
    - Audit Logger:
        Receives activation, denial, failure, unlock, and component result events.

No external dependency is required.
No secret is hardcoded.
No raw destructive OS command is executed.
"""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import hmac
import inspect
import json
import logging
import os
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    Iterator,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Protocol,
    Sequence,
    Set,
    Tuple,
    Union,
)


# =============================================================================
# Import-safe William/Jarvis compatibility
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Import-safe fallback BaseAgent.

        The real William BaseAgent can replace this automatically when available.
        """

        agent_name = "BaseAgent"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get(
                "agent_name",
                getattr(self, "agent_name", self.__class__.__name__),
            )
            self.agent_id = kwargs.get(
                "agent_id",
                self.agent_name.lower().replace(" ", "_"),
            )
            self.logger = kwargs.get(
                "logger",
                logging.getLogger(self.agent_name),
            )

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback BaseAgent event %s: %s", event_name, payload)

        def log_audit(self, event_name: str, payload: Dict[str, Any]) -> None:
            self.logger.info("Fallback BaseAgent audit %s: %s", event_name, payload)


# =============================================================================
# Constants
# =============================================================================

EMERGENCY_LOCK_SCHEMA_VERSION = "1.0"
DEFAULT_STATE_ROOT = "storage/security/emergency_lock"
DEFAULT_COMPONENT_TIMEOUT_SECONDS = 10.0
DEFAULT_MAX_REASON_LENGTH = 2_000
DEFAULT_MAX_COMPONENTS = 1_000
DEFAULT_HISTORY_LIMIT = 250

GLOBAL_SCOPE_USER_ID = "__platform__"
GLOBAL_SCOPE_WORKSPACE_ID = "__global__"

SYSTEM_ADMIN_ROLES: Set[str] = {
    "system_admin",
    "platform_admin",
    "super_admin",
    "security_admin",
}

WORKSPACE_ACTIVATION_ROLES: Set[str] = {
    "owner",
    "workspace_owner",
    "admin",
    "workspace_admin",
    "security_admin",
    "incident_responder",
}

WORKSPACE_UNLOCK_ROLES: Set[str] = {
    "owner",
    "workspace_owner",
    "security_admin",
}

ACTIVATION_PERMISSIONS: Set[str] = {
    "security:emergency_lock:activate",
    "security:incident:respond",
    "security:admin",
}

UNLOCK_PERMISSIONS: Set[str] = {
    "security:emergency_lock:deactivate",
    "security:emergency_lock:unlock",
    "security:admin",
}

GLOBAL_ACTIVATION_PERMISSIONS: Set[str] = {
    "security:emergency_lock:global_activate",
    "security:platform:lock",
    "security:admin",
}

GLOBAL_UNLOCK_PERMISSIONS: Set[str] = {
    "security:emergency_lock:global_deactivate",
    "security:platform:unlock",
    "security:admin",
}

DEFAULT_ALLOWED_DURING_LOCK: Set[str] = {
    "security.emergency_lock.status",
    "security.emergency_lock.activate",
    "security.emergency_lock.deactivate",
    "security.emergency_lock.unlock",
    "security.incident.report",
    "security.audit.read",
    "security.verification.submit",
    "security.health.read",
    "security.session.logout",
    "system.health.read",
    "system.shutdown.safe",
}

SENSITIVE_APP_CATEGORIES: Set[str] = {
    "banking",
    "finance",
    "payments",
    "email",
    "messaging",
    "browser",
    "terminal",
    "developer_tools",
    "cloud_console",
    "password_manager",
    "identity",
    "administration",
    "file_manager",
    "crm",
    "billing",
    "call",
}


# =============================================================================
# Enumerations
# =============================================================================

class EmergencyLevel(str, Enum):
    """
    Emergency severity and breadth.

    RESTRICTED:
        Block sensitive actions and freeze selected automation.

    WORKSPACE:
        Stop/freeze all registered components for a workspace.

    PLATFORM:
        Stop/freeze all registered components platform-wide.
    """

    RESTRICTED = "restricted"
    WORKSPACE = "workspace"
    PLATFORM = "platform"


class EmergencyStatus(str, Enum):
    """
    Lifecycle state of an emergency lock.
    """

    INACTIVE = "inactive"
    ACTIVATING = "activating"
    ACTIVE = "active"
    PARTIAL = "partial"
    DEACTIVATING = "deactivating"
    FAILED = "failed"


class ComponentType(str, Enum):
    AGENT = "agent"
    AUTOMATION = "automation"
    SENSITIVE_APP = "sensitive_app"
    TASK_QUEUE = "task_queue"
    ROUTER = "router"
    SESSION = "session"
    CUSTOM = "custom"


class ComponentAction(str, Enum):
    STOP = "stop"
    FREEZE = "freeze"
    LOCK = "lock"
    CANCEL = "cancel"
    RESUME = "resume"
    UNLOCK = "unlock"
    START = "start"


# =============================================================================
# Protocols
# =============================================================================

class EventEmitterProtocol(Protocol):
    def __call__(self, event_name: str, payload: Dict[str, Any]) -> Any:
        ...


class ComponentCallbackProtocol(Protocol):
    def __call__(self, payload: Dict[str, Any]) -> Any:
        ...


# =============================================================================
# Data models
# =============================================================================

@dataclass(frozen=True)
class EmergencyContext:
    """
    Validated SaaS task context.

    A platform lock still carries a requesting user's original tenant context,
    but its state scope is stored under the reserved platform/global identifiers.
    """

    user_id: str
    workspace_id: str
    actor_id: Optional[str] = None
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    task_id: Optional[str] = None
    session_id: Optional[str] = None
    source_agent: str = "security_agent"
    source_channel: str = "internal"
    roles: Tuple[str, ...] = field(default_factory=tuple)
    permissions: Tuple[str, ...] = field(default_factory=tuple)
    ip_address: Optional[str] = None
    device_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "actor_id": self.actor_id,
            "request_id": self.request_id,
            "task_id": self.task_id,
            "session_id": self.session_id,
            "source_agent": self.source_agent,
            "source_channel": self.source_channel,
            "roles": list(self.roles),
            "permissions": list(self.permissions),
            "ip_address": self.ip_address,
            "device_id": self.device_id,
        }


@dataclass
class EmergencyLockConfig:
    """
    Runtime configuration.

    fail_closed:
        If state cannot be read safely, guard_action() blocks execution.

    require_security_approval_for_activation:
        Allows emergency activation to be subjected to the central approval
        mechanism. Role/permission checks still always apply.

    require_security_approval_for_unlock:
        Unlock is high risk and should normally remain True.

    require_biometric_for_unlock:
        Passed as a requirement to the Security/Biometric Agent adapter.

    auto_snapshot_before_lock:
        Requests a Memory Agent snapshot through a callback, when registered.

    persist_state:
        Writes lock state to tenant-isolated JSON files.

    unlock_on_component_failure:
        Should remain False. If False, failed component unlock attempts keep the
        emergency state partial/active rather than falsely reporting success.
    """

    state_root: Union[str, Path] = DEFAULT_STATE_ROOT
    fail_closed: bool = True
    persist_state: bool = True
    require_security_approval_for_activation: bool = False
    require_security_approval_for_unlock: bool = True
    require_biometric_for_unlock: bool = True
    auto_snapshot_before_lock: bool = True
    component_timeout_seconds: float = DEFAULT_COMPONENT_TIMEOUT_SECONDS
    max_reason_length: int = DEFAULT_MAX_REASON_LENGTH
    max_components: int = DEFAULT_MAX_COMPONENTS
    history_limit: int = DEFAULT_HISTORY_LIMIT
    allow_emergency_activation_without_external_security_agent: bool = True
    unlock_on_component_failure: bool = False
    allowed_actions_during_lock: Set[str] = field(
        default_factory=lambda: set(DEFAULT_ALLOWED_DURING_LOCK)
    )

    def normalized_state_root(self) -> Path:
        return Path(self.state_root).expanduser().resolve()


@dataclass
class RegisteredComponent:
    """
    One registered stoppable/freezeable/lockable component.

    callback:
        Called when the emergency lock activates.

    release_callback:
        Called when the lock is deactivated.

    health_callback:
        Optionally verifies component state after activation/deactivation.

    scope:
        "global" means registration is available to all tenants.
        "tenant" means user_id/workspace_id matching is required.
    """

    component_id: str
    name: str
    component_type: ComponentType
    callback: ComponentCallbackProtocol
    release_callback: Optional[ComponentCallbackProtocol] = None
    health_callback: Optional[ComponentCallbackProtocol] = None
    priority: int = 100
    required: bool = True
    enabled: bool = True
    sensitive: bool = False
    scope: str = "global"
    user_id: Optional[str] = None
    workspace_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    registered_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def public_dict(self) -> Dict[str, Any]:
        return {
            "component_id": self.component_id,
            "name": self.name,
            "component_type": self.component_type.value,
            "priority": self.priority,
            "required": self.required,
            "enabled": self.enabled,
            "sensitive": self.sensitive,
            "scope": self.scope,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "metadata": copy.deepcopy(self.metadata),
            "registered_at": self.registered_at,
            "has_release_callback": self.release_callback is not None,
            "has_health_callback": self.health_callback is not None,
        }


@dataclass
class ComponentExecutionResult:
    """
    Result from one component activation/deactivation operation.
    """

    component_id: str
    component_name: str
    component_type: str
    operation: str
    success: bool
    required: bool
    started_at: str
    completed_at: str
    duration_ms: float
    message: str
    error: Optional[Dict[str, Any]] = None
    response: Any = None
    health: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EmergencyState:
    """
    Persisted state for one tenant scope or platform-global scope.
    """

    lock_id: str
    status: EmergencyStatus
    level: EmergencyLevel
    scope_user_id: str
    scope_workspace_id: str
    activated_at: Optional[str]
    activated_by: Optional[str]
    activation_request_id: Optional[str]
    reason: str
    incident_id: Optional[str] = None
    expires_at: Optional[str] = None
    automation_frozen: bool = False
    agents_stopped: bool = False
    sensitive_apps_locked: bool = False
    task_admission_blocked: bool = False
    task_queues_frozen: bool = False
    sessions_restricted: bool = False
    deactivated_at: Optional[str] = None
    deactivated_by: Optional[str] = None
    deactivation_request_id: Optional[str] = None
    activation_results: List[Dict[str, Any]] = field(default_factory=list)
    deactivation_results: List[Dict[str, Any]] = field(default_factory=list)
    failed_components: List[str] = field(default_factory=list)
    allowed_actions: List[str] = field(default_factory=list)
    generation: int = 1
    updated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    metadata: Dict[str, Any] = field(default_factory=dict)
    integrity_sha256: Optional[str] = None

    def to_dict(self, include_integrity: bool = True) -> Dict[str, Any]:
        result = {
            "lock_id": self.lock_id,
            "status": self.status.value,
            "level": self.level.value,
            "scope_user_id": self.scope_user_id,
            "scope_workspace_id": self.scope_workspace_id,
            "activated_at": self.activated_at,
            "activated_by": self.activated_by,
            "activation_request_id": self.activation_request_id,
            "reason": self.reason,
            "incident_id": self.incident_id,
            "expires_at": self.expires_at,
            "automation_frozen": self.automation_frozen,
            "agents_stopped": self.agents_stopped,
            "sensitive_apps_locked": self.sensitive_apps_locked,
            "task_admission_blocked": self.task_admission_blocked,
            "task_queues_frozen": self.task_queues_frozen,
            "sessions_restricted": self.sessions_restricted,
            "deactivated_at": self.deactivated_at,
            "deactivated_by": self.deactivated_by,
            "deactivation_request_id": self.deactivation_request_id,
            "activation_results": copy.deepcopy(self.activation_results),
            "deactivation_results": copy.deepcopy(self.deactivation_results),
            "failed_components": list(self.failed_components),
            "allowed_actions": list(self.allowed_actions),
            "generation": self.generation,
            "updated_at": self.updated_at,
            "metadata": copy.deepcopy(self.metadata),
        }
        if include_integrity:
            result["integrity_sha256"] = self.integrity_sha256
        return result

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "EmergencyState":
        return cls(
            lock_id=str(data["lock_id"]),
            status=EmergencyStatus(str(data["status"])),
            level=EmergencyLevel(str(data["level"])),
            scope_user_id=str(data["scope_user_id"]),
            scope_workspace_id=str(data["scope_workspace_id"]),
            activated_at=data.get("activated_at"),
            activated_by=data.get("activated_by"),
            activation_request_id=data.get("activation_request_id"),
            reason=str(data.get("reason", "")),
            incident_id=data.get("incident_id"),
            expires_at=data.get("expires_at"),
            automation_frozen=bool(data.get("automation_frozen", False)),
            agents_stopped=bool(data.get("agents_stopped", False)),
            sensitive_apps_locked=bool(
                data.get("sensitive_apps_locked", False)
            ),
            task_admission_blocked=bool(
                data.get("task_admission_blocked", False)
            ),
            task_queues_frozen=bool(data.get("task_queues_frozen", False)),
            sessions_restricted=bool(data.get("sessions_restricted", False)),
            deactivated_at=data.get("deactivated_at"),
            deactivated_by=data.get("deactivated_by"),
            deactivation_request_id=data.get("deactivation_request_id"),
            activation_results=list(data.get("activation_results", [])),
            deactivation_results=list(data.get("deactivation_results", [])),
            failed_components=list(data.get("failed_components", [])),
            allowed_actions=list(data.get("allowed_actions", [])),
            generation=int(data.get("generation", 1)),
            updated_at=str(
                data.get(
                    "updated_at",
                    datetime.now(timezone.utc).isoformat(),
                )
            ),
            metadata=dict(data.get("metadata", {})),
            integrity_sha256=data.get("integrity_sha256"),
        )


# =============================================================================
# EmergencyLock
# =============================================================================

class EmergencyLock(BaseAgent):
    """
    William/Jarvis emergency kill-switch coordinator.

    The class deliberately coordinates safe callbacks instead of terminating
    arbitrary operating-system processes. Registered agents, workflow engines,
    app-lock services, queues, routers, and session guards are responsible for
    their own bounded shutdown/freeze/lock operations.

    Important public methods:
        register_agent()
        register_automation_controller()
        register_sensitive_app()
        register_task_queue()
        register_router()
        register_session_guard()
        register_component()
        unregister_component()
        activate()
        deactivate()
        guard_action()
        is_locked()
        get_status()
        list_registered_components()
        reconcile()
        handle_task()
        execute()
    """

    agent_name = "EmergencyLock"
    agent_type = "security_agent_helper"
    module_name = "security_agent"
    file_path = "agents/security_agent/emergency_lock.py"
    schema_version = EMERGENCY_LOCK_SCHEMA_VERSION

    def __init__(
        self,
        security_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        event_emitter: Optional[EventEmitterProtocol] = None,
        config: Optional[Union[EmergencyLockConfig, Mapping[str, Any]]] = None,
        logger: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            agent_name=self.agent_name,
            logger=logger,
            **kwargs,
        )

        self.logger = logger or getattr(
            self,
            "logger",
            logging.getLogger(self.agent_name),
        )
        self.security_agent = security_agent
        self.verification_agent = verification_agent
        self.memory_agent = memory_agent
        self.audit_logger = audit_logger
        self.event_emitter = event_emitter
        self.config = self._normalize_config(config)

        self._registry: Dict[str, RegisteredComponent] = {}
        self._registry_lock = threading.RLock()
        self._state_lock = threading.RLock()
        self._operation_locks: Dict[str, threading.RLock] = {}
        self._operation_locks_guard = threading.RLock()
        self._memory_states: Dict[str, EmergencyState] = {}
        self._history: List[Dict[str, Any]] = []

        self.config.normalized_state_root().mkdir(
            parents=True,
            exist_ok=True,
        )

    # =========================================================================
    # Registry and compatibility metadata
    # =========================================================================

    def get_agent_metadata(self) -> Dict[str, Any]:
        """
        Return Agent Registry / Loader / Router metadata.
        """

        return self._safe_result(
            message="EmergencyLock metadata loaded.",
            data={
                "agent_name": self.agent_name,
                "agent_type": self.agent_type,
                "module_name": self.module_name,
                "file_path": self.file_path,
                "schema_version": self.schema_version,
                "capabilities": [
                    "emergency_lock.activate",
                    "emergency_lock.deactivate",
                    "emergency_lock.status",
                    "emergency_lock.guard_action",
                    "emergency_lock.freeze_automation",
                    "emergency_lock.stop_agents",
                    "emergency_lock.lock_sensitive_apps",
                    "emergency_lock.reconcile",
                ],
                "supported_levels": [item.value for item in EmergencyLevel],
                "public_methods": [
                    "register_agent",
                    "register_automation_controller",
                    "register_sensitive_app",
                    "register_task_queue",
                    "register_router",
                    "register_session_guard",
                    "register_component",
                    "unregister_component",
                    "activate",
                    "deactivate",
                    "guard_action",
                    "is_locked",
                    "get_status",
                    "list_registered_components",
                    "reconcile",
                    "handle_task",
                    "execute",
                ],
                "ready_for_registry": True,
                "ready_for_master_agent": True,
                "ready_for_fastapi": True,
                "tenant_isolated": True,
            },
            metadata={"operation": "get_agent_metadata"},
        )

    def register_agent(
        self,
        agent: Any,
        component_id: Optional[str] = None,
        name: Optional[str] = None,
        stop_callback: Optional[ComponentCallbackProtocol] = None,
        resume_callback: Optional[ComponentCallbackProtocol] = None,
        health_callback: Optional[ComponentCallbackProtocol] = None,
        priority: int = 100,
        required: bool = True,
        scope: str = "global",
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Register one agent with the emergency lock.

        Callback discovery order for activation:
            emergency_stop
            stop
            shutdown
            pause
            freeze

        Callback discovery order for release:
            emergency_resume
            resume
            start
            unfreeze

        The Security Agent itself should normally be registered as required=False
        or omitted so emergency unlock/status operations remain available.
        """

        resolved_id = component_id or self._extract_component_identifier(agent)
        resolved_name = name or self._extract_component_name(agent)

        activate_cb = stop_callback or self._discover_callback(
            agent,
            (
                "emergency_stop",
                "stop",
                "shutdown",
                "pause",
                "freeze",
            ),
        )
        release_cb = resume_callback or self._discover_callback(
            agent,
            (
                "emergency_resume",
                "resume",
                "start",
                "unfreeze",
            ),
        )
        health_cb = health_callback or self._discover_callback(
            agent,
            (
                "emergency_status",
                "health",
                "health_check",
                "get_status",
                "status",
            ),
        )

        if activate_cb is None:
            return self._error_result(
                message="Agent does not expose a compatible emergency-stop callback.",
                error_code="AGENT_STOP_CALLBACK_MISSING",
                metadata={
                    "component_id": resolved_id,
                    "component_name": resolved_name,
                },
            )

        return self.register_component(
            component_id=resolved_id,
            name=resolved_name,
            component_type=ComponentType.AGENT,
            callback=activate_cb,
            release_callback=release_cb,
            health_callback=health_cb,
            priority=priority,
            required=required,
            sensitive=False,
            scope=scope,
            user_id=user_id,
            workspace_id=workspace_id,
            metadata={
                "registered_object_type": agent.__class__.__name__,
                **(metadata or {}),
            },
        )

    def register_automation_controller(
        self,
        controller: Any,
        component_id: Optional[str] = None,
        name: Optional[str] = None,
        freeze_callback: Optional[ComponentCallbackProtocol] = None,
        resume_callback: Optional[ComponentCallbackProtocol] = None,
        health_callback: Optional[ComponentCallbackProtocol] = None,
        priority: int = 20,
        required: bool = True,
        scope: str = "global",
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Register Workflow Agent, scheduler, automation engine, or job runner.
        """

        activate_cb = freeze_callback or self._discover_callback(
            controller,
            (
                "freeze_automation",
                "freeze",
                "pause_all",
                "pause",
                "emergency_stop",
                "stop",
            ),
        )
        release_cb = resume_callback or self._discover_callback(
            controller,
            (
                "resume_automation",
                "unfreeze",
                "resume_all",
                "resume",
                "start",
            ),
        )
        health_cb = health_callback or self._discover_callback(
            controller,
            ("health", "health_check", "get_status", "status"),
        )

        if activate_cb is None:
            return self._error_result(
                message="Automation controller has no compatible freeze callback.",
                error_code="AUTOMATION_FREEZE_CALLBACK_MISSING",
            )

        return self.register_component(
            component_id=component_id
            or self._extract_component_identifier(controller),
            name=name or self._extract_component_name(controller),
            component_type=ComponentType.AUTOMATION,
            callback=activate_cb,
            release_callback=release_cb,
            health_callback=health_cb,
            priority=priority,
            required=required,
            sensitive=True,
            scope=scope,
            user_id=user_id,
            workspace_id=workspace_id,
            metadata=metadata,
        )

    def register_sensitive_app(
        self,
        app: Any,
        component_id: Optional[str] = None,
        name: Optional[str] = None,
        lock_callback: Optional[ComponentCallbackProtocol] = None,
        unlock_callback: Optional[ComponentCallbackProtocol] = None,
        health_callback: Optional[ComponentCallbackProtocol] = None,
        category: str = "administration",
        priority: int = 30,
        required: bool = True,
        scope: str = "global",
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Register AppLock adapter or a sensitive application controller.
        """

        normalized_category = str(category).strip().lower()
        activate_cb = lock_callback or self._discover_callback(
            app,
            (
                "emergency_lock",
                "lock",
                "lock_app",
                "disable_access",
                "freeze",
            ),
        )
        release_cb = unlock_callback or self._discover_callback(
            app,
            (
                "emergency_unlock",
                "unlock",
                "unlock_app",
                "enable_access",
                "unfreeze",
            ),
        )
        health_cb = health_callback or self._discover_callback(
            app,
            ("is_locked", "health", "health_check", "get_status", "status"),
        )

        if activate_cb is None:
            return self._error_result(
                message="Sensitive app has no compatible lock callback.",
                error_code="APP_LOCK_CALLBACK_MISSING",
            )

        return self.register_component(
            component_id=component_id or self._extract_component_identifier(app),
            name=name or self._extract_component_name(app),
            component_type=ComponentType.SENSITIVE_APP,
            callback=activate_cb,
            release_callback=release_cb,
            health_callback=health_cb,
            priority=priority,
            required=required,
            sensitive=True,
            scope=scope,
            user_id=user_id,
            workspace_id=workspace_id,
            metadata={
                "category": normalized_category,
                "recognized_sensitive_category": (
                    normalized_category in SENSITIVE_APP_CATEGORIES
                ),
                **(metadata or {}),
            },
        )

    def register_task_queue(
        self,
        queue: Any,
        component_id: Optional[str] = None,
        name: Optional[str] = None,
        freeze_callback: Optional[ComponentCallbackProtocol] = None,
        resume_callback: Optional[ComponentCallbackProtocol] = None,
        health_callback: Optional[ComponentCallbackProtocol] = None,
        priority: int = 10,
        required: bool = True,
        scope: str = "global",
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Register task queue or scheduler.

        Queues receive high priority so new work stops before agents are frozen.
        """

        activate_cb = freeze_callback or self._discover_callback(
            queue,
            (
                "freeze",
                "pause",
                "pause_consumers",
                "stop_consumers",
                "cancel_pending",
                "emergency_stop",
            ),
        )
        release_cb = resume_callback or self._discover_callback(
            queue,
            (
                "unfreeze",
                "resume",
                "resume_consumers",
                "start_consumers",
            ),
        )
        health_cb = health_callback or self._discover_callback(
            queue,
            ("health", "health_check", "get_status", "status"),
        )

        if activate_cb is None:
            return self._error_result(
                message="Task queue has no compatible freeze callback.",
                error_code="QUEUE_FREEZE_CALLBACK_MISSING",
            )

        return self.register_component(
            component_id=component_id or self._extract_component_identifier(queue),
            name=name or self._extract_component_name(queue),
            component_type=ComponentType.TASK_QUEUE,
            callback=activate_cb,
            release_callback=release_cb,
            health_callback=health_cb,
            priority=priority,
            required=required,
            sensitive=True,
            scope=scope,
            user_id=user_id,
            workspace_id=workspace_id,
            metadata=metadata,
        )

    def register_router(
        self,
        router: Any,
        component_id: Optional[str] = None,
        name: Optional[str] = None,
        block_callback: Optional[ComponentCallbackProtocol] = None,
        release_callback: Optional[ComponentCallbackProtocol] = None,
        health_callback: Optional[ComponentCallbackProtocol] = None,
        priority: int = 0,
        required: bool = True,
        scope: str = "global",
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Register MasterAgent Router / Agent Router admission controller.

        Routers receive the highest default activation priority.
        """

        activate_cb = block_callback or self._discover_callback(
            router,
            (
                "block_new_tasks",
                "freeze_routing",
                "pause",
                "emergency_stop",
                "stop",
            ),
        )
        release_cb = release_callback or self._discover_callback(
            router,
            (
                "allow_new_tasks",
                "resume_routing",
                "resume",
                "start",
            ),
        )
        health_cb = health_callback or self._discover_callback(
            router,
            ("health", "health_check", "get_status", "status"),
        )

        if activate_cb is None:
            return self._error_result(
                message="Router has no compatible admission-block callback.",
                error_code="ROUTER_BLOCK_CALLBACK_MISSING",
            )

        return self.register_component(
            component_id=component_id or self._extract_component_identifier(router),
            name=name or self._extract_component_name(router),
            component_type=ComponentType.ROUTER,
            callback=activate_cb,
            release_callback=release_cb,
            health_callback=health_cb,
            priority=priority,
            required=required,
            sensitive=True,
            scope=scope,
            user_id=user_id,
            workspace_id=workspace_id,
            metadata=metadata,
        )

    def register_session_guard(
        self,
        session_guard: Any,
        component_id: Optional[str] = None,
        name: Optional[str] = None,
        restrict_callback: Optional[ComponentCallbackProtocol] = None,
        release_callback: Optional[ComponentCallbackProtocol] = None,
        health_callback: Optional[ComponentCallbackProtocol] = None,
        priority: int = 15,
        required: bool = True,
        scope: str = "global",
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Register SessionGuard to invalidate or restrict risky sessions.
        """

        activate_cb = restrict_callback or self._discover_callback(
            session_guard,
            (
                "activate_emergency_restrictions",
                "restrict_sessions",
                "freeze_sessions",
                "lock_sessions",
                "emergency_lock",
            ),
        )
        release_cb = release_callback or self._discover_callback(
            session_guard,
            (
                "deactivate_emergency_restrictions",
                "release_sessions",
                "unfreeze_sessions",
                "unlock_sessions",
                "emergency_unlock",
            ),
        )
        health_cb = health_callback or self._discover_callback(
            session_guard,
            ("health", "health_check", "get_status", "status"),
        )

        if activate_cb is None:
            return self._error_result(
                message="Session guard has no compatible restriction callback.",
                error_code="SESSION_GUARD_CALLBACK_MISSING",
            )

        return self.register_component(
            component_id=component_id
            or self._extract_component_identifier(session_guard),
            name=name or self._extract_component_name(session_guard),
            component_type=ComponentType.SESSION,
            callback=activate_cb,
            release_callback=release_cb,
            health_callback=health_cb,
            priority=priority,
            required=required,
            sensitive=True,
            scope=scope,
            user_id=user_id,
            workspace_id=workspace_id,
            metadata=metadata,
        )

    def register_component(
        self,
        component_id: str,
        name: str,
        component_type: Union[ComponentType, str],
        callback: ComponentCallbackProtocol,
        release_callback: Optional[ComponentCallbackProtocol] = None,
        health_callback: Optional[ComponentCallbackProtocol] = None,
        priority: int = 100,
        required: bool = True,
        enabled: bool = True,
        sensitive: bool = False,
        scope: str = "global",
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        replace: bool = False,
    ) -> Dict[str, Any]:
        """
        Register a generic emergency-managed component.
        """

        normalized_id = self._validate_component_id(component_id)
        if normalized_id is None:
            return self._error_result(
                message="A valid component_id is required.",
                error_code="INVALID_COMPONENT_ID",
            )

        if not callable(callback):
            return self._error_result(
                message="Component callback must be callable.",
                error_code="INVALID_COMPONENT_CALLBACK",
                metadata={"component_id": component_id},
            )

        if release_callback is not None and not callable(release_callback):
            return self._error_result(
                message="release_callback must be callable when provided.",
                error_code="INVALID_RELEASE_CALLBACK",
                metadata={"component_id": component_id},
            )

        if health_callback is not None and not callable(health_callback):
            return self._error_result(
                message="health_callback must be callable when provided.",
                error_code="INVALID_HEALTH_CALLBACK",
                metadata={"component_id": component_id},
            )

        normalized_scope = str(scope).strip().lower()
        if normalized_scope not in {"global", "tenant"}:
            return self._error_result(
                message="Component scope must be 'global' or 'tenant'.",
                error_code="INVALID_COMPONENT_SCOPE",
                metadata={"component_id": component_id},
            )

        if normalized_scope == "tenant":
            if not self._valid_identifier(user_id):
                return self._error_result(
                    message="Tenant-scoped component requires valid user_id.",
                    error_code="TENANT_COMPONENT_USER_ID_REQUIRED",
                    metadata={"component_id": component_id},
                )
            if not self._valid_identifier(workspace_id):
                return self._error_result(
                    message="Tenant-scoped component requires valid workspace_id.",
                    error_code="TENANT_COMPONENT_WORKSPACE_ID_REQUIRED",
                    metadata={"component_id": component_id},
                )

        try:
            normalized_type = (
                component_type
                if isinstance(component_type, ComponentType)
                else ComponentType(str(component_type))
            )
        except ValueError:
            return self._error_result(
                message="Invalid component_type.",
                error_code="INVALID_COMPONENT_TYPE",
                metadata={
                    "component_id": component_id,
                    "supported_types": [item.value for item in ComponentType],
                },
            )

        with self._registry_lock:
            if len(self._registry) >= self.config.max_components:
                return self._error_result(
                    message="Emergency component registry limit reached.",
                    error_code="COMPONENT_REGISTRY_LIMIT_REACHED",
                )

            if normalized_id in self._registry and not replace:
                return self._error_result(
                    message="Component is already registered.",
                    error_code="COMPONENT_ALREADY_REGISTERED",
                    metadata={"component_id": normalized_id},
                )

            component = RegisteredComponent(
                component_id=normalized_id,
                name=str(name).strip() or normalized_id,
                component_type=normalized_type,
                callback=callback,
                release_callback=release_callback,
                health_callback=health_callback,
                priority=int(priority),
                required=bool(required),
                enabled=bool(enabled),
                sensitive=bool(sensitive),
                scope=normalized_scope,
                user_id=str(user_id) if user_id is not None else None,
                workspace_id=(
                    str(workspace_id) if workspace_id is not None else None
                ),
                metadata=self._safe_json_data(metadata or {}),
            )
            self._registry[normalized_id] = component

        self._emit_agent_event(
            "security.emergency_lock.component_registered",
            {"component": component.public_dict()},
        )

        return self._safe_result(
            message="Emergency-managed component registered.",
            data={"component": component.public_dict()},
            metadata={"operation": "register_component"},
        )

    def unregister_component(
        self,
        component_id: str,
    ) -> Dict[str, Any]:
        """
        Remove a component from the emergency registry.

        This does not unlock or resume the component.
        """

        normalized_id = self._validate_component_id(component_id)
        if normalized_id is None:
            return self._error_result(
                message="A valid component_id is required.",
                error_code="INVALID_COMPONENT_ID",
            )

        with self._registry_lock:
            component = self._registry.pop(normalized_id, None)

        if component is None:
            return self._error_result(
                message="Component is not registered.",
                error_code="COMPONENT_NOT_FOUND",
                metadata={"component_id": normalized_id},
            )

        self._emit_agent_event(
            "security.emergency_lock.component_unregistered",
            {"component": component.public_dict()},
        )

        return self._safe_result(
            message="Component unregistered.",
            data={"component": component.public_dict()},
            metadata={"operation": "unregister_component"},
        )

    def list_registered_components(
        self,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        List global components and optionally matching tenant components.
        """

        with self._registry_lock:
            components = list(self._registry.values())

        if user_id is not None or workspace_id is not None:
            components = [
                component
                for component in components
                if component.scope == "global"
                or (
                    component.user_id == user_id
                    and component.workspace_id == workspace_id
                )
            ]

        components.sort(
            key=lambda item: (
                item.priority,
                item.component_type.value,
                item.component_id,
            )
        )

        return self._safe_result(
            message="Emergency component registry listed.",
            data={
                "components": [
                    component.public_dict() for component in components
                ],
                "count": len(components),
            },
            metadata={"operation": "list_registered_components"},
        )

    # =========================================================================
    # Emergency activation
    # =========================================================================

    def activate(
        self,
        user_id: str,
        workspace_id: str,
        reason: str,
        actor_id: Optional[str] = None,
        level: Union[EmergencyLevel, str] = EmergencyLevel.WORKSPACE,
        incident_id: Optional[str] = None,
        task_id: Optional[str] = None,
        request_id: Optional[str] = None,
        session_id: Optional[str] = None,
        source_agent: str = "security_agent",
        source_channel: str = "internal",
        roles: Optional[Iterable[str]] = None,
        permissions: Optional[Iterable[str]] = None,
        ip_address: Optional[str] = None,
        device_id: Optional[str] = None,
        allowed_actions: Optional[Iterable[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        force_reapply: bool = False,
    ) -> Dict[str, Any]:
        """
        Activate the emergency lock.

        Activation order:
            1. Validate tenant and authorization.
            2. Persist ACTIVATING state immediately.
            3. Block Router admission and task queues first.
            4. Freeze automation/session handling.
            5. Lock sensitive applications.
            6. Stop ordinary registered agents.
            7. Verify registered component states.
            8. Persist ACTIVE or PARTIAL state.
            9. Emit audit, memory, event, and verification payloads.

        An emergency action is intentionally allowed to become active even when
        some component callbacks fail. The final status becomes PARTIAL and the
        failed required components are clearly reported.
        """

        action = "security.emergency_lock.activate"
        started_at = self._utc_now()

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id,
            task_id=task_id,
            request_id=request_id,
            session_id=session_id,
            source_agent=source_agent,
            source_channel=source_channel,
            roles=roles,
            permissions=permissions,
            ip_address=ip_address,
            device_id=device_id,
            action=action,
        )
        if not context_result["success"]:
            return context_result

        context: EmergencyContext = context_result["data"]["context"]

        level_result = self._normalize_level(level, context)
        if not level_result["success"]:
            return level_result
        normalized_level: EmergencyLevel = level_result["data"]["level"]

        reason_result = self._validate_reason(reason, context)
        if not reason_result["success"]:
            return reason_result
        normalized_reason: str = reason_result["data"]["reason"]

        authorization = self._authorize_activation(
            context=context,
            level=normalized_level,
        )
        if not authorization["success"]:
            self._log_audit_event(
                action=action,
                context=context,
                details={
                    "status": "denied",
                    "reason": normalized_reason,
                    "level": normalized_level.value,
                    "authorization_error": authorization.get("error"),
                },
            )
            return authorization

        if self.config.require_security_approval_for_activation:
            approval = self._request_security_approval(
                action=action,
                context=context,
                payload={
                    "level": normalized_level.value,
                    "reason": normalized_reason,
                    "incident_id": incident_id,
                },
                required=True,
                biometric_required=False,
            )
            if not approval["success"]:
                return approval

        scope_user_id, scope_workspace_id = self._resolve_state_scope(
            context,
            normalized_level,
        )
        scope_key = self._scope_key(scope_user_id, scope_workspace_id)

        with self._operation_lock(scope_key):
            current_result = self._load_state(
                scope_user_id,
                scope_workspace_id,
            )
            current_state = current_result.get("data", {}).get("state")

            if (
                isinstance(current_state, EmergencyState)
                and current_state.status
                in {
                    EmergencyStatus.ACTIVE,
                    EmergencyStatus.PARTIAL,
                    EmergencyStatus.ACTIVATING,
                }
                and not force_reapply
            ):
                return self._safe_result(
                    message="Emergency lock is already active for this scope.",
                    data={
                        "state": current_state.to_dict(),
                        "already_active": True,
                    },
                    context=context,
                    metadata={
                        "action": action,
                        "scope_key": scope_key,
                    },
                )

            generation = (
                current_state.generation + 1
                if isinstance(current_state, EmergencyState)
                else 1
            )
            lock_id = str(uuid.uuid4())
            normalized_allowed = self._normalize_allowed_actions(
                allowed_actions
            )

            activating_state = EmergencyState(
                lock_id=lock_id,
                status=EmergencyStatus.ACTIVATING,
                level=normalized_level,
                scope_user_id=scope_user_id,
                scope_workspace_id=scope_workspace_id,
                activated_at=started_at,
                activated_by=context.actor_id,
                activation_request_id=context.request_id,
                reason=normalized_reason,
                incident_id=incident_id,
                automation_frozen=False,
                agents_stopped=False,
                sensitive_apps_locked=False,
                task_admission_blocked=True,
                task_queues_frozen=False,
                sessions_restricted=False,
                activation_results=[],
                failed_components=[],
                allowed_actions=sorted(normalized_allowed),
                generation=generation,
                updated_at=self._utc_now(),
                metadata={
                    "request_context": self._redacted_context(context),
                    "activation_metadata": self._safe_json_data(metadata or {}),
                    "authorization_method": authorization.get(
                        "data",
                        {},
                    ).get("method"),
                },
            )

            persist_result = self._save_state(activating_state)
            if not persist_result["success"]:
                return self._error_result(
                    message=(
                        "Emergency state could not be persisted; activation "
                        "aborted using fail-closed safety."
                    ),
                    error_code="EMERGENCY_STATE_PERSIST_FAILED",
                    context=context,
                    metadata={
                        "action": action,
                        "scope_key": scope_key,
                        "state_error": persist_result.get("error"),
                    },
                )

            self._emit_agent_event(
                "security.emergency_lock.activating",
                {
                    "lock_id": lock_id,
                    "level": normalized_level.value,
                    "scope_user_id": scope_user_id,
                    "scope_workspace_id": scope_workspace_id,
                    "reason": normalized_reason,
                    "incident_id": incident_id,
                    "context": self._redacted_context(context),
                },
            )

            self._log_audit_event(
                action=action,
                context=context,
                details={
                    "status": "activating",
                    "lock_id": lock_id,
                    "level": normalized_level.value,
                    "reason": normalized_reason,
                    "incident_id": incident_id,
                },
            )

            snapshot_result: Optional[Dict[str, Any]] = None
            if self.config.auto_snapshot_before_lock:
                snapshot_result = self._request_safe_memory_snapshot(
                    context=context,
                    lock_id=lock_id,
                    reason=normalized_reason,
                )

            components = self._matching_components(
                context=context,
                level=normalized_level,
            )
            execution_payload = self._build_component_payload(
                operation="activate",
                action=action,
                context=context,
                state=activating_state,
            )

            activation_results: List[ComponentExecutionResult] = []
            for component in components:
                result = self._execute_component_callback(
                    component=component,
                    operation="activate",
                    payload=execution_payload,
                )
                activation_results.append(result)

            state_flags = self._derive_activation_flags(
                activation_results,
                components,
            )
            failed_required = [
                result.component_id
                for result in activation_results
                if result.required and not result.success
            ]

            final_status = (
                EmergencyStatus.ACTIVE
                if not failed_required
                else EmergencyStatus.PARTIAL
            )

            final_state = copy.deepcopy(activating_state)
            final_state.status = final_status
            final_state.automation_frozen = state_flags["automation_frozen"]
            final_state.agents_stopped = state_flags["agents_stopped"]
            final_state.sensitive_apps_locked = state_flags[
                "sensitive_apps_locked"
            ]
            final_state.task_admission_blocked = True
            final_state.task_queues_frozen = state_flags[
                "task_queues_frozen"
            ]
            final_state.sessions_restricted = state_flags[
                "sessions_restricted"
            ]
            final_state.activation_results = [
                result.to_dict() for result in activation_results
            ]
            final_state.failed_components = failed_required
            final_state.updated_at = self._utc_now()
            final_state.metadata["snapshot_result"] = self._safe_json_data(
                snapshot_result
            )
            final_state.metadata["registered_component_count"] = len(
                components
            )

            final_persist = self._save_state(final_state)
            if not final_persist["success"]:
                # Admission remains blocked through the in-memory ACTIVATING
                # state and fail-closed guard behavior.
                self._memory_states[scope_key] = final_state
                self._log_audit_event(
                    action=action,
                    context=context,
                    details={
                        "status": "state_persist_failed_after_activation",
                        "lock_id": lock_id,
                        "failed_components": failed_required,
                    },
                )
                return self._error_result(
                    message=(
                        "Emergency callbacks were executed, but final state "
                        "persistence failed. The system remains fail-closed."
                    ),
                    error_code="EMERGENCY_FINAL_STATE_PERSIST_FAILED",
                    context=context,
                    metadata={
                        "action": action,
                        "lock_id": lock_id,
                        "state": final_state.to_dict(),
                    },
                )

            verification_payload = self._prepare_verification_payload(
                action=action,
                context=context,
                success=(final_status == EmergencyStatus.ACTIVE),
                data={
                    "state": final_state.to_dict(),
                    "component_results": [
                        result.to_dict() for result in activation_results
                    ],
                },
                error=(
                    None
                    if not failed_required
                    else {
                        "code": "PARTIAL_EMERGENCY_ACTIVATION",
                        "failed_required_components": failed_required,
                    }
                ),
            )

            memory_payload = self._prepare_memory_payload(
                action=action,
                context=context,
                data={
                    "lock_id": lock_id,
                    "level": normalized_level.value,
                    "status": final_status.value,
                    "incident_id": incident_id,
                    "reason": normalized_reason,
                    "failed_components": failed_required,
                },
            )
            self._send_memory_payload(memory_payload)
            self._send_verification_payload(verification_payload)

            completion_event = (
                "security.emergency_lock.activated"
                if final_status == EmergencyStatus.ACTIVE
                else "security.emergency_lock.partially_activated"
            )
            self._emit_agent_event(
                completion_event,
                {
                    "state": final_state.to_dict(),
                    "context": self._redacted_context(context),
                },
            )

            self._log_audit_event(
                action=action,
                context=context,
                details={
                    "status": final_status.value,
                    "lock_id": lock_id,
                    "level": normalized_level.value,
                    "failed_components": failed_required,
                    "component_count": len(components),
                },
            )

            self._append_history(
                {
                    "event": completion_event,
                    "lock_id": lock_id,
                    "scope_key": scope_key,
                    "context": self._redacted_context(context),
                    "status": final_status.value,
                    "timestamp": self._utc_now(),
                }
            )

            return self._safe_result(
                message=(
                    "Emergency lock activated successfully."
                    if final_status == EmergencyStatus.ACTIVE
                    else (
                        "Emergency lock activated with component failures. "
                        "Task admission remains blocked."
                    )
                ),
                data={
                    "state": final_state.to_dict(),
                    "component_results": [
                        result.to_dict() for result in activation_results
                    ],
                    "failed_required_components": failed_required,
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                    "snapshot_result": snapshot_result,
                    "fully_activated": (
                        final_status == EmergencyStatus.ACTIVE
                    ),
                },
                context=context,
                metadata={
                    "action": action,
                    "started_at": started_at,
                    "completed_at": self._utc_now(),
                    "scope_key": scope_key,
                },
            )

    # =========================================================================
    # Emergency deactivation
    # =========================================================================

    def deactivate(
        self,
        user_id: str,
        workspace_id: str,
        reason: str,
        actor_id: Optional[str] = None,
        level: Union[EmergencyLevel, str] = EmergencyLevel.WORKSPACE,
        task_id: Optional[str] = None,
        request_id: Optional[str] = None,
        session_id: Optional[str] = None,
        source_agent: str = "security_agent",
        source_channel: str = "internal",
        roles: Optional[Iterable[str]] = None,
        permissions: Optional[Iterable[str]] = None,
        ip_address: Optional[str] = None,
        device_id: Optional[str] = None,
        approval_token: Optional[str] = None,
        biometric_assertion: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        force: bool = False,
    ) -> Dict[str, Any]:
        """
        Deactivate and release an emergency lock.

        Unlock is intentionally stricter than activation:
            - Requires unlock role or permission.
            - Usually requires Security Agent approval.
            - Can require biometric verification.
            - Release callbacks run in reverse activation priority.
            - Required component failures leave the state PARTIAL unless force
              and policy explicitly allow a forced administrative release.
        """

        action = "security.emergency_lock.deactivate"
        started_at = self._utc_now()

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id,
            task_id=task_id,
            request_id=request_id,
            session_id=session_id,
            source_agent=source_agent,
            source_channel=source_channel,
            roles=roles,
            permissions=permissions,
            ip_address=ip_address,
            device_id=device_id,
            action=action,
        )
        if not context_result["success"]:
            return context_result

        context: EmergencyContext = context_result["data"]["context"]

        level_result = self._normalize_level(level, context)
        if not level_result["success"]:
            return level_result
        normalized_level: EmergencyLevel = level_result["data"]["level"]

        reason_result = self._validate_reason(reason, context)
        if not reason_result["success"]:
            return reason_result
        normalized_reason: str = reason_result["data"]["reason"]

        authorization = self._authorize_unlock(
            context=context,
            level=normalized_level,
        )
        if not authorization["success"]:
            self._log_audit_event(
                action=action,
                context=context,
                details={
                    "status": "denied",
                    "level": normalized_level.value,
                    "reason": normalized_reason,
                    "authorization_error": authorization.get("error"),
                },
            )
            return authorization

        scope_user_id, scope_workspace_id = self._resolve_state_scope(
            context,
            normalized_level,
        )
        scope_key = self._scope_key(scope_user_id, scope_workspace_id)

        with self._operation_lock(scope_key):
            state_result = self._load_state(
                scope_user_id,
                scope_workspace_id,
            )
            if not state_result["success"]:
                return state_result

            current_state = state_result["data"].get("state")
            if current_state is None:
                return self._safe_result(
                    message="Emergency lock is already inactive.",
                    data={
                        "already_inactive": True,
                        "state": None,
                    },
                    context=context,
                    metadata={
                        "action": action,
                        "scope_key": scope_key,
                    },
                )

            if current_state.status == EmergencyStatus.INACTIVE:
                return self._safe_result(
                    message="Emergency lock is already inactive.",
                    data={
                        "already_inactive": True,
                        "state": current_state.to_dict(),
                    },
                    context=context,
                    metadata={
                        "action": action,
                        "scope_key": scope_key,
                    },
                )

            if current_state.level != normalized_level:
                return self._error_result(
                    message="Requested unlock level does not match active lock.",
                    error_code="EMERGENCY_LOCK_LEVEL_MISMATCH",
                    context=context,
                    metadata={
                        "requested_level": normalized_level.value,
                        "active_level": current_state.level.value,
                        "lock_id": current_state.lock_id,
                    },
                )

            approval = self._request_security_approval(
                action=action,
                context=context,
                payload={
                    "lock_id": current_state.lock_id,
                    "active_level": current_state.level.value,
                    "activation_reason": current_state.reason,
                    "unlock_reason": normalized_reason,
                    "approval_token_present": bool(approval_token),
                    "biometric_assertion_present": bool(
                        biometric_assertion
                    ),
                    "force": bool(force),
                },
                required=self.config.require_security_approval_for_unlock,
                biometric_required=(
                    self.config.require_biometric_for_unlock
                ),
                approval_token=approval_token,
                biometric_assertion=biometric_assertion,
            )
            if not approval["success"]:
                self._log_audit_event(
                    action=action,
                    context=context,
                    details={
                        "status": "approval_denied",
                        "lock_id": current_state.lock_id,
                        "reason": normalized_reason,
                    },
                )
                return approval

            deactivating_state = copy.deepcopy(current_state)
            deactivating_state.status = EmergencyStatus.DEACTIVATING
            deactivating_state.deactivated_by = context.actor_id
            deactivating_state.deactivation_request_id = context.request_id
            deactivating_state.updated_at = self._utc_now()
            deactivating_state.metadata["unlock_reason"] = normalized_reason
            deactivating_state.metadata["unlock_metadata"] = (
                self._safe_json_data(metadata or {})
            )

            persist_result = self._save_state(deactivating_state)
            if not persist_result["success"]:
                return self._error_result(
                    message=(
                        "Unable to persist deactivation state. Emergency lock "
                        "remains active."
                    ),
                    error_code="EMERGENCY_DEACTIVATION_STATE_PERSIST_FAILED",
                    context=context,
                    metadata={
                        "lock_id": current_state.lock_id,
                        "state_error": persist_result.get("error"),
                    },
                )

            self._emit_agent_event(
                "security.emergency_lock.deactivating",
                {
                    "state": deactivating_state.to_dict(),
                    "context": self._redacted_context(context),
                },
            )
            self._log_audit_event(
                action=action,
                context=context,
                details={
                    "status": "deactivating",
                    "lock_id": current_state.lock_id,
                    "reason": normalized_reason,
                },
            )

            components = self._matching_components(
                context=context,
                level=normalized_level,
                reverse=True,
            )
            payload = self._build_component_payload(
                operation="deactivate",
                action=action,
                context=context,
                state=deactivating_state,
            )
            payload["unlock_reason"] = normalized_reason
            payload["force"] = bool(force)

            deactivation_results: List[ComponentExecutionResult] = []
            for component in components:
                result = self._execute_component_callback(
                    component=component,
                    operation="deactivate",
                    payload=payload,
                )
                deactivation_results.append(result)

            failed_required = [
                result.component_id
                for result in deactivation_results
                if result.required and not result.success
            ]

            can_mark_inactive = (
                not failed_required
                or (
                    force
                    and self.config.unlock_on_component_failure
                    and self._has_system_admin_authority(context)
                )
            )

            final_state = copy.deepcopy(deactivating_state)
            final_state.deactivation_results = [
                result.to_dict() for result in deactivation_results
            ]
            final_state.failed_components = failed_required
            final_state.updated_at = self._utc_now()

            if can_mark_inactive:
                final_state.status = EmergencyStatus.INACTIVE
                final_state.deactivated_at = self._utc_now()
                final_state.automation_frozen = False
                final_state.agents_stopped = False
                final_state.sensitive_apps_locked = False
                final_state.task_admission_blocked = False
                final_state.task_queues_frozen = False
                final_state.sessions_restricted = False
            else:
                final_state.status = EmergencyStatus.PARTIAL
                final_state.task_admission_blocked = True
                final_state.metadata[
                    "deactivation_failure_message"
                ] = (
                    "Required components failed to release; lock remains "
                    "fail-closed."
                )

            final_persist = self._save_state(final_state)
            if not final_persist["success"]:
                self._memory_states[scope_key] = final_state
                return self._error_result(
                    message=(
                        "Component release callbacks completed, but final "
                        "deactivation state could not be persisted. The system "
                        "remains fail-closed."
                    ),
                    error_code="EMERGENCY_UNLOCK_FINAL_PERSIST_FAILED",
                    context=context,
                    metadata={
                        "lock_id": final_state.lock_id,
                        "state": final_state.to_dict(),
                    },
                )

            verification_payload = self._prepare_verification_payload(
                action=action,
                context=context,
                success=can_mark_inactive,
                data={
                    "state": final_state.to_dict(),
                    "component_results": [
                        result.to_dict() for result in deactivation_results
                    ],
                },
                error=(
                    None
                    if can_mark_inactive
                    else {
                        "code": "PARTIAL_EMERGENCY_DEACTIVATION",
                        "failed_required_components": failed_required,
                    }
                ),
            )
            memory_payload = self._prepare_memory_payload(
                action=action,
                context=context,
                data={
                    "lock_id": final_state.lock_id,
                    "level": final_state.level.value,
                    "status": final_state.status.value,
                    "unlock_reason": normalized_reason,
                    "failed_components": failed_required,
                },
            )

            self._send_verification_payload(verification_payload)
            self._send_memory_payload(memory_payload)

            event_name = (
                "security.emergency_lock.deactivated"
                if can_mark_inactive
                else "security.emergency_lock.deactivation_failed"
            )
            self._emit_agent_event(
                event_name,
                {
                    "state": final_state.to_dict(),
                    "context": self._redacted_context(context),
                },
            )
            self._log_audit_event(
                action=action,
                context=context,
                details={
                    "status": final_state.status.value,
                    "lock_id": final_state.lock_id,
                    "failed_components": failed_required,
                    "force": bool(force),
                },
            )
            self._append_history(
                {
                    "event": event_name,
                    "lock_id": final_state.lock_id,
                    "scope_key": scope_key,
                    "context": self._redacted_context(context),
                    "status": final_state.status.value,
                    "timestamp": self._utc_now(),
                }
            )

            if not can_mark_inactive:
                return self._error_result(
                    message=(
                        "Emergency lock could not be fully deactivated because "
                        "required components failed to release."
                    ),
                    error_code="EMERGENCY_DEACTIVATION_PARTIAL",
                    context=context,
                    metadata={
                        "action": action,
                        "state": final_state.to_dict(),
                        "failed_required_components": failed_required,
                        "verification_payload": verification_payload,
                    },
                )

            return self._safe_result(
                message="Emergency lock deactivated safely.",
                data={
                    "state": final_state.to_dict(),
                    "component_results": [
                        result.to_dict() for result in deactivation_results
                    ],
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                    "fully_deactivated": True,
                },
                context=context,
                metadata={
                    "action": action,
                    "started_at": started_at,
                    "completed_at": self._utc_now(),
                    "scope_key": scope_key,
                },
            )

    # =========================================================================
    # Admission guard
    # =========================================================================

    def guard_action(
        self,
        user_id: str,
        workspace_id: str,
        action: str,
        actor_id: Optional[str] = None,
        source_agent: Optional[str] = None,
        task_id: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Determine whether an action may execute.

        Master Agent and Agent Router should call this before dispatching every
        task. The function checks both:
            - Platform-global emergency state.
            - Matching workspace emergency state.

        If state cannot be read and fail_closed=True, execution is blocked.
        """

        if not self._valid_identifier(user_id):
            return self._error_result(
                message="Valid user_id is required.",
                error_code="INVALID_USER_ID",
            )
        if not self._valid_identifier(workspace_id):
            return self._error_result(
                message="Valid workspace_id is required.",
                error_code="INVALID_WORKSPACE_ID",
            )

        normalized_action = str(action or "").strip().lower()
        if not normalized_action:
            return self._error_result(
                message="Action name is required.",
                error_code="ACTION_REQUIRED",
            )

        checked_states: List[EmergencyState] = []
        state_errors: List[Dict[str, Any]] = []

        for scope_user_id, scope_workspace_id in (
            (GLOBAL_SCOPE_USER_ID, GLOBAL_SCOPE_WORKSPACE_ID),
            (str(user_id), str(workspace_id)),
        ):
            state_result = self._load_state(
                scope_user_id,
                scope_workspace_id,
            )
            if not state_result["success"]:
                state_errors.append(
                    {
                        "scope_user_id": scope_user_id,
                        "scope_workspace_id": scope_workspace_id,
                        "error": state_result.get("error"),
                    }
                )
                continue

            state = state_result["data"].get("state")
            if isinstance(state, EmergencyState):
                checked_states.append(state)

        if state_errors and self.config.fail_closed:
            return self._error_result(
                message=(
                    "Action blocked because emergency state could not be "
                    "verified safely."
                ),
                error_code="EMERGENCY_STATE_UNAVAILABLE_FAIL_CLOSED",
                metadata={
                    "action": normalized_action,
                    "source_agent": source_agent,
                    "state_errors": state_errors,
                    "blocked": True,
                },
            )

        blocking_states = [
            state
            for state in checked_states
            if state.status
            in {
                EmergencyStatus.ACTIVE,
                EmergencyStatus.PARTIAL,
                EmergencyStatus.ACTIVATING,
                EmergencyStatus.DEACTIVATING,
                EmergencyStatus.FAILED,
            }
            and state.task_admission_blocked
        ]

        for state in blocking_states:
            allowed = set(state.allowed_actions) | set(
                self.config.allowed_actions_during_lock
            )
            if normalized_action in allowed:
                continue

            result = self._error_result(
                message="Action blocked by the William emergency lock.",
                error_code="EMERGENCY_LOCK_ACTIVE",
                metadata={
                    "blocked": True,
                    "action": normalized_action,
                    "source_agent": source_agent,
                    "task_id": task_id,
                    "request_id": request_id,
                    "actor_id": actor_id,
                    "lock_id": state.lock_id,
                    "lock_status": state.status.value,
                    "lock_level": state.level.value,
                    "scope_user_id": state.scope_user_id,
                    "scope_workspace_id": state.scope_workspace_id,
                    "incident_id": state.incident_id,
                    "reason": state.reason,
                    "metadata": self._safe_json_data(metadata or {}),
                },
            )
            self._emit_agent_event(
                "security.emergency_lock.action_blocked",
                result["metadata"],
            )
            return result

        return self._safe_result(
            message="Action allowed by emergency lock policy.",
            data={
                "allowed": True,
                "action": normalized_action,
                "active_lock_count": len(blocking_states),
            },
            metadata={
                "operation": "guard_action",
                "user_id": user_id,
                "workspace_id": workspace_id,
                "state_errors": state_errors,
            },
        )

    def is_locked(
        self,
        user_id: str,
        workspace_id: str,
        include_platform_lock: bool = True,
    ) -> bool:
        """
        Lightweight boolean helper.

        Returns True on uncertain state when fail_closed=True.
        """

        scopes = [(str(user_id), str(workspace_id))]
        if include_platform_lock:
            scopes.insert(
                0,
                (GLOBAL_SCOPE_USER_ID, GLOBAL_SCOPE_WORKSPACE_ID),
            )

        for scope_user_id, scope_workspace_id in scopes:
            result = self._load_state(
                scope_user_id,
                scope_workspace_id,
            )
            if not result["success"]:
                if self.config.fail_closed:
                    return True
                continue

            state = result.get("data", {}).get("state")
            if (
                isinstance(state, EmergencyState)
                and state.status != EmergencyStatus.INACTIVE
                and state.task_admission_blocked
            ):
                return True

        return False

    def get_status(
        self,
        user_id: str,
        workspace_id: str,
        include_platform_status: bool = True,
    ) -> Dict[str, Any]:
        """
        Return workspace and optional global emergency status.
        """

        if not self._valid_identifier(user_id):
            return self._error_result(
                message="Valid user_id is required.",
                error_code="INVALID_USER_ID",
            )
        if not self._valid_identifier(workspace_id):
            return self._error_result(
                message="Valid workspace_id is required.",
                error_code="INVALID_WORKSPACE_ID",
            )

        workspace_result = self._load_state(
            str(user_id),
            str(workspace_id),
        )
        platform_result: Optional[Dict[str, Any]] = None

        if include_platform_status:
            platform_result = self._load_state(
                GLOBAL_SCOPE_USER_ID,
                GLOBAL_SCOPE_WORKSPACE_ID,
            )

        workspace_state = workspace_result.get("data", {}).get("state")
        platform_state = (
            platform_result.get("data", {}).get("state")
            if platform_result
            else None
        )

        effective_locked = any(
            isinstance(state, EmergencyState)
            and state.status != EmergencyStatus.INACTIVE
            and state.task_admission_blocked
            for state in (workspace_state, platform_state)
        )

        read_errors = []
        if not workspace_result["success"]:
            read_errors.append(workspace_result.get("error"))
        if platform_result and not platform_result["success"]:
            read_errors.append(platform_result.get("error"))

        if read_errors and self.config.fail_closed:
            effective_locked = True

        return self._safe_result(
            message="Emergency lock status loaded.",
            data={
                "effective_locked": effective_locked,
                "workspace_state": (
                    workspace_state.to_dict()
                    if isinstance(workspace_state, EmergencyState)
                    else None
                ),
                "platform_state": (
                    platform_state.to_dict()
                    if isinstance(platform_state, EmergencyState)
                    else None
                ),
                "read_errors": read_errors,
                "fail_closed": self.config.fail_closed,
            },
            metadata={
                "operation": "get_status",
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )

    # =========================================================================
    # Reconciliation
    # =========================================================================

    def reconcile(
        self,
        user_id: str,
        workspace_id: str,
        actor_id: Optional[str] = None,
        level: Union[EmergencyLevel, str] = EmergencyLevel.WORKSPACE,
        roles: Optional[Iterable[str]] = None,
        permissions: Optional[Iterable[str]] = None,
        request_id: Optional[str] = None,
        task_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Re-run health checks and reapply emergency callbacks when needed.

        This is useful after:
            - Application restart.
            - Agent Registry reload.
            - New component registration while a lock is active.
            - Temporary component failure.
        """

        action = "security.emergency_lock.reconcile"
        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id,
            request_id=request_id,
            task_id=task_id,
            roles=roles,
            permissions=permissions,
            action=action,
        )
        if not context_result["success"]:
            return context_result

        context: EmergencyContext = context_result["data"]["context"]
        level_result = self._normalize_level(level, context)
        if not level_result["success"]:
            return level_result
        normalized_level: EmergencyLevel = level_result["data"]["level"]

        authorization = self._authorize_activation(context, normalized_level)
        if not authorization["success"]:
            return authorization

        scope_user_id, scope_workspace_id = self._resolve_state_scope(
            context,
            normalized_level,
        )
        scope_key = self._scope_key(scope_user_id, scope_workspace_id)

        with self._operation_lock(scope_key):
            state_result = self._load_state(
                scope_user_id,
                scope_workspace_id,
            )
            if not state_result["success"]:
                return state_result

            state = state_result["data"].get("state")
            if not isinstance(state, EmergencyState):
                return self._safe_result(
                    message="No emergency lock exists to reconcile.",
                    data={"reconciled": False, "state": None},
                    context=context,
                    metadata={"action": action},
                )

            if state.status == EmergencyStatus.INACTIVE:
                return self._safe_result(
                    message="Emergency lock is inactive; reconciliation was not required.",
                    data={
                        "reconciled": False,
                        "state": state.to_dict(),
                    },
                    context=context,
                    metadata={"action": action},
                )

            components = self._matching_components(
                context=context,
                level=normalized_level,
            )
            payload = self._build_component_payload(
                operation="reconcile",
                action=action,
                context=context,
                state=state,
            )

            results: List[ComponentExecutionResult] = []
            for component in components:
                health = self._execute_health_check(component, payload)
                healthy_locked = self._health_indicates_emergency_state(
                    component,
                    health,
                )
                if healthy_locked:
                    results.append(
                        ComponentExecutionResult(
                            component_id=component.component_id,
                            component_name=component.name,
                            component_type=component.component_type.value,
                            operation="reconcile",
                            success=True,
                            required=component.required,
                            started_at=self._utc_now(),
                            completed_at=self._utc_now(),
                            duration_ms=0.0,
                            message="Component already reflects emergency state.",
                            response=None,
                            health=health,
                        )
                    )
                else:
                    results.append(
                        self._execute_component_callback(
                            component=component,
                            operation="activate",
                            payload=payload,
                        )
                    )

            failed_required = [
                result.component_id
                for result in results
                if result.required and not result.success
            ]

            state.status = (
                EmergencyStatus.ACTIVE
                if not failed_required
                else EmergencyStatus.PARTIAL
            )
            state.failed_components = failed_required
            state.activation_results.extend(
                [result.to_dict() for result in results]
            )
            state.updated_at = self._utc_now()
            state.generation += 1

            save_result = self._save_state(state)
            if not save_result["success"]:
                return save_result

            verification_payload = self._prepare_verification_payload(
                action=action,
                context=context,
                success=not failed_required,
                data={
                    "state": state.to_dict(),
                    "reconciliation_results": [
                        result.to_dict() for result in results
                    ],
                },
            )
            self._send_verification_payload(verification_payload)

            self._log_audit_event(
                action=action,
                context=context,
                details={
                    "status": state.status.value,
                    "lock_id": state.lock_id,
                    "failed_components": failed_required,
                },
            )

            return self._safe_result(
                message=(
                    "Emergency lock reconciliation completed."
                    if not failed_required
                    else (
                        "Emergency lock reconciliation completed with "
                        "component failures."
                    )
                ),
                data={
                    "reconciled": True,
                    "state": state.to_dict(),
                    "component_results": [
                        result.to_dict() for result in results
                    ],
                    "verification_payload": verification_payload,
                },
                context=context,
                metadata={"action": action},
            )

    # =========================================================================
    # Master Agent / Router execution interface
    # =========================================================================

    def handle_task(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Master Agent compatible task entry point.

        Supported actions:
            activate
            deactivate
            status
            guard
            reconcile
            list_components

        The task may provide context either at the top level or in:
            task["context"]
            task["payload"]
        """

        if not isinstance(task, Mapping):
            return self._error_result(
                message="Task must be a mapping/dict.",
                error_code="INVALID_TASK",
            )

        context = task.get("context")
        payload = task.get("payload")

        context_dict = dict(context) if isinstance(context, Mapping) else {}
        payload_dict = dict(payload) if isinstance(payload, Mapping) else {}

        merged: Dict[str, Any] = {}
        merged.update(dict(task))
        merged.update(context_dict)
        merged.update(payload_dict)

        action = str(
            task.get("action")
            or task.get("command")
            or payload_dict.get("action")
            or ""
        ).strip().lower()

        aliases = {
            "lock": "activate",
            "emergency_lock": "activate",
            "kill_switch": "activate",
            "unlock": "deactivate",
            "release": "deactivate",
            "get_status": "status",
            "check": "status",
            "guard_action": "guard",
            "list": "list_components",
        }
        action = aliases.get(action, action)

        if action == "activate":
            return self.activate(
                user_id=str(merged.get("user_id", "")),
                workspace_id=str(merged.get("workspace_id", "")),
                reason=str(merged.get("reason", "")),
                actor_id=self._optional_str(merged.get("actor_id")),
                level=merged.get("level", EmergencyLevel.WORKSPACE.value),
                incident_id=self._optional_str(merged.get("incident_id")),
                task_id=self._optional_str(merged.get("task_id")),
                request_id=self._optional_str(merged.get("request_id")),
                session_id=self._optional_str(merged.get("session_id")),
                source_agent=str(
                    merged.get("source_agent", "master_agent")
                ),
                source_channel=str(
                    merged.get("source_channel", "internal")
                ),
                roles=self._as_string_list(merged.get("roles")),
                permissions=self._as_string_list(
                    merged.get("permissions")
                ),
                ip_address=self._optional_str(merged.get("ip_address")),
                device_id=self._optional_str(merged.get("device_id")),
                allowed_actions=self._as_string_list(
                    merged.get("allowed_actions")
                ),
                metadata=self._as_dict(merged.get("metadata")),
                force_reapply=bool(merged.get("force_reapply", False)),
            )

        if action == "deactivate":
            return self.deactivate(
                user_id=str(merged.get("user_id", "")),
                workspace_id=str(merged.get("workspace_id", "")),
                reason=str(merged.get("reason", "")),
                actor_id=self._optional_str(merged.get("actor_id")),
                level=merged.get("level", EmergencyLevel.WORKSPACE.value),
                task_id=self._optional_str(merged.get("task_id")),
                request_id=self._optional_str(merged.get("request_id")),
                session_id=self._optional_str(merged.get("session_id")),
                source_agent=str(
                    merged.get("source_agent", "master_agent")
                ),
                source_channel=str(
                    merged.get("source_channel", "internal")
                ),
                roles=self._as_string_list(merged.get("roles")),
                permissions=self._as_string_list(
                    merged.get("permissions")
                ),
                ip_address=self._optional_str(merged.get("ip_address")),
                device_id=self._optional_str(merged.get("device_id")),
                approval_token=self._optional_str(
                    merged.get("approval_token")
                ),
                biometric_assertion=self._as_optional_dict(
                    merged.get("biometric_assertion")
                ),
                metadata=self._as_dict(merged.get("metadata")),
                force=bool(merged.get("force", False)),
            )

        if action == "status":
            return self.get_status(
                user_id=str(merged.get("user_id", "")),
                workspace_id=str(merged.get("workspace_id", "")),
                include_platform_status=bool(
                    merged.get("include_platform_status", True)
                ),
            )

        if action == "guard":
            return self.guard_action(
                user_id=str(merged.get("user_id", "")),
                workspace_id=str(merged.get("workspace_id", "")),
                action=str(
                    merged.get("guarded_action")
                    or merged.get("target_action")
                    or ""
                ),
                actor_id=self._optional_str(merged.get("actor_id")),
                source_agent=self._optional_str(
                    merged.get("source_agent")
                ),
                task_id=self._optional_str(merged.get("task_id")),
                request_id=self._optional_str(merged.get("request_id")),
                metadata=self._as_dict(merged.get("metadata")),
            )

        if action == "reconcile":
            return self.reconcile(
                user_id=str(merged.get("user_id", "")),
                workspace_id=str(merged.get("workspace_id", "")),
                actor_id=self._optional_str(merged.get("actor_id")),
                level=merged.get("level", EmergencyLevel.WORKSPACE.value),
                roles=self._as_string_list(merged.get("roles")),
                permissions=self._as_string_list(
                    merged.get("permissions")
                ),
                request_id=self._optional_str(merged.get("request_id")),
                task_id=self._optional_str(merged.get("task_id")),
            )

        if action == "list_components":
            return self.list_registered_components(
                user_id=self._optional_str(merged.get("user_id")),
                workspace_id=self._optional_str(
                    merged.get("workspace_id")
                ),
            )

        return self._error_result(
            message="Unsupported EmergencyLock task action.",
            error_code="UNSUPPORTED_EMERGENCY_LOCK_ACTION",
            metadata={
                "requested_action": action,
                "supported_actions": [
                    "activate",
                    "deactivate",
                    "status",
                    "guard",
                    "reconcile",
                    "list_components",
                ],
            },
        )

    def execute(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        BaseAgent-style alias for handle_task().
        """

        return self.handle_task(task)

    # =========================================================================
    # Required compatibility hooks
    # =========================================================================

    def _validate_task_context(
        self,
        user_id: Optional[str],
        workspace_id: Optional[str],
        actor_id: Optional[str] = None,
        request_id: Optional[str] = None,
        task_id: Optional[str] = None,
        session_id: Optional[str] = None,
        source_agent: str = "security_agent",
        source_channel: str = "internal",
        roles: Optional[Iterable[str]] = None,
        permissions: Optional[Iterable[str]] = None,
        ip_address: Optional[str] = None,
        device_id: Optional[str] = None,
        action: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Validate SaaS user/workspace context.
        """

        if not self._valid_identifier(user_id):
            return self._error_result(
                message="Valid user_id is required.",
                error_code="INVALID_USER_ID",
                metadata={"action": action},
            )

        if not self._valid_identifier(workspace_id):
            return self._error_result(
                message="Valid workspace_id is required.",
                error_code="INVALID_WORKSPACE_ID",
                metadata={"action": action},
            )

        if actor_id is not None and not self._valid_identifier(actor_id):
            return self._error_result(
                message="actor_id is invalid.",
                error_code="INVALID_ACTOR_ID",
                metadata={"action": action},
            )

        context = EmergencyContext(
            user_id=str(user_id).strip(),
            workspace_id=str(workspace_id).strip(),
            actor_id=(
                str(actor_id).strip() if actor_id is not None else None
            ),
            request_id=(
                str(request_id).strip()
                if request_id
                else str(uuid.uuid4())
            ),
            task_id=str(task_id).strip() if task_id else None,
            session_id=str(session_id).strip() if session_id else None,
            source_agent=str(source_agent or "security_agent").strip(),
            source_channel=str(source_channel or "internal").strip(),
            roles=tuple(
                sorted(
                    {
                        str(role).strip().lower()
                        for role in (roles or [])
                        if str(role).strip()
                    }
                )
            ),
            permissions=tuple(
                sorted(
                    {
                        str(permission).strip().lower()
                        for permission in (permissions or [])
                        if str(permission).strip()
                    }
                )
            ),
            ip_address=str(ip_address).strip() if ip_address else None,
            device_id=str(device_id).strip() if device_id else None,
        )

        return self._safe_result(
            message="Emergency task context validated.",
            data={"context": context},
            context=context,
            metadata={"action": action},
        )

    def _requires_security_check(self, action: str) -> bool:
        """
        Emergency activation and deactivation are always security-sensitive.
        """

        normalized = str(action).strip().lower()
        return normalized in {
            "security.emergency_lock.activate",
            "security.emergency_lock.deactivate",
            "security.emergency_lock.unlock",
            "security.emergency_lock.reconcile",
        }

    def _request_security_approval(
        self,
        action: str,
        context: EmergencyContext,
        payload: Dict[str, Any],
        required: bool = True,
        biometric_required: bool = False,
        approval_token: Optional[str] = None,
        biometric_assertion: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request approval from Security Agent / Approval Manager.

        The method supports common future William Security Agent method names.
        It never logs approval tokens or biometric material.
        """

        if not required:
            return self._safe_result(
                message="External security approval is not required.",
                data={
                    "approved": True,
                    "method": "not_required",
                },
                context=context,
                metadata={"action": action},
            )

        approval_request = {
            "action": action,
            "context": self._redacted_context(context),
            "payload": self._safe_json_data(payload),
            "requirements": {
                "explicit_approval": True,
                "biometric_required": bool(biometric_required),
                "approval_token_present": bool(approval_token),
                "biometric_assertion_present": bool(
                    biometric_assertion
                ),
            },
            "requested_at": self._utc_now(),
            "source_component": self.agent_name,
        }

        if self.security_agent is not None:
            methods = (
                "request_approval",
                "approve_action",
                "authorize_sensitive_action",
                "validate_sensitive_action",
                "authorize",
                "check_permission",
            )

            for method_name in methods:
                method = getattr(self.security_agent, method_name, None)
                if not callable(method):
                    continue

                try:
                    response = self._invoke_callable(
                        method,
                        {
                            **approval_request,
                            "approval_token": approval_token,
                            "biometric_assertion": biometric_assertion,
                        },
                    )
                    return self._normalize_approval_response(
                        response=response,
                        action=action,
                        context=context,
                    )
                except Exception as exc:
                    self.logger.exception(
                        "Security approval method %s failed.",
                        method_name,
                    )
                    return self._error_result(
                        message="Security approval service failed.",
                        error_code="SECURITY_APPROVAL_SERVICE_FAILED",
                        context=context,
                        exception=exc,
                        metadata={
                            "action": action,
                            "approval_method": method_name,
                        },
                    )

        if action == "security.emergency_lock.activate":
            if (
                self.config.allow_emergency_activation_without_external_security_agent
                and self._has_activation_authority(context)
            ):
                return self._safe_result(
                    message=(
                        "Emergency activation approved by local fail-safe "
                        "authorization policy."
                    ),
                    data={
                        "approved": True,
                        "method": "local_emergency_failsafe_policy",
                    },
                    context=context,
                    metadata={"action": action},
                )

        return self._error_result(
            message=(
                "Security approval is required, but no approving Security "
                "Agent is available."
            ),
            error_code="SECURITY_APPROVAL_REQUIRED",
            context=context,
            metadata={
                "action": action,
                "biometric_required": biometric_required,
                "security_agent_available": (
                    self.security_agent is not None
                ),
            },
        )

    def _prepare_verification_payload(
        self,
        action: str,
        context: EmergencyContext,
        success: bool,
        data: Optional[Dict[str, Any]] = None,
        error: Optional[Union[str, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent compatible payload.
        """

        return {
            "verification_id": str(uuid.uuid4()),
            "source_agent": self.agent_name,
            "source_module": self.module_name,
            "action": action,
            "success": bool(success),
            "context": self._redacted_context(context),
            "data": self._safe_json_data(data or {}),
            "error": self._safe_json_data(error),
            "checks": {
                "tenant_context_validated": True,
                "security_authorization_checked": True,
                "state_persisted": True,
                "component_results_recorded": True,
                "task_admission_guard_available": True,
                "structured_result": True,
            },
            "created_at": self._utc_now(),
        }

    def _prepare_memory_payload(
        self,
        action: str,
        context: EmergencyContext,
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare a privacy-safe Memory Agent event payload.
        """

        return {
            "memory_event_id": str(uuid.uuid4()),
            "source_agent": self.agent_name,
            "source_module": self.module_name,
            "action": action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "actor_id": context.actor_id,
            "request_id": context.request_id,
            "task_id": context.task_id,
            "data": self._safe_json_data(data or {}),
            "importance": "critical",
            "privacy_level": "workspace_private",
            "retention_class": "security_audit",
            "created_at": self._utc_now(),
        }

    def _emit_agent_event(
        self,
        event_name: str,
        payload: Dict[str, Any],
    ) -> None:
        """
        Emit event without allowing event failures to bypass safety.
        """

        safe_payload = self._safe_json_data(payload)

        try:
            if self.event_emitter is not None:
                self.event_emitter(event_name, safe_payload)
                return

            parent_emit = getattr(super(), "emit_event", None)
            if callable(parent_emit):
                parent_emit(event_name, safe_payload)
                return
        except Exception:
            self.logger.exception(
                "EmergencyLock event emission failed: %s",
                event_name,
            )

        self.logger.info(
            "EmergencyLock event %s: %s",
            event_name,
            safe_payload,
        )

    def _log_audit_event(
        self,
        action: str,
        context: EmergencyContext,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Record an immutable-style audit event through available adapters.
        """

        audit_payload = {
            "audit_id": str(uuid.uuid4()),
            "event_type": "security_emergency_lock",
            "action": action,
            "source_agent": self.agent_name,
            "context": self._redacted_context(context),
            "details": self._safe_json_data(details or {}),
            "created_at": self._utc_now(),
        }

        try:
            if self.audit_logger is not None:
                if callable(self.audit_logger):
                    self.audit_logger(audit_payload)
                    return

                for method_name in (
                    "log_event",
                    "record_event",
                    "write",
                    "log",
                    "record",
                ):
                    method = getattr(
                        self.audit_logger,
                        method_name,
                        None,
                    )
                    if callable(method):
                        self._invoke_callable(method, audit_payload)
                        return

            parent_log = getattr(super(), "log_audit", None)
            if callable(parent_log):
                parent_log(action, audit_payload)
                return
        except Exception:
            self.logger.exception(
                "EmergencyLock audit logging failed."
            )

        self.logger.warning("Emergency audit: %s", audit_payload)

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        context: Optional[EmergencyContext] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard William/Jarvis success response.
        """

        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": {
                "agent": self.agent_name,
                "module": self.module_name,
                "schema_version": self.schema_version,
                "timestamp": self._utc_now(),
                "context": (
                    self._redacted_context(context) if context else None
                ),
                **self._safe_json_data(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str,
        error_code: str = "EMERGENCY_LOCK_ERROR",
        context: Optional[EmergencyContext] = None,
        exception: Optional[BaseException] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard William/Jarvis error response.
        """

        error: Dict[str, Any] = {
            "code": error_code,
            "message": message,
        }
        if exception is not None:
            error["exception_type"] = exception.__class__.__name__
            error["exception_message"] = str(exception)

        return {
            "success": False,
            "message": message,
            "data": {},
            "error": error,
            "metadata": {
                "agent": self.agent_name,
                "module": self.module_name,
                "schema_version": self.schema_version,
                "timestamp": self._utc_now(),
                "context": (
                    self._redacted_context(context) if context else None
                ),
                **self._safe_json_data(metadata or {}),
            },
        }

    # =========================================================================
    # Authorization
    # =========================================================================

    def _authorize_activation(
        self,
        context: EmergencyContext,
        level: EmergencyLevel,
    ) -> Dict[str, Any]:
        roles = set(context.roles)
        permissions = set(context.permissions)

        if level == EmergencyLevel.PLATFORM:
            if not self._has_system_admin_authority(context):
                return self._error_result(
                    message=(
                        "Platform emergency lock requires system-level "
                        "security authority."
                    ),
                    error_code="PLATFORM_EMERGENCY_AUTHORITY_REQUIRED",
                    context=context,
                    metadata={
                        "required_roles": sorted(SYSTEM_ADMIN_ROLES),
                        "required_permissions": sorted(
                            GLOBAL_ACTIVATION_PERMISSIONS
                        ),
                    },
                )

            return self._safe_result(
                message="Platform emergency activation authorized.",
                data={
                    "authorized": True,
                    "method": "platform_role_or_permission",
                },
                context=context,
            )

        if (
            roles.intersection(WORKSPACE_ACTIVATION_ROLES)
            or permissions.intersection(ACTIVATION_PERMISSIONS)
            or self._has_system_admin_authority(context)
        ):
            return self._safe_result(
                message="Workspace emergency activation authorized.",
                data={
                    "authorized": True,
                    "method": "workspace_role_or_permission",
                },
                context=context,
            )

        return self._error_result(
            message="Actor is not authorized to activate emergency lock.",
            error_code="EMERGENCY_ACTIVATION_FORBIDDEN",
            context=context,
            metadata={
                "required_roles": sorted(WORKSPACE_ACTIVATION_ROLES),
                "required_permissions": sorted(ACTIVATION_PERMISSIONS),
            },
        )

    def _authorize_unlock(
        self,
        context: EmergencyContext,
        level: EmergencyLevel,
    ) -> Dict[str, Any]:
        roles = set(context.roles)
        permissions = set(context.permissions)

        if level == EmergencyLevel.PLATFORM:
            if not (
                roles.intersection(SYSTEM_ADMIN_ROLES)
                and permissions.intersection(GLOBAL_UNLOCK_PERMISSIONS)
            ):
                return self._error_result(
                    message=(
                        "Platform emergency unlock requires both a system "
                        "administrator role and global unlock permission."
                    ),
                    error_code="PLATFORM_UNLOCK_AUTHORITY_REQUIRED",
                    context=context,
                    metadata={
                        "required_roles": sorted(SYSTEM_ADMIN_ROLES),
                        "required_permissions": sorted(
                            GLOBAL_UNLOCK_PERMISSIONS
                        ),
                    },
                )

            return self._safe_result(
                message="Platform emergency unlock authority validated.",
                data={
                    "authorized": True,
                    "method": "platform_role_and_permission",
                },
                context=context,
            )

        role_allowed = bool(
            roles.intersection(WORKSPACE_UNLOCK_ROLES)
            or roles.intersection(SYSTEM_ADMIN_ROLES)
        )
        permission_allowed = bool(
            permissions.intersection(UNLOCK_PERMISSIONS)
        )

        if role_allowed and permission_allowed:
            return self._safe_result(
                message="Workspace emergency unlock authority validated.",
                data={
                    "authorized": True,
                    "method": "workspace_role_and_permission",
                },
                context=context,
            )

        return self._error_result(
            message=(
                "Emergency unlock requires both an authorized role and an "
                "explicit unlock permission."
            ),
            error_code="EMERGENCY_UNLOCK_FORBIDDEN",
            context=context,
            metadata={
                "required_roles": sorted(
                    WORKSPACE_UNLOCK_ROLES | SYSTEM_ADMIN_ROLES
                ),
                "required_permissions": sorted(UNLOCK_PERMISSIONS),
            },
        )

    def _has_activation_authority(
        self,
        context: EmergencyContext,
    ) -> bool:
        return bool(
            set(context.roles).intersection(
                WORKSPACE_ACTIVATION_ROLES | SYSTEM_ADMIN_ROLES
            )
            or set(context.permissions).intersection(
                ACTIVATION_PERMISSIONS | GLOBAL_ACTIVATION_PERMISSIONS
            )
        )

    def _has_system_admin_authority(
        self,
        context: EmergencyContext,
    ) -> bool:
        return bool(
            set(context.roles).intersection(SYSTEM_ADMIN_ROLES)
            or set(context.permissions).intersection(
                GLOBAL_ACTIVATION_PERMISSIONS
                | GLOBAL_UNLOCK_PERMISSIONS
            )
        )

    # =========================================================================
    # Component execution
    # =========================================================================

    def _matching_components(
        self,
        context: EmergencyContext,
        level: EmergencyLevel,
        reverse: bool = False,
    ) -> List[RegisteredComponent]:
        with self._registry_lock:
            components = [
                copy.copy(component)
                for component in self._registry.values()
                if component.enabled
            ]

        matching: List[RegisteredComponent] = []
        for component in components:
            if level == EmergencyLevel.PLATFORM:
                matching.append(component)
                continue

            if component.scope == "global":
                matching.append(component)
                continue

            if (
                component.user_id == context.user_id
                and component.workspace_id == context.workspace_id
            ):
                matching.append(component)

        if level == EmergencyLevel.RESTRICTED:
            matching = [
                component
                for component in matching
                if component.sensitive
                or component.component_type
                in {
                    ComponentType.ROUTER,
                    ComponentType.TASK_QUEUE,
                    ComponentType.AUTOMATION,
                    ComponentType.SENSITIVE_APP,
                    ComponentType.SESSION,
                }
            ]

        matching.sort(
            key=lambda component: (
                component.priority,
                component.component_type.value,
                component.component_id,
            ),
            reverse=reverse,
        )
        return matching

    def _execute_component_callback(
        self,
        component: RegisteredComponent,
        operation: str,
        payload: Dict[str, Any],
    ) -> ComponentExecutionResult:
        started_monotonic = time.monotonic()
        started_at = self._utc_now()

        callback: Optional[ComponentCallbackProtocol]
        if operation in {"activate", "reconcile"}:
            callback = component.callback
        elif operation == "deactivate":
            callback = component.release_callback
        else:
            callback = None

        if callback is None:
            completed_at = self._utc_now()
            success = not component.required
            return ComponentExecutionResult(
                component_id=component.component_id,
                component_name=component.name,
                component_type=component.component_type.value,
                operation=operation,
                success=success,
                required=component.required,
                started_at=started_at,
                completed_at=completed_at,
                duration_ms=round(
                    (time.monotonic() - started_monotonic) * 1000,
                    3,
                ),
                message=(
                    "Optional component has no release callback."
                    if success
                    else "Required component has no release callback."
                ),
                error=(
                    None
                    if success
                    else {
                        "code": "COMPONENT_RELEASE_CALLBACK_MISSING",
                        "message": (
                            "Required component does not expose a release "
                            "callback."
                        ),
                    }
                ),
            )

        component_payload = {
            **payload,
            "component": component.public_dict(),
        }

        try:
            response = self._invoke_callable(
                callback,
                component_payload,
            )
            normalized = self._normalize_component_response(response)

            health_result = self._execute_health_check(
                component,
                component_payload,
            )

            success = normalized["success"]
            if health_result is not None:
                if operation in {"activate", "reconcile"}:
                    success = success and self._health_indicates_emergency_state(
                        component,
                        health_result,
                    )
                elif operation == "deactivate":
                    success = success and self._health_indicates_released_state(
                        component,
                        health_result,
                    )

            return ComponentExecutionResult(
                component_id=component.component_id,
                component_name=component.name,
                component_type=component.component_type.value,
                operation=operation,
                success=success,
                required=component.required,
                started_at=started_at,
                completed_at=self._utc_now(),
                duration_ms=round(
                    (time.monotonic() - started_monotonic) * 1000,
                    3,
                ),
                message=normalized["message"],
                error=(
                    normalized.get("error")
                    if not success
                    else None
                ),
                response=self._safe_json_data(response),
                health=health_result,
            )
        except Exception as exc:
            self.logger.exception(
                "Emergency component operation failed: %s",
                component.component_id,
            )
            return ComponentExecutionResult(
                component_id=component.component_id,
                component_name=component.name,
                component_type=component.component_type.value,
                operation=operation,
                success=False,
                required=component.required,
                started_at=started_at,
                completed_at=self._utc_now(),
                duration_ms=round(
                    (time.monotonic() - started_monotonic) * 1000,
                    3,
                ),
                message="Component emergency callback raised an exception.",
                error={
                    "code": "COMPONENT_CALLBACK_EXCEPTION",
                    "exception_type": exc.__class__.__name__,
                    "message": str(exc),
                },
            )

    def _execute_health_check(
        self,
        component: RegisteredComponent,
        payload: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        if component.health_callback is None:
            return None

        try:
            response = self._invoke_callable(
                component.health_callback,
                payload,
            )
            normalized = self._normalize_health_response(response)
            return normalized
        except Exception as exc:
            return {
                "success": False,
                "healthy": False,
                "message": "Component health check raised an exception.",
                "error": {
                    "code": "COMPONENT_HEALTH_EXCEPTION",
                    "exception_type": exc.__class__.__name__,
                    "message": str(exc),
                },
            }

    def _invoke_callable(
        self,
        callback: Callable[..., Any],
        payload: Dict[str, Any],
    ) -> Any:
        """
        Invoke callbacks with broad compatibility.

        Supported callback forms:
            callback(payload)
            callback(**payload)
            callback()
        """

        try:
            signature = inspect.signature(callback)
            parameters = list(signature.parameters.values())
        except (TypeError, ValueError):
            return callback(payload)

        if not parameters:
            return callback()

        accepts_kwargs = any(
            parameter.kind == inspect.Parameter.VAR_KEYWORD
            for parameter in parameters
        )
        if accepts_kwargs:
            return callback(**payload)

        keyword_parameters = {
            parameter.name
            for parameter in parameters
            if parameter.kind
            in {
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                inspect.Parameter.KEYWORD_ONLY,
            }
        }

        if len(parameters) == 1:
            only_parameter = parameters[0]
            if only_parameter.name in payload:
                return callback(payload[only_parameter.name])
            return callback(payload)

        filtered = {
            key: value
            for key, value in payload.items()
            if key in keyword_parameters
        }
        if filtered:
            return callback(**filtered)

        return callback(payload)

    def _normalize_component_response(
        self,
        response: Any,
    ) -> Dict[str, Any]:
        if isinstance(response, Mapping):
            success = bool(
                response.get(
                    "success",
                    response.get(
                        "ok",
                        response.get(
                            "completed",
                            response.get("approved", False),
                        ),
                    ),
                )
            )
            return {
                "success": success,
                "message": str(
                    response.get(
                        "message",
                        (
                            "Component operation completed."
                            if success
                            else "Component operation failed."
                        ),
                    )
                ),
                "error": self._safe_json_data(response.get("error")),
            }

        if response is True:
            return {
                "success": True,
                "message": "Component operation completed.",
                "error": None,
            }

        if response is False or response is None:
            return {
                "success": False,
                "message": "Component did not confirm successful completion.",
                "error": {
                    "code": "COMPONENT_DID_NOT_CONFIRM",
                    "response": self._safe_json_data(response),
                },
            }

        return {
            "success": True,
            "message": "Component operation returned a result.",
            "error": None,
        }

    def _normalize_health_response(
        self,
        response: Any,
    ) -> Dict[str, Any]:
        if isinstance(response, Mapping):
            result = self._safe_json_data(dict(response))
            result.setdefault(
                "success",
                bool(
                    response.get(
                        "success",
                        response.get("healthy", True),
                    )
                ),
            )
            return result

        if isinstance(response, bool):
            return {
                "success": True,
                "healthy": response,
                "locked": response,
                "frozen": response,
                "stopped": response,
            }

        return {
            "success": True,
            "healthy": True,
            "raw_response": self._safe_json_data(response),
        }

    def _health_indicates_emergency_state(
        self,
        component: RegisteredComponent,
        health: Optional[Dict[str, Any]],
    ) -> bool:
        if health is None:
            return True
        if health.get("success") is False:
            return False

        keys_by_type = {
            ComponentType.AGENT: ("stopped", "paused", "frozen", "locked"),
            ComponentType.AUTOMATION: ("frozen", "paused", "stopped"),
            ComponentType.SENSITIVE_APP: ("locked", "access_disabled"),
            ComponentType.TASK_QUEUE: ("frozen", "paused", "stopped"),
            ComponentType.ROUTER: (
                "blocked",
                "routing_frozen",
                "accepting_tasks",
            ),
            ComponentType.SESSION: (
                "restricted",
                "locked",
                "frozen",
            ),
            ComponentType.CUSTOM: (
                "locked",
                "frozen",
                "stopped",
            ),
        }

        keys = keys_by_type.get(component.component_type, ())
        found = False
        for key in keys:
            if key not in health:
                continue
            found = True
            value = bool(health[key])
            if (
                component.component_type == ComponentType.ROUTER
                and key == "accepting_tasks"
            ):
                value = not value
            if value:
                return True

        if found:
            return False

        return bool(health.get("healthy", True))

    def _health_indicates_released_state(
        self,
        component: RegisteredComponent,
        health: Optional[Dict[str, Any]],
    ) -> bool:
        if health is None:
            return True
        if health.get("success") is False:
            return False

        emergency_keys = (
            "stopped",
            "paused",
            "frozen",
            "locked",
            "blocked",
            "restricted",
            "access_disabled",
            "routing_frozen",
        )
        for key in emergency_keys:
            if key in health and bool(health[key]):
                return False

        if "accepting_tasks" in health:
            return bool(health["accepting_tasks"])

        return bool(health.get("healthy", True))

    def _derive_activation_flags(
        self,
        results: Sequence[ComponentExecutionResult],
        components: Sequence[RegisteredComponent],
    ) -> Dict[str, bool]:
        successful_ids = {
            result.component_id
            for result in results
            if result.success
        }

        def type_satisfied(component_type: ComponentType) -> bool:
            selected = [
                component
                for component in components
                if component.component_type == component_type
            ]
            required = [
                component
                for component in selected
                if component.required
            ]
            if not selected:
                return False
            if required:
                return all(
                    component.component_id in successful_ids
                    for component in required
                )
            return any(
                component.component_id in successful_ids
                for component in selected
            )

        return {
            "automation_frozen": type_satisfied(
                ComponentType.AUTOMATION
            ),
            "agents_stopped": type_satisfied(ComponentType.AGENT),
            "sensitive_apps_locked": type_satisfied(
                ComponentType.SENSITIVE_APP
            ),
            "task_queues_frozen": type_satisfied(
                ComponentType.TASK_QUEUE
            ),
            "sessions_restricted": type_satisfied(
                ComponentType.SESSION
            ),
        }

    # =========================================================================
    # State persistence
    # =========================================================================

    def _save_state(
        self,
        state: EmergencyState,
    ) -> Dict[str, Any]:
        scope_key = self._scope_key(
            state.scope_user_id,
            state.scope_workspace_id,
        )

        state.updated_at = self._utc_now()
        state.integrity_sha256 = self._calculate_state_integrity(state)
        self._memory_states[scope_key] = copy.deepcopy(state)

        if not self.config.persist_state:
            return self._safe_result(
                message="Emergency state stored in memory.",
                data={"state": state},
                metadata={"scope_key": scope_key},
            )

        state_path = self._state_file_path(
            state.scope_user_id,
            state.scope_workspace_id,
        )
        state_path.parent.mkdir(parents=True, exist_ok=True)

        serialized = json.dumps(
            state.to_dict(),
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        ).encode("utf-8")

        temp_fd, temp_name = tempfile.mkstemp(
            prefix=f".{state_path.name}.",
            suffix=".tmp",
            dir=str(state_path.parent),
        )
        os.close(temp_fd)
        temp_path = Path(temp_name)

        try:
            temp_path.write_bytes(serialized)
            self._restrict_file_permissions(temp_path)
            os.replace(str(temp_path), str(state_path))
            self._restrict_file_permissions(state_path)

            return self._safe_result(
                message="Emergency state persisted.",
                data={
                    "state": state,
                    "state_path": str(state_path),
                },
                metadata={"scope_key": scope_key},
            )
        except Exception as exc:
            self.logger.exception("Failed to persist emergency state.")
            return self._error_result(
                message="Unable to persist emergency state.",
                error_code="EMERGENCY_STATE_WRITE_FAILED",
                exception=exc,
                metadata={
                    "scope_key": scope_key,
                    "state_path": str(state_path),
                },
            )
        finally:
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except OSError:
                    self.logger.debug(
                        "Unable to remove emergency temp file.",
                        exc_info=True,
                    )

    def _load_state(
        self,
        scope_user_id: str,
        scope_workspace_id: str,
    ) -> Dict[str, Any]:
        scope_key = self._scope_key(
            scope_user_id,
            scope_workspace_id,
        )

        memory_state = self._memory_states.get(scope_key)
        if isinstance(memory_state, EmergencyState):
            return self._safe_result(
                message="Emergency state loaded from memory.",
                data={"state": copy.deepcopy(memory_state)},
                metadata={"scope_key": scope_key},
            )

        if not self.config.persist_state:
            return self._safe_result(
                message="No emergency state exists.",
                data={"state": None},
                metadata={"scope_key": scope_key},
            )

        state_path = self._state_file_path(
            scope_user_id,
            scope_workspace_id,
        )
        if not state_path.exists():
            return self._safe_result(
                message="No emergency state exists.",
                data={"state": None},
                metadata={
                    "scope_key": scope_key,
                    "state_path": str(state_path),
                },
            )

        try:
            raw = json.loads(state_path.read_text(encoding="utf-8"))
            if not isinstance(raw, Mapping):
                raise ValueError("Emergency state root must be a JSON object.")

            state = EmergencyState.from_dict(raw)
            expected = state.integrity_sha256
            actual = self._calculate_state_integrity(state)

            if not expected or not hmac.compare_digest(expected, actual):
                return self._error_result(
                    message="Emergency state integrity validation failed.",
                    error_code="EMERGENCY_STATE_INTEGRITY_FAILED",
                    metadata={
                        "scope_key": scope_key,
                        "state_path": str(state_path),
                    },
                )

            if (
                state.scope_user_id != scope_user_id
                or state.scope_workspace_id != scope_workspace_id
            ):
                return self._error_result(
                    message="Emergency state tenant scope mismatch.",
                    error_code="EMERGENCY_STATE_SCOPE_MISMATCH",
                    metadata={
                        "requested_scope_user_id": scope_user_id,
                        "requested_scope_workspace_id": scope_workspace_id,
                        "stored_scope_user_id": state.scope_user_id,
                        "stored_scope_workspace_id": (
                            state.scope_workspace_id
                        ),
                    },
                )

            self._memory_states[scope_key] = copy.deepcopy(state)
            return self._safe_result(
                message="Emergency state loaded.",
                data={"state": state},
                metadata={
                    "scope_key": scope_key,
                    "state_path": str(state_path),
                },
            )
        except Exception as exc:
            self.logger.exception("Failed to load emergency state.")
            return self._error_result(
                message="Unable to load emergency state safely.",
                error_code="EMERGENCY_STATE_READ_FAILED",
                exception=exc,
                metadata={
                    "scope_key": scope_key,
                    "state_path": str(state_path),
                },
            )

    def _calculate_state_integrity(
        self,
        state: EmergencyState,
    ) -> str:
        data = state.to_dict(include_integrity=False)
        canonical = json.dumps(
            self._safe_json_data(data),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def _state_file_path(
        self,
        scope_user_id: str,
        scope_workspace_id: str,
    ) -> Path:
        root = self.config.normalized_state_root()
        user_dir = root / self._safe_path_segment(scope_user_id)
        workspace_dir = user_dir / self._safe_path_segment(
            scope_workspace_id
        )
        return (workspace_dir / "emergency_state.json").resolve()

    def _restrict_file_permissions(self, path: Path) -> None:
        try:
            os.chmod(path, 0o600)
        except OSError:
            # Windows and some mounted filesystems may not fully support POSIX
            # permissions. The exception must not invalidate the saved state.
            self.logger.debug(
                "Could not apply restrictive state-file permissions.",
                exc_info=True,
            )

    # =========================================================================
    # External payload delivery
    # =========================================================================

    def _request_safe_memory_snapshot(
        self,
        context: EmergencyContext,
        lock_id: str,
        reason: str,
    ) -> Dict[str, Any]:
        if self.memory_agent is None:
            return {
                "success": False,
                "message": "Memory Agent is not available for pre-lock snapshot.",
                "data": {},
                "error": {
                    "code": "MEMORY_AGENT_UNAVAILABLE",
                    "message": (
                        "Memory Agent is not available for pre-lock snapshot."
                    ),
                },
                "metadata": {
                    "optional": True,
                    "lock_id": lock_id,
                },
            }

        for method_name in (
            "create_snapshot",
            "snapshot",
            "backup_memory",
            "export_memory",
        ):
            method = getattr(self.memory_agent, method_name, None)
            if not callable(method):
                continue

            try:
                response = self._invoke_callable(
                    method,
                    {
                        "user_id": context.user_id,
                        "workspace_id": context.workspace_id,
                        "actor_id": context.actor_id,
                        "task_id": context.task_id,
                        "request_id": context.request_id,
                        "reason": (
                            f"Emergency lock pre-activation snapshot: {reason}"
                        ),
                        "metadata": {
                            "lock_id": lock_id,
                            "source_agent": self.agent_name,
                        },
                    },
                )
                return {
                    "success": bool(
                        response.get("success", True)
                        if isinstance(response, Mapping)
                        else True
                    ),
                    "message": "Pre-lock memory snapshot request completed.",
                    "data": {
                        "method": method_name,
                        "response": self._safe_json_data(response),
                    },
                    "error": (
                        response.get("error")
                        if isinstance(response, Mapping)
                        and response.get("success") is False
                        else None
                    ),
                    "metadata": {"optional": True},
                }
            except Exception as exc:
                return {
                    "success": False,
                    "message": "Pre-lock memory snapshot request failed.",
                    "data": {},
                    "error": {
                        "code": "MEMORY_SNAPSHOT_REQUEST_FAILED",
                        "exception_type": exc.__class__.__name__,
                        "message": str(exc),
                    },
                    "metadata": {
                        "optional": True,
                        "method": method_name,
                    },
                }

        return {
            "success": False,
            "message": "Memory Agent has no compatible snapshot method.",
            "data": {},
            "error": {
                "code": "MEMORY_SNAPSHOT_METHOD_MISSING",
                "message": (
                    "Memory Agent has no compatible snapshot method."
                ),
            },
            "metadata": {"optional": True},
        }

    def _send_verification_payload(
        self,
        payload: Dict[str, Any],
    ) -> None:
        if self.verification_agent is None:
            return

        for method_name in (
            "verify",
            "submit_verification",
            "receive_payload",
            "record_verification",
            "handle_payload",
        ):
            method = getattr(
                self.verification_agent,
                method_name,
                None,
            )
            if not callable(method):
                continue
            try:
                self._invoke_callable(method, payload)
                return
            except Exception:
                self.logger.exception(
                    "Verification payload delivery failed."
                )
                return

    def _send_memory_payload(
        self,
        payload: Dict[str, Any],
    ) -> None:
        if self.memory_agent is None:
            return

        for method_name in (
            "store_event",
            "remember",
            "store_memory",
            "add_memory",
            "handle_payload",
        ):
            method = getattr(self.memory_agent, method_name, None)
            if not callable(method):
                continue
            try:
                self._invoke_callable(method, payload)
                return
            except Exception:
                self.logger.exception("Memory payload delivery failed.")
                return

    # =========================================================================
    # Normalization and validation helpers
    # =========================================================================

    def _normalize_config(
        self,
        config: Optional[
            Union[EmergencyLockConfig, Mapping[str, Any]]
        ],
    ) -> EmergencyLockConfig:
        if config is None:
            return EmergencyLockConfig()

        if isinstance(config, EmergencyLockConfig):
            return config

        if isinstance(config, Mapping):
            allowed = {
                field_info.name
                for field_info in dataclasses.fields(EmergencyLockConfig)
            }
            values = {
                key: value
                for key, value in config.items()
                if key in allowed
            }
            if "allowed_actions_during_lock" in values:
                values["allowed_actions_during_lock"] = {
                    str(item).strip().lower()
                    for item in values["allowed_actions_during_lock"]
                    if str(item).strip()
                }
            return EmergencyLockConfig(**values)

        raise TypeError(
            "config must be EmergencyLockConfig, mapping, or None"
        )

    def _normalize_level(
        self,
        level: Union[EmergencyLevel, str],
        context: EmergencyContext,
    ) -> Dict[str, Any]:
        try:
            normalized = (
                level
                if isinstance(level, EmergencyLevel)
                else EmergencyLevel(str(level).strip().lower())
            )
            return self._safe_result(
                message="Emergency level validated.",
                data={"level": normalized},
                context=context,
            )
        except ValueError:
            return self._error_result(
                message="Invalid emergency lock level.",
                error_code="INVALID_EMERGENCY_LEVEL",
                context=context,
                metadata={
                    "provided_level": str(level),
                    "supported_levels": [
                        item.value for item in EmergencyLevel
                    ],
                },
            )

    def _validate_reason(
        self,
        reason: str,
        context: EmergencyContext,
    ) -> Dict[str, Any]:
        normalized = str(reason or "").strip()
        if len(normalized) < 3:
            return self._error_result(
                message="Emergency reason must contain at least 3 characters.",
                error_code="EMERGENCY_REASON_REQUIRED",
                context=context,
            )
        if len(normalized) > self.config.max_reason_length:
            return self._error_result(
                message="Emergency reason exceeds maximum length.",
                error_code="EMERGENCY_REASON_TOO_LONG",
                context=context,
                metadata={
                    "maximum_length": self.config.max_reason_length,
                    "provided_length": len(normalized),
                },
            )
        return self._safe_result(
            message="Emergency reason validated.",
            data={"reason": normalized},
            context=context,
        )

    def _normalize_allowed_actions(
        self,
        allowed_actions: Optional[Iterable[str]],
    ) -> Set[str]:
        result = set(self.config.allowed_actions_during_lock)
        for action in allowed_actions or []:
            normalized = str(action).strip().lower()
            if normalized:
                result.add(normalized)
        return result

    def _normalize_approval_response(
        self,
        response: Any,
        action: str,
        context: EmergencyContext,
    ) -> Dict[str, Any]:
        if isinstance(response, Mapping):
            approved = bool(
                response.get(
                    "approved",
                    response.get(
                        "success",
                        response.get(
                            "allowed",
                            response.get("authorized", False),
                        ),
                    ),
                )
            )
            if approved:
                return self._safe_result(
                    message=str(
                        response.get(
                            "message",
                            "Security approval granted.",
                        )
                    ),
                    data={
                        "approved": True,
                        "method": response.get(
                            "method",
                            "security_agent",
                        ),
                        "approval_id": response.get("approval_id"),
                    },
                    context=context,
                    metadata={"action": action},
                )

            return self._error_result(
                message=str(
                    response.get(
                        "message",
                        "Security approval denied.",
                    )
                ),
                error_code="SECURITY_APPROVAL_DENIED",
                context=context,
                metadata={
                    "action": action,
                    "security_error": self._safe_json_data(
                        response.get("error")
                    ),
                },
            )

        if response is True:
            return self._safe_result(
                message="Security approval granted.",
                data={
                    "approved": True,
                    "method": "security_agent_boolean",
                },
                context=context,
                metadata={"action": action},
            )

        return self._error_result(
            message="Security approval denied.",
            error_code="SECURITY_APPROVAL_DENIED",
            context=context,
            metadata={"action": action},
        )

    def _resolve_state_scope(
        self,
        context: EmergencyContext,
        level: EmergencyLevel,
    ) -> Tuple[str, str]:
        if level == EmergencyLevel.PLATFORM:
            return GLOBAL_SCOPE_USER_ID, GLOBAL_SCOPE_WORKSPACE_ID
        return context.user_id, context.workspace_id

    def _scope_key(
        self,
        user_id: str,
        workspace_id: str,
    ) -> str:
        return f"{user_id}::{workspace_id}"

    def _build_component_payload(
        self,
        operation: str,
        action: str,
        context: EmergencyContext,
        state: EmergencyState,
    ) -> Dict[str, Any]:
        return {
            "operation": operation,
            "action": action,
            "lock_id": state.lock_id,
            "emergency_status": state.status.value,
            "emergency_level": state.level.value,
            "reason": state.reason,
            "incident_id": state.incident_id,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "scope_user_id": state.scope_user_id,
            "scope_workspace_id": state.scope_workspace_id,
            "actor_id": context.actor_id,
            "request_id": context.request_id,
            "task_id": context.task_id,
            "source_agent": self.agent_name,
            "requested_at": self._utc_now(),
            "graceful": True,
            "destructive_os_process_kill_allowed": False,
        }

    def _discover_callback(
        self,
        target: Any,
        names: Sequence[str],
    ) -> Optional[ComponentCallbackProtocol]:
        for name in names:
            method = getattr(target, name, None)
            if callable(method):
                return method
        return None

    def _extract_component_identifier(self, target: Any) -> str:
        candidate = (
            getattr(target, "agent_id", None)
            or getattr(target, "component_id", None)
            or getattr(target, "name", None)
            or getattr(target, "agent_name", None)
            or target.__class__.__name__
        )
        safe = self._safe_path_segment(str(candidate))
        return safe or f"component_{uuid.uuid4().hex[:12]}"

    def _extract_component_name(self, target: Any) -> str:
        return str(
            getattr(target, "agent_name", None)
            or getattr(target, "name", None)
            or target.__class__.__name__
        )

    def _validate_component_id(
        self,
        component_id: Optional[str],
    ) -> Optional[str]:
        if not self._valid_identifier(component_id):
            return None
        return self._safe_path_segment(str(component_id))

    def _valid_identifier(
        self,
        value: Optional[str],
    ) -> bool:
        if not isinstance(value, str):
            return False
        normalized = value.strip()
        if not normalized or len(normalized) > 200:
            return False
        if "\x00" in normalized:
            return False
        if normalized in {".", ".."}:
            return False
        if "/" in normalized or "\\" in normalized:
            return False
        return True

    def _safe_path_segment(self, value: str) -> str:
        output = []
        for character in str(value):
            if character.isalnum() or character in {"-", "_", "."}:
                output.append(character)
            else:
                output.append("_")
        return "".join(output).strip("._")[:160] or "unknown"

    def _safe_json_data(self, value: Any) -> Any:
        if value is None or isinstance(
            value,
            (str, int, float, bool),
        ):
            return value

        if isinstance(value, Path):
            return str(value)

        if isinstance(value, Enum):
            return value.value

        if dataclasses.is_dataclass(value):
            return self._safe_json_data(asdict(value))

        if isinstance(value, Mapping):
            result: Dict[str, Any] = {}
            for key, item in value.items():
                key_string = str(key)
                if self._is_sensitive_key(key_string):
                    result[key_string] = "[REDACTED]"
                else:
                    result[key_string] = self._safe_json_data(item)
            return result

        if isinstance(value, (list, tuple, set, frozenset)):
            return [self._safe_json_data(item) for item in value]

        if isinstance(value, datetime):
            return value.astimezone(timezone.utc).isoformat()

        if isinstance(value, bytes):
            return f"<bytes:{len(value)}>"

        return str(value)

    def _is_sensitive_key(self, key: str) -> bool:
        normalized = (
            key.strip().lower().replace("-", "_").replace(" ", "_")
        )
        sensitive_tokens = {
            "password",
            "passwd",
            "secret",
            "token",
            "approval_token",
            "access_token",
            "refresh_token",
            "api_key",
            "apikey",
            "private_key",
            "authorization",
            "cookie",
            "biometric",
            "biometric_assertion",
            "fingerprint",
            "face_template",
            "voice_template",
            "pin",
        }
        return normalized in sensitive_tokens or any(
            token in normalized
            for token in {
                "password",
                "secret",
                "private_key",
                "access_token",
                "refresh_token",
                "biometric",
            }
        )

    def _redacted_context(
        self,
        context: Optional[EmergencyContext],
    ) -> Optional[Dict[str, Any]]:
        if context is None:
            return None
        data = context.to_dict()
        if data.get("ip_address"):
            data["ip_address"] = self._mask_ip(
                str(data["ip_address"])
            )
        if data.get("device_id"):
            data["device_id"] = self._hash_identifier(
                str(data["device_id"])
            )
        return self._safe_json_data(data)

    def _mask_ip(self, ip_address: str) -> str:
        if ":" in ip_address:
            parts = ip_address.split(":")
            return ":".join(parts[:2] + ["****"])
        parts = ip_address.split(".")
        if len(parts) == 4:
            return ".".join(parts[:2] + ["***", "***"])
        return "[REDACTED_IP]"

    def _hash_identifier(self, value: str) -> str:
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
        return f"sha256:{digest[:16]}"

    def _utc_now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _append_history(self, event: Dict[str, Any]) -> None:
        self._history.append(self._safe_json_data(event))
        if len(self._history) > self.config.history_limit:
            self._history = self._history[
                -self.config.history_limit:
            ]

    def _as_string_list(self, value: Any) -> List[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        if isinstance(value, Iterable):
            return [
                str(item)
                for item in value
                if str(item).strip()
            ]
        return []

    def _as_dict(self, value: Any) -> Dict[str, Any]:
        return dict(value) if isinstance(value, Mapping) else {}

    def _as_optional_dict(
        self,
        value: Any,
    ) -> Optional[Dict[str, Any]]:
        return dict(value) if isinstance(value, Mapping) else None

    def _optional_str(self, value: Any) -> Optional[str]:
        if value is None:
            return None
        normalized = str(value).strip()
        return normalized or None

    @contextmanager
    def _operation_lock(
        self,
        scope_key: str,
    ) -> Iterator[None]:
        with self._operation_locks_guard:
            lock = self._operation_locks.setdefault(
                scope_key,
                threading.RLock(),
            )
        with lock:
            yield


# =============================================================================
# Import-safe test adapters
# =============================================================================

class _TestAgent:
    """Simple stoppable test agent."""

    def __init__(self, name: str) -> None:
        self.agent_name = name
        self.agent_id = name.lower().replace(" ", "_")
        self.stopped = False

    def emergency_stop(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        self.stopped = True
        return {
            "success": True,
            "message": f"{self.agent_name} stopped.",
        }

    def emergency_resume(
        self,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        self.stopped = False
        return {
            "success": True,
            "message": f"{self.agent_name} resumed.",
        }

    def health(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "success": True,
            "healthy": True,
            "stopped": self.stopped,
        }


class _TestAutomation:
    """Simple freezeable automation test adapter."""

    def __init__(self) -> None:
        self.name = "test_automation"
        self.frozen = False

    def freeze(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        self.frozen = True
        return {
            "success": True,
            "message": "Automation frozen.",
        }

    def unfreeze(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        self.frozen = False
        return {
            "success": True,
            "message": "Automation resumed.",
        }

    def health(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "success": True,
            "healthy": True,
            "frozen": self.frozen,
        }


class _TestAppLock:
    """Simple sensitive-app lock test adapter."""

    def __init__(self) -> None:
        self.name = "test_sensitive_app"
        self.locked = False

    def lock(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        self.locked = True
        return {
            "success": True,
            "message": "Sensitive app locked.",
        }

    def unlock(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        self.locked = False
        return {
            "success": True,
            "message": "Sensitive app unlocked.",
        }

    def is_locked(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "success": True,
            "healthy": True,
            "locked": self.locked,
        }


class _TestSecurityAgent:
    """Approves self-test unlock requests only."""

    def request_approval(self, **payload: Any) -> Dict[str, Any]:
        return {
            "success": True,
            "approved": True,
            "approval_id": f"test_{uuid.uuid4().hex[:12]}",
            "method": "self_test_security_agent",
            "message": "Self-test approval granted.",
        }


# =============================================================================
# Self-test
# =============================================================================

def _self_test() -> Dict[str, Any]:
    """
    Run a complete isolated activation/guard/deactivation test.

    Command:
        python agents/security_agent/emergency_lock.py
    """

    temp_root = Path(
        tempfile.mkdtemp(prefix="william_emergency_lock_test_")
    )

    try:
        emergency_lock = EmergencyLock(
            security_agent=_TestSecurityAgent(),
            config=EmergencyLockConfig(
                state_root=temp_root,
                auto_snapshot_before_lock=False,
                require_security_approval_for_activation=False,
                require_security_approval_for_unlock=True,
                require_biometric_for_unlock=True,
            ),
        )

        agent = _TestAgent("Browser Agent")
        automation = _TestAutomation()
        app_lock = _TestAppLock()

        registration_results = [
            emergency_lock.register_agent(
                agent,
                priority=100,
                required=True,
            ),
            emergency_lock.register_automation_controller(
                automation,
                priority=20,
                required=True,
            ),
            emergency_lock.register_sensitive_app(
                app_lock,
                category="browser",
                priority=30,
                required=True,
            ),
        ]

        activation = emergency_lock.activate(
            user_id="user_test",
            workspace_id="workspace_test",
            actor_id="security_admin_test",
            reason="Self-test emergency activation.",
            level=EmergencyLevel.WORKSPACE,
            roles=["security_admin"],
            permissions=["security:emergency_lock:activate"],
        )

        blocked_action = emergency_lock.guard_action(
            user_id="user_test",
            workspace_id="workspace_test",
            action="browser.open_url",
            actor_id="user_test",
            source_agent="browser_agent",
        )

        allowed_action = emergency_lock.guard_action(
            user_id="user_test",
            workspace_id="workspace_test",
            action="security.emergency_lock.status",
            actor_id="security_admin_test",
            source_agent="security_agent",
        )

        status_during_lock = emergency_lock.get_status(
            user_id="user_test",
            workspace_id="workspace_test",
        )

        deactivation = emergency_lock.deactivate(
            user_id="user_test",
            workspace_id="workspace_test",
            actor_id="security_admin_test",
            reason="Self-test emergency resolved.",
            level=EmergencyLevel.WORKSPACE,
            roles=["security_admin"],
            permissions=[
                "security:emergency_lock:deactivate",
            ],
            approval_token="redacted_demo_approval_token",
            biometric_assertion={
                "verified": True,
                "method": "self_test",
            },
        )

        allowed_after_unlock = emergency_lock.guard_action(
            user_id="user_test",
            workspace_id="workspace_test",
            action="browser.open_url",
            actor_id="user_test",
            source_agent="browser_agent",
        )

        assertions = {
            "registrations_succeeded": all(
                result["success"]
                for result in registration_results
            ),
            "activation_succeeded": activation["success"],
            "agent_stopped": agent.stopped is False
            if deactivation["success"]
            else agent.stopped,
            "automation_released": automation.frozen is False,
            "app_unlocked": app_lock.locked is False,
            "normal_action_blocked_during_lock": (
                blocked_action["success"] is False
                and blocked_action.get("error", {}).get("code")
                == "EMERGENCY_LOCK_ACTIVE"
            ),
            "status_action_allowed_during_lock": (
                allowed_action["success"] is True
            ),
            "deactivation_succeeded": deactivation["success"],
            "action_allowed_after_unlock": (
                allowed_after_unlock["success"] is True
            ),
        }

        success = all(assertions.values())

        return {
            "success": success,
            "message": (
                "EmergencyLock self-test completed successfully."
                if success
                else "EmergencyLock self-test failed."
            ),
            "data": {
                "assertions": assertions,
                "registration_results": registration_results,
                "activation": activation,
                "blocked_action": blocked_action,
                "allowed_action": allowed_action,
                "status_during_lock": status_during_lock,
                "deactivation": deactivation,
                "allowed_after_unlock": allowed_after_unlock,
            },
            "error": None if success else {
                "code": "SELF_TEST_ASSERTION_FAILED",
                "message": "One or more self-test assertions failed.",
            },
            "metadata": {
                "agent": EmergencyLock.agent_name,
                "temporary_state_root": str(temp_root),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        }
    finally:
        try:
            import shutil

            shutil.rmtree(temp_root, ignore_errors=True)
        except Exception:
            pass


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format=(
            "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
        ),
    )
    print(
        json.dumps(
            _self_test(),
            indent=2,
            ensure_ascii=False,
            default=str,
        )
    )