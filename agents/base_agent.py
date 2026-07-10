"""
agents/base_agent.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

BaseAgent is the standard parent class for every William agent.

It provides:

- SaaS user/workspace context validation
- Permission metadata support
- Security Agent approval hooks
- Verification Agent payload preparation
- Memory Agent payload preparation
- Dashboard/API-ready structured responses
- Audit logging hooks
- Agent event hooks
- Health checks
- Safe execution wrappers
- Future compatibility with:
    - Master Agent
    - Agent Registry
    - Agent Loader
    - Agent Router
    - Security Agent
    - Memory Agent
    - Verification Agent
    - Dashboard/API layer

This file is intentionally import-safe.
If future William modules are not created yet, this file still imports and works.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import traceback
import uuid
from abc import ABC
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    List,
    Optional,
    Tuple,
    Union,
)


# ============================================================
# Logging
# ============================================================

logger = logging.getLogger("william.agents.base_agent")

if not logger.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


# ============================================================
# Optional Future Imports
# ============================================================
# These imports are intentionally optional.
# Later files like agent_events.py, agent_permissions.py, registry.py,
# SecurityAgent, MemoryAgent, VerificationAgent can replace these stubs.

try:
    from agents.agent_events import emit_agent_event  # type: ignore
except Exception:
    emit_agent_event = None  # type: ignore


try:
    from agents.agent_permissions import check_agent_permission  # type: ignore
except Exception:
    check_agent_permission = None  # type: ignore


try:
    from agents.agent_health import build_agent_health_payload  # type: ignore
except Exception:
    build_agent_health_payload = None  # type: ignore


# ============================================================
# Enums
# ============================================================

class AgentStatus(str, Enum):
    """
    Standard lifecycle status for William agents.
    """

    IDLE = "idle"
    RUNNING = "running"
    WAITING_SECURITY_APPROVAL = "waiting_security_approval"
    COMPLETED = "completed"
    FAILED = "failed"
    DISABLED = "disabled"
    DEGRADED = "degraded"


class TaskRiskLevel(str, Enum):
    """
    Risk level for actions performed by agents.

    LOW:
        Read-only or harmless actions.

    MEDIUM:
        Actions that may change internal application state.

    HIGH:
        Sensitive actions involving messages, calls, browser automation,
        file writes, payments, user data, external integrations, or system control.

    CRITICAL:
        Destructive, financial, security-sensitive, irreversible, or external execution actions.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityDecision(str, Enum):
    """
    Security approval decision.
    """

    APPROVED = "approved"
    DENIED = "denied"
    PENDING = "pending"
    NOT_REQUIRED = "not_required"


class AgentEventType(str, Enum):
    """
    Standard event types for dashboard/API/event stream.
    """

    TASK_RECEIVED = "task_received"
    TASK_STARTED = "task_started"
    TASK_COMPLETED = "task_completed"
    TASK_FAILED = "task_failed"
    SECURITY_CHECK_REQUIRED = "security_check_required"
    SECURITY_APPROVED = "security_approved"
    SECURITY_DENIED = "security_denied"
    MEMORY_PAYLOAD_PREPARED = "memory_payload_prepared"
    VERIFICATION_PAYLOAD_PREPARED = "verification_payload_prepared"
    HEALTH_CHECK = "health_check"
    AUDIT_LOG = "audit_log"


# ============================================================
# Dataclasses
# ============================================================

@dataclass
class AgentIdentity:
    """
    Static identity metadata for one William agent.

    This is useful for:
    - Agent Registry
    - Agent Loader
    - Dashboard listing
    - Master Agent routing
    - Agent health monitoring
    """

    agent_name: str
    agent_type: str = "generic"
    agent_version: str = "1.0.0"
    description: str = ""
    capabilities: List[str] = field(default_factory=list)
    module_path: Optional[str] = None
    class_name: Optional[str] = None
    enabled: bool = True


@dataclass
class AgentContext:
    """
    Runtime SaaS context.

    user_id and workspace_id must be present for user-specific execution.
    This prevents cross-user or cross-workspace leakage.
    """

    user_id: Optional[Union[str, int]] = None
    workspace_id: Optional[Union[str, int]] = None
    role: Optional[str] = None
    subscription_plan: Optional[str] = None
    request_id: Optional[str] = None
    session_id: Optional[str] = None
    trace_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentTask:
    """
    Standard task payload used by Master Agent, Agent Router,
    Dashboard/API, or another agent.
    """

    task_name: str
    payload: Dict[str, Any] = field(default_factory=dict)
    context: AgentContext = field(default_factory=AgentContext)
    risk_level: TaskRiskLevel = TaskRiskLevel.LOW
    requires_security: bool = False
    permissions: List[str] = field(default_factory=list)
    source_agent: Optional[str] = None
    target_agent: Optional[str] = None
    created_at: str = field(default_factory=lambda: utc_now_iso())
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityApprovalPayload:
    """
    Payload sent to Security Agent before sensitive actions.
    """

    approval_id: str
    agent_name: str
    task_name: str
    user_id: Optional[Union[str, int]]
    workspace_id: Optional[Union[str, int]]
    risk_level: str
    permissions: List[str]
    payload_summary: Dict[str, Any]
    reason: str
    created_at: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VerificationPayload:
    """
    Payload prepared for Verification Agent after an action.

    Verification Agent may use this to confirm:
    - action result
    - output correctness
    - business rule compliance
    - user/workspace isolation
    - external side effects
    """

    verification_id: str
    agent_name: str
    task_name: str
    user_id: Optional[Union[str, int]]
    workspace_id: Optional[Union[str, int]]
    action_summary: str
    result_snapshot: Dict[str, Any]
    success: bool
    created_at: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MemoryPayload:
    """
    Payload prepared for Memory Agent.

    This file does not store memory directly.
    It only prepares memory-compatible records.
    """

    memory_id: str
    agent_name: str
    user_id: Optional[Union[str, int]]
    workspace_id: Optional[Union[str, int]]
    memory_type: str
    content: Dict[str, Any]
    importance: str = "normal"
    created_at: str = field(default_factory=lambda: utc_now_iso())
    metadata: Dict[str, Any] = field(default_factory=dict)


# ============================================================
# Utility Functions
# ============================================================

def utc_now_iso() -> str:
    """
    Return timezone-aware UTC timestamp.
    """

    return datetime.now(timezone.utc).isoformat()


def safe_uuid(prefix: Optional[str] = None) -> str:
    """
    Generate a safe unique id.

    Example:
        task_8f1f...
    """

    raw = uuid.uuid4().hex

    if prefix:
        return f"{prefix}_{raw}"

    return raw


def sanitize_for_log(value: Any, max_length: int = 500) -> Any:
    """
    Reduce sensitive/log-heavy content.

    This does not guarantee full PII removal.
    It prevents large payload dumps and masks obvious secret keys.
    """

    secret_keys = {
        "password",
        "token",
        "secret",
        "api_key",
        "apikey",
        "authorization",
        "auth",
        "access_token",
        "refresh_token",
        "private_key",
    }

    if isinstance(value, dict):
        cleaned: Dict[str, Any] = {}

        for key, item in value.items():
            key_lower = str(key).lower()

            if key_lower in secret_keys or any(secret in key_lower for secret in secret_keys):
                cleaned[key] = "***REDACTED***"
            else:
                cleaned[key] = sanitize_for_log(item, max_length=max_length)

        return cleaned

    if isinstance(value, list):
        return [sanitize_for_log(item, max_length=max_length) for item in value[:20]]

    if isinstance(value, tuple):
        return tuple(sanitize_for_log(item, max_length=max_length) for item in value[:20])

    if isinstance(value, str):
        if len(value) > max_length:
            return value[:max_length] + "...[TRUNCATED]"
        return value

    return value


def ensure_dict(value: Any) -> Dict[str, Any]:
    """
    Convert supported values into dictionaries.
    """

    if value is None:
        return {}

    if isinstance(value, dict):
        return value

    if hasattr(value, "__dataclass_fields__"):
        return asdict(value)

    if hasattr(value, "dict") and callable(value.dict):
        try:
            return value.dict()
        except Exception:
            return {"value": str(value)}

    return {"value": value}


def normalize_context(context: Optional[Union[AgentContext, Dict[str, Any]]]) -> AgentContext:
    """
    Normalize context into AgentContext.
    """

    if context is None:
        return AgentContext()

    if isinstance(context, AgentContext):
        return context

    if isinstance(context, dict):
        return AgentContext(
            user_id=context.get("user_id"),
            workspace_id=context.get("workspace_id"),
            role=context.get("role"),
            subscription_plan=context.get("subscription_plan"),
            request_id=context.get("request_id"),
            session_id=context.get("session_id"),
            trace_id=context.get("trace_id"),
            metadata=ensure_dict(context.get("metadata")),
        )

    return AgentContext(metadata={"raw_context": str(context)})


def normalize_task(task: Union[AgentTask, Dict[str, Any], str]) -> AgentTask:
    """
    Normalize incoming task into AgentTask.

    Supports:
    - AgentTask
    - dict payload
    - plain string task name
    """

    if isinstance(task, AgentTask):
        return task

    if isinstance(task, str):
        return AgentTask(task_name=task)

    if isinstance(task, dict):
        context = normalize_context(task.get("context"))

        raw_risk = task.get("risk_level", TaskRiskLevel.LOW)

        try:
            risk_level = raw_risk if isinstance(raw_risk, TaskRiskLevel) else TaskRiskLevel(str(raw_risk))
        except Exception:
            risk_level = TaskRiskLevel.LOW

        return AgentTask(
            task_name=str(task.get("task_name") or task.get("name") or "unnamed_task"),
            payload=ensure_dict(task.get("payload")),
            context=context,
            risk_level=risk_level,
            requires_security=bool(task.get("requires_security", False)),
            permissions=list(task.get("permissions") or []),
            source_agent=task.get("source_agent"),
            target_agent=task.get("target_agent"),
            created_at=str(task.get("created_at") or utc_now_iso()),
            metadata=ensure_dict(task.get("metadata")),
        )

    return AgentTask(
        task_name="unknown_task",
        payload={"raw_task": str(task)},
    )


def maybe_await(value: Union[Any, Awaitable[Any]]) -> Awaitable[Any]:
    """
    Wrap sync/async return values so caller can await safely.
    """

    if inspect.isawaitable(value):
        return value  # type: ignore

    async def _wrapper() -> Any:
        return value

    return _wrapper()


# ============================================================
# BaseAgent
# ============================================================

class BaseAgent(ABC):
    """
    Standard parent class for every William/Jarvis agent.

    Every future agent should inherit from BaseAgent.

    Example:
        class VoiceAgent(BaseAgent):
            async def run(self, task):
                ...

    BaseAgent is designed to stay compatible with:
    - Master Agent routing
    - Agent Registry metadata
    - Agent Loader imports
    - Agent Router task dispatch
    - Security Agent approval flow
    - Verification Agent result review
    - Memory Agent context storage
    - Dashboard/API analytics and audit logs
    """

    agent_name: str = "base_agent"
    agent_type: str = "base"
    agent_version: str = "1.0.0"
    description: str = "Base parent class for William agents."
    capabilities: List[str] = []

    default_risk_level: TaskRiskLevel = TaskRiskLevel.LOW
    sensitive_permissions: List[str] = []
    requires_workspace_context: bool = True
    requires_user_context: bool = True

    def __init__(
        self,
        agent_name: Optional[str] = None,
        agent_type: Optional[str] = None,
        agent_version: Optional[str] = None,
        version: Optional[str] = None,
        description: Optional[str] = None,
        capabilities: Optional[List[str]] = None,
        enabled: bool = True,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        role: Optional[str] = None,
        subscription_plan: Optional[str] = None,
        request_id: Optional[str] = None,
        session_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        security_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], Any]] = None,
        event_emitter: Optional[Callable[[Dict[str, Any]], Any]] = None,
        permission_checker: Optional[Callable[..., Any]] = None,
        config: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        """
        Compatibility-first constructor for all William/Jarvis agents.

        Many generated agents pass slightly different keyword names such as
        version, user_id, workspace_id, role, agent_key, event_sink, audit_sink,
        or other future fields. BaseAgent must accept those safely instead of
        crashing during loader/runtime boot.
        """

        self.agent_name = agent_name or kwargs.get("name") or kwargs.get("agent_key") or self.agent_name
        self.agent_type = agent_type or self.agent_type
        self.agent_version = agent_version or version or kwargs.get("agent_version") or kwargs.get("version") or self.agent_version
        self.version = self.agent_version
        self.description = description or self.description
        self.capabilities = capabilities if capabilities is not None else list(self.capabilities)

        self.user_id = user_id if user_id is not None else kwargs.get("tenant_user_id")
        self.workspace_id = workspace_id if workspace_id is not None else kwargs.get("tenant_workspace_id")
        self.role = role
        self.subscription_plan = subscription_plan
        self.request_id = request_id
        self.session_id = session_id
        self.trace_id = trace_id
        self.extra_context = dict(kwargs)

        self.enabled = enabled
        self.status = AgentStatus.IDLE

        self.security_agent = security_agent or kwargs.get("security")
        self.memory_agent = memory_agent or kwargs.get("memory")
        self.verification_agent = verification_agent or kwargs.get("verification")

        self.audit_logger = audit_logger or kwargs.get("audit_sink") or kwargs.get("audit_callback")
        self.event_emitter = event_emitter or kwargs.get("event_sink") or kwargs.get("event_callback")
        self.permission_checker = permission_checker

        self.config = config or kwargs.get("agent_config") or {}

        self.created_at = utc_now_iso()
        self.last_health_check_at: Optional[str] = None
        self.last_task_at: Optional[str] = None
        self.last_error: Optional[str] = None

        self.total_tasks = 0
        self.successful_tasks = 0
        self.failed_tasks = 0

    # ========================================================
    # Identity / Registry Compatibility
    # ========================================================

    def get_identity(self) -> Dict[str, Any]:
        """
        Return registry-compatible identity metadata.
        """

        identity = AgentIdentity(
            agent_name=self.agent_name,
            agent_type=self.agent_type,
            agent_version=self.agent_version,
            description=self.description,
            capabilities=list(self.capabilities),
            module_path=self.__class__.__module__,
            class_name=self.__class__.__name__,
            enabled=self.enabled,
        )

        return asdict(identity)

    def get_manifest(self) -> Dict[str, Any]:
        """
        Return manifest-compatible metadata for future agent_manifest.py.
        """

        return {
            "identity": self.get_identity(),
            "status": self.status.value,
            "requires_user_context": self.requires_user_context,
            "requires_workspace_context": self.requires_workspace_context,
            "default_risk_level": self.default_risk_level.value,
            "sensitive_permissions": list(self.sensitive_permissions),
            "created_at": self.created_at,
            "config_keys": sorted(list(self.config.keys())),
        }

    def get_capabilities(self) -> List[str]:
        """
        Return declared capabilities.
        """

        return list(self.capabilities)

    def supports_capability(self, capability: str) -> bool:
        """
        Check whether this agent supports a capability.
        """

        return capability in self.capabilities

    # ========================================================
    # Main Execution API
    # ========================================================

    async def execute_task(
        self,
        task: Union[AgentTask, Dict[str, Any], str],
        *,
        auto_prepare_memory: bool = True,
        auto_prepare_verification: bool = True,
    ) -> Dict[str, Any]:
        """
        Standard task execution entrypoint.

        Master Agent / Agent Router should call this method.

        Flow:
        1. Normalize task
        2. Validate SaaS context
        3. Check permissions
        4. Security approval if required
        5. Run actual agent logic
        6. Prepare verification payload
        7. Prepare memory payload
        8. Emit events and audit logs
        9. Return structured result
        """

        normalized_task = normalize_task(task)

        self.total_tasks += 1
        self.last_task_at = utc_now_iso()
        self.status = AgentStatus.RUNNING

        await self._emit_agent_event(
            AgentEventType.TASK_RECEIVED,
            normalized_task,
            {"message": "Task received by agent."},
        )

        await self._emit_agent_event(
            AgentEventType.TASK_STARTED,
            normalized_task,
            {"message": "Task execution started."},
        )

        try:
            if not self.enabled:
                self.status = AgentStatus.DISABLED

                result = self._error_result(
                    message="Agent is disabled.",
                    error="AGENT_DISABLED",
                    task=normalized_task,
                    status_code=403,
                )

                await self._log_audit_event(
                    normalized_task,
                    "agent_disabled",
                    result,
                )

                return result

            context_validation = self._validate_task_context(normalized_task)

            if not context_validation["success"]:
                self.status = AgentStatus.FAILED
                self.failed_tasks += 1

                result = self._error_result(
                    message=context_validation["message"],
                    error="INVALID_TASK_CONTEXT",
                    data=context_validation.get("data"),
                    task=normalized_task,
                    status_code=400,
                )

                await self._log_audit_event(
                    normalized_task,
                    "context_validation_failed",
                    result,
                )

                return result

            permission_result = await self._check_permissions(normalized_task)

            if not permission_result["success"]:
                self.status = AgentStatus.FAILED
                self.failed_tasks += 1

                result = self._error_result(
                    message=permission_result["message"],
                    error="PERMISSION_DENIED",
                    data=permission_result.get("data"),
                    task=normalized_task,
                    status_code=403,
                )

                await self._log_audit_event(
                    normalized_task,
                    "permission_denied",
                    result,
                )

                return result

            if self._requires_security_check(normalized_task):
                self.status = AgentStatus.WAITING_SECURITY_APPROVAL

                await self._emit_agent_event(
                    AgentEventType.SECURITY_CHECK_REQUIRED,
                    normalized_task,
                    {"message": "Security approval required."},
                )

                security_result = await self._request_security_approval(normalized_task)

                if not security_result["success"]:
                    self.status = AgentStatus.FAILED
                    self.failed_tasks += 1

                    await self._emit_agent_event(
                        AgentEventType.SECURITY_DENIED,
                        normalized_task,
                        security_result,
                    )

                    result = self._error_result(
                        message=security_result.get("message", "Security approval denied."),
                        error="SECURITY_APPROVAL_DENIED",
                        data=security_result.get("data"),
                        task=normalized_task,
                        status_code=403,
                    )

                    await self._log_audit_event(
                        normalized_task,
                        "security_denied",
                        result,
                    )

                    return result

                await self._emit_agent_event(
                    AgentEventType.SECURITY_APPROVED,
                    normalized_task,
                    security_result,
                )

            self.status = AgentStatus.RUNNING

            raw_result = await maybe_await(self.run(normalized_task))

            result = self._normalize_agent_output(raw_result, normalized_task)

            if result.get("success"):
                self.status = AgentStatus.COMPLETED
                self.successful_tasks += 1
            else:
                self.status = AgentStatus.FAILED
                self.failed_tasks += 1

            if auto_prepare_verification:
                verification_payload = self._prepare_verification_payload(
                    normalized_task,
                    result,
                )

                result.setdefault("metadata", {})
                result["metadata"]["verification_payload"] = verification_payload

                await self._emit_agent_event(
                    AgentEventType.VERIFICATION_PAYLOAD_PREPARED,
                    normalized_task,
                    verification_payload,
                )

            if auto_prepare_memory:
                memory_payload = self._prepare_memory_payload(
                    normalized_task,
                    result,
                )

                result.setdefault("metadata", {})
                result["metadata"]["memory_payload"] = memory_payload

                await self._emit_agent_event(
                    AgentEventType.MEMORY_PAYLOAD_PREPARED,
                    normalized_task,
                    memory_payload,
                )

            await self._log_audit_event(
                normalized_task,
                "task_completed" if result.get("success") else "task_failed",
                result,
            )

            await self._emit_agent_event(
                AgentEventType.TASK_COMPLETED if result.get("success") else AgentEventType.TASK_FAILED,
                normalized_task,
                result,
            )

            return result

        except Exception as exc:
            self.status = AgentStatus.FAILED
            self.failed_tasks += 1
            self.last_error = str(exc)

            error_data = {
                "exception_type": exc.__class__.__name__,
                "traceback": traceback.format_exc(),
            }

            result = self._error_result(
                message="Agent task execution failed.",
                error=str(exc),
                data=error_data,
                task=normalized_task,
                status_code=500,
            )

            await self._log_audit_event(
                normalized_task,
                "task_exception",
                result,
            )

            await self._emit_agent_event(
                AgentEventType.TASK_FAILED,
                normalized_task,
                result,
            )

            logger.exception("Agent task execution failed: %s", self.agent_name)

            return result

        finally:
            if self.status not in {AgentStatus.DISABLED, AgentStatus.DEGRADED}:
                if self.status == AgentStatus.RUNNING:
                    self.status = AgentStatus.IDLE

    async def run(self, task: AgentTask) -> Dict[str, Any]:
        """
        Override this in child agents.

        Child agents should return a structured dict:
            {
                "success": True,
                "message": "...",
                "data": {},
                "error": None,
                "metadata": {}
            }

        BaseAgent returns a safe default response so the file is testable.
        """

        return self._safe_result(
            message="BaseAgent received task. Override run() in child agent.",
            data={
                "task_name": task.task_name,
                "payload": sanitize_for_log(task.payload),
            },
            task=task,
        )

    def execute_task_sync(
        self,
        task: Union[AgentTask, Dict[str, Any], str],
        *,
        auto_prepare_memory: bool = True,
        auto_prepare_verification: bool = True,
    ) -> Dict[str, Any]:
        """
        Sync wrapper for environments that do not use async directly.

        Useful for:
        - CLI testing
        - simple scripts
        - early dashboard integrations
        """

        try:
            loop = asyncio.get_event_loop()

            if loop.is_running():
                raise RuntimeError(
                    "execute_task_sync cannot run inside an already running event loop. "
                    "Use await execute_task(...) instead."
                )

            return loop.run_until_complete(
                self.execute_task(
                    task,
                    auto_prepare_memory=auto_prepare_memory,
                    auto_prepare_verification=auto_prepare_verification,
                )
            )

        except RuntimeError as exc:
            if "There is no current event loop" in str(exc):
                return asyncio.run(
                    self.execute_task(
                        task,
                        auto_prepare_memory=auto_prepare_memory,
                        auto_prepare_verification=auto_prepare_verification,
                    )
                )

            raise

    # ========================================================
    # Context Validation
    # ========================================================

    def _validate_task_context(self, task: AgentTask) -> Dict[str, Any]:
        """
        Validate SaaS user/workspace isolation context.

        Every user-specific action should include:
        - user_id
        - workspace_id

        This prevents accidental cross-user data mixing.
        """

        missing: List[str] = []

        if self.requires_user_context and not task.context.user_id:
            missing.append("user_id")

        if self.requires_workspace_context and not task.context.workspace_id:
            missing.append("workspace_id")

        if missing:
            return {
                "success": False,
                "message": f"Missing required SaaS context: {', '.join(missing)}.",
                "data": {
                    "missing": missing,
                    "requires_user_context": self.requires_user_context,
                    "requires_workspace_context": self.requires_workspace_context,
                },
            }

        return {
            "success": True,
            "message": "Task context is valid.",
            "data": {
                "user_id": task.context.user_id,
                "workspace_id": task.context.workspace_id,
                "request_id": task.context.request_id,
                "session_id": task.context.session_id,
                "trace_id": task.context.trace_id,
            },
        }

    def validate_context_public(
        self,
        context: Optional[Union[AgentContext, Dict[str, Any]]],
    ) -> Dict[str, Any]:
        """
        Public helper for Dashboard/API tests.
        """

        task = AgentTask(
            task_name="context_validation",
            context=normalize_context(context),
        )

        return self._validate_task_context(task)

    # ========================================================
    # Permissions
    # ========================================================

    async def _check_permissions(self, task: AgentTask) -> Dict[str, Any]:
        """
        Check task permissions.

        This supports:
        - injected permission_checker
        - future agents.agent_permissions.check_agent_permission
        - safe default permissive behavior for early development

        Production systems should inject or implement strict permission checks.
        """

        if not task.permissions:
            return {
                "success": True,
                "message": "No explicit permissions required.",
                "data": {
                    "permissions": [],
                },
            }

        payload = {
            "agent_name": self.agent_name,
            "task_name": task.task_name,
            "user_id": task.context.user_id,
            "workspace_id": task.context.workspace_id,
            "permissions": task.permissions,
            "role": task.context.role,
            "subscription_plan": task.context.subscription_plan,
        }

        checker = self.permission_checker or check_agent_permission

        if checker:
            try:
                checked = await maybe_await(checker(**payload))

                if isinstance(checked, dict):
                    return {
                        "success": bool(checked.get("success", False)),
                        "message": checked.get("message", "Permission check completed."),
                        "data": checked.get("data", checked),
                    }

                if isinstance(checked, bool):
                    return {
                        "success": checked,
                        "message": "Permission allowed." if checked else "Permission denied.",
                        "data": payload,
                    }

            except Exception as exc:
                return {
                    "success": False,
                    "message": "Permission check failed.",
                    "data": {
                        "error": str(exc),
                        "payload": sanitize_for_log(payload),
                    },
                }

        return {
            "success": True,
            "message": "Permission checker unavailable. Allowed by development fallback.",
            "data": {
                "permissions": task.permissions,
                "fallback": True,
                "warning": "Install strict permission checker before production.",
            },
        }

    # ========================================================
    # Security Hooks
    # ========================================================

    def _requires_security_check(self, task: AgentTask) -> bool:
        """
        Decide whether this task requires Security Agent approval.

        Sensitive actions must go through Security Agent.

        Security is required when:
        - task.requires_security is True
        - risk level is HIGH or CRITICAL
        - task asks for sensitive permissions
        """

        if task.requires_security:
            return True

        if task.risk_level in {TaskRiskLevel.HIGH, TaskRiskLevel.CRITICAL}:
            return True

        sensitive_set = set(self.sensitive_permissions)

        if sensitive_set.intersection(set(task.permissions)):
            return True

        return False

    def _build_security_approval_payload(self, task: AgentTask) -> Dict[str, Any]:
        """
        Build Security Agent compatible approval payload.
        """

        payload = SecurityApprovalPayload(
            approval_id=safe_uuid("security"),
            agent_name=self.agent_name,
            task_name=task.task_name,
            user_id=task.context.user_id,
            workspace_id=task.context.workspace_id,
            risk_level=task.risk_level.value,
            permissions=list(task.permissions),
            payload_summary=sanitize_for_log(task.payload),
            reason="Sensitive action requires Security Agent approval.",
            created_at=utc_now_iso(),
            metadata={
                "source_agent": task.source_agent,
                "target_agent": task.target_agent or self.agent_name,
                "request_id": task.context.request_id,
                "session_id": task.context.session_id,
                "trace_id": task.context.trace_id,
            },
        )

        return asdict(payload)

    async def _request_security_approval(self, task: AgentTask) -> Dict[str, Any]:
        """
        Request approval from Security Agent.

        This method is protected and safe:
        - If a Security Agent is injected and supports approve_action(),
          it will be called.
        - If it supports execute_task(), it will be called.
        - Without Security Agent, LOW/MEDIUM tasks can continue.
        - HIGH/CRITICAL tasks are denied by default without Security Agent.
        """

        approval_payload = self._build_security_approval_payload(task)

        if self.security_agent:
            try:
                if hasattr(self.security_agent, "approve_action"):
                    decision = await maybe_await(
                        self.security_agent.approve_action(approval_payload)
                    )

                    return self._normalize_security_decision(decision, approval_payload)

                if hasattr(self.security_agent, "execute_task"):
                    decision = await maybe_await(
                        self.security_agent.execute_task(
                            {
                                "task_name": "approve_agent_action",
                                "payload": approval_payload,
                                "context": asdict(task.context),
                                "risk_level": TaskRiskLevel.HIGH.value,
                                "requires_security": False,
                            }
                        )
                    )

                    return self._normalize_security_decision(decision, approval_payload)

            except Exception as exc:
                return {
                    "success": False,
                    "message": "Security Agent approval failed.",
                    "data": {
                        "decision": SecurityDecision.DENIED.value,
                        "error": str(exc),
                        "approval_payload": approval_payload,
                    },
                }

        if task.risk_level in {TaskRiskLevel.HIGH, TaskRiskLevel.CRITICAL}:
            return {
                "success": False,
                "message": "Security Agent is required for high-risk task but is unavailable.",
                "data": {
                    "decision": SecurityDecision.DENIED.value,
                    "approval_payload": approval_payload,
                },
            }

        return {
            "success": True,
            "message": "Security Agent unavailable. Task allowed by low/medium-risk fallback.",
            "data": {
                "decision": SecurityDecision.APPROVED.value,
                "fallback": True,
                "approval_payload": approval_payload,
                "warning": "Configure Security Agent before production sensitive actions.",
            },
        }

    def _normalize_security_decision(
        self,
        decision: Any,
        approval_payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Normalize different Security Agent response styles.
        """

        if isinstance(decision, bool):
            return {
                "success": decision,
                "message": "Security approved." if decision else "Security denied.",
                "data": {
                    "decision": SecurityDecision.APPROVED.value if decision else SecurityDecision.DENIED.value,
                    "approval_payload": approval_payload,
                },
            }

        if isinstance(decision, dict):
            success = bool(decision.get("success", False))

            raw_decision = (
                decision.get("decision")
                or decision.get("data", {}).get("decision")
                or SecurityDecision.APPROVED.value if success else SecurityDecision.DENIED.value
            )

            return {
                "success": success,
                "message": decision.get(
                    "message",
                    "Security approved." if success else "Security denied.",
                ),
                "data": {
                    "decision": raw_decision,
                    "approval_payload": approval_payload,
                    "security_response": sanitize_for_log(decision),
                },
            }

        return {
            "success": False,
            "message": "Invalid Security Agent decision format.",
            "data": {
                "decision": SecurityDecision.DENIED.value,
                "approval_payload": approval_payload,
                "raw_decision": sanitize_for_log(decision),
            },
        }

    # ========================================================
    # Verification Hook
    # ========================================================

    def _prepare_verification_payload(
        self,
        task: AgentTask,
        result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent compatible payload.

        This does not call Verification Agent directly.
        Router/Master Agent can pass this payload to Verification Agent.
        """

        payload = VerificationPayload(
            verification_id=safe_uuid("verify"),
            agent_name=self.agent_name,
            task_name=task.task_name,
            user_id=task.context.user_id,
            workspace_id=task.context.workspace_id,
            action_summary=result.get("message", "Agent task completed."),
            result_snapshot=sanitize_for_log(
                {
                    "success": result.get("success"),
                    "message": result.get("message"),
                    "data": result.get("data"),
                    "error": result.get("error"),
                }
            ),
            success=bool(result.get("success", False)),
            created_at=utc_now_iso(),
            metadata={
                "request_id": task.context.request_id,
                "session_id": task.context.session_id,
                "trace_id": task.context.trace_id,
                "source_agent": task.source_agent,
                "target_agent": task.target_agent or self.agent_name,
                "risk_level": task.risk_level.value,
            },
        )

        return asdict(payload)

    async def send_to_verification_agent(
        self,
        verification_payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Optional public method to send prepared payload to Verification Agent.
        """

        if not self.verification_agent:
            return {
                "success": False,
                "message": "Verification Agent is not configured.",
                "data": {
                    "verification_payload": verification_payload,
                },
            }

        try:
            if hasattr(self.verification_agent, "verify"):
                response = await maybe_await(
                    self.verification_agent.verify(verification_payload)
                )
            elif hasattr(self.verification_agent, "execute_task"):
                response = await maybe_await(
                    self.verification_agent.execute_task(
                        {
                            "task_name": "verify_agent_result",
                            "payload": verification_payload,
                            "requires_security": False,
                        }
                    )
                )
            else:
                response = {
                    "success": False,
                    "message": "Verification Agent has no supported interface.",
                }

            return self._normalize_agent_output(
                response,
                AgentTask(task_name="send_to_verification_agent"),
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to send payload to Verification Agent.",
                error=str(exc),
                data={
                    "verification_payload": sanitize_for_log(verification_payload),
                },
            )

    # ========================================================
    # Memory Hook
    # ========================================================

    def _prepare_memory_payload(
        self,
        task: AgentTask,
        result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        This does not store memory directly.
        """

        content = {
            "task_name": task.task_name,
            "task_payload": sanitize_for_log(task.payload),
            "result": sanitize_for_log(
                {
                    "success": result.get("success"),
                    "message": result.get("message"),
                    "data": result.get("data"),
                    "error": result.get("error"),
                }
            ),
        }

        payload = MemoryPayload(
            memory_id=safe_uuid("memory"),
            agent_name=self.agent_name,
            user_id=task.context.user_id,
            workspace_id=task.context.workspace_id,
            memory_type="agent_task_result",
            content=content,
            importance="normal",
            metadata={
                "request_id": task.context.request_id,
                "session_id": task.context.session_id,
                "trace_id": task.context.trace_id,
                "risk_level": task.risk_level.value,
                "source_agent": task.source_agent,
                "target_agent": task.target_agent or self.agent_name,
            },
        )

        return asdict(payload)

    async def send_to_memory_agent(
        self,
        memory_payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Optional public method to send prepared payload to Memory Agent.
        """

        if not self.memory_agent:
            return {
                "success": False,
                "message": "Memory Agent is not configured.",
                "data": {
                    "memory_payload": memory_payload,
                },
            }

        try:
            if hasattr(self.memory_agent, "store_memory"):
                response = await maybe_await(
                    self.memory_agent.store_memory(memory_payload)
                )
            elif hasattr(self.memory_agent, "execute_task"):
                response = await maybe_await(
                    self.memory_agent.execute_task(
                        {
                            "task_name": "store_agent_memory",
                            "payload": memory_payload,
                            "requires_security": False,
                        }
                    )
                )
            else:
                response = {
                    "success": False,
                    "message": "Memory Agent has no supported interface.",
                }

            return self._normalize_agent_output(
                response,
                AgentTask(task_name="send_to_memory_agent"),
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to send payload to Memory Agent.",
                error=str(exc),
                data={
                    "memory_payload": sanitize_for_log(memory_payload),
                },
            )

    # ========================================================
    # Events / Audit
    # ========================================================

    async def _emit_agent_event(
        self,
        event_type: Union[AgentEventType, str],
        task: Optional[AgentTask] = None,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Emit event for dashboard/API/event stream.

        Supports:
        - injected event_emitter
        - future agents.agent_events.emit_agent_event
        - logger fallback
        """

        event_name = event_type.value if isinstance(event_type, AgentEventType) else str(event_type)

        event = {
            "event_id": safe_uuid("event"),
            "event_type": event_name,
            "agent_name": self.agent_name,
            "agent_type": self.agent_type,
            "agent_version": self.agent_version,
            "status": self.status.value,
            "timestamp": utc_now_iso(),
            "task_name": task.task_name if task else None,
            "user_id": task.context.user_id if task else None,
            "workspace_id": task.context.workspace_id if task else None,
            "request_id": task.context.request_id if task else None,
            "session_id": task.context.session_id if task else None,
            "trace_id": task.context.trace_id if task else None,
            "payload": sanitize_for_log(payload or {}),
        }

        emitter = self.event_emitter or emit_agent_event

        if emitter:
            try:
                emitted = await maybe_await(emitter(event))

                return {
                    "success": True,
                    "message": "Agent event emitted.",
                    "data": {
                        "event": event,
                        "emitter_response": sanitize_for_log(emitted),
                    },
                }

            except Exception as exc:
                logger.warning("Agent event emitter failed: %s", exc)

                return {
                    "success": False,
                    "message": "Agent event emitter failed.",
                    "error": str(exc),
                    "data": {
                        "event": event,
                    },
                }

        logger.debug("Agent event: %s", event)

        return {
            "success": True,
            "message": "Agent event logged by fallback.",
            "data": {
                "event": event,
                "fallback": True,
            },
        }

    async def _log_audit_event(
        self,
        task: Optional[AgentTask],
        action: str,
        result: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Log audit event.

        Audit logs should later be persisted by dashboard/API/database layer.
        This method keeps the payload consistent and SaaS-safe.
        """

        audit_payload = {
            "audit_id": safe_uuid("audit"),
            "agent_name": self.agent_name,
            "agent_type": self.agent_type,
            "action": action,
            "timestamp": utc_now_iso(),
            "user_id": task.context.user_id if task else None,
            "workspace_id": task.context.workspace_id if task else None,
            "task_name": task.task_name if task else None,
            "request_id": task.context.request_id if task else None,
            "session_id": task.context.session_id if task else None,
            "trace_id": task.context.trace_id if task else None,
            "risk_level": task.risk_level.value if task else None,
            "permissions": list(task.permissions) if task else [],
            "result": sanitize_for_log(result or {}),
        }

        if self.audit_logger:
            try:
                response = await maybe_await(self.audit_logger(audit_payload))

                return {
                    "success": True,
                    "message": "Audit event logged.",
                    "data": {
                        "audit": audit_payload,
                        "logger_response": sanitize_for_log(response),
                    },
                }

            except Exception as exc:
                logger.warning("Audit logger failed: %s", exc)

                return {
                    "success": False,
                    "message": "Audit logger failed.",
                    "error": str(exc),
                    "data": {
                        "audit": audit_payload,
                    },
                }

        logger.info("AUDIT | %s | %s | %s", self.agent_name, action, sanitize_for_log(audit_payload))

        await self._emit_agent_event(
            AgentEventType.AUDIT_LOG,
            task,
            audit_payload,
        )

        return {
            "success": True,
            "message": "Audit event logged by fallback logger.",
            "data": {
                "audit": audit_payload,
                "fallback": True,
            },
        }

    # ========================================================
    # Health
    # ========================================================

    def health_check(self) -> Dict[str, Any]:
        """
        Return dashboard/API-compatible health payload.
        """

        self.last_health_check_at = utc_now_iso()

        base_payload = {
            "success": True,
            "message": "Agent health check completed.",
            "data": {
                "agent_name": self.agent_name,
                "agent_type": self.agent_type,
                "agent_version": self.agent_version,
                "enabled": self.enabled,
                "status": self.status.value,
                "created_at": self.created_at,
                "last_health_check_at": self.last_health_check_at,
                "last_task_at": self.last_task_at,
                "last_error": self.last_error,
                "total_tasks": self.total_tasks,
                "successful_tasks": self.successful_tasks,
                "failed_tasks": self.failed_tasks,
                "success_rate": self._calculate_success_rate(),
                "capabilities": list(self.capabilities),
                "requires_user_context": self.requires_user_context,
                "requires_workspace_context": self.requires_workspace_context,
            },
            "error": None,
            "metadata": {
                "source": "BaseAgent.health_check",
                "timestamp": self.last_health_check_at,
            },
        }

        if build_agent_health_payload:
            try:
                custom_payload = build_agent_health_payload(self)

                if isinstance(custom_payload, dict):
                    base_payload["metadata"]["custom_health_payload"] = custom_payload

            except Exception as exc:
                base_payload["metadata"]["custom_health_error"] = str(exc)

        return base_payload

    async def health_check_async(self) -> Dict[str, Any]:
        """
        Async health check wrapper.
        """

        result = self.health_check()

        await self._emit_agent_event(
            AgentEventType.HEALTH_CHECK,
            None,
            result,
        )

        return result

    def _calculate_success_rate(self) -> float:
        """
        Calculate task success rate.
        """

        if self.total_tasks <= 0:
            return 0.0

        return round((self.successful_tasks / self.total_tasks) * 100, 2)

    # ========================================================
    # Result Helpers
    # ========================================================

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        task: Optional[AgentTask] = None,
        status_code: int = 200,
    ) -> Dict[str, Any]:
        """
        Build standard success response.

        Every agent result should follow this structure.
        """

        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": {
                "agent_name": self.agent_name,
                "agent_type": self.agent_type,
                "agent_version": self.agent_version,
                "status": self.status.value,
                "status_code": status_code,
                "timestamp": utc_now_iso(),
                "task_name": task.task_name if task else None,
                "user_id": task.context.user_id if task else None,
                "workspace_id": task.context.workspace_id if task else None,
                "request_id": task.context.request_id if task else None,
                "session_id": task.context.session_id if task else None,
                "trace_id": task.context.trace_id if task else None,
                **(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Any] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        task: Optional[AgentTask] = None,
        status_code: int = 500,
    ) -> Dict[str, Any]:
        """
        Build standard error response.
        """

        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": str(error) if error is not None else message,
            "metadata": {
                "agent_name": self.agent_name,
                "agent_type": self.agent_type,
                "agent_version": self.agent_version,
                "status": self.status.value,
                "status_code": status_code,
                "timestamp": utc_now_iso(),
                "task_name": task.task_name if task else None,
                "user_id": task.context.user_id if task else None,
                "workspace_id": task.context.workspace_id if task else None,
                "request_id": task.context.request_id if task else None,
                "session_id": task.context.session_id if task else None,
                "trace_id": task.context.trace_id if task else None,
                **(metadata or {}),
            },
        }

    def _normalize_agent_output(
        self,
        output: Any,
        task: Optional[AgentTask] = None,
    ) -> Dict[str, Any]:
        """
        Normalize any child-agent output into standard result format.
        """

        if isinstance(output, dict):
            normalized = {
                "success": bool(output.get("success", True)),
                "message": str(output.get("message", "Agent task completed.")),
                "data": ensure_dict(output.get("data")),
                "error": output.get("error"),
                "metadata": ensure_dict(output.get("metadata")),
            }

            normalized["metadata"].setdefault("agent_name", self.agent_name)
            normalized["metadata"].setdefault("agent_type", self.agent_type)
            normalized["metadata"].setdefault("agent_version", self.agent_version)
            normalized["metadata"].setdefault("timestamp", utc_now_iso())

            if task:
                normalized["metadata"].setdefault("task_name", task.task_name)
                normalized["metadata"].setdefault("user_id", task.context.user_id)
                normalized["metadata"].setdefault("workspace_id", task.context.workspace_id)
                normalized["metadata"].setdefault("request_id", task.context.request_id)
                normalized["metadata"].setdefault("session_id", task.context.session_id)
                normalized["metadata"].setdefault("trace_id", task.context.trace_id)

            return normalized

        return self._safe_result(
            message="Agent returned non-dict output. Wrapped safely.",
            data={
                "output": output,
            },
            task=task,
        )

    # ========================================================
    # Safe Execution Helpers
    # ========================================================

    async def safe_call(
        self,
        func: Callable[..., Any],
        *args: Any,
        task: Optional[AgentTask] = None,
        error_message: str = "Safe call failed.",
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Safely execute a sync or async function and return structured result.
        """

        try:
            response = await maybe_await(func(*args, **kwargs))

            return self._safe_result(
                message="Safe call completed.",
                data={
                    "response": response,
                },
                task=task,
            )

        except Exception as exc:
            return self._error_result(
                message=error_message,
                error=str(exc),
                data={
                    "exception_type": exc.__class__.__name__,
                    "traceback": traceback.format_exc(),
                },
                task=task,
            )

    def safe_call_sync(
        self,
        func: Callable[..., Any],
        *args: Any,
        task: Optional[AgentTask] = None,
        error_message: str = "Safe sync call failed.",
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Sync safe-call helper.
        """

        try:
            response = func(*args, **kwargs)

            return self._safe_result(
                message="Safe sync call completed.",
                data={
                    "response": response,
                },
                task=task,
            )

        except Exception as exc:
            return self._error_result(
                message=error_message,
                error=str(exc),
                data={
                    "exception_type": exc.__class__.__name__,
                    "traceback": traceback.format_exc(),
                },
                task=task,
            )

    # ========================================================
    # SaaS Isolation Helpers
    # ========================================================

    def build_scoped_query_filter(
        self,
        context: Union[AgentContext, Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Build a SaaS-safe filter for database queries.

        Future database layer can use this to ensure:
        - only this user's records are accessed
        - only this workspace's records are accessed
        """

        ctx = normalize_context(context)

        filter_data: Dict[str, Any] = {}

        if ctx.user_id:
            filter_data["user_id"] = ctx.user_id

        if ctx.workspace_id:
            filter_data["workspace_id"] = ctx.workspace_id

        return filter_data

    def assert_same_scope(
        self,
        source_context: Union[AgentContext, Dict[str, Any]],
        target_record: Dict[str, Any],
    ) -> Tuple[bool, str]:
        """
        Check whether a target record belongs to the same SaaS scope.
        """

        ctx = normalize_context(source_context)

        if self.requires_user_context:
            if str(target_record.get("user_id")) != str(ctx.user_id):
                return False, "Target record does not belong to the same user."

        if self.requires_workspace_context:
            if str(target_record.get("workspace_id")) != str(ctx.workspace_id):
                return False, "Target record does not belong to the same workspace."

        return True, "Target record is in the same SaaS scope."

    # ========================================================
    # Configuration
    # ========================================================

    def update_config(self, values: Dict[str, Any]) -> Dict[str, Any]:
        """
        Safely update runtime config.
        """

        if not isinstance(values, dict):
            return self._error_result(
                message="Config update requires a dictionary.",
                error="INVALID_CONFIG",
                status_code=400,
            )

        blocked_keys = {
            "password",
            "secret",
            "token",
            "api_key",
            "private_key",
        }

        for key in values:
            key_lower = str(key).lower()

            if key_lower in blocked_keys or any(blocked in key_lower for blocked in blocked_keys):
                return self._error_result(
                    message=f"Refusing to store sensitive config key: {key}",
                    error="SENSITIVE_CONFIG_BLOCKED",
                    status_code=400,
                )

        self.config.update(values)

        return self._safe_result(
            message="Agent config updated.",
            data={
                "config_keys": sorted(list(self.config.keys())),
            },
        )

    def get_config_value(
        self,
        key: str,
        default: Any = None,
    ) -> Any:
        """
        Read runtime config value.
        """

        return self.config.get(key, default)

    # ========================================================
    # Representation
    # ========================================================

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} "
            f"agent_name={self.agent_name!r} "
            f"agent_type={self.agent_type!r} "
            f"version={self.agent_version!r} "
            f"status={self.status.value!r} "
            f"enabled={self.enabled}>"
        )


# ============================================================
# Development Self-Test
# ============================================================

async def _self_test_async() -> Dict[str, Any]:
    """
    Minimal async self-test.

    Run:
        python agents/base_agent.py
    """

    agent = BaseAgent(
        agent_name="base_agent_self_test",
        agent_type="test",
        capabilities=["health_check", "task_execution", "safe_result"],
    )

    task = AgentTask(
        task_name="self_test_task",
        payload={
            "hello": "world",
        },
        context=AgentContext(
            user_id="test_user",
            workspace_id="test_workspace",
            request_id=safe_uuid("request"),
        ),
        risk_level=TaskRiskLevel.LOW,
    )

    result = await agent.execute_task(task)
    health = agent.health_check()

    return {
        "task_result": result,
        "health": health,
    }


def _self_test_sync() -> None:
    """
    Print self-test result.
    """

    import json

    result = asyncio.run(_self_test_async())

    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    _self_test_sync()


# ============================================================
# Completion Tracking
# ============================================================

"""
Agent/Module: Global Agent Infrastructure Files
File Completed: base_agent.py
Completion: 11.1%
Completed Files: ['base_agent.py']
Remaining Files: ['registry.py', 'agent_loader.py', 'agent_router.py', 'agent_manifest.py', 'agent_permissions.py', 'agent_events.py', 'agent_health.py', 'agent_config.py']
Next Recommended File: agents/registry.py
FILE COMPLETE.
"""