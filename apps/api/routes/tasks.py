"""
apps/api/routes/tasks.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Task routes with SaaS-ready isolation.

Purpose:
- Create task
- Run task
- Create + run task
- Cancel task
- Task history
- Task detail
- Progress events
- Security Agent approval for sensitive tasks
- Master Agent routing hook
- Memory Agent context hook
- Verification Agent confirmation hook

This file imports safely even when future files are missing.
"""

from __future__ import annotations

import importlib
import inspect
import logging
import os
import traceback
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Tuple

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field, validator


# =============================================================================
# Logging
# =============================================================================

LOGGER_NAME = "william.api.routes.tasks"
logger = logging.getLogger(LOGGER_NAME)

if not logger.handlers:
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(
        logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")
    )
    logger.addHandler(stream_handler)

logger.setLevel(os.getenv("WILLIAM_LOG_LEVEL", "INFO").upper())


# =============================================================================
# Utilities
# =============================================================================

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def parse_bool(value: Optional[str], default: bool = False) -> bool:
    if value is None:
        return default

    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def parse_int(value: Optional[str], default: int) -> int:
    try:
        if value is None:
            return default

        return int(value)
    except Exception:
        return default


def model_to_dict(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value

    if hasattr(value, "model_dump"):
        return value.model_dump()

    if hasattr(value, "dict"):
        return value.dict()

    return {"value": value}


async def maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value

    return value


def safe_error_detail(exc: Exception, debug: bool = False) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "type": exc.__class__.__name__,
        "message": str(exc) or "Unexpected error",
    }

    if debug:
        payload["traceback"] = traceback.format_exc()

    return payload


def normalize_agent_name(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None

    clean = value.strip().lower().replace("-", "_").replace(" ", "_")

    if not clean:
        return None

    if len(clean) > 80:
        raise ValueError("Agent name is too long.")

    return clean


def normalize_task_text(value: Optional[str]) -> str:
    clean = (value or "").strip()

    if len(clean) > 30000:
        raise ValueError("Task message is too long.")

    return clean


# =============================================================================
# Settings
# =============================================================================

@dataclass(frozen=True)
class TaskRouteSettings:
    environment: str = field(default_factory=lambda: os.getenv("WILLIAM_ENV", "development"))
    debug: bool = field(default_factory=lambda: parse_bool(os.getenv("WILLIAM_DEBUG"), False))

    audit_enabled: bool = field(default_factory=lambda: parse_bool(os.getenv("WILLIAM_AUDIT_LOG_ENABLED"), True))
    security_agent_enabled: bool = field(default_factory=lambda: parse_bool(os.getenv("WILLIAM_SECURITY_AGENT_ENABLED"), True))
    memory_agent_enabled: bool = field(default_factory=lambda: parse_bool(os.getenv("WILLIAM_MEMORY_AGENT_ENABLED"), True))
    verification_agent_enabled: bool = field(
        default_factory=lambda: parse_bool(os.getenv("WILLIAM_VERIFICATION_AGENT_ENABLED"), True)
    )

    max_task_history_per_workspace: int = field(
        default_factory=lambda: parse_int(os.getenv("WILLIAM_MAX_TASK_HISTORY_PER_WORKSPACE"), 1000)
    )
    max_progress_events_per_task: int = field(
        default_factory=lambda: parse_int(os.getenv("WILLIAM_MAX_PROGRESS_EVENTS_PER_TASK"), 500)
    )
    allow_cancel_completed_tasks: bool = field(
        default_factory=lambda: parse_bool(os.getenv("WILLIAM_ALLOW_CANCEL_COMPLETED_TASKS"), False)
    )

    def public_dict(self) -> Dict[str, Any]:
        return asdict(self)


TASK_SETTINGS = TaskRouteSettings()


# =============================================================================
# Roles / Plans
# =============================================================================

class Role(str, Enum):
    OWNER = "owner"
    ADMIN = "admin"
    MANAGER = "manager"
    DEVELOPER = "developer"
    ANALYST = "analyst"
    AGENT = "agent"
    USER = "user"
    VIEWER = "viewer"


class Plan(str, Enum):
    FREE = "free"
    STARTER = "starter"
    PRO = "pro"
    BUSINESS = "business"
    ENTERPRISE = "enterprise"


ROLE_RANK: Dict[str, int] = {
    Role.VIEWER.value: 10,
    Role.USER.value: 20,
    # "member" is the real database-level WorkspaceMemberRole (see the
    # identical mapping + comment in apps/api/routes/agents.py's own
    # ROLE_RANK) that flows straight into AuthContext.role for every real
    # request. Without this entry, ROLE_RANK.get("member", 0) fell
    # through to 0 -- below even "viewer" -- so every real non-owner
    # workspace member was denied task creation (_enforce_task_create_policy
    # requires only Role.USER) even on the free plan.
    "member": 20,
    Role.AGENT.value: 30,
    Role.ANALYST.value: 35,
    Role.DEVELOPER.value: 40,
    Role.MANAGER.value: 50,
    Role.ADMIN.value: 80,
    Role.OWNER.value: 100,
}

PLAN_RANK: Dict[str, int] = {
    Plan.FREE.value: 10,
    Plan.STARTER.value: 20,
    Plan.PRO.value: 40,
    Plan.BUSINESS.value: 70,
    Plan.ENTERPRISE.value: 100,
}


def normalize_role(role: Optional[str]) -> str:
    clean = (role or Role.USER.value).strip().lower()
    return clean if clean in ROLE_RANK else Role.USER.value


def normalize_plan(plan: Optional[str]) -> str:
    clean = (plan or Plan.FREE.value).strip().lower()
    return clean if clean in PLAN_RANK else Plan.FREE.value


def has_min_role(current_role: str, required_role: str) -> bool:
    return ROLE_RANK.get(current_role, 0) >= ROLE_RANK.get(required_role, 0)


def has_min_plan(current_plan: str, required_plan: str) -> bool:
    return PLAN_RANK.get(current_plan, 0) >= PLAN_RANK.get(required_plan, 0)


def task_monthly_limit(plan: str) -> Any:
    normalized = normalize_plan(plan)

    limits = {
        Plan.FREE.value: 25,
        Plan.STARTER.value: 500,
        Plan.PRO.value: 5000,
        Plan.BUSINESS.value: 50000,
        Plan.ENTERPRISE.value: "custom",
    }

    return limits[normalized]


# =============================================================================
# Response Helpers
# =============================================================================

def api_success(
    message: str,
    data: Optional[Dict[str, Any]] = None,
    request_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return {
        "success": True,
        "message": message,
        "data": data or {},
        "error": None,
        "metadata": {
            "request_id": request_id,
            "timestamp": utc_now(),
            "module": "tasks",
            **(metadata or {}),
        },
    }


def raise_api_error(
    status_code: int,
    message: str,
    code: str,
    request_id: Optional[str] = None,
    details: Optional[Any] = None,
) -> None:
    raise HTTPException(
        status_code=status_code,
        detail={
            "success": False,
            "message": message,
            "data": {},
            "error": {
                "code": code,
                "details": details,
            },
            "metadata": {
                "request_id": request_id,
                "timestamp": utc_now(),
                "module": "tasks",
            },
        },
    )


# =============================================================================
# Auth Compatibility
# =============================================================================

class FallbackAuthContext(BaseModel):
    request_id: str
    user_id: str
    workspace_id: str
    session_id: str = "dev_session"
    role: str = Role.OWNER.value
    plan: str = Plan.FREE.value
    email: str = "dev@example.com"
    permissions: List[str] = Field(default_factory=list)
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None


try:
    from apps.api.routes.auth import (  # type: ignore
        AuthContext,
        get_current_auth_context,
        require_auth_role,
    )
except Exception as auth_import_exc:
    logger.warning("Auth import fallback enabled in tasks.py: %s", auth_import_exc)
    AuthContext = FallbackAuthContext

    async def get_current_auth_context(
        request: Request,
        x_request_id: Optional[str] = Header(default=None, alias="X-Request-ID"),
        x_user_id: Optional[str] = Header(default="demo_user", alias="X-User-ID"),
        x_workspace_id: Optional[str] = Header(default="demo_workspace", alias="X-Workspace-ID"),
        x_user_role: Optional[str] = Header(default=Role.OWNER.value, alias="X-User-Role"),
        x_subscription_plan: Optional[str] = Header(default=Plan.FREE.value, alias="X-Subscription-Plan"),
    ) -> FallbackAuthContext:
        return FallbackAuthContext(
            request_id=x_request_id or new_id("req"),
            user_id=x_user_id or "demo_user",
            workspace_id=x_workspace_id or "demo_workspace",
            role=normalize_role(x_user_role),
            plan=normalize_plan(x_subscription_plan),
            email="dev@example.com",
            permissions=["task:create", "task:run", "task:cancel", "task:read", "agent:execute"],
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )

    def require_auth_role(required_role: str) -> Callable[[FallbackAuthContext], Awaitable[FallbackAuthContext]]:
        async def dependency(context: FallbackAuthContext = Depends(get_current_auth_context)) -> FallbackAuthContext:
            if not has_min_role(context.role, required_role):
                raise_api_error(
                    status_code=status.HTTP_403_FORBIDDEN,
                    message=f"Role '{required_role}' or higher is required.",
                    code="INSUFFICIENT_ROLE",
                    request_id=context.request_id,
                )
            return context

        return dependency


# =============================================================================
# Optional Hooks
# =============================================================================

class OptionalHook:
    def __init__(
        self,
        component_name: str,
        import_candidates: Iterable[Tuple[str, str]],
        method_candidates: Iterable[str],
    ) -> None:
        self.component_name = component_name
        self.import_candidates = list(import_candidates)
        self.method_candidates = list(method_candidates)
        self.instance: Optional[Any] = None
        self.loaded_from: Optional[str] = None
        self.import_error: Optional[str] = None

    def load(self) -> bool:
        if self.instance is not None:
            return True

        for module_path, attr_name in self.import_candidates:
            try:
                module = importlib.import_module(module_path)
                attr = getattr(module, attr_name)

                if inspect.isclass(attr):
                    self.instance = self._instantiate(attr)
                else:
                    self.instance = attr

                self.loaded_from = f"{module_path}.{attr_name}"
                logger.info("Loaded optional task hook: %s from %s", self.component_name, self.loaded_from)
                return True

            except Exception as exc:
                self.import_error = f"{module_path}.{attr_name}: {exc}"

        return False

    @staticmethod
    def _instantiate(cls: Any) -> Any:
        attempts = [{"settings": TASK_SETTINGS}, {}]
        last_error: Optional[Exception] = None

        for kwargs in attempts:
            try:
                return cls(**kwargs)
            except TypeError as exc:
                last_error = exc

        raise last_error or RuntimeError(f"Could not instantiate {cls}")

    async def call(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if not self.load() or self.instance is None:
            return {
                "success": False,
                "message": f"{self.component_name} is not available yet.",
                "data": {
                    "component": self.component_name,
                    "loaded": False,
                    "import_error": self.import_error,
                },
                "error": {"code": "OPTIONAL_COMPONENT_UNAVAILABLE"},
                "metadata": {"timestamp": utc_now()},
            }

        try:
            if callable(self.instance) and not inspect.isclass(self.instance):
                result = await maybe_await(self.instance(payload))
                return self._normalize(result)

            for method_name in self.method_candidates:
                method = getattr(self.instance, method_name, None)

                if callable(method):
                    result = await maybe_await(method(payload))
                    return self._normalize(result)

            return {
                "success": False,
                "message": f"{self.component_name} has no compatible method.",
                "data": {
                    "component": self.component_name,
                    "method_candidates": self.method_candidates,
                },
                "error": {"code": "COMPONENT_METHOD_MISSING"},
                "metadata": {"timestamp": utc_now()},
            }

        except Exception as exc:
            return {
                "success": False,
                "message": f"{self.component_name} failed.",
                "data": {"component": self.component_name},
                "error": safe_error_detail(exc, TASK_SETTINGS.debug),
                "metadata": {"timestamp": utc_now()},
            }

    @staticmethod
    def _normalize(result: Any) -> Dict[str, Any]:
        if isinstance(result, dict):
            return {
                "success": bool(result.get("success", True)),
                "message": str(result.get("message", "Component completed.")),
                "data": result.get("data", {}),
                "error": result.get("error"),
                "metadata": result.get("metadata", {"timestamp": utc_now()}),
            }

        return {
            "success": True,
            "message": "Component completed.",
            "data": {"result": result},
            "error": None,
            "metadata": {"timestamp": utc_now()},
        }


MASTER_AGENT = OptionalHook(
    component_name="Master Agent",
    import_candidates=[
        ("apps.api.services.master_agent_bridge", "MasterAgentBridge"),
        ("core.master_agent", "MasterAgent"),
        ("agents.master_agent.master_agent", "MasterAgent"),
        ("agents.master.master_agent", "MasterAgent"),
    ],
    # "execute" must come before "handle_request": OptionalHook.call() always
    # invokes whichever method it finds with a single dict positional arg
    # (method(payload)). The real core.master_agent.MasterAgent has both --
    # handle_request(message, user_id, workspace_id, ...) takes three
    # required keyword args and cannot accept a single dict, while
    # execute(task: dict) is the BaseAgent-compatible entrypoint specifically
    # built to unpack a dict and call handle_request() correctly. Trying
    # handle_request first (the old order) always raised "missing 2 required
    # positional arguments: 'user_id' and 'workspace_id'" for every task.
    method_candidates=["handle_task", "handle_api_task", "execute", "handle_request", "run", "route_task"],
)

SECURITY_AGENT = OptionalHook(
    component_name="Security Agent",
    import_candidates=[
        ("apps.api.services.security_agent_bridge", "SecurityAgentBridge"),
        ("agents.security_agent.security_agent", "SecurityAgent"),
        ("agents.security.security_agent", "SecurityAgent"),
    ],
    # "run_task" (real agents.security_agent.security_agent.SecurityAgent's
    # actual, bespoke, sync entrypoint) and "execute_task" (BaseAgent's own
    # safe dict-normalizing entrypoint) must come before "execute"/"run":
    # neither of the hopeful approve_*/check_permission names exist on the
    # real class, so OptionalHook.call() fell through to "run" -- which
    # SecurityAgent never overrides, hitting BaseAgent.run()'s placeholder
    # body and crashing with "'dict' object has no attribute 'task_name'"
    # instead of reaching real logic.
    method_candidates=["run_task", "execute_task", "approve_task_action", "approve_api_action", "approve_action", "check_permission", "execute", "run"],
)

MEMORY_AGENT = OptionalHook(
    component_name="Memory Agent",
    import_candidates=[
        ("apps.api.services.memory_agent_bridge", "MemoryAgentBridge"),
        ("agents.memory_agent.memory_agent", "MemoryAgent"),
        ("agents.memory.memory_agent", "MemoryAgent"),
    ],
    # Same root cause/fix as SECURITY_AGENT above: agents.memory_agent.
    # memory_agent.MemoryAgent's real entrypoint is run_task(), not any of
    # the hopeful record_*/save_context/remember names.
    method_candidates=["run_task", "execute_task", "record_task_context", "record_api_context", "save_context", "remember", "execute", "run"],
)

# NOTE (honest, documented gap -- not fixed here): the real
# agents.verification_agent.verification_agent.VerificationAgent has no
# run_task()/execute_task()/single-dict-argument entrypoint. Its real method
# is verify_task(context, task_payload, expected_state=None, ...) -- TWO
# required positional arguments, not one. OptionalHook.call() always invokes
# method(payload) with a single dict, so verify_task can never be dispatched
# through this generic mechanism without a purpose-built adapter that splits
# one payload into (context=, task_payload=). Real, separate adapter work,
# out of scope for this runtime-verification pass -- verification_result
# will keep failing honestly (not silently) until that adapter is built.
VERIFICATION_AGENT = OptionalHook(
    component_name="Verification Agent",
    import_candidates=[
        ("apps.api.services.verification_agent_bridge", "VerificationAgentBridge"),
        ("agents.verification_agent.verification_agent", "VerificationAgent"),
        ("agents.verification.verification_agent", "VerificationAgent"),
    ],
    method_candidates=["execute_task", "prepare_task_confirmation", "prepare_confirmation", "verify_result", "confirm", "execute", "run"],
)


async def security_review(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not TASK_SETTINGS.security_agent_enabled:
        return {
            "success": True,
            "message": "Security Agent hook disabled; action allowed by local policy.",
            "data": {"approved": True, "local_policy": True},
            "error": None,
            "metadata": {"timestamp": utc_now()},
        }

    return await SECURITY_AGENT.call(payload)


async def emit_memory_context(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not TASK_SETTINGS.memory_agent_enabled:
        return {
            "success": False,
            "message": "Memory Agent hook disabled.",
            "data": {},
            "error": {"code": "MEMORY_HOOK_DISABLED"},
            "metadata": {"timestamp": utc_now()},
        }

    return await MEMORY_AGENT.call(payload)


async def prepare_verification(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not TASK_SETTINGS.verification_agent_enabled:
        return {
            "success": False,
            "message": "Verification Agent hook disabled.",
            "data": {},
            "error": {"code": "VERIFICATION_HOOK_DISABLED"},
            "metadata": {"timestamp": utc_now()},
        }

    return await VERIFICATION_AGENT.call(payload)


def security_approved(result: Dict[str, Any]) -> bool:
    data = result.get("data", {}) if isinstance(result, dict) else {}

    return bool(
        result.get("success")
        and (
            data.get("approved") is True
            or data.get("allowed") is True
            or data.get("local_policy") is True
        )
    )


# =============================================================================
# Task Models
# =============================================================================

class TaskStatus(str, Enum):
    CREATED = "created"
    QUEUED = "queued"
    RUNNING = "running"
    WAITING_SECURITY = "waiting_security"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TaskPriority(str, Enum):
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


class TaskCreateRequest(BaseModel):
    action: str = Field(default="general_request", min_length=1, max_length=128)
    message: str = Field(default="", max_length=30000)
    preferred_agent: Optional[str] = Field(default=None, max_length=80)
    input_data: Dict[str, Any] = Field(default_factory=dict)
    priority: str = Field(default=TaskPriority.NORMAL.value)
    auto_run: bool = False
    approved_by_security: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @validator("message")
    def validate_message(cls, value: str) -> str:
        return normalize_task_text(value)

    @validator("preferred_agent")
    def validate_agent(cls, value: Optional[str]) -> Optional[str]:
        return normalize_agent_name(value)

    @validator("priority")
    def validate_priority(cls, value: str) -> str:
        clean = (value or TaskPriority.NORMAL.value).strip().lower()
        allowed = {item.value for item in TaskPriority}

        if clean not in allowed:
            raise ValueError("Invalid task priority.")

        return clean


class TaskRunRequest(BaseModel):
    approved_by_security: bool = False
    runtime_input: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class TaskCancelRequest(BaseModel):
    reason: Optional[str] = Field(default=None, max_length=500)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class TaskProgressEvent(BaseModel):
    event_id: str
    task_id: str
    user_id: str
    workspace_id: str
    event_type: str
    message: str
    progress: Optional[float] = None
    created_at: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class TaskRecord(BaseModel):
    task_id: str
    user_id: str
    workspace_id: str
    created_by_user_id: str
    action: str
    message: str
    preferred_agent: Optional[str] = None
    input_data: Dict[str, Any] = Field(default_factory=dict)
    priority: str = TaskPriority.NORMAL.value
    status: str = TaskStatus.CREATED.value
    result: Optional[Dict[str, Any]] = None
    error: Optional[Dict[str, Any]] = None
    approved_by_security: bool = False
    security_result: Optional[Dict[str, Any]] = None
    memory_payload: Optional[Dict[str, Any]] = None
    memory_result: Optional[Dict[str, Any]] = None
    verification_payload: Optional[Dict[str, Any]] = None
    verification_result: Optional[Dict[str, Any]] = None
    created_at: str
    updated_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    cancelled_at: Optional[str] = None
    cancelled_by_user_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


# =============================================================================
# Sensitive Task Detection
# =============================================================================

SENSITIVE_ACTION_KEYWORDS = {
    "delete",
    "remove",
    "purge",
    "shutdown",
    "restart",
    "execute",
    "terminal",
    "shell",
    "browser_submit",
    "submit_form",
    "send_email",
    "send_message",
    "call",
    "make_call",
    "payment",
    "purchase",
    "billing",
    "subscription",
    "secret",
    "token",
    "credential",
    "password",
    "file_write",
    "file_delete",
    "system_write",
    "finance_trade",
    "trade",
    "transfer_money",
}


def looks_sensitive_task(payload: Dict[str, Any]) -> bool:
    pieces = [
        str(payload.get("action", "")),
        str(payload.get("message", "")),
        str(payload.get("preferred_agent", "")),
        str(payload.get("input_data", "")),
    ]
    combined = " ".join(pieces).lower()

    return any(keyword in combined for keyword in SENSITIVE_ACTION_KEYWORDS)


# =============================================================================
# Task Store
# =============================================================================

class TaskStore:
    """
    In-memory development store.

    Replace later with database tables:
    - tasks
    - task_events
    - task_audit_logs
    """

    def __init__(self) -> None:
        self.tasks_by_id: Dict[str, TaskRecord] = {}
        self.task_ids_by_workspace: Dict[str, List[str]] = {}
        self.task_ids_by_user_workspace: Dict[str, List[str]] = {}
        self.events_by_task_id: Dict[str, List[TaskProgressEvent]] = {}

    @staticmethod
    def user_workspace_key(user_id: str, workspace_id: str) -> str:
        return f"{user_id}:{workspace_id}"

    def create_task(
        self,
        context: AuthContext,
        payload: TaskCreateRequest,
    ) -> TaskRecord:
        now = utc_now()
        task = TaskRecord(
            task_id=new_id("task"),
            user_id=context.user_id,
            workspace_id=context.workspace_id,
            created_by_user_id=context.user_id,
            action=payload.action,
            message=payload.message,
            preferred_agent=payload.preferred_agent,
            input_data=payload.input_data,
            priority=payload.priority,
            status=TaskStatus.CREATED.value,
            approved_by_security=payload.approved_by_security,
            created_at=now,
            updated_at=now,
            metadata={
                **payload.metadata,
                "source": "tasks_route",
                "role": context.role,
                "plan": context.plan,
            },
        )

        self.tasks_by_id[task.task_id] = task
        self.task_ids_by_workspace.setdefault(context.workspace_id, []).append(task.task_id)
        self.task_ids_by_user_workspace.setdefault(
            self.user_workspace_key(context.user_id, context.workspace_id),
            [],
        ).append(task.task_id)

        self.add_event(
            task=task,
            event_type="task_created",
            message="Task created.",
            progress=0,
            metadata={"priority": task.priority, "preferred_agent": task.preferred_agent},
        )

        self.trim_workspace_history(context.workspace_id)
        return task

    def require_task(self, task_id: str, context: AuthContext, allow_workspace_admin: bool = True) -> TaskRecord:
        task = self.tasks_by_id.get(task_id)

        if not task:
            raise ValueError("Task not found.")

        if task.workspace_id != context.workspace_id:
            raise PermissionError("Task is outside the current workspace scope.")

        if task.user_id != context.user_id and not (allow_workspace_admin and has_min_role(context.role, Role.MANAGER.value)):
            raise PermissionError("Task is outside the current user scope.")

        return task

    def update_task(self, task_id: str, update: Dict[str, Any]) -> TaskRecord:
        task = self.tasks_by_id.get(task_id)

        if not task:
            raise ValueError("Task not found.")

        update.setdefault("updated_at", utc_now())

        if hasattr(task, "model_copy"):
            updated = task.model_copy(update=update)
        else:
            updated = task.copy(update=update)

        self.tasks_by_id[task_id] = updated
        return updated

    def add_event(
        self,
        task: TaskRecord,
        event_type: str,
        message: str,
        progress: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> TaskProgressEvent:
        event = TaskProgressEvent(
            event_id=new_id("event"),
            task_id=task.task_id,
            user_id=task.user_id,
            workspace_id=task.workspace_id,
            event_type=event_type,
            message=message,
            progress=progress,
            created_at=utc_now(),
            metadata=metadata or {},
        )

        events = self.events_by_task_id.setdefault(task.task_id, [])
        events.append(event)

        if len(events) > TASK_SETTINGS.max_progress_events_per_task:
            self.events_by_task_id[task.task_id] = events[-TASK_SETTINGS.max_progress_events_per_task :]

        return event

    def list_tasks(
        self,
        context: AuthContext,
        status_filter: Optional[str] = None,
        agent_filter: Optional[str] = None,
        include_workspace_tasks: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> List[TaskRecord]:
        if include_workspace_tasks and has_min_role(context.role, Role.MANAGER.value):
            ids = self.task_ids_by_workspace.get(context.workspace_id, [])
        else:
            ids = self.task_ids_by_user_workspace.get(
                self.user_workspace_key(context.user_id, context.workspace_id),
                [],
            )

        tasks: List[TaskRecord] = []

        for task_id in ids:
            task = self.tasks_by_id.get(task_id)
            if not task:
                continue

            if status_filter and task.status != status_filter:
                continue

            if agent_filter and task.preferred_agent != agent_filter:
                continue

            tasks.append(task)

        tasks = sorted(tasks, key=lambda item: item.created_at, reverse=True)
        return tasks[offset : offset + limit]

    def count_tasks_for_scope(self, context: AuthContext) -> int:
        ids = self.task_ids_by_user_workspace.get(
            self.user_workspace_key(context.user_id, context.workspace_id),
            [],
        )
        return len(ids)

    def list_events(self, task_id: str) -> List[TaskProgressEvent]:
        return self.events_by_task_id.get(task_id, [])

    def trim_workspace_history(self, workspace_id: str) -> None:
        ids = self.task_ids_by_workspace.get(workspace_id, [])

        if len(ids) <= TASK_SETTINGS.max_task_history_per_workspace:
            return

        extra_count = len(ids) - TASK_SETTINGS.max_task_history_per_workspace
        old_ids = ids[:extra_count]
        self.task_ids_by_workspace[workspace_id] = ids[extra_count:]

        for task_id in old_ids:
            task = self.tasks_by_id.get(task_id)
            if task and task.status in {TaskStatus.COMPLETED.value, TaskStatus.FAILED.value, TaskStatus.CANCELLED.value}:
                self.tasks_by_id.pop(task_id, None)
                self.events_by_task_id.pop(task_id, None)


TASK_STORE = TaskStore()


# =============================================================================
# Audit
# =============================================================================

TASK_AUDIT_EVENTS: List[Dict[str, Any]] = []


def write_task_audit(
    request: Request,
    context: AuthContext,
    event_type: str,
    action: str,
    result: str,
    task_id: Optional[str] = None,
    status_code: Optional[int] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    event = {
        "audit_id": new_id("audit"),
        "event_type": event_type,
        "action": action,
        "result": result,
        "task_id": task_id,
        "actor_user_id": context.user_id,
        "workspace_id": context.workspace_id,
        "request_id": context.request_id,
        "route": str(request.url.path),
        "method": request.method,
        "status_code": status_code,
        "ip_address": getattr(context, "ip_address", None),
        "user_agent": getattr(context, "user_agent", None),
        "created_at": utc_now(),
        "metadata": metadata or {},
    }

    if TASK_SETTINGS.audit_enabled:
        TASK_AUDIT_EVENTS.append(event)

        if len(TASK_AUDIT_EVENTS) > 1000:
            del TASK_AUDIT_EVENTS[: len(TASK_AUDIT_EVENTS) - 1000]

        logger.info(
            "Task audit | type=%s | action=%s | actor=%s | workspace=%s | task=%s | result=%s",
            event_type,
            action,
            context.user_id,
            context.workspace_id,
            task_id,
            result,
        )

    return event


# =============================================================================
# Serialization
# =============================================================================

def public_task(task: TaskRecord) -> Dict[str, Any]:
    data = task.model_dump() if hasattr(task, "model_dump") else task.dict()
    return data


def public_event(event: TaskProgressEvent) -> Dict[str, Any]:
    return event.model_dump() if hasattr(event, "model_dump") else event.dict()


# =============================================================================
# Execution
# =============================================================================

async def run_task_through_master(task: TaskRecord, context: AuthContext, runtime_input: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    master_payload = {
        "task_id": task.task_id,
        "request_id": context.request_id,
        "user_id": task.user_id,
        "workspace_id": task.workspace_id,
        "role": context.role,
        "plan": context.plan,
        "action": task.action,
        "message": task.message,
        "preferred_agent": task.preferred_agent,
        "input_data": {
            **task.input_data,
            **(runtime_input or {}),
        },
        "approved_by_security": task.approved_by_security,
        "metadata": {
            **task.metadata,
            "source": "apps/api/routes/tasks.py",
            "run_started_at": utc_now(),
        },
    }

    master_result = await MASTER_AGENT.call(master_payload)

    # core.master_agent.MasterAgent's own _error_result() always puts a
    # plain string in "error" (its consistent internal convention across
    # the whole class) -- only OptionalHook.call()'s own "component never
    # loaded" short-circuit uses the {"code": ...} dict shape this check is
    # actually looking for. Calling .get() unconditionally on "error"
    # crashed with AttributeError as soon as the real MasterAgent ran and
    # returned a normal string-shaped failure instead of the "unavailable"
    # dict shape.
    master_error = master_result.get("error")
    master_error_code = master_error.get("code") if isinstance(master_error, dict) else None

    if master_result.get("success") is False and master_error_code == "OPTIONAL_COMPONENT_UNAVAILABLE":
        return {
            "success": True,
            "message": "Task accepted and marked complete by fallback executor because Master Agent is not connected yet.",
            "data": {
                "fallback_executor": True,
                "master_agent_available": False,
                "task_echo": master_payload,
                "next_step": "Connect MasterAgentBridge or core MasterAgent for real execution.",
            },
            "error": None,
            "metadata": {"timestamp": utc_now(), "component": "fallback_task_executor"},
        }

    return master_result


# =============================================================================
# Tasks Class / Router
# =============================================================================

class Tasks:
    """
    Required component name: Tasks

    Provides create/run/cancel task, task history, and progress event routes.
    """

    def __init__(self) -> None:
        self.router = APIRouter(tags=["Tasks"])
        self._register_routes()

    def _register_routes(self) -> None:
        self.router.post("")(self.create_task)
        self.router.post("/run")(self.create_and_run_task)
        self.router.get("")(self.list_tasks)
        self.router.get("/audit")(self.get_task_audit)
        self.router.get("/{task_id}")(self.get_task)
        self.router.post("/{task_id}/run")(self.run_task)
        self.router.post("/{task_id}/cancel")(self.cancel_task)
        self.router.get("/{task_id}/events")(self.get_task_events)

    async def create_task(
        self,
        payload: TaskCreateRequest,
        request: Request,
        context: AuthContext = Depends(get_current_auth_context),
    ) -> Dict[str, Any]:
        self._enforce_task_create_policy(context)

        task = TASK_STORE.create_task(context=context, payload=payload)

        audit = write_task_audit(
            request=request,
            context=context,
            event_type="task_create",
            action="create_task",
            result="success",
            task_id=task.task_id,
            status_code=status.HTTP_201_CREATED,
            metadata={
                "preferred_agent": task.preferred_agent,
                "priority": task.priority,
                "auto_run": payload.auto_run,
            },
        )

        memory_result = await emit_memory_context(
            {
                "type": "task_create",
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
                "request_id": context.request_id,
                "content": {
                    "event": "task_created",
                    "task_id": task.task_id,
                    "action": task.action,
                    "preferred_agent": task.preferred_agent,
                    "message_preview": task.message[:250],
                },
                "created_at": utc_now(),
            }
        )

        task = TASK_STORE.update_task(
            task.task_id,
            {
                "memory_result": memory_result,
            },
        )

        if payload.auto_run:
            run_response = await self._run_existing_task(
                task=task,
                request=request,
                context=context,
                run_payload=TaskRunRequest(
                    approved_by_security=payload.approved_by_security,
                    runtime_input={},
                    metadata={"auto_run": True},
                ),
            )
            run_response["data"]["created_audit"] = audit
            return run_response

        return api_success(
            message="Task created successfully.",
            data={
                "task": public_task(task),
                "audit": audit,
                "memory_result": memory_result,
            },
            request_id=context.request_id,
        )

    async def create_and_run_task(
        self,
        payload: TaskCreateRequest,
        request: Request,
        context: AuthContext = Depends(get_current_auth_context),
    ) -> Dict[str, Any]:
        payload.auto_run = True
        return await self.create_task(payload=payload, request=request, context=context)

    async def run_task(
        self,
        task_id: str,
        payload: TaskRunRequest,
        request: Request,
        context: AuthContext = Depends(get_current_auth_context),
    ) -> Dict[str, Any]:
        try:
            task = TASK_STORE.require_task(task_id, context)
            return await self._run_existing_task(task=task, request=request, context=context, run_payload=payload)

        except PermissionError as exc:
            raise_api_error(
                status_code=status.HTTP_403_FORBIDDEN,
                message=str(exc),
                code="TASK_SCOPE_DENIED",
                request_id=context.request_id,
            )
        except ValueError as exc:
            raise_api_error(
                status_code=status.HTTP_404_NOT_FOUND,
                message=str(exc),
                code="TASK_NOT_FOUND",
                request_id=context.request_id,
            )

    async def cancel_task(
        self,
        task_id: str,
        payload: TaskCancelRequest,
        request: Request,
        context: AuthContext = Depends(get_current_auth_context),
    ) -> Dict[str, Any]:
        try:
            task = TASK_STORE.require_task(task_id, context)

            if task.status in {TaskStatus.COMPLETED.value, TaskStatus.FAILED.value, TaskStatus.CANCELLED.value}:
                if not TASK_SETTINGS.allow_cancel_completed_tasks:
                    raise_api_error(
                        status_code=status.HTTP_409_CONFLICT,
                        message="Task is already finished and cannot be cancelled.",
                        code="TASK_ALREADY_FINISHED",
                        request_id=context.request_id,
                        details={"status": task.status},
                    )

            security_result = await security_review(
                {
                    "type": "task_cancel",
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "task_id": task.task_id,
                    "task_status": task.status,
                    "reason": payload.reason,
                    "request_id": context.request_id,
                    "created_at": utc_now(),
                }
            )

            if not security_approved(security_result):
                raise_api_error(
                    status_code=status.HTTP_403_FORBIDDEN,
                    message="Task cancellation was blocked by Security Agent.",
                    code="SECURITY_AGENT_DENIED",
                    request_id=context.request_id,
                    details=security_result,
                )

            updated = TASK_STORE.update_task(
                task.task_id,
                {
                    "status": TaskStatus.CANCELLED.value,
                    "cancelled_at": utc_now(),
                    "cancelled_by_user_id": context.user_id,
                    "security_result": security_result,
                    "metadata": {
                        **task.metadata,
                        **payload.metadata,
                        "cancel_reason": payload.reason,
                    },
                },
            )

            event = TASK_STORE.add_event(
                task=updated,
                event_type="task_cancelled",
                message="Task cancelled.",
                progress=None,
                metadata={"reason": payload.reason},
            )

            audit = write_task_audit(
                request=request,
                context=context,
                event_type="task_cancel",
                action="cancel_task",
                result="success",
                task_id=task.task_id,
                status_code=status.HTTP_200_OK,
                metadata={
                    "reason": payload.reason,
                    "security_result": security_result,
                },
            )

            verification_result = await prepare_verification(
                {
                    "type": "task_cancel_confirmation",
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "request_id": context.request_id,
                    "task_id": task.task_id,
                    "result": "cancelled",
                    "created_at": utc_now(),
                }
            )

            updated = TASK_STORE.update_task(
                task.task_id,
                {
                    "verification_result": verification_result,
                    "verification_payload": {
                        "type": "task_cancel_confirmation",
                        "task_id": task.task_id,
                        "user_id": context.user_id,
                        "workspace_id": context.workspace_id,
                    },
                },
            )

            return api_success(
                message="Task cancelled successfully.",
                data={
                    "task": public_task(updated),
                    "event": public_event(event),
                    "audit": audit,
                    "verification_result": verification_result,
                },
                request_id=context.request_id,
            )

        except PermissionError as exc:
            raise_api_error(
                status_code=status.HTTP_403_FORBIDDEN,
                message=str(exc),
                code="TASK_SCOPE_DENIED",
                request_id=context.request_id,
            )
        except ValueError as exc:
            raise_api_error(
                status_code=status.HTTP_404_NOT_FOUND,
                message=str(exc),
                code="TASK_CANCEL_FAILED",
                request_id=context.request_id,
            )

    async def get_task(
        self,
        task_id: str,
        context: AuthContext = Depends(get_current_auth_context),
    ) -> Dict[str, Any]:
        try:
            task = TASK_STORE.require_task(task_id, context)
            events = TASK_STORE.list_events(task.task_id)

            return api_success(
                message="Task loaded.",
                data={
                    "task": public_task(task),
                    "events": [public_event(event) for event in events],
                    "isolation": {
                        "user_id": context.user_id,
                        "workspace_id": context.workspace_id,
                    },
                },
                request_id=context.request_id,
            )

        except PermissionError as exc:
            raise_api_error(
                status_code=status.HTTP_403_FORBIDDEN,
                message=str(exc),
                code="TASK_SCOPE_DENIED",
                request_id=context.request_id,
            )
        except ValueError as exc:
            raise_api_error(
                status_code=status.HTTP_404_NOT_FOUND,
                message=str(exc),
                code="TASK_NOT_FOUND",
                request_id=context.request_id,
            )

    async def list_tasks(
        self,
        status_filter: Optional[str] = None,
        agent: Optional[str] = None,
        include_workspace_tasks: bool = False,
        limit: int = 50,
        offset: int = 0,
        context: AuthContext = Depends(get_current_auth_context),
    ) -> Dict[str, Any]:
        safe_limit = max(1, min(limit, 200))
        safe_offset = max(0, offset)

        normalized_agent = normalize_agent_name(agent) if agent else None

        tasks = TASK_STORE.list_tasks(
            context=context,
            status_filter=status_filter,
            agent_filter=normalized_agent,
            include_workspace_tasks=include_workspace_tasks,
            limit=safe_limit,
            offset=safe_offset,
        )

        return api_success(
            message="Task history loaded.",
            data={
                "tasks": [public_task(task) for task in tasks],
                "pagination": {
                    "limit": safe_limit,
                    "offset": safe_offset,
                    "returned": len(tasks),
                },
                "filters": {
                    "status": status_filter,
                    "agent": normalized_agent,
                    "include_workspace_tasks": include_workspace_tasks,
                },
                "isolation": {
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                },
            },
            request_id=context.request_id,
        )

    async def get_task_events(
        self,
        task_id: str,
        context: AuthContext = Depends(get_current_auth_context),
    ) -> Dict[str, Any]:
        try:
            task = TASK_STORE.require_task(task_id, context)
            events = TASK_STORE.list_events(task.task_id)

            return api_success(
                message="Task progress events loaded.",
                data={
                    "task_id": task.task_id,
                    "events": [public_event(event) for event in events],
                    "count": len(events),
                },
                request_id=context.request_id,
            )

        except PermissionError as exc:
            raise_api_error(
                status_code=status.HTTP_403_FORBIDDEN,
                message=str(exc),
                code="TASK_SCOPE_DENIED",
                request_id=context.request_id,
            )
        except ValueError as exc:
            raise_api_error(
                status_code=status.HTTP_404_NOT_FOUND,
                message=str(exc),
                code="TASK_EVENTS_NOT_FOUND",
                request_id=context.request_id,
            )

    async def get_task_audit(
        self,
        context: AuthContext = Depends(require_auth_role(Role.MANAGER.value)),
    ) -> Dict[str, Any]:
        scoped = [
            event
            for event in TASK_AUDIT_EVENTS
            if event.get("workspace_id") == context.workspace_id
        ]

        return api_success(
            message="Workspace-scoped task audit logs loaded.",
            data={
                "logs": scoped[-100:],
                "count": len(scoped[-100:]),
                "isolation": {
                    "workspace_id": context.workspace_id,
                    "requested_by_user_id": context.user_id,
                },
            },
            request_id=context.request_id,
        )

    async def _run_existing_task(
        self,
        task: TaskRecord,
        request: Request,
        context: AuthContext,
        run_payload: TaskRunRequest,
    ) -> Dict[str, Any]:
        if task.status in {TaskStatus.RUNNING.value}:
            raise_api_error(
                status_code=status.HTTP_409_CONFLICT,
                message="Task is already running.",
                code="TASK_ALREADY_RUNNING",
                request_id=context.request_id,
            )

        if task.status in {TaskStatus.COMPLETED.value, TaskStatus.CANCELLED.value}:
            raise_api_error(
                status_code=status.HTTP_409_CONFLICT,
                message="Task is already finished.",
                code="TASK_ALREADY_FINISHED",
                request_id=context.request_id,
                details={"status": task.status},
            )

        sensitive = looks_sensitive_task(public_task(task))

        if sensitive and not (task.approved_by_security or run_payload.approved_by_security):
            TASK_STORE.add_event(
                task=task,
                event_type="security_review_started",
                message="Sensitive task requires Security Agent review.",
                progress=10,
                metadata={"sensitive": True},
            )

            security_result = await security_review(
                {
                    "type": "task_run_security_review",
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "task": public_task(task),
                    "runtime_input": run_payload.runtime_input,
                    "request_id": context.request_id,
                    "created_at": utc_now(),
                }
            )

            if not security_approved(security_result):
                updated = TASK_STORE.update_task(
                    task.task_id,
                    {
                        "status": TaskStatus.WAITING_SECURITY.value,
                        "security_result": security_result,
                    },
                )

                TASK_STORE.add_event(
                    task=updated,
                    event_type="security_review_denied_or_pending",
                    message="Sensitive task was not approved by Security Agent.",
                    progress=10,
                    metadata={"security_result": security_result},
                )

                write_task_audit(
                    request=request,
                    context=context,
                    event_type="task_security_review",
                    action="run_task",
                    result="blocked",
                    task_id=task.task_id,
                    status_code=status.HTTP_403_FORBIDDEN,
                    metadata={"security_result": security_result},
                )

                raise_api_error(
                    status_code=status.HTTP_403_FORBIDDEN,
                    message="Sensitive task requires Security Agent approval.",
                    code="SECURITY_APPROVAL_REQUIRED",
                    request_id=context.request_id,
                    details=security_result,
                )

            task = TASK_STORE.update_task(
                task.task_id,
                {
                    "approved_by_security": True,
                    "security_result": security_result,
                },
            )
        elif run_payload.approved_by_security and not task.approved_by_security:
            task = TASK_STORE.update_task(
                task.task_id,
                {
                    "approved_by_security": True,
                    "security_result": {
                        "success": True,
                        "message": "Security approval flag supplied by caller.",
                        "data": {"approved": True, "caller_supplied": True},
                        "error": None,
                        "metadata": {"timestamp": utc_now()},
                    },
                },
            )

        running = TASK_STORE.update_task(
            task.task_id,
            {
                "status": TaskStatus.RUNNING.value,
                "started_at": utc_now(),
                "metadata": {
                    **task.metadata,
                    **run_payload.metadata,
                },
            },
        )

        TASK_STORE.add_event(
            task=running,
            event_type="task_running",
            message="Task execution started.",
            progress=25,
            metadata={"preferred_agent": running.preferred_agent},
        )

        result = await run_task_through_master(
            task=running,
            context=context,
            runtime_input=run_payload.runtime_input,
        )

        final_status = TaskStatus.COMPLETED.value if result.get("success") else TaskStatus.FAILED.value

        verification_payload = {
            "type": "task_completion_verification",
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "task_id": running.task_id,
            "task": public_task(running),
            "result": result,
            "created_at": utc_now(),
        }

        verification_result = await prepare_verification(verification_payload)

        memory_payload = {
            "type": "task_result_memory",
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "content": {
                "event": "task_finished",
                "task_id": running.task_id,
                "action": running.action,
                "preferred_agent": running.preferred_agent,
                "result_success": result.get("success"),
                "result_message": result.get("message"),
            },
            "created_at": utc_now(),
        }

        memory_result = await emit_memory_context(memory_payload)

        completed = TASK_STORE.update_task(
            running.task_id,
            {
                "status": final_status,
                "result": result if result.get("success") else None,
                "error": result.get("error") if not result.get("success") else None,
                "completed_at": utc_now(),
                "verification_payload": verification_payload,
                "verification_result": verification_result,
                "memory_payload": memory_payload,
                "memory_result": memory_result,
            },
        )

        TASK_STORE.add_event(
            task=completed,
            event_type="task_completed" if result.get("success") else "task_failed",
            message=result.get("message", "Task execution finished."),
            progress=100 if result.get("success") else None,
            metadata={
                "result_success": result.get("success"),
                "verification_success": verification_result.get("success"),
                "memory_success": memory_result.get("success"),
            },
        )

        audit = write_task_audit(
            request=request,
            context=context,
            event_type="task_run",
            action="run_task",
            result="success" if result.get("success") else "failed",
            task_id=running.task_id,
            status_code=status.HTTP_200_OK if result.get("success") else status.HTTP_500_INTERNAL_SERVER_ERROR,
            metadata={
                "preferred_agent": running.preferred_agent,
                "sensitive": sensitive,
                "final_status": final_status,
            },
        )

        return api_success(
            message="Task executed.",
            data={
                "task": public_task(completed),
                "result": result,
                "audit": audit,
                "verification_payload": verification_payload,
                "verification_result": verification_result,
                "memory_payload": memory_payload,
                "memory_result": memory_result,
            },
            request_id=context.request_id,
        )

    @staticmethod
    def _enforce_task_create_policy(context: AuthContext) -> None:
        if not has_min_role(context.role, Role.USER.value):
            raise_api_error(
                status_code=status.HTTP_403_FORBIDDEN,
                message="User role cannot create tasks.",
                code="TASK_CREATE_ROLE_REQUIRED",
                request_id=context.request_id,
            )

        if not has_min_plan(context.plan, Plan.FREE.value):
            raise_api_error(
                status_code=status.HTTP_402_PAYMENT_REQUIRED,
                message="A valid subscription plan is required to create tasks.",
                code="TASK_CREATE_PLAN_REQUIRED",
                request_id=context.request_id,
            )

        limit = task_monthly_limit(context.plan)
        current_count = TASK_STORE.count_tasks_for_scope(context)

        if limit != "custom" and current_count >= int(limit):
            raise_api_error(
                status_code=status.HTTP_402_PAYMENT_REQUIRED,
                message="Task limit reached for current plan.",
                code="TASK_LIMIT_REACHED",
                request_id=context.request_id,
                details={
                    "plan": context.plan,
                    "limit": limit,
                    "current_count": current_count,
                },
            )


tasks = Tasks()
router = tasks.router