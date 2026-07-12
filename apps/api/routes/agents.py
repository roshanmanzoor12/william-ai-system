"""
apps/api/routes/agents.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Agent management routes.

Purpose:
- List available agents
- Show agent capabilities
- Show agent health
- Enable/disable agents per workspace
- Manage user/workspace access to agents
- Prepare audit, memory, security, and verification payloads
- Keep strict user_id + workspace_id isolation

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

LOGGER_NAME = "william.api.routes.agents"
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


def parse_csv(value: Optional[str], default: Optional[List[str]] = None) -> List[str]:
    if not value:
        return default or []

    return [item.strip() for item in value.split(",") if item.strip()]


def normalize_agent_name(value: str) -> str:
    clean = (value or "").strip().lower().replace("-", "_").replace(" ", "_")

    if not clean:
        raise ValueError("Agent name is required.")

    if len(clean) > 80:
        raise ValueError("Agent name is too long.")

    return clean


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


# =============================================================================
# Settings
# =============================================================================

@dataclass(frozen=True)
class AgentRouteSettings:
    environment: str = field(default_factory=lambda: os.getenv("WILLIAM_ENV", "development"))
    debug: bool = field(default_factory=lambda: parse_bool(os.getenv("WILLIAM_DEBUG"), False))

    audit_enabled: bool = field(default_factory=lambda: parse_bool(os.getenv("WILLIAM_AUDIT_LOG_ENABLED"), True))
    security_agent_enabled: bool = field(default_factory=lambda: parse_bool(os.getenv("WILLIAM_SECURITY_AGENT_ENABLED"), True))
    memory_agent_enabled: bool = field(default_factory=lambda: parse_bool(os.getenv("WILLIAM_MEMORY_AGENT_ENABLED"), True))
    verification_agent_enabled: bool = field(
        default_factory=lambda: parse_bool(os.getenv("WILLIAM_VERIFICATION_AGENT_ENABLED"), True)
    )

    default_enabled_agents: List[str] = field(
        default_factory=lambda: parse_csv(
            os.getenv("WILLIAM_DEFAULT_ENABLED_AGENTS"),
            [
                "master",
                "memory",
                "security",
                "verification",
                "business",
                "creator",
            ],
        )
    )
    allow_runtime_disable_core_agents: bool = field(
        default_factory=lambda: parse_bool(os.getenv("WILLIAM_ALLOW_DISABLE_CORE_AGENTS"), False)
    )

    def public_dict(self) -> Dict[str, Any]:
        return asdict(self)


AGENT_SETTINGS = AgentRouteSettings()


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
    # "member" is not one of this enum's own values -- it is the real
    # database-level WorkspaceMemberRole (database/models/workspace.py)
    # string that flows straight into AuthContext.role for every real,
    # JWT-authenticated request (see apps/api/routes/auth.py's
    # get_current_auth_context: role=membership.role). Without this
    # mapping, ROLE_RANK.get("member", 0) silently fell through to 0 --
    # lower than even "viewer" -- so any real workspace member (the most
    # common non-owner role) was denied every agent that only requires
    # the baseline Role.USER tier (master, memory, security, verification,
    # business, creator), even though workspace membership rules
    # (default_member_agent_access in database/models/workspace.py)
    # clearly intend members to reach those. "member" is the DB-level
    # equivalent of this enum's "user" tier, so it gets the same rank.
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

    if clean not in ROLE_RANK:
        return Role.USER.value

    return clean


def normalize_plan(plan: Optional[str]) -> str:
    clean = (plan or Plan.FREE.value).strip().lower()

    if clean not in PLAN_RANK:
        return Plan.FREE.value

    return clean


def has_min_role(current_role: str, required_role: str) -> bool:
    return ROLE_RANK.get(current_role, 0) >= ROLE_RANK.get(required_role, 0)


def has_min_plan(current_plan: str, required_plan: str) -> bool:
    return PLAN_RANK.get(current_plan, 0) >= PLAN_RANK.get(required_plan, 0)


# =============================================================================
# API Response Helpers
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
            "module": "agents",
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
                "module": "agents",
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
    is_platform_admin: bool = False


try:
    from apps.api.routes.auth import (  # type: ignore
        AuthContext,
        get_current_auth_context,
        require_auth_role,
        platform_admin_gets_unlimited_plan,
    )
except Exception as auth_import_exc:
    logger.warning("Auth import fallback enabled in agents.py: %s", auth_import_exc)
    AuthContext = FallbackAuthContext

    def platform_admin_gets_unlimited_plan(context: Any) -> bool:  # type: ignore
        return False

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
            permissions=["agent:read", "agent:execute", "agent:manage"],
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
# Optional Agent Hooks
# =============================================================================

class OptionalAgentHook:
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
                logger.info("Loaded optional agents hook: %s from %s", self.component_name, self.loaded_from)
                return True

            except Exception as exc:
                self.import_error = f"{module_path}.{attr_name}: {exc}"

        return False

    @staticmethod
    def _instantiate(cls: Any) -> Any:
        attempts = [{"settings": AGENT_SETTINGS}, {}]
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
                "error": {"code": "OPTIONAL_AGENT_UNAVAILABLE"},
                "metadata": {"timestamp": utc_now()},
            }

        try:
            if callable(self.instance) and not inspect.isclass(self.instance):
                result = await maybe_await(self.instance(payload))
                return self._normalize(result)

            for method_name in self.method_candidates:
                method = getattr(self.instance, method_name, None)
                if callable(method):
                    if method_name == "check_permission":
                        # agents.security_agent.security_agent.SecurityAgent.
                        # check_permission(task_context, action, ...) needs
                        # a real task_context (with "user_id", not this
                        # generic payload's "actor_user_id") plus a
                        # required positional "action" -- calling it with
                        # just `payload` raised a bare TypeError that
                        # `except Exception` below silently turned into a
                        # "Security Agent denied" 403 for every caller,
                        # regardless of role, on every agent enable/
                        # disable/access-update call. Adapt the payload
                        # instead of crashing.
                        task_context = dict(payload)
                        task_context.setdefault("user_id", payload.get("actor_user_id"))
                        action = str(payload.get("type") or payload.get("action") or "unknown_action")
                        result = await maybe_await(method(task_context, action))
                    else:
                        result = await maybe_await(method(payload))
                    return self._normalize(result)

            return {
                "success": False,
                "message": f"{self.component_name} has no compatible method.",
                "data": {
                    "component": self.component_name,
                    "method_candidates": self.method_candidates,
                },
                "error": {"code": "AGENT_METHOD_MISSING"},
                "metadata": {"timestamp": utc_now()},
            }

        except Exception as exc:
            return {
                "success": False,
                "message": f"{self.component_name} failed.",
                "data": {"component": self.component_name},
                "error": safe_error_detail(exc, AGENT_SETTINGS.debug),
                "metadata": {"timestamp": utc_now()},
            }

    @staticmethod
    def _normalize(result: Any) -> Dict[str, Any]:
        if isinstance(result, dict):
            return {
                "success": bool(result.get("success", True)),
                "message": str(result.get("message", "Agent hook completed.")),
                "data": result.get("data", {}),
                "error": result.get("error"),
                "metadata": result.get("metadata", {"timestamp": utc_now()}),
            }

        return {
            "success": True,
            "message": "Agent hook completed.",
            "data": {"result": result},
            "error": None,
            "metadata": {"timestamp": utc_now()},
        }


SECURITY_AGENT = OptionalAgentHook(
    component_name="Security Agent",
    import_candidates=[
        ("apps.api.services.security_agent_bridge", "SecurityAgentBridge"),
        ("agents.security_agent.security_agent", "SecurityAgent"),
        ("agents.security.security_agent", "SecurityAgent"),
    ],
    method_candidates=["approve_agent_action", "approve_api_action", "approve_action", "check_permission", "execute", "run"],
)

MEMORY_AGENT = OptionalAgentHook(
    component_name="Memory Agent",
    import_candidates=[
        ("apps.api.services.memory_agent_bridge", "MemoryAgentBridge"),
        ("agents.memory_agent.memory_agent", "MemoryAgent"),
        ("agents.memory.memory_agent", "MemoryAgent"),
    ],
    method_candidates=["record_agent_context", "record_api_context", "save_context", "remember", "execute", "run"],
)

VERIFICATION_AGENT = OptionalAgentHook(
    component_name="Verification Agent",
    import_candidates=[
        ("apps.api.services.verification_agent_bridge", "VerificationAgentBridge"),
        ("agents.verification_agent.verification_agent", "VerificationAgent"),
        ("agents.verification.verification_agent", "VerificationAgent"),
    ],
    method_candidates=["prepare_agent_confirmation", "prepare_confirmation", "verify_result", "confirm", "execute", "run"],
)

REGISTRY_BRIDGE = OptionalAgentHook(
    component_name="Agent Registry",
    import_candidates=[
        ("apps.api.services.agent_registry_bridge", "AgentRegistryBridge"),
        ("agents.registry", "AgentRegistry"),
        ("agents.agent_registry", "AgentRegistry"),
        ("core.agent_registry", "AgentRegistry"),
    ],
    method_candidates=["list_agents", "get_agent_status", "get_capabilities", "health", "execute", "run"],
)


async def security_review(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not AGENT_SETTINGS.security_agent_enabled:
        return {
            "success": True,
            "message": "Security Agent hook disabled; action allowed by local policy.",
            "data": {"approved": True, "local_policy": True},
            "error": None,
            "metadata": {"timestamp": utc_now()},
        }

    return await SECURITY_AGENT.call(payload)


async def emit_memory_context(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not AGENT_SETTINGS.memory_agent_enabled:
        return {
            "success": False,
            "message": "Memory Agent hook disabled.",
            "data": {},
            "error": {"code": "MEMORY_HOOK_DISABLED"},
            "metadata": {"timestamp": utc_now()},
        }

    return await MEMORY_AGENT.call(payload)


async def prepare_verification(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not AGENT_SETTINGS.verification_agent_enabled:
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
            # SecurityAgent.check_permission's real return shape uses
            # "granted", not "approved"/"allowed".
            or data.get("granted") is True
        )
    )


# =============================================================================
# Agent Catalog
# =============================================================================

class AgentTier(str, Enum):
    CORE = "core"
    STANDARD = "standard"
    SUPER = "super"
    FUTURE = "future"


class AgentStatus(str, Enum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    DISABLED = "disabled"
    DEGRADED = "degraded"


class AgentCapability(BaseModel):
    key: str
    label: str
    description: str
    sensitive: bool = False
    required_permission: Optional[str] = None


class AgentDefinition(BaseModel):
    agent_name: str
    display_name: str
    description: str
    tier: str
    required_plan: str
    required_role: str
    core_agent: bool = False
    default_enabled: bool = False
    import_candidates: List[Tuple[str, str]] = Field(default_factory=list)
    capabilities: List[AgentCapability] = Field(default_factory=list)


AGENT_CATALOG: Dict[str, AgentDefinition] = {
    "master": AgentDefinition(
        agent_name="master",
        display_name="Master Agent",
        description="Routes tasks to the correct William/Jarvis agent and controls high-level execution flow.",
        tier=AgentTier.CORE.value,
        required_plan=Plan.FREE.value,
        required_role=Role.USER.value,
        core_agent=True,
        default_enabled=True,
        import_candidates=[
            ("core.master_agent", "MasterAgent"),
            ("agents.master_agent.master_agent", "MasterAgent"),
            ("agents.master.master_agent", "MasterAgent"),
        ],
        capabilities=[
            AgentCapability(key="route_task", label="Route Task", description="Routes user tasks to the best agent."),
            AgentCapability(key="coordinate_agents", label="Coordinate Agents", description="Coordinates multi-agent workflows."),
        ],
    ),
    "voice": AgentDefinition(
        agent_name="voice",
        display_name="Voice Agent",
        description="Handles voice input/output, speech responses, and voice interaction workflows.",
        tier=AgentTier.STANDARD.value,
        required_plan=Plan.STARTER.value,
        required_role=Role.USER.value,
        default_enabled=False,
        import_candidates=[
            ("agents.voice_agent.voice_agent", "VoiceAgent"),
            ("voice_agent.voice_agent", "VoiceAgent"),
        ],
        capabilities=[
            AgentCapability(key="speak", label="Speak", description="Generate spoken responses."),
            AgentCapability(key="listen", label="Listen", description="Handle microphone or voice stream input.", sensitive=True),
        ],
    ),
    "system": AgentDefinition(
        agent_name="system",
        display_name="System Agent",
        description="Handles local/device system tasks when worker permissions allow it.",
        tier=AgentTier.STANDARD.value,
        required_plan=Plan.BUSINESS.value,
        required_role=Role.ADMIN.value,
        default_enabled=False,
        import_candidates=[
            ("agents.system_agent.system_agent", "SystemAgent"),
        ],
        capabilities=[
            AgentCapability(
                key="system_control",
                label="System Control",
                description="Controls approved system/device actions.",
                sensitive=True,
                required_permission="agent:system",
            ),
            AgentCapability(
                key="safe_action_report",
                label="Safe Action Report",
                description="Reports system action results safely.",
            ),
        ],
    ),
    "browser": AgentDefinition(
        agent_name="browser",
        display_name="Browser Agent",
        description="Handles browser automation and web workflows with approval gates.",
        tier=AgentTier.STANDARD.value,
        required_plan=Plan.PRO.value,
        required_role=Role.DEVELOPER.value,
        default_enabled=False,
        import_candidates=[
            ("agents.browser_agent.browser_agent", "BrowserAgent"),
        ],
        capabilities=[
            AgentCapability(key="open_page", label="Open Page", description="Open and inspect pages."),
            AgentCapability(
                key="submit_form",
                label="Submit Form",
                description="Submit approved browser forms.",
                sensitive=True,
                required_permission="agent:browser_submit",
            ),
        ],
    ),
    "code": AgentDefinition(
        agent_name="code",
        display_name="Code Agent",
        description="Reviews, generates, patches, and explains project code.",
        tier=AgentTier.STANDARD.value,
        required_plan=Plan.PRO.value,
        required_role=Role.DEVELOPER.value,
        default_enabled=False,
        import_candidates=[
            ("agents.code_agent.code_agent", "CodeAgent"),
        ],
        capabilities=[
            AgentCapability(key="review_code", label="Review Code", description="Review code quality and bugs."),
            AgentCapability(key="generate_code", label="Generate Code", description="Generate project files."),
            AgentCapability(
                key="patch_files",
                label="Patch Files",
                description="Modify project files with approval.",
                sensitive=True,
                required_permission="agent:code_patch",
            ),
        ],
    ),
    "memory": AgentDefinition(
        agent_name="memory",
        display_name="Memory Agent",
        description="Stores and retrieves useful user/workspace context with strict isolation.",
        tier=AgentTier.CORE.value,
        required_plan=Plan.FREE.value,
        required_role=Role.USER.value,
        core_agent=True,
        default_enabled=True,
        import_candidates=[
            ("agents.memory_agent.memory_agent", "MemoryAgent"),
            ("agents.memory.memory_agent", "MemoryAgent"),
        ],
        capabilities=[
            AgentCapability(key="remember", label="Remember", description="Save useful scoped context."),
            AgentCapability(key="recall", label="Recall", description="Retrieve user/workspace scoped context."),
        ],
    ),
    "security": AgentDefinition(
        agent_name="security",
        display_name="Security Agent",
        description="Approves sensitive actions, checks policy, and blocks unsafe execution.",
        tier=AgentTier.CORE.value,
        required_plan=Plan.FREE.value,
        required_role=Role.USER.value,
        core_agent=True,
        default_enabled=True,
        import_candidates=[
            ("agents.security_agent.security_agent", "SecurityAgent"),
            ("agents.security.security_agent", "SecurityAgent"),
        ],
        capabilities=[
            AgentCapability(key="approve_action", label="Approve Action", description="Approve or deny sensitive tasks."),
            AgentCapability(key="policy_check", label="Policy Check", description="Check user/workspace permissions."),
        ],
    ),
    "verification": AgentDefinition(
        agent_name="verification",
        display_name="Verification Agent",
        description="Prepares completion confirmations and checks action results.",
        tier=AgentTier.CORE.value,
        required_plan=Plan.FREE.value,
        required_role=Role.USER.value,
        core_agent=True,
        default_enabled=True,
        import_candidates=[
            ("agents.verification_agent.verification_agent", "VerificationAgent"),
            ("agents.verification.verification_agent", "VerificationAgent"),
        ],
        capabilities=[
            AgentCapability(key="verify_result", label="Verify Result", description="Verify task completion."),
            AgentCapability(key="prepare_confirmation", label="Prepare Confirmation", description="Prepare confirmation payloads."),
        ],
    ),
    "visual": AgentDefinition(
        agent_name="visual",
        display_name="Visual Agent",
        description="Handles visual understanding, screenshots, UI checks, and visual reports.",
        tier=AgentTier.STANDARD.value,
        required_plan=Plan.PRO.value,
        required_role=Role.USER.value,
        default_enabled=False,
        import_candidates=[
            ("agents.visual_agent.visual_agent", "VisualAgent"),
        ],
        capabilities=[
            AgentCapability(key="analyze_image", label="Analyze Image", description="Analyze visual input."),
            AgentCapability(key="ui_review", label="UI Review", description="Review UI/UX screenshots."),
        ],
    ),
    "workflow": AgentDefinition(
        agent_name="workflow",
        display_name="Workflow Agent",
        description="Builds and manages multi-step workflows and automation plans.",
        tier=AgentTier.STANDARD.value,
        required_plan=Plan.PRO.value,
        required_role=Role.MANAGER.value,
        default_enabled=False,
        import_candidates=[
            ("agents.workflow_agent.workflow_agent", "WorkflowAgent"),
        ],
        capabilities=[
            AgentCapability(key="create_workflow", label="Create Workflow", description="Create workflow plans."),
            AgentCapability(
                key="run_workflow",
                label="Run Workflow",
                description="Run approved workflow automations.",
                sensitive=True,
                required_permission="agent:workflow_run",
            ),
        ],
    ),
    "hologram": AgentDefinition(
        agent_name="hologram",
        display_name="Hologram Agent",
        description="Future-facing visual/avatar/hologram interface layer.",
        tier=AgentTier.SUPER.value,
        required_plan=Plan.ENTERPRISE.value,
        required_role=Role.ADMIN.value,
        default_enabled=False,
        import_candidates=[
            ("agents.super_agents.hologram_agent.hologram_agent", "HologramAgent"),
        ],
        capabilities=[
            AgentCapability(key="render_avatar", label="Render Avatar", description="Render avatar/hologram responses."),
        ],
    ),
    "call": AgentDefinition(
        agent_name="call",
        display_name="Call Agent",
        description="Handles approved calling workflows, call summaries, and call action reports.",
        tier=AgentTier.SUPER.value,
        required_plan=Plan.BUSINESS.value,
        required_role=Role.MANAGER.value,
        default_enabled=False,
        import_candidates=[
            ("agents.super_agents.call_agent.call_agent", "CallAgent"),
        ],
        capabilities=[
            AgentCapability(
                key="make_call",
                label="Make Call",
                description="Place approved calls.",
                sensitive=True,
                required_permission="agent:call_make",
            ),
            AgentCapability(key="summarize_call", label="Summarize Call", description="Summarize call outcomes."),
        ],
    ),
    "business": AgentDefinition(
        agent_name="business",
        display_name="Business Agent",
        description="Handles business strategy, operations, proposals, customer workflows, and SaaS planning.",
        tier=AgentTier.SUPER.value,
        required_plan=Plan.STARTER.value,
        required_role=Role.USER.value,
        default_enabled=True,
        import_candidates=[
            ("agents.super_agents.business_agent.business_agent", "BusinessAgent"),
        ],
        capabilities=[
            AgentCapability(key="business_plan", label="Business Plan", description="Generate business strategy and plans."),
            AgentCapability(key="proposal", label="Proposal", description="Create proposals and business documents."),
        ],
    ),
    "finance": AgentDefinition(
        agent_name="finance",
        display_name="Finance Agent",
        description="Handles finance summaries, budget planning, and approved financial analysis.",
        tier=AgentTier.SUPER.value,
        required_plan=Plan.BUSINESS.value,
        required_role=Role.MANAGER.value,
        default_enabled=False,
        import_candidates=[
            ("agents.super_agents.finance_agent.finance_agent", "FinanceAgent"),
        ],
        capabilities=[
            AgentCapability(key="budget_review", label="Budget Review", description="Review budget and financial data."),
            AgentCapability(
                key="financial_action",
                label="Financial Action",
                description="Prepare approved financial actions.",
                sensitive=True,
                required_permission="agent:finance_action",
            ),
        ],
    ),
    "creator": AgentDefinition(
        agent_name="creator",
        display_name="Creator Agent",
        description="Creates marketing content, campaigns, creative assets, scripts, and social content.",
        tier=AgentTier.SUPER.value,
        required_plan=Plan.STARTER.value,
        required_role=Role.USER.value,
        default_enabled=True,
        import_candidates=[
            ("agents.super_agents.creator_agent.creator_agent", "CreatorAgent"),
        ],
        capabilities=[
            AgentCapability(key="create_content", label="Create Content", description="Generate marketing and creative content."),
            AgentCapability(key="campaign_ideas", label="Campaign Ideas", description="Create campaign ideas and assets."),
        ],
    ),
}


CORE_AGENT_NAMES = {
    name
    for name, definition in AGENT_CATALOG.items()
    if definition.core_agent
}


# =============================================================================
# Workspace Agent Store
# =============================================================================

class WorkspaceAgentConfig(BaseModel):
    workspace_id: str
    agent_name: str
    enabled: bool = True
    enabled_by_user_id: Optional[str] = None
    disabled_by_user_id: Optional[str] = None
    allowed_user_ids: List[str] = Field(default_factory=list)
    denied_user_ids: List[str] = Field(default_factory=list)
    custom_permissions: List[str] = Field(default_factory=list)
    created_at: str
    updated_at: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AgentHealthRecord(BaseModel):
    agent_name: str
    status: str
    available: bool
    loaded: bool
    source: Optional[str] = None
    error: Optional[str] = None
    checked_at: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AgentAccessDecision(BaseModel):
    allowed: bool
    reason: str
    user_id: str
    workspace_id: str
    agent_name: str
    role: str
    plan: str
    enabled_for_workspace: bool
    required_role: str
    required_plan: str
    missing_permissions: List[str] = Field(default_factory=list)


class AgentStore:
    """
    In-memory development store.

    Replace later with database tables:
    - workspace_agent_settings
    - user_agent_access
    - agent_health_events
    - agent_audit_logs
    """

    def __init__(self) -> None:
        self.configs: Dict[str, WorkspaceAgentConfig] = {}
        self.health_cache: Dict[str, AgentHealthRecord] = {}

    @staticmethod
    def config_key(workspace_id: str, agent_name: str) -> str:
        return f"{workspace_id}:{agent_name}"

    def get_or_create_config(self, workspace_id: str, agent_name: str) -> WorkspaceAgentConfig:
        clean_agent = normalize_agent_name(agent_name)
        key = self.config_key(workspace_id, clean_agent)

        if key in self.configs:
            return self.configs[key]

        definition = require_agent_definition(clean_agent)
        now = utc_now()
        default_enabled = definition.default_enabled or clean_agent in AGENT_SETTINGS.default_enabled_agents

        config = WorkspaceAgentConfig(
            workspace_id=workspace_id,
            agent_name=clean_agent,
            enabled=default_enabled,
            created_at=now,
            updated_at=now,
            metadata={"source": "default_workspace_agent_config"},
        )

        self.configs[key] = config
        return config

    def set_enabled(
        self,
        workspace_id: str,
        agent_name: str,
        enabled: bool,
        actor_user_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> WorkspaceAgentConfig:
        config = self.get_or_create_config(workspace_id, agent_name)

        update = {
            "enabled": enabled,
            "updated_at": utc_now(),
            "metadata": {
                **config.metadata,
                **(metadata or {}),
            },
        }

        if enabled:
            update["enabled_by_user_id"] = actor_user_id
        else:
            update["disabled_by_user_id"] = actor_user_id

        updated = self._copy_config(config, update)
        self.configs[self.config_key(workspace_id, agent_name)] = updated
        return updated

    def update_access(
        self,
        workspace_id: str,
        agent_name: str,
        allowed_user_ids: Optional[List[str]] = None,
        denied_user_ids: Optional[List[str]] = None,
        custom_permissions: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> WorkspaceAgentConfig:
        config = self.get_or_create_config(workspace_id, agent_name)

        update: Dict[str, Any] = {
            "updated_at": utc_now(),
            "metadata": {
                **config.metadata,
                **(metadata or {}),
            },
        }

        if allowed_user_ids is not None:
            update["allowed_user_ids"] = sorted(set(allowed_user_ids))

        if denied_user_ids is not None:
            update["denied_user_ids"] = sorted(set(denied_user_ids))

        if custom_permissions is not None:
            update["custom_permissions"] = sorted(set(custom_permissions))

        updated = self._copy_config(config, update)
        self.configs[self.config_key(workspace_id, agent_name)] = updated
        return updated

    def list_workspace_configs(self, workspace_id: str) -> List[WorkspaceAgentConfig]:
        return [
            self.get_or_create_config(workspace_id, agent_name)
            for agent_name in AGENT_CATALOG.keys()
        ]

    def set_health(self, record: AgentHealthRecord) -> AgentHealthRecord:
        self.health_cache[record.agent_name] = record
        return record

    def get_health(self, agent_name: str) -> Optional[AgentHealthRecord]:
        return self.health_cache.get(normalize_agent_name(agent_name))

    @staticmethod
    def _copy_config(config: WorkspaceAgentConfig, update: Dict[str, Any]) -> WorkspaceAgentConfig:
        if hasattr(config, "model_copy"):
            return config.model_copy(update=update)

        return config.copy(update=update)


AGENT_STORE = AgentStore()


# =============================================================================
# Audit
# =============================================================================

AGENT_AUDIT_EVENTS: List[Dict[str, Any]] = []


def write_agent_audit(
    request: Request,
    context: AuthContext,
    event_type: str,
    action: str,
    result: str,
    agent_name: Optional[str] = None,
    target_user_id: Optional[str] = None,
    status_code: Optional[int] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    event = {
        "audit_id": new_id("audit"),
        "event_type": event_type,
        "action": action,
        "result": result,
        "agent_name": agent_name,
        "actor_user_id": context.user_id,
        "target_user_id": target_user_id,
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

    if AGENT_SETTINGS.audit_enabled:
        AGENT_AUDIT_EVENTS.append(event)

        if len(AGENT_AUDIT_EVENTS) > 1000:
            del AGENT_AUDIT_EVENTS[: len(AGENT_AUDIT_EVENTS) - 1000]

        logger.info(
            "Agent audit | type=%s | action=%s | actor=%s | workspace=%s | agent=%s | result=%s",
            event_type,
            action,
            context.user_id,
            context.workspace_id,
            agent_name,
            result,
        )

    return event


# =============================================================================
# Models
# =============================================================================

class AgentEnableRequest(BaseModel):
    reason: Optional[str] = Field(default=None, max_length=500)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AgentDisableRequest(BaseModel):
    reason: Optional[str] = Field(default=None, max_length=500)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AgentAccessUpdateRequest(BaseModel):
    allowed_user_ids: Optional[List[str]] = None
    denied_user_ids: Optional[List[str]] = None
    custom_permissions: Optional[List[str]] = None
    reason: Optional[str] = Field(default=None, max_length=500)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AgentAccessCheckRequest(BaseModel):
    agent_name: str = Field(..., min_length=1, max_length=80)
    capability_key: Optional[str] = Field(default=None, max_length=128)

    @validator("agent_name")
    def validate_agent_name(cls, value: str) -> str:
        return normalize_agent_name(value)


# =============================================================================
# Catalog / Health Helpers
# =============================================================================

def require_agent_definition(agent_name: str) -> AgentDefinition:
    clean = normalize_agent_name(agent_name)

    if clean not in AGENT_CATALOG:
        raise ValueError("Agent not found.")

    return AGENT_CATALOG[clean]


def public_agent_definition(definition: AgentDefinition) -> Dict[str, Any]:
    data = definition.model_dump() if hasattr(definition, "model_dump") else definition.dict()
    data["capabilities"] = [
        capability.model_dump() if hasattr(capability, "model_dump") else capability.dict()
        for capability in definition.capabilities
    ]

    # Full 50-capability futuristic manifest (agents/capability_manifest.py),
    # additive alongside the short `capabilities` list above (which real
    # permission-gate logic elsewhere in this file keys off of and must not
    # change shape). Import-safe: agents outside the 14 capability-bearing
    # keys (e.g. "master") or any capability_data import failure simply
    # yield an empty manifest here rather than breaking this endpoint.
    try:
        from agents.capability_manifest import (
            REQUIRED_CAPABILITY_COUNT,
            get_capabilities_as_dicts,
        )

        manifest = get_capabilities_as_dicts(definition.agent_name)
    except Exception as exc:  # noqa: BLE001 - import-safe by design
        logger.warning("public_agent_definition: capability_manifest unavailable for %s: %s", definition.agent_name, exc)
        manifest = []
        REQUIRED_CAPABILITY_COUNT = 50

    status_counts: Dict[str, int] = {}
    for entry in manifest:
        status_value = entry.get("status", "unknown")
        status_counts[status_value] = status_counts.get(status_value, 0) + 1

    data["capability_manifest"] = manifest
    data["capability_manifest_meta"] = {
        "count": len(manifest),
        "expected_count": REQUIRED_CAPABILITY_COUNT,
        "complete": len(manifest) == REQUIRED_CAPABILITY_COUNT,
        "status_breakdown": status_counts,
    }
    return data


def public_agent_config(config: WorkspaceAgentConfig) -> Dict[str, Any]:
    return config.model_dump() if hasattr(config, "model_dump") else config.dict()


def public_health(record: AgentHealthRecord) -> Dict[str, Any]:
    return record.model_dump() if hasattr(record, "model_dump") else record.dict()


def find_import_source(definition: AgentDefinition) -> Tuple[bool, Optional[str], Optional[str]]:
    for module_path, attr_name in definition.import_candidates:
        try:
            module = importlib.import_module(module_path)
            getattr(module, attr_name)
            return True, f"{module_path}.{attr_name}", None
        except Exception as exc:
            last_error = f"{module_path}.{attr_name}: {exc}"

    return False, None, locals().get("last_error", "No import candidates were available.")


async def get_agent_health(agent_name: str) -> AgentHealthRecord:
    definition = require_agent_definition(agent_name)

    loaded, source, error = find_import_source(definition)
    enabled_somewhere = any(
        config.agent_name == definition.agent_name and config.enabled
        for config in AGENT_STORE.configs.values()
    )

    status_value = AgentStatus.AVAILABLE.value if loaded else AgentStatus.UNAVAILABLE.value

    if not loaded and definition.core_agent:
        status_value = AgentStatus.DEGRADED.value

    record = AgentHealthRecord(
        agent_name=definition.agent_name,
        status=status_value,
        available=loaded,
        loaded=loaded,
        source=source,
        error=error,
        checked_at=utc_now(),
        metadata={
            "display_name": definition.display_name,
            "tier": definition.tier,
            "core_agent": definition.core_agent,
            "enabled_in_any_workspace": enabled_somewhere,
        },
    )

    AGENT_STORE.set_health(record)
    return record


def effective_plan_for(context: AuthContext) -> str:
    """
    A real platform admin testing locally (never in production, never a
    normal user) is treated as Plan.ENTERPRISE for every plan-gating check
    in this file -- see apps.api.routes.auth.platform_admin_gets_unlimited_plan
    for the shared, environment-aware predicate this relies on. The
    workspace's REAL stored plan (database.models.workspace.Workspace.plan)
    is never modified by this -- /admin/workspaces still shows and edits
    the true value.
    """
    if platform_admin_gets_unlimited_plan(context):
        return Plan.ENTERPRISE.value
    return normalize_plan(context.plan)


def evaluate_agent_access(
    context: AuthContext,
    agent_name: str,
    capability_key: Optional[str] = None,
) -> AgentAccessDecision:
    definition = require_agent_definition(agent_name)
    config = AGENT_STORE.get_or_create_config(context.workspace_id, definition.agent_name)
    plan = effective_plan_for(context)

    missing_permissions: List[str] = []

    if not config.enabled:
        return AgentAccessDecision(
            allowed=False,
            reason="Agent is disabled for this workspace.",
            user_id=context.user_id,
            workspace_id=context.workspace_id,
            agent_name=definition.agent_name,
            role=context.role,
            plan=plan,
            enabled_for_workspace=False,
            required_role=definition.required_role,
            required_plan=definition.required_plan,
            missing_permissions=[],
        )

    if context.user_id in config.denied_user_ids:
        return AgentAccessDecision(
            allowed=False,
            reason="User is denied access to this agent in this workspace.",
            user_id=context.user_id,
            workspace_id=context.workspace_id,
            agent_name=definition.agent_name,
            role=context.role,
            plan=plan,
            enabled_for_workspace=True,
            required_role=definition.required_role,
            required_plan=definition.required_plan,
            missing_permissions=[],
        )

    if config.allowed_user_ids and context.user_id not in config.allowed_user_ids:
        return AgentAccessDecision(
            allowed=False,
            reason="Agent is restricted to selected users in this workspace.",
            user_id=context.user_id,
            workspace_id=context.workspace_id,
            agent_name=definition.agent_name,
            role=context.role,
            plan=plan,
            enabled_for_workspace=True,
            required_role=definition.required_role,
            required_plan=definition.required_plan,
            missing_permissions=[],
        )

    if not has_min_role(context.role, definition.required_role):
        return AgentAccessDecision(
            allowed=False,
            reason="User role is not high enough for this agent.",
            user_id=context.user_id,
            workspace_id=context.workspace_id,
            agent_name=definition.agent_name,
            role=context.role,
            plan=plan,
            enabled_for_workspace=True,
            required_role=definition.required_role,
            required_plan=definition.required_plan,
            missing_permissions=[],
        )

    if not has_min_plan(plan, definition.required_plan):
        return AgentAccessDecision(
            allowed=False,
            reason="Workspace plan is not high enough for this agent.",
            user_id=context.user_id,
            workspace_id=context.workspace_id,
            agent_name=definition.agent_name,
            role=context.role,
            plan=plan,
            enabled_for_workspace=True,
            required_role=definition.required_role,
            required_plan=definition.required_plan,
            missing_permissions=[],
        )

    if capability_key:
        capability = next(
            (item for item in definition.capabilities if item.key == capability_key),
            None,
        )

        if not capability:
            return AgentAccessDecision(
                allowed=False,
                reason="Capability not found for this agent.",
                user_id=context.user_id,
                workspace_id=context.workspace_id,
                agent_name=definition.agent_name,
                role=context.role,
                plan=plan,
                enabled_for_workspace=True,
                required_role=definition.required_role,
                required_plan=definition.required_plan,
                missing_permissions=[],
            )

        required_permission = capability.required_permission
        user_permissions = set(getattr(context, "permissions", []) or [])
        config_permissions = set(config.custom_permissions or [])

        if required_permission and required_permission not in user_permissions and required_permission not in config_permissions:
            missing_permissions.append(required_permission)

    if missing_permissions:
        return AgentAccessDecision(
            allowed=False,
            reason="Required capability permissions are missing.",
            user_id=context.user_id,
            workspace_id=context.workspace_id,
            agent_name=definition.agent_name,
            role=context.role,
            plan=plan,
            enabled_for_workspace=True,
            required_role=definition.required_role,
            required_plan=definition.required_plan,
            missing_permissions=missing_permissions,
        )

    return AgentAccessDecision(
        allowed=True,
        reason="Access granted.",
        user_id=context.user_id,
        workspace_id=context.workspace_id,
        agent_name=definition.agent_name,
        role=context.role,
        plan=plan,
        enabled_for_workspace=True,
        required_role=definition.required_role,
        required_plan=definition.required_plan,
        missing_permissions=[],
    )


# =============================================================================
# Agents Class / Router
# =============================================================================

class Agents:
    """
    Required component name: Agents

    Provides agent list, capabilities, health, enable/disable, and user access.
    """

    def __init__(self) -> None:
        self.router = APIRouter(tags=["Agents"])
        self._register_routes()

    def _register_routes(self) -> None:
        self.router.get("")(self.list_agents)
        self.router.get("/catalog")(self.get_catalog)
        self.router.get("/health")(self.health_all_agents)
        self.router.post("/access/check")(self.check_access)
        self.router.get("/audit")(self.get_agent_audit)
        self.router.get("/{agent_name}")(self.get_agent)
        self.router.get("/{agent_name}/capabilities")(self.get_agent_capabilities)
        self.router.get("/{agent_name}/health")(self.health_agent)
        self.router.get("/{agent_name}/access")(self.get_agent_access)
        self.router.post("/{agent_name}/enable")(self.enable_agent)
        self.router.post("/{agent_name}/disable")(self.disable_agent)
        self.router.patch("/{agent_name}/access")(self.update_agent_access)

    async def list_agents(
        self,
        include_disabled: bool = True,
        context: AuthContext = Depends(get_current_auth_context),
    ) -> Dict[str, Any]:
        items: List[Dict[str, Any]] = []

        for definition in AGENT_CATALOG.values():
            config = AGENT_STORE.get_or_create_config(context.workspace_id, definition.agent_name)

            if not include_disabled and not config.enabled:
                continue

            access = evaluate_agent_access(context, definition.agent_name)
            health = AGENT_STORE.get_health(definition.agent_name)

            items.append(
                {
                    "agent": public_agent_definition(definition),
                    "workspace_config": public_agent_config(config),
                    "access": access.model_dump() if hasattr(access, "model_dump") else access.dict(),
                    "health": public_health(health) if health else None,
                }
            )

        return api_success(
            message="Workspace agent list loaded.",
            data={
                "agents": items,
                "count": len(items),
                "isolation": {
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                },
            },
            request_id=context.request_id,
        )

    async def get_catalog(
        self,
        context: AuthContext = Depends(get_current_auth_context),
    ) -> Dict[str, Any]:
        return api_success(
            message="Agent catalog loaded.",
            data={
                "catalog": [
                    public_agent_definition(definition)
                    for definition in AGENT_CATALOG.values()
                ],
                "count": len(AGENT_CATALOG),
                "core_agents": sorted(CORE_AGENT_NAMES),
                "total_named_agents": 15,
                "system_note": "Catalog includes Master plus the 14 William/Jarvis agents.",
            },
            request_id=context.request_id,
        )

    async def get_agent(
        self,
        agent_name: str,
        context: AuthContext = Depends(get_current_auth_context),
    ) -> Dict[str, Any]:
        try:
            clean = normalize_agent_name(agent_name)
            definition = require_agent_definition(clean)
            config = AGENT_STORE.get_or_create_config(context.workspace_id, clean)
            access = evaluate_agent_access(context, clean)
            health = await get_agent_health(clean)

            return api_success(
                message="Agent details loaded.",
                data={
                    "agent": public_agent_definition(definition),
                    "workspace_config": public_agent_config(config),
                    "access": access.model_dump() if hasattr(access, "model_dump") else access.dict(),
                    "health": public_health(health),
                    "isolation": {
                        "user_id": context.user_id,
                        "workspace_id": context.workspace_id,
                    },
                },
                request_id=context.request_id,
            )

        except ValueError as exc:
            raise_api_error(
                status_code=status.HTTP_404_NOT_FOUND,
                message=str(exc),
                code="AGENT_NOT_FOUND",
                request_id=context.request_id,
            )

    async def get_agent_capabilities(
        self,
        agent_name: str,
        context: AuthContext = Depends(get_current_auth_context),
    ) -> Dict[str, Any]:
        try:
            definition = require_agent_definition(agent_name)
            access = evaluate_agent_access(context, definition.agent_name)

            return api_success(
                message="Agent capabilities loaded.",
                data={
                    "agent_name": definition.agent_name,
                    "display_name": definition.display_name,
                    "capabilities": [
                        capability.model_dump() if hasattr(capability, "model_dump") else capability.dict()
                        for capability in definition.capabilities
                    ],
                    "access": access.model_dump() if hasattr(access, "model_dump") else access.dict(),
                },
                request_id=context.request_id,
            )

        except ValueError as exc:
            raise_api_error(
                status_code=status.HTTP_404_NOT_FOUND,
                message=str(exc),
                code="AGENT_NOT_FOUND",
                request_id=context.request_id,
            )

    async def health_all_agents(
        self,
        context: AuthContext = Depends(require_auth_role(Role.ANALYST.value)),
    ) -> Dict[str, Any]:
        records: List[AgentHealthRecord] = []

        for agent_name in AGENT_CATALOG.keys():
            records.append(await get_agent_health(agent_name))

        available_count = sum(1 for item in records if item.available)
        degraded_count = sum(1 for item in records if item.status == AgentStatus.DEGRADED.value)

        return api_success(
            message="Agent health check completed.",
            data={
                "health": [public_health(record) for record in records],
                "summary": {
                    "total": len(records),
                    "available": available_count,
                    "unavailable": len(records) - available_count,
                    "degraded": degraded_count,
                },
                "isolation": {
                    "workspace_id": context.workspace_id,
                    "requested_by_user_id": context.user_id,
                },
            },
            request_id=context.request_id,
        )

    async def health_agent(
        self,
        agent_name: str,
        context: AuthContext = Depends(require_auth_role(Role.ANALYST.value)),
    ) -> Dict[str, Any]:
        try:
            record = await get_agent_health(agent_name)

            return api_success(
                message="Agent health loaded.",
                data={"health": public_health(record)},
                request_id=context.request_id,
            )

        except ValueError as exc:
            raise_api_error(
                status_code=status.HTTP_404_NOT_FOUND,
                message=str(exc),
                code="AGENT_NOT_FOUND",
                request_id=context.request_id,
            )

    async def get_agent_access(
        self,
        agent_name: str,
        capability_key: Optional[str] = None,
        context: AuthContext = Depends(get_current_auth_context),
    ) -> Dict[str, Any]:
        try:
            definition = require_agent_definition(agent_name)
            config = AGENT_STORE.get_or_create_config(context.workspace_id, definition.agent_name)
            access = evaluate_agent_access(context, definition.agent_name, capability_key)

            return api_success(
                message="Agent access decision loaded.",
                data={
                    "agent_name": definition.agent_name,
                    "workspace_config": public_agent_config(config),
                    "access": access.model_dump() if hasattr(access, "model_dump") else access.dict(),
                },
                request_id=context.request_id,
            )

        except ValueError as exc:
            raise_api_error(
                status_code=status.HTTP_404_NOT_FOUND,
                message=str(exc),
                code="AGENT_ACCESS_CHECK_FAILED",
                request_id=context.request_id,
            )

    async def check_access(
        self,
        payload: AgentAccessCheckRequest,
        context: AuthContext = Depends(get_current_auth_context),
    ) -> Dict[str, Any]:
        try:
            access = evaluate_agent_access(
                context=context,
                agent_name=payload.agent_name,
                capability_key=payload.capability_key,
            )

            return api_success(
                message="Agent access checked.",
                data={
                    "access": access.model_dump() if hasattr(access, "model_dump") else access.dict(),
                    "capability_key": payload.capability_key,
                },
                request_id=context.request_id,
            )

        except ValueError as exc:
            raise_api_error(
                status_code=status.HTTP_404_NOT_FOUND,
                message=str(exc),
                code="AGENT_ACCESS_CHECK_FAILED",
                request_id=context.request_id,
            )

    async def enable_agent(
        self,
        agent_name: str,
        payload: AgentEnableRequest,
        request: Request,
        context: AuthContext = Depends(require_auth_role(Role.ADMIN.value)),
    ) -> Dict[str, Any]:
        try:
            definition = require_agent_definition(agent_name)
            plan = effective_plan_for(context)

            if not has_min_plan(plan, definition.required_plan):
                raise_api_error(
                    status_code=status.HTTP_402_PAYMENT_REQUIRED,
                    message="Current workspace plan cannot enable this agent.",
                    code="PLAN_REQUIRED",
                    request_id=context.request_id,
                    details={
                        "current_plan": plan,
                        "required_plan": definition.required_plan,
                    },
                )

            if not has_min_role(context.role, definition.required_role):
                raise_api_error(
                    status_code=status.HTTP_403_FORBIDDEN,
                    message="Current role cannot enable this agent.",
                    code="ROLE_REQUIRED",
                    request_id=context.request_id,
                    details={
                        "current_role": context.role,
                        "required_role": definition.required_role,
                    },
                )

            security_result = await security_review(
                {
                    "type": "agent_enable",
                    "actor_user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "agent_name": definition.agent_name,
                    "reason": payload.reason,
                    "request_id": context.request_id,
                    "created_at": utc_now(),
                }
            )

            if not security_approved(security_result):
                raise_api_error(
                    status_code=status.HTTP_403_FORBIDDEN,
                    message="Agent enable action was blocked by Security Agent.",
                    code="SECURITY_AGENT_DENIED",
                    request_id=context.request_id,
                    details=security_result,
                )

            config = AGENT_STORE.set_enabled(
                workspace_id=context.workspace_id,
                agent_name=definition.agent_name,
                enabled=True,
                actor_user_id=context.user_id,
                metadata={
                    **payload.metadata,
                    "reason": payload.reason,
                },
            )

            audit = write_agent_audit(
                request=request,
                context=context,
                event_type="agent_enable",
                action="enable_agent",
                result="success",
                agent_name=definition.agent_name,
                status_code=status.HTTP_200_OK,
                metadata={
                    "reason": payload.reason,
                    "security_result": security_result,
                },
            )

            memory_result = await emit_memory_context(
                {
                    "type": "agent_enable",
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "request_id": context.request_id,
                    "content": {
                        "event": "agent_enabled",
                        "agent_name": definition.agent_name,
                        "reason": payload.reason,
                    },
                    "created_at": utc_now(),
                }
            )

            verification_result = await prepare_verification(
                {
                    "type": "agent_enable_confirmation",
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "request_id": context.request_id,
                    "result": "success",
                    "agent_name": definition.agent_name,
                    "created_at": utc_now(),
                }
            )

            return api_success(
                message="Agent enabled for workspace.",
                data={
                    "agent": public_agent_definition(definition),
                    "workspace_config": public_agent_config(config),
                    "audit": audit,
                    "memory_result": memory_result,
                    "verification_result": verification_result,
                },
                request_id=context.request_id,
            )

        except ValueError as exc:
            raise_api_error(
                status_code=status.HTTP_404_NOT_FOUND,
                message=str(exc),
                code="AGENT_ENABLE_FAILED",
                request_id=context.request_id,
            )

    async def disable_agent(
        self,
        agent_name: str,
        payload: AgentDisableRequest,
        request: Request,
        context: AuthContext = Depends(require_auth_role(Role.ADMIN.value)),
    ) -> Dict[str, Any]:
        try:
            definition = require_agent_definition(agent_name)

            if definition.core_agent and not AGENT_SETTINGS.allow_runtime_disable_core_agents:
                raise_api_error(
                    status_code=status.HTTP_403_FORBIDDEN,
                    message="Core agents cannot be disabled by runtime API policy.",
                    code="CORE_AGENT_DISABLE_BLOCKED",
                    request_id=context.request_id,
                    details={
                        "agent_name": definition.agent_name,
                        "core_agent": True,
                    },
                )

            security_result = await security_review(
                {
                    "type": "agent_disable",
                    "actor_user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "agent_name": definition.agent_name,
                    "reason": payload.reason,
                    "request_id": context.request_id,
                    "created_at": utc_now(),
                }
            )

            if not security_approved(security_result):
                raise_api_error(
                    status_code=status.HTTP_403_FORBIDDEN,
                    message="Agent disable action was blocked by Security Agent.",
                    code="SECURITY_AGENT_DENIED",
                    request_id=context.request_id,
                    details=security_result,
                )

            config = AGENT_STORE.set_enabled(
                workspace_id=context.workspace_id,
                agent_name=definition.agent_name,
                enabled=False,
                actor_user_id=context.user_id,
                metadata={
                    **payload.metadata,
                    "reason": payload.reason,
                },
            )

            audit = write_agent_audit(
                request=request,
                context=context,
                event_type="agent_disable",
                action="disable_agent",
                result="success",
                agent_name=definition.agent_name,
                status_code=status.HTTP_200_OK,
                metadata={
                    "reason": payload.reason,
                    "security_result": security_result,
                },
            )

            memory_result = await emit_memory_context(
                {
                    "type": "agent_disable",
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "request_id": context.request_id,
                    "content": {
                        "event": "agent_disabled",
                        "agent_name": definition.agent_name,
                        "reason": payload.reason,
                    },
                    "created_at": utc_now(),
                }
            )

            verification_result = await prepare_verification(
                {
                    "type": "agent_disable_confirmation",
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "request_id": context.request_id,
                    "result": "success",
                    "agent_name": definition.agent_name,
                    "created_at": utc_now(),
                }
            )

            return api_success(
                message="Agent disabled for workspace.",
                data={
                    "agent": public_agent_definition(definition),
                    "workspace_config": public_agent_config(config),
                    "audit": audit,
                    "memory_result": memory_result,
                    "verification_result": verification_result,
                },
                request_id=context.request_id,
            )

        except ValueError as exc:
            raise_api_error(
                status_code=status.HTTP_404_NOT_FOUND,
                message=str(exc),
                code="AGENT_DISABLE_FAILED",
                request_id=context.request_id,
            )

    async def update_agent_access(
        self,
        agent_name: str,
        payload: AgentAccessUpdateRequest,
        request: Request,
        context: AuthContext = Depends(require_auth_role(Role.ADMIN.value)),
    ) -> Dict[str, Any]:
        try:
            definition = require_agent_definition(agent_name)

            security_result = await security_review(
                {
                    "type": "agent_access_update",
                    "actor_user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "agent_name": definition.agent_name,
                    "allowed_user_ids": payload.allowed_user_ids,
                    "denied_user_ids": payload.denied_user_ids,
                    "custom_permissions": payload.custom_permissions,
                    "reason": payload.reason,
                    "request_id": context.request_id,
                    "created_at": utc_now(),
                }
            )

            if not security_approved(security_result):
                raise_api_error(
                    status_code=status.HTTP_403_FORBIDDEN,
                    message="Agent access update was blocked by Security Agent.",
                    code="SECURITY_AGENT_DENIED",
                    request_id=context.request_id,
                    details=security_result,
                )

            config = AGENT_STORE.update_access(
                workspace_id=context.workspace_id,
                agent_name=definition.agent_name,
                allowed_user_ids=payload.allowed_user_ids,
                denied_user_ids=payload.denied_user_ids,
                custom_permissions=payload.custom_permissions,
                metadata={
                    **payload.metadata,
                    "reason": payload.reason,
                    "updated_by_user_id": context.user_id,
                },
            )

            audit = write_agent_audit(
                request=request,
                context=context,
                event_type="agent_access_update",
                action="update_agent_access",
                result="success",
                agent_name=definition.agent_name,
                status_code=status.HTTP_200_OK,
                metadata={
                    "allowed_user_ids": payload.allowed_user_ids,
                    "denied_user_ids": payload.denied_user_ids,
                    "custom_permissions": payload.custom_permissions,
                    "reason": payload.reason,
                    "security_result": security_result,
                },
            )

            memory_result = await emit_memory_context(
                {
                    "type": "agent_access_update",
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "request_id": context.request_id,
                    "content": {
                        "event": "agent_access_updated",
                        "agent_name": definition.agent_name,
                        "reason": payload.reason,
                    },
                    "created_at": utc_now(),
                }
            )

            verification_result = await prepare_verification(
                {
                    "type": "agent_access_update_confirmation",
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "request_id": context.request_id,
                    "result": "success",
                    "agent_name": definition.agent_name,
                    "created_at": utc_now(),
                }
            )

            return api_success(
                message="Agent access updated for workspace.",
                data={
                    "agent": public_agent_definition(definition),
                    "workspace_config": public_agent_config(config),
                    "audit": audit,
                    "memory_result": memory_result,
                    "verification_result": verification_result,
                },
                request_id=context.request_id,
            )

        except ValueError as exc:
            raise_api_error(
                status_code=status.HTTP_404_NOT_FOUND,
                message=str(exc),
                code="AGENT_ACCESS_UPDATE_FAILED",
                request_id=context.request_id,
            )

    async def get_agent_audit(
        self,
        context: AuthContext = Depends(require_auth_role(Role.ADMIN.value)),
    ) -> Dict[str, Any]:
        scoped = [
            event
            for event in AGENT_AUDIT_EVENTS
            if event.get("workspace_id") == context.workspace_id
        ]

        return api_success(
            message="Workspace-scoped agent audit logs loaded.",
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


agents = Agents()
router = agents.router