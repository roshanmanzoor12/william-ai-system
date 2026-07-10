"""
apps/api/routes/workspaces.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Workspace routes with SaaS-ready isolation.

Purpose:
- Workspace create/update
- Workspace list/detail
- Member invite/access management
- Invite accept/revoke
- Member role/permission updates
- Member removal
- Workspace audit visibility
- Security Agent review for sensitive actions
- Memory Agent compatible context payloads
- Verification Agent confirmation payloads

This file imports safely even when future files are missing.
"""

from __future__ import annotations

import importlib
import inspect
import logging
import os
import re
import secrets
import traceback
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Tuple

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field, validator


# =============================================================================
# Logging
# =============================================================================

LOGGER_NAME = "william.api.routes.workspaces"
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


def utc_now_dt() -> datetime:
    return datetime.now(timezone.utc)


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


def normalize_email(email: str) -> str:
    clean = (email or "").strip().lower()

    if not clean:
        raise ValueError("Email is required.")

    if len(clean) > 254:
        raise ValueError("Email is too long.")

    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", clean):
        raise ValueError("Email format is invalid.")

    return clean


def clean_name(value: str, field_name: str = "name") -> str:
    clean = (value or "").strip()

    if not clean:
        raise ValueError(f"{field_name} is required.")

    if len(clean) > 120:
        raise ValueError(f"{field_name} is too long.")

    return clean


# =============================================================================
# Settings
# =============================================================================

@dataclass(frozen=True)
class WorkspaceRouteSettings:
    environment: str = field(default_factory=lambda: os.getenv("WILLIAM_ENV", "development"))
    debug: bool = field(default_factory=lambda: parse_bool(os.getenv("WILLIAM_DEBUG"), False))

    audit_enabled: bool = field(default_factory=lambda: parse_bool(os.getenv("WILLIAM_AUDIT_LOG_ENABLED"), True))
    security_agent_enabled: bool = field(default_factory=lambda: parse_bool(os.getenv("WILLIAM_SECURITY_AGENT_ENABLED"), True))
    memory_agent_enabled: bool = field(default_factory=lambda: parse_bool(os.getenv("WILLIAM_MEMORY_AGENT_ENABLED"), True))
    verification_agent_enabled: bool = field(
        default_factory=lambda: parse_bool(os.getenv("WILLIAM_VERIFICATION_AGENT_ENABLED"), True)
    )

    default_plan: str = field(default_factory=lambda: os.getenv("WILLIAM_DEFAULT_PLAN", "free"))
    default_invite_expiry_hours: int = field(
        default_factory=lambda: parse_int(os.getenv("WILLIAM_INVITE_EXPIRY_HOURS"), 72)
    )
    max_workspaces_free: int = field(default_factory=lambda: parse_int(os.getenv("WILLIAM_MAX_WORKSPACES_FREE"), 1))
    max_workspaces_starter: int = field(default_factory=lambda: parse_int(os.getenv("WILLIAM_MAX_WORKSPACES_STARTER"), 1))
    max_workspaces_pro: int = field(default_factory=lambda: parse_int(os.getenv("WILLIAM_MAX_WORKSPACES_PRO"), 3))
    max_workspaces_business: int = field(default_factory=lambda: parse_int(os.getenv("WILLIAM_MAX_WORKSPACES_BUSINESS"), 10))
    max_members_free: int = field(default_factory=lambda: parse_int(os.getenv("WILLIAM_MAX_MEMBERS_FREE"), 1))
    max_members_starter: int = field(default_factory=lambda: parse_int(os.getenv("WILLIAM_MAX_MEMBERS_STARTER"), 3))
    max_members_pro: int = field(default_factory=lambda: parse_int(os.getenv("WILLIAM_MAX_MEMBERS_PRO"), 10))
    max_members_business: int = field(default_factory=lambda: parse_int(os.getenv("WILLIAM_MAX_MEMBERS_BUSINESS"), 50))

    allow_owner_removal: bool = field(default_factory=lambda: parse_bool(os.getenv("WILLIAM_ALLOW_OWNER_REMOVAL"), False))

    def public_dict(self) -> Dict[str, Any]:
        return asdict(self)


WORKSPACE_SETTINGS = WorkspaceRouteSettings()


# =============================================================================
# Roles / Plans / Permissions
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


DEFAULT_PERMISSIONS_BY_ROLE: Dict[str, List[str]] = {
    Role.OWNER.value: [
        "workspace:read",
        "workspace:update",
        "workspace:delete",
        "workspace:members:invite",
        "workspace:members:update",
        "workspace:members:remove",
        "workspace:audit:read",
        "agent:execute",
        "agent:manage",
        "billing:read",
        "billing:update",
    ],
    Role.ADMIN.value: [
        "workspace:read",
        "workspace:update",
        "workspace:members:invite",
        "workspace:members:update",
        "workspace:members:remove",
        "workspace:audit:read",
        "agent:execute",
        "agent:manage",
        "billing:read",
    ],
    Role.MANAGER.value: [
        "workspace:read",
        "workspace:members:invite",
        "workspace:audit:read",
        "agent:execute",
    ],
    Role.DEVELOPER.value: [
        "workspace:read",
        "agent:execute",
        "agent:manage",
    ],
    Role.ANALYST.value: [
        "workspace:read",
        "workspace:audit:read",
        "agent:execute",
    ],
    Role.AGENT.value: [
        "workspace:read",
        "agent:execute",
    ],
    Role.USER.value: [
        "workspace:read",
        "agent:execute",
    ],
    Role.VIEWER.value: [
        "workspace:read",
    ],
}


def normalize_role(role: Optional[str]) -> str:
    clean = (role or Role.USER.value).strip().lower()

    if clean not in ROLE_RANK:
        raise ValueError("Invalid role.")

    return clean


def normalize_plan(plan: Optional[str]) -> str:
    clean = (plan or WORKSPACE_SETTINGS.default_plan).strip().lower()

    if clean not in PLAN_RANK:
        raise ValueError("Invalid plan.")

    return clean


def has_min_role(current_role: str, required_role: str) -> bool:
    return ROLE_RANK.get(current_role, 0) >= ROLE_RANK.get(required_role, 0)


def can_manage_target(actor_role: str, target_role: str) -> bool:
    if actor_role == Role.OWNER.value:
        return True

    return ROLE_RANK.get(actor_role, 0) > ROLE_RANK.get(target_role, 0)


def plan_workspace_limit(plan: str) -> Any:
    normalized = normalize_plan(plan)

    limits = {
        Plan.FREE.value: WORKSPACE_SETTINGS.max_workspaces_free,
        Plan.STARTER.value: WORKSPACE_SETTINGS.max_workspaces_starter,
        Plan.PRO.value: WORKSPACE_SETTINGS.max_workspaces_pro,
        Plan.BUSINESS.value: WORKSPACE_SETTINGS.max_workspaces_business,
        Plan.ENTERPRISE.value: "custom",
    }

    return limits[normalized]


def plan_member_limit(plan: str) -> Any:
    normalized = normalize_plan(plan)

    limits = {
        Plan.FREE.value: WORKSPACE_SETTINGS.max_members_free,
        Plan.STARTER.value: WORKSPACE_SETTINGS.max_members_starter,
        Plan.PRO.value: WORKSPACE_SETTINGS.max_members_pro,
        Plan.BUSINESS.value: WORKSPACE_SETTINGS.max_members_business,
        Plan.ENTERPRISE.value: "custom",
    }

    return limits[normalized]


# =============================================================================
# Responses
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
            "module": "workspaces",
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
                "module": "workspaces",
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


class FallbackUserRecord(BaseModel):
    user_id: str
    email: str
    full_name: str
    created_at: str
    updated_at: str
    is_active: bool = True
    metadata: Dict[str, Any] = Field(default_factory=dict)


class FallbackWorkspaceRecord(BaseModel):
    workspace_id: str
    name: str
    owner_user_id: str
    plan: str = Plan.FREE.value
    subscription_status: str = "active"
    created_at: str
    updated_at: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class FallbackMembershipRecord(BaseModel):
    membership_id: str
    user_id: str
    workspace_id: str
    role: str
    plan: str
    permissions: List[str] = Field(default_factory=list)
    created_at: str
    updated_at: str
    is_active: bool = True


class FallbackAuthStore:
    def __init__(self) -> None:
        now = utc_now()
        self.users_by_id: Dict[str, Any] = {
            "demo_user": FallbackUserRecord(
                user_id="demo_user",
                email="dev@example.com",
                full_name="Demo Owner",
                created_at=now,
                updated_at=now,
                is_active=True,
                metadata={"source": "fallback_workspace_store"},
            )
        }
        self.user_id_by_email: Dict[str, str] = {"dev@example.com": "demo_user"}
        self.workspaces_by_id: Dict[str, Any] = {
            "demo_workspace": FallbackWorkspaceRecord(
                workspace_id="demo_workspace",
                name="Demo Workspace",
                owner_user_id="demo_user",
                plan=Plan.FREE.value,
                subscription_status="active",
                created_at=now,
                updated_at=now,
                metadata={},
            )
        }
        self.memberships_by_id: Dict[str, Any] = {
            "membership_demo": FallbackMembershipRecord(
                membership_id="membership_demo",
                user_id="demo_user",
                workspace_id="demo_workspace",
                role=Role.OWNER.value,
                plan=Plan.FREE.value,
                permissions=DEFAULT_PERMISSIONS_BY_ROLE[Role.OWNER.value],
                created_at=now,
                updated_at=now,
                is_active=True,
            )
        }
        self.membership_ids_by_user: Dict[str, List[str]] = {"demo_user": ["membership_demo"]}

    def get_user_by_id(self, user_id: str) -> Optional[Any]:
        return self.users_by_id.get(user_id)

    def get_user_by_email(self, email: str) -> Optional[Any]:
        user_id = self.user_id_by_email.get(normalize_email(email))
        if not user_id:
            return None
        return self.users_by_id.get(user_id)

    def get_workspace(self, workspace_id: str) -> Optional[Any]:
        return self.workspaces_by_id.get(workspace_id)

    def list_memberships_for_user(self, user_id: str) -> List[Any]:
        ids = self.membership_ids_by_user.get(user_id, [])
        return [self.memberships_by_id[item] for item in ids if item in self.memberships_by_id]

    def get_membership(self, user_id: str, workspace_id: str) -> Optional[Any]:
        for membership in self.list_memberships_for_user(user_id):
            if getattr(membership, "workspace_id", None) == workspace_id and getattr(membership, "is_active", True):
                return membership
        return None


try:
    from apps.api.routes.auth import (  # type: ignore
        AUTH_STORE,
        AuthContext,
        get_current_auth_context,
        require_auth_role,
    )
except Exception as auth_import_exc:
    logger.warning("Auth import fallback enabled in workspaces.py: %s", auth_import_exc)
    AUTH_STORE = FallbackAuthStore()
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
            permissions=DEFAULT_PERMISSIONS_BY_ROLE.get(normalize_role(x_user_role), []),
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
                logger.info("Loaded optional workspace hook: %s from %s", self.component_name, self.loaded_from)
                return True

            except Exception as exc:
                self.import_error = f"{module_path}.{attr_name}: {exc}"

        return False

    @staticmethod
    def _instantiate(cls: Any) -> Any:
        attempts = [{"settings": WORKSPACE_SETTINGS}, {}]
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
                "error": safe_error_detail(exc, WORKSPACE_SETTINGS.debug),
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
    method_candidates=["approve_workspace_action", "approve_api_action", "approve_action", "check_permission", "execute", "run"],
)

MEMORY_AGENT = OptionalAgentHook(
    component_name="Memory Agent",
    import_candidates=[
        ("apps.api.services.memory_agent_bridge", "MemoryAgentBridge"),
        ("agents.memory_agent.memory_agent", "MemoryAgent"),
        ("agents.memory.memory_agent", "MemoryAgent"),
    ],
    method_candidates=["record_workspace_context", "record_api_context", "save_context", "remember", "execute", "run"],
)

VERIFICATION_AGENT = OptionalAgentHook(
    component_name="Verification Agent",
    import_candidates=[
        ("apps.api.services.verification_agent_bridge", "VerificationAgentBridge"),
        ("agents.verification_agent.verification_agent", "VerificationAgent"),
        ("agents.verification.verification_agent", "VerificationAgent"),
    ],
    method_candidates=["prepare_workspace_confirmation", "prepare_confirmation", "verify_result", "confirm", "execute", "run"],
)


async def security_review(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not WORKSPACE_SETTINGS.security_agent_enabled:
        return {
            "success": True,
            "message": "Security Agent hook disabled; action allowed by local policy.",
            "data": {"approved": True, "local_policy": True},
            "error": None,
            "metadata": {"timestamp": utc_now()},
        }

    return await SECURITY_AGENT.call(payload)


async def emit_memory_context(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not WORKSPACE_SETTINGS.memory_agent_enabled:
        return {
            "success": False,
            "message": "Memory Agent hook disabled.",
            "data": {},
            "error": {"code": "MEMORY_HOOK_DISABLED"},
            "metadata": {"timestamp": utc_now()},
        }

    return await MEMORY_AGENT.call(payload)


async def prepare_verification(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not WORKSPACE_SETTINGS.verification_agent_enabled:
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
# Audit
# =============================================================================

WORKSPACE_AUDIT_EVENTS: List[Dict[str, Any]] = []


def write_workspace_audit(
    request: Request,
    context: AuthContext,
    event_type: str,
    action: str,
    result: str,
    target_workspace_id: Optional[str] = None,
    target_user_id: Optional[str] = None,
    status_code: Optional[int] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    event = {
        "audit_id": new_id("audit"),
        "event_type": event_type,
        "action": action,
        "result": result,
        "actor_user_id": context.user_id,
        "target_user_id": target_user_id,
        "workspace_id": target_workspace_id or context.workspace_id,
        "request_id": context.request_id,
        "route": str(request.url.path),
        "method": request.method,
        "status_code": status_code,
        "ip_address": getattr(context, "ip_address", None),
        "user_agent": getattr(context, "user_agent", None),
        "created_at": utc_now(),
        "metadata": metadata or {},
    }

    if WORKSPACE_SETTINGS.audit_enabled:
        WORKSPACE_AUDIT_EVENTS.append(event)

        if len(WORKSPACE_AUDIT_EVENTS) > 1000:
            del WORKSPACE_AUDIT_EVENTS[: len(WORKSPACE_AUDIT_EVENTS) - 1000]

        logger.info(
            "Workspace audit | type=%s | action=%s | actor=%s | workspace=%s | result=%s",
            event_type,
            action,
            context.user_id,
            event["workspace_id"],
            result,
        )

    return event


# =============================================================================
# Data Models
# =============================================================================

class WorkspaceCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    plan: Optional[str] = Field(default=None)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @validator("name")
    def validate_name(cls, value: str) -> str:
        return clean_name(value, "Workspace name")

    @validator("plan")
    def validate_plan(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        return normalize_plan(value)


class WorkspaceUpdateRequest(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=120)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @validator("name")
    def validate_name(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        return clean_name(value, "Workspace name")


class WorkspaceInviteRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=254)
    role: str = Field(default=Role.USER.value)
    permissions: Optional[List[str]] = None
    message: Optional[str] = Field(default=None, max_length=1000)
    expires_in_hours: Optional[int] = Field(default=None, ge=1, le=720)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @validator("email")
    def validate_email(cls, value: str) -> str:
        return normalize_email(value)

    @validator("role")
    def validate_role(cls, value: str) -> str:
        return normalize_role(value)


class InviteAcceptRequest(BaseModel):
    invite_token: str = Field(..., min_length=20, max_length=256)


class MemberRoleUpdateRequest(BaseModel):
    role: str
    permissions: Optional[List[str]] = None

    @validator("role")
    def validate_role(cls, value: str) -> str:
        return normalize_role(value)


class MemberAccessUpdateRequest(BaseModel):
    permissions: List[str] = Field(default_factory=list)
    is_active: Optional[bool] = None


class InviteRevokeRequest(BaseModel):
    invite_id: str = Field(..., min_length=1, max_length=128)


class WorkspaceInviteRecord(BaseModel):
    invite_id: str
    workspace_id: str
    invited_email: str
    invited_by_user_id: str
    role: str
    permissions: List[str] = Field(default_factory=list)
    token_hash: str
    message: Optional[str] = None
    status: str = "pending"
    expires_at: str
    created_at: str
    accepted_at: Optional[str] = None
    revoked_at: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


# =============================================================================
# Workspace Store Adapter
# =============================================================================

class WorkspaceStoreAdapter:
    def __init__(self, auth_store: Any) -> None:
        self.store = auth_store
        self.invites_by_id: Dict[str, WorkspaceInviteRecord] = {}
        self.invite_id_by_token_hash: Dict[str, str] = {}

    def get_user(self, user_id: str) -> Optional[Any]:
        getter = getattr(self.store, "get_user_by_id", None)
        if callable(getter):
            return getter(user_id)
        return getattr(self.store, "users_by_id", {}).get(user_id)

    def get_user_by_email(self, email: str) -> Optional[Any]:
        getter = getattr(self.store, "get_user_by_email", None)
        if callable(getter):
            return getter(email)

        user_id = getattr(self.store, "user_id_by_email", {}).get(normalize_email(email))
        if not user_id:
            return None
        return self.get_user(user_id)

    def get_workspace(self, workspace_id: str) -> Optional[Any]:
        getter = getattr(self.store, "get_workspace", None)
        if callable(getter):
            return getter(workspace_id)
        return getattr(self.store, "workspaces_by_id", {}).get(workspace_id)

    def list_user_memberships(self, user_id: str) -> List[Any]:
        getter = getattr(self.store, "list_memberships_for_user", None)
        if callable(getter):
            return getter(user_id)

        ids = getattr(self.store, "membership_ids_by_user", {}).get(user_id, [])
        memberships = getattr(self.store, "memberships_by_id", {})
        return [memberships[item] for item in ids if item in memberships]

    def get_membership(self, user_id: str, workspace_id: str) -> Optional[Any]:
        getter = getattr(self.store, "get_membership", None)
        if callable(getter):
            return getter(user_id, workspace_id)

        for membership in self.list_user_memberships(user_id):
            if getattr(membership, "workspace_id", None) == workspace_id and getattr(membership, "is_active", True):
                return membership

        return None

    def require_workspace(self, workspace_id: str) -> Any:
        workspace = self.get_workspace(workspace_id)
        if not workspace:
            raise ValueError("Workspace not found.")
        return workspace

    def require_membership(self, user_id: str, workspace_id: str) -> Any:
        membership = self.get_membership(user_id, workspace_id)
        if not membership:
            raise ValueError("User does not have access to this workspace.")
        return membership

    def list_workspaces_for_user(self, user_id: str) -> List[Tuple[Any, Any]]:
        rows: List[Tuple[Any, Any]] = []

        for membership in self.list_user_memberships(user_id):
            if not getattr(membership, "is_active", True):
                continue

            workspace = self.get_workspace(getattr(membership, "workspace_id"))
            if workspace:
                rows.append((workspace, membership))

        return rows

    def list_workspace_members(self, workspace_id: str) -> List[Tuple[Any, Any]]:
        memberships = getattr(self.store, "memberships_by_id", {})
        rows: List[Tuple[Any, Any]] = []

        for membership in memberships.values():
            if getattr(membership, "workspace_id", None) != workspace_id:
                continue
            if not getattr(membership, "is_active", True):
                continue

            user = self.get_user(getattr(membership, "user_id"))
            if user:
                rows.append((user, membership))

        return rows

    def create_workspace(
        self,
        owner_user_id: str,
        name: str,
        plan: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Any, Any]:
        users_by_id = getattr(self.store, "users_by_id", None)
        workspaces_by_id = getattr(self.store, "workspaces_by_id", None)
        memberships_by_id = getattr(self.store, "memberships_by_id", None)
        membership_ids_by_user = getattr(self.store, "membership_ids_by_user", None)

        if not isinstance(users_by_id, dict) or owner_user_id not in users_by_id:
            raise ValueError("Owner user not found.")

        if not isinstance(workspaces_by_id, dict):
            raise RuntimeError("Workspace store is not writable.")

        if not isinstance(memberships_by_id, dict) or not isinstance(membership_ids_by_user, dict):
            raise RuntimeError("Membership store is not writable.")

        now = utc_now()
        workspace_cls = self._infer_workspace_class()
        membership_cls = self._infer_membership_class()

        workspace = workspace_cls(
            workspace_id=new_id("workspace"),
            name=clean_name(name, "Workspace name"),
            owner_user_id=owner_user_id,
            plan=normalize_plan(plan),
            subscription_status="active",
            created_at=now,
            updated_at=now,
            metadata=metadata or {},
        )

        membership = membership_cls(
            membership_id=new_id("membership"),
            user_id=owner_user_id,
            workspace_id=getattr(workspace, "workspace_id"),
            role=Role.OWNER.value,
            plan=normalize_plan(plan),
            permissions=DEFAULT_PERMISSIONS_BY_ROLE[Role.OWNER.value],
            created_at=now,
            updated_at=now,
            is_active=True,
        )

        workspaces_by_id[getattr(workspace, "workspace_id")] = workspace
        memberships_by_id[getattr(membership, "membership_id")] = membership
        membership_ids_by_user.setdefault(owner_user_id, []).append(getattr(membership, "membership_id"))

        return workspace, membership

    def update_workspace(self, workspace_id: str, name: Optional[str], metadata: Optional[Dict[str, Any]]) -> Any:
        workspace = self.require_workspace(workspace_id)
        update_data: Dict[str, Any] = {}

        if name is not None:
            update_data["name"] = clean_name(name, "Workspace name")

        if metadata:
            current_metadata = dict(getattr(workspace, "metadata", {}) or {})
            current_metadata.update(metadata)
            update_data["metadata"] = current_metadata

        update_data["updated_at"] = utc_now()

        return self._replace_record("workspaces_by_id", workspace_id, workspace, update_data)

    def update_member(
        self,
        user_id: str,
        workspace_id: str,
        role: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        is_active: Optional[bool] = None,
    ) -> Any:
        membership = self.require_membership(user_id, workspace_id)
        update_data: Dict[str, Any] = {}

        if role is not None:
            update_data["role"] = normalize_role(role)

        if permissions is not None:
            update_data["permissions"] = permissions

        if is_active is not None:
            update_data["is_active"] = is_active

        update_data["updated_at"] = utc_now()

        return self._replace_record("memberships_by_id", getattr(membership, "membership_id"), membership, update_data)

    def add_member(
        self,
        user_id: str,
        workspace_id: str,
        role: str,
        permissions: Optional[List[str]] = None,
    ) -> Any:
        existing = self.get_membership(user_id, workspace_id)
        if existing:
            return self.update_member(
                user_id=user_id,
                workspace_id=workspace_id,
                role=role,
                permissions=permissions or DEFAULT_PERMISSIONS_BY_ROLE.get(role, []),
                is_active=True,
            )

        memberships_by_id = getattr(self.store, "memberships_by_id", None)
        membership_ids_by_user = getattr(self.store, "membership_ids_by_user", None)

        if not isinstance(memberships_by_id, dict) or not isinstance(membership_ids_by_user, dict):
            raise RuntimeError("Membership store is not writable.")

        workspace = self.require_workspace(workspace_id)
        membership_cls = self._infer_membership_class()
        now = utc_now()
        normalized_role = normalize_role(role)

        membership = membership_cls(
            membership_id=new_id("membership"),
            user_id=user_id,
            workspace_id=workspace_id,
            role=normalized_role,
            plan=getattr(workspace, "plan", WORKSPACE_SETTINGS.default_plan),
            permissions=permissions or DEFAULT_PERMISSIONS_BY_ROLE.get(normalized_role, []),
            created_at=now,
            updated_at=now,
            is_active=True,
        )

        memberships_by_id[getattr(membership, "membership_id")] = membership
        membership_ids_by_user.setdefault(user_id, []).append(getattr(membership, "membership_id"))

        return membership

    def create_invite(
        self,
        workspace_id: str,
        invited_email: str,
        invited_by_user_id: str,
        role: str,
        permissions: List[str],
        message: Optional[str],
        expires_in_hours: Optional[int],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[WorkspaceInviteRecord, str]:
        token = secrets.token_urlsafe(48)
        token_hash = self.hash_invite_token(token)
        expiry_hours = expires_in_hours or WORKSPACE_SETTINGS.default_invite_expiry_hours
        expires_at = (utc_now_dt() + timedelta(hours=expiry_hours)).isoformat()
        normalized_role = normalize_role(role)

        invite = WorkspaceInviteRecord(
            invite_id=new_id("invite"),
            workspace_id=workspace_id,
            invited_email=normalize_email(invited_email),
            invited_by_user_id=invited_by_user_id,
            role=normalized_role,
            permissions=permissions or DEFAULT_PERMISSIONS_BY_ROLE.get(normalized_role, []),
            token_hash=token_hash,
            message=message,
            status="pending",
            expires_at=expires_at,
            created_at=utc_now(),
            metadata=metadata or {},
        )

        self.invites_by_id[invite.invite_id] = invite
        self.invite_id_by_token_hash[token_hash] = invite.invite_id

        return invite, token

    def get_invite_by_token(self, token: str) -> Optional[WorkspaceInviteRecord]:
        invite_id = self.invite_id_by_token_hash.get(self.hash_invite_token(token))
        if not invite_id:
            return None
        return self.invites_by_id.get(invite_id)

    def get_invite(self, invite_id: str) -> Optional[WorkspaceInviteRecord]:
        return self.invites_by_id.get(invite_id)

    def list_invites_for_workspace(self, workspace_id: str) -> List[WorkspaceInviteRecord]:
        return [
            invite
            for invite in self.invites_by_id.values()
            if invite.workspace_id == workspace_id
        ]

    def update_invite(self, invite_id: str, update_data: Dict[str, Any]) -> WorkspaceInviteRecord:
        invite = self.invites_by_id.get(invite_id)
        if not invite:
            raise ValueError("Invite not found.")

        if hasattr(invite, "model_copy"):
            updated = invite.model_copy(update=update_data)
        else:
            updated = invite.copy(update=update_data)

        self.invites_by_id[invite_id] = updated
        return updated

    @staticmethod
    def hash_invite_token(token: str) -> str:
        import hashlib

        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def count_user_workspaces(self, user_id: str) -> int:
        return len(self.list_workspaces_for_user(user_id))

    def count_workspace_members(self, workspace_id: str) -> int:
        return len(self.list_workspace_members(workspace_id))

    def _replace_record(self, store_attr: str, record_id: str, record: Any, update_data: Dict[str, Any]) -> Any:
        mapping = getattr(self.store, store_attr, None)
        if not isinstance(mapping, dict):
            raise RuntimeError(f"Store does not expose {store_attr}.")

        if hasattr(record, "model_copy"):
            updated = record.model_copy(update=update_data)
        elif hasattr(record, "copy"):
            updated = record.copy(update=update_data)
        else:
            data = model_to_dict(record)
            data.update(update_data)
            updated = data

        mapping[record_id] = updated
        return updated

    def _infer_workspace_class(self) -> Any:
        workspaces = getattr(self.store, "workspaces_by_id", {})
        for workspace in workspaces.values():
            return workspace.__class__
        return FallbackWorkspaceRecord

    def _infer_membership_class(self) -> Any:
        memberships = getattr(self.store, "memberships_by_id", {})
        for membership in memberships.values():
            return membership.__class__
        return FallbackMembershipRecord


WORKSPACE_STORE = WorkspaceStoreAdapter(AUTH_STORE)


# =============================================================================
# Serialization
# =============================================================================

def safe_user(user: Any) -> Dict[str, Any]:
    data = model_to_dict(user)

    return {
        "user_id": data.get("user_id"),
        "email": data.get("email"),
        "full_name": data.get("full_name"),
        "created_at": data.get("created_at"),
        "updated_at": data.get("updated_at"),
        "is_active": data.get("is_active", True),
        "metadata": data.get("metadata", {}),
    }


def safe_workspace(workspace: Any) -> Dict[str, Any]:
    data = model_to_dict(workspace)

    return {
        "workspace_id": data.get("workspace_id"),
        "name": data.get("name"),
        "owner_user_id": data.get("owner_user_id"),
        "plan": data.get("plan", Plan.FREE.value),
        "subscription_status": data.get("subscription_status", "active"),
        "created_at": data.get("created_at"),
        "updated_at": data.get("updated_at"),
        "metadata": data.get("metadata", {}),
    }


def safe_membership(membership: Any) -> Dict[str, Any]:
    data = model_to_dict(membership)

    return {
        "membership_id": data.get("membership_id"),
        "user_id": data.get("user_id"),
        "workspace_id": data.get("workspace_id"),
        "role": data.get("role"),
        "plan": data.get("plan"),
        "permissions": data.get("permissions", []),
        "created_at": data.get("created_at"),
        "updated_at": data.get("updated_at"),
        "is_active": data.get("is_active", True),
    }


def safe_member(user: Any, membership: Any) -> Dict[str, Any]:
    return {
        "user": safe_user(user),
        "membership": safe_membership(membership),
    }


def safe_invite(invite: WorkspaceInviteRecord, include_token: Optional[str] = None) -> Dict[str, Any]:
    data = invite.model_dump() if hasattr(invite, "model_dump") else invite.dict()
    data.pop("token_hash", None)

    if include_token:
        data["invite_token"] = include_token

    return data


# =============================================================================
# Workspaces Class / Router
# =============================================================================

class Workspaces:
    """
    Required component name: Workspaces

    Workspace create/update/member invite/access management.
    """

    def __init__(self) -> None:
        self.router = APIRouter(tags=["Workspaces"])
        self._register_routes()

    def _register_routes(self) -> None:
        self.router.get("")(self.list_workspaces)
        self.router.post("")(self.create_workspace)
        self.router.get("/current")(self.get_current_workspace)
        self.router.patch("/current")(self.update_current_workspace)
        self.router.get("/current/members")(self.list_current_workspace_members)
        self.router.post("/current/invites")(self.invite_member)
        self.router.get("/current/invites")(self.list_invites)
        self.router.post("/invites/accept")(self.accept_invite)
        self.router.post("/current/invites/revoke")(self.revoke_invite)
        self.router.patch("/current/members/{target_user_id}/role")(self.update_member_role)
        self.router.patch("/current/members/{target_user_id}/access")(self.update_member_access)
        self.router.delete("/current/members/{target_user_id}")(self.remove_member)
        self.router.get("/current/audit")(self.get_workspace_audit)
        self.router.get("/{workspace_id}")(self.get_workspace_by_id)

    async def list_workspaces(
        self,
        context: AuthContext = Depends(get_current_auth_context),
    ) -> Dict[str, Any]:
        rows = WORKSPACE_STORE.list_workspaces_for_user(context.user_id)

        return api_success(
            message="User workspaces loaded.",
            data={
                "workspaces": [
                    {
                        "workspace": safe_workspace(workspace),
                        "membership": safe_membership(membership),
                    }
                    for workspace, membership in rows
                ],
                "count": len(rows),
                "isolation": {
                    "user_id": context.user_id,
                    "current_workspace_id": context.workspace_id,
                },
            },
            request_id=context.request_id,
        )

    async def create_workspace(
        self,
        payload: WorkspaceCreateRequest,
        request: Request,
        context: AuthContext = Depends(get_current_auth_context),
    ) -> Dict[str, Any]:
        try:
            current_plan = normalize_plan(context.plan)
            limit = plan_workspace_limit(current_plan)
            current_count = WORKSPACE_STORE.count_user_workspaces(context.user_id)

            if limit != "custom" and current_count >= int(limit):
                raise_api_error(
                    status_code=status.HTTP_402_PAYMENT_REQUIRED,
                    message="Workspace creation limit reached for current plan.",
                    code="WORKSPACE_LIMIT_REACHED",
                    request_id=context.request_id,
                    details={
                        "current_plan": current_plan,
                        "limit": limit,
                        "current_count": current_count,
                    },
                )

            security_result = await security_review(
                {
                    "type": "workspace_create",
                    "actor_user_id": context.user_id,
                    "current_workspace_id": context.workspace_id,
                    "new_workspace_name": payload.name,
                    "requested_plan": payload.plan or current_plan,
                    "request_id": context.request_id,
                    "created_at": utc_now(),
                }
            )

            if not security_approved(security_result):
                raise_api_error(
                    status_code=status.HTTP_403_FORBIDDEN,
                    message="Workspace creation was blocked by Security Agent.",
                    code="SECURITY_AGENT_DENIED",
                    request_id=context.request_id,
                    details=security_result,
                )

            workspace, membership = WORKSPACE_STORE.create_workspace(
                owner_user_id=context.user_id,
                name=payload.name,
                plan=payload.plan or current_plan,
                metadata={
                    **payload.metadata,
                    "created_by_user_id": context.user_id,
                    "created_from": "workspaces_route",
                },
            )

            audit = write_workspace_audit(
                request=request,
                context=context,
                event_type="workspace_create",
                action="create_workspace",
                result="success",
                target_workspace_id=getattr(workspace, "workspace_id"),
                status_code=status.HTTP_201_CREATED,
                metadata={"security_result": security_result},
            )

            memory_result = await emit_memory_context(
                {
                    "type": "workspace_create",
                    "user_id": context.user_id,
                    "workspace_id": getattr(workspace, "workspace_id"),
                    "request_id": context.request_id,
                    "content": {
                        "event": "workspace_created",
                        "workspace_name": getattr(workspace, "name"),
                        "owner_user_id": context.user_id,
                    },
                    "created_at": utc_now(),
                }
            )

            verification_result = await prepare_verification(
                {
                    "type": "workspace_create_confirmation",
                    "user_id": context.user_id,
                    "workspace_id": getattr(workspace, "workspace_id"),
                    "request_id": context.request_id,
                    "result": "success",
                    "created_at": utc_now(),
                }
            )

            return api_success(
                message="Workspace created successfully.",
                data={
                    "workspace": safe_workspace(workspace),
                    "membership": safe_membership(membership),
                    "audit": audit,
                    "memory_result": memory_result,
                    "verification_result": verification_result,
                },
                request_id=context.request_id,
            )

        except ValueError as exc:
            raise_api_error(
                status_code=status.HTTP_400_BAD_REQUEST,
                message=str(exc),
                code="WORKSPACE_CREATE_FAILED",
                request_id=context.request_id,
            )

    async def get_current_workspace(
        self,
        context: AuthContext = Depends(get_current_auth_context),
    ) -> Dict[str, Any]:
        workspace = WORKSPACE_STORE.get_workspace(context.workspace_id)
        membership = WORKSPACE_STORE.get_membership(context.user_id, context.workspace_id)

        if not workspace or not membership:
            raise_api_error(
                status_code=status.HTTP_404_NOT_FOUND,
                message="Current workspace scope could not be loaded.",
                code="WORKSPACE_SCOPE_NOT_FOUND",
                request_id=context.request_id,
            )

        member_count = WORKSPACE_STORE.count_workspace_members(context.workspace_id)

        return api_success(
            message="Current workspace loaded.",
            data={
                "workspace": safe_workspace(workspace),
                "membership": safe_membership(membership),
                "limits": {
                    "member_limit": plan_member_limit(safe_workspace(workspace)["plan"]),
                    "current_members": member_count,
                },
                "isolation": {
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                },
            },
            request_id=context.request_id,
        )

    async def get_workspace_by_id(
        self,
        workspace_id: str,
        context: AuthContext = Depends(get_current_auth_context),
    ) -> Dict[str, Any]:
        membership = WORKSPACE_STORE.get_membership(context.user_id, workspace_id)

        if not membership:
            raise_api_error(
                status_code=status.HTTP_403_FORBIDDEN,
                message="You do not have access to this workspace.",
                code="WORKSPACE_ACCESS_DENIED",
                request_id=context.request_id,
            )

        workspace = WORKSPACE_STORE.get_workspace(workspace_id)

        if not workspace:
            raise_api_error(
                status_code=status.HTTP_404_NOT_FOUND,
                message="Workspace not found.",
                code="WORKSPACE_NOT_FOUND",
                request_id=context.request_id,
            )

        return api_success(
            message="Workspace loaded.",
            data={
                "workspace": safe_workspace(workspace),
                "membership": safe_membership(membership),
            },
            request_id=context.request_id,
        )

    async def update_current_workspace(
        self,
        payload: WorkspaceUpdateRequest,
        request: Request,
        context: AuthContext = Depends(require_auth_role(Role.ADMIN.value)),
    ) -> Dict[str, Any]:
        try:
            membership = WORKSPACE_STORE.require_membership(context.user_id, context.workspace_id)

            if not has_min_role(safe_membership(membership)["role"], Role.ADMIN.value):
                raise_api_error(
                    status_code=status.HTTP_403_FORBIDDEN,
                    message="Admin role or higher is required to update workspace.",
                    code="INSUFFICIENT_WORKSPACE_ROLE",
                    request_id=context.request_id,
                )

            security_result = await security_review(
                {
                    "type": "workspace_update",
                    "actor_user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "updates": {
                        "name": payload.name,
                        "metadata": payload.metadata,
                    },
                    "request_id": context.request_id,
                    "created_at": utc_now(),
                }
            )

            if not security_approved(security_result):
                raise_api_error(
                    status_code=status.HTTP_403_FORBIDDEN,
                    message="Workspace update was blocked by Security Agent.",
                    code="SECURITY_AGENT_DENIED",
                    request_id=context.request_id,
                    details=security_result,
                )

            updated = WORKSPACE_STORE.update_workspace(
                workspace_id=context.workspace_id,
                name=payload.name,
                metadata=payload.metadata,
            )

            audit = write_workspace_audit(
                request=request,
                context=context,
                event_type="workspace_update",
                action="update_current_workspace",
                result="success",
                status_code=status.HTTP_200_OK,
                metadata={"security_result": security_result},
            )

            memory_result = await emit_memory_context(
                {
                    "type": "workspace_update",
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "request_id": context.request_id,
                    "content": {
                        "event": "workspace_updated",
                        "updates": {
                            "name": payload.name,
                            "metadata_keys": list(payload.metadata.keys()),
                        },
                    },
                    "created_at": utc_now(),
                }
            )

            verification_result = await prepare_verification(
                {
                    "type": "workspace_update_confirmation",
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "request_id": context.request_id,
                    "result": "success",
                    "created_at": utc_now(),
                }
            )

            return api_success(
                message="Workspace updated successfully.",
                data={
                    "workspace": safe_workspace(updated),
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
                code="WORKSPACE_UPDATE_FAILED",
                request_id=context.request_id,
            )

    async def list_current_workspace_members(
        self,
        q: Optional[str] = None,
        role: Optional[str] = None,
        context: AuthContext = Depends(require_auth_role(Role.MANAGER.value)),
    ) -> Dict[str, Any]:
        rows = WORKSPACE_STORE.list_workspace_members(context.workspace_id)
        filtered: List[Tuple[Any, Any]] = []

        for user, membership in rows:
            user_data = safe_user(user)
            membership_data = safe_membership(membership)

            if q:
                needle = q.strip().lower()
                if needle not in str(user_data.get("email", "")).lower() and needle not in str(user_data.get("full_name", "")).lower():
                    continue

            if role and membership_data.get("role") != normalize_role(role):
                continue

            filtered.append((user, membership))

        return api_success(
            message="Workspace members loaded.",
            data={
                "members": [safe_member(user, membership) for user, membership in filtered],
                "count": len(filtered),
                "isolation": {
                    "workspace_id": context.workspace_id,
                    "requested_by_user_id": context.user_id,
                },
            },
            request_id=context.request_id,
        )

    async def invite_member(
        self,
        payload: WorkspaceInviteRequest,
        request: Request,
        context: AuthContext = Depends(require_auth_role(Role.MANAGER.value)),
    ) -> Dict[str, Any]:
        try:
            workspace = WORKSPACE_STORE.require_workspace(context.workspace_id)
            workspace_data = safe_workspace(workspace)
            member_limit = plan_member_limit(workspace_data["plan"])
            member_count = WORKSPACE_STORE.count_workspace_members(context.workspace_id)

            if member_limit != "custom" and member_count >= int(member_limit):
                raise_api_error(
                    status_code=status.HTTP_402_PAYMENT_REQUIRED,
                    message="Member limit reached for this workspace plan.",
                    code="MEMBER_LIMIT_REACHED",
                    request_id=context.request_id,
                    details={
                        "plan": workspace_data["plan"],
                        "limit": member_limit,
                        "current_members": member_count,
                    },
                )

            actor_membership = WORKSPACE_STORE.require_membership(context.user_id, context.workspace_id)
            actor_role = safe_membership(actor_membership)["role"]
            invited_role = normalize_role(payload.role)

            if not can_manage_target(actor_role, invited_role):
                raise_api_error(
                    status_code=status.HTTP_403_FORBIDDEN,
                    message="You cannot invite a member with an equal or higher role.",
                    code="ROLE_ESCALATION_BLOCKED",
                    request_id=context.request_id,
                )

            existing_user = WORKSPACE_STORE.get_user_by_email(payload.email)
            if existing_user and WORKSPACE_STORE.get_membership(getattr(existing_user, "user_id"), context.workspace_id):
                raise_api_error(
                    status_code=status.HTTP_409_CONFLICT,
                    message="This user is already a member of the workspace.",
                    code="USER_ALREADY_MEMBER",
                    request_id=context.request_id,
                )

            security_result = await security_review(
                {
                    "type": "workspace_invite_member",
                    "actor_user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "invited_email": payload.email,
                    "invited_role": invited_role,
                    "request_id": context.request_id,
                    "created_at": utc_now(),
                }
            )

            if not security_approved(security_result):
                raise_api_error(
                    status_code=status.HTTP_403_FORBIDDEN,
                    message="Member invite was blocked by Security Agent.",
                    code="SECURITY_AGENT_DENIED",
                    request_id=context.request_id,
                    details=security_result,
                )

            invite, invite_token = WORKSPACE_STORE.create_invite(
                workspace_id=context.workspace_id,
                invited_email=payload.email,
                invited_by_user_id=context.user_id,
                role=invited_role,
                permissions=payload.permissions or DEFAULT_PERMISSIONS_BY_ROLE.get(invited_role, []),
                message=payload.message,
                expires_in_hours=payload.expires_in_hours,
                metadata=payload.metadata,
            )

            audit = write_workspace_audit(
                request=request,
                context=context,
                event_type="workspace_member_invite",
                action="invite_member",
                result="success",
                target_workspace_id=context.workspace_id,
                status_code=status.HTTP_201_CREATED,
                metadata={
                    "invite_id": invite.invite_id,
                    "invited_email": payload.email,
                    "invited_role": invited_role,
                    "security_result": security_result,
                },
            )

            memory_result = await emit_memory_context(
                {
                    "type": "workspace_member_invite",
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "request_id": context.request_id,
                    "content": {
                        "event": "workspace_member_invited",
                        "invite_id": invite.invite_id,
                        "invited_email": payload.email,
                        "role": invited_role,
                    },
                    "created_at": utc_now(),
                }
            )

            verification_result = await prepare_verification(
                {
                    "type": "workspace_member_invite_confirmation",
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "request_id": context.request_id,
                    "result": "success",
                    "invite_id": invite.invite_id,
                    "created_at": utc_now(),
                }
            )

            return api_success(
                message="Workspace invite created successfully.",
                data={
                    "invite": safe_invite(invite, include_token=invite_token),
                    "audit": audit,
                    "memory_result": memory_result,
                    "verification_result": verification_result,
                    "delivery_note": "Email delivery should be connected later through notification/email service.",
                },
                request_id=context.request_id,
            )

        except ValueError as exc:
            raise_api_error(
                status_code=status.HTTP_400_BAD_REQUEST,
                message=str(exc),
                code="INVITE_CREATE_FAILED",
                request_id=context.request_id,
            )

    async def list_invites(
        self,
        status_filter: Optional[str] = None,
        context: AuthContext = Depends(require_auth_role(Role.MANAGER.value)),
    ) -> Dict[str, Any]:
        invites = WORKSPACE_STORE.list_invites_for_workspace(context.workspace_id)

        if status_filter:
            invites = [invite for invite in invites if invite.status == status_filter]

        return api_success(
            message="Workspace invites loaded.",
            data={
                "invites": [safe_invite(invite) for invite in invites],
                "count": len(invites),
                "isolation": {
                    "workspace_id": context.workspace_id,
                    "requested_by_user_id": context.user_id,
                },
            },
            request_id=context.request_id,
        )

    async def accept_invite(
        self,
        payload: InviteAcceptRequest,
        request: Request,
        context: AuthContext = Depends(get_current_auth_context),
    ) -> Dict[str, Any]:
        invite = WORKSPACE_STORE.get_invite_by_token(payload.invite_token)

        if not invite:
            raise_api_error(
                status_code=status.HTTP_404_NOT_FOUND,
                message="Invite not found.",
                code="INVITE_NOT_FOUND",
                request_id=context.request_id,
            )

        if invite.status != "pending":
            raise_api_error(
                status_code=status.HTTP_409_CONFLICT,
                message="Invite is no longer pending.",
                code="INVITE_NOT_PENDING",
                request_id=context.request_id,
            )

        expires_at = datetime.fromisoformat(invite.expires_at)
        if expires_at < utc_now_dt():
            WORKSPACE_STORE.update_invite(invite.invite_id, {"status": "expired"})
            raise_api_error(
                status_code=status.HTTP_410_GONE,
                message="Invite has expired.",
                code="INVITE_EXPIRED",
                request_id=context.request_id,
            )

        user = WORKSPACE_STORE.get_user(context.user_id)
        if not user:
            raise_api_error(
                status_code=status.HTTP_404_NOT_FOUND,
                message="Current user not found.",
                code="USER_NOT_FOUND",
                request_id=context.request_id,
            )

        user_email = safe_user(user)["email"]
        if user_email != invite.invited_email:
            raise_api_error(
                status_code=status.HTTP_403_FORBIDDEN,
                message="Invite email does not match authenticated user.",
                code="INVITE_EMAIL_MISMATCH",
                request_id=context.request_id,
            )

        workspace = WORKSPACE_STORE.require_workspace(invite.workspace_id)
        workspace_data = safe_workspace(workspace)
        member_limit = plan_member_limit(workspace_data["plan"])
        member_count = WORKSPACE_STORE.count_workspace_members(invite.workspace_id)

        if member_limit != "custom" and member_count >= int(member_limit):
            raise_api_error(
                status_code=status.HTTP_402_PAYMENT_REQUIRED,
                message="Member limit reached for target workspace.",
                code="MEMBER_LIMIT_REACHED",
                request_id=context.request_id,
            )

        security_result = await security_review(
            {
                "type": "workspace_invite_accept",
                "user_id": context.user_id,
                "workspace_id": invite.workspace_id,
                "invite_id": invite.invite_id,
                "request_id": context.request_id,
                "created_at": utc_now(),
            }
        )

        if not security_approved(security_result):
            raise_api_error(
                status_code=status.HTTP_403_FORBIDDEN,
                message="Invite acceptance was blocked by Security Agent.",
                code="SECURITY_AGENT_DENIED",
                request_id=context.request_id,
                details=security_result,
            )

        membership = WORKSPACE_STORE.add_member(
            user_id=context.user_id,
            workspace_id=invite.workspace_id,
            role=invite.role,
            permissions=invite.permissions,
        )

        updated_invite = WORKSPACE_STORE.update_invite(
            invite.invite_id,
            {
                "status": "accepted",
                "accepted_at": utc_now(),
            },
        )

        audit = write_workspace_audit(
            request=request,
            context=context,
            event_type="workspace_invite_accept",
            action="accept_invite",
            result="success",
            target_workspace_id=invite.workspace_id,
            target_user_id=context.user_id,
            status_code=status.HTTP_200_OK,
            metadata={
                "invite_id": invite.invite_id,
                "security_result": security_result,
            },
        )

        memory_result = await emit_memory_context(
            {
                "type": "workspace_invite_accept",
                "user_id": context.user_id,
                "workspace_id": invite.workspace_id,
                "request_id": context.request_id,
                "content": {
                    "event": "workspace_invite_accepted",
                    "invite_id": invite.invite_id,
                    "role": invite.role,
                },
                "created_at": utc_now(),
            }
        )

        verification_result = await prepare_verification(
            {
                "type": "workspace_invite_accept_confirmation",
                "user_id": context.user_id,
                "workspace_id": invite.workspace_id,
                "request_id": context.request_id,
                "result": "success",
                "invite_id": invite.invite_id,
                "created_at": utc_now(),
            }
        )

        return api_success(
            message="Workspace invite accepted successfully.",
            data={
                "workspace": safe_workspace(workspace),
                "membership": safe_membership(membership),
                "invite": safe_invite(updated_invite),
                "audit": audit,
                "memory_result": memory_result,
                "verification_result": verification_result,
            },
            request_id=context.request_id,
        )

    async def revoke_invite(
        self,
        payload: InviteRevokeRequest,
        request: Request,
        context: AuthContext = Depends(require_auth_role(Role.MANAGER.value)),
    ) -> Dict[str, Any]:
        invite = WORKSPACE_STORE.get_invite(payload.invite_id)

        if not invite or invite.workspace_id != context.workspace_id:
            raise_api_error(
                status_code=status.HTTP_404_NOT_FOUND,
                message="Invite not found in current workspace.",
                code="INVITE_NOT_FOUND",
                request_id=context.request_id,
            )

        if invite.status != "pending":
            raise_api_error(
                status_code=status.HTTP_409_CONFLICT,
                message="Only pending invites can be revoked.",
                code="INVITE_NOT_PENDING",
                request_id=context.request_id,
            )

        security_result = await security_review(
            {
                "type": "workspace_invite_revoke",
                "actor_user_id": context.user_id,
                "workspace_id": context.workspace_id,
                "invite_id": invite.invite_id,
                "request_id": context.request_id,
                "created_at": utc_now(),
            }
        )

        if not security_approved(security_result):
            raise_api_error(
                status_code=status.HTTP_403_FORBIDDEN,
                message="Invite revocation was blocked by Security Agent.",
                code="SECURITY_AGENT_DENIED",
                request_id=context.request_id,
                details=security_result,
            )

        updated_invite = WORKSPACE_STORE.update_invite(
            invite.invite_id,
            {
                "status": "revoked",
                "revoked_at": utc_now(),
            },
        )

        audit = write_workspace_audit(
            request=request,
            context=context,
            event_type="workspace_invite_revoke",
            action="revoke_invite",
            result="success",
            target_workspace_id=context.workspace_id,
            status_code=status.HTTP_200_OK,
            metadata={
                "invite_id": invite.invite_id,
                "security_result": security_result,
            },
        )

        verification_result = await prepare_verification(
            {
                "type": "workspace_invite_revoke_confirmation",
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
                "request_id": context.request_id,
                "result": "success",
                "invite_id": invite.invite_id,
                "created_at": utc_now(),
            }
        )

        return api_success(
            message="Workspace invite revoked successfully.",
            data={
                "invite": safe_invite(updated_invite),
                "audit": audit,
                "verification_result": verification_result,
            },
            request_id=context.request_id,
        )

    async def update_member_role(
        self,
        target_user_id: str,
        payload: MemberRoleUpdateRequest,
        request: Request,
        context: AuthContext = Depends(require_auth_role(Role.ADMIN.value)),
    ) -> Dict[str, Any]:
        try:
            actor_membership = WORKSPACE_STORE.require_membership(context.user_id, context.workspace_id)
            target_membership = WORKSPACE_STORE.require_membership(target_user_id, context.workspace_id)

            actor_role = safe_membership(actor_membership)["role"]
            target_role = safe_membership(target_membership)["role"]
            new_role = normalize_role(payload.role)

            if target_user_id == context.user_id:
                raise_api_error(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    message="You cannot change your own role through this endpoint.",
                    code="SELF_ROLE_CHANGE_BLOCKED",
                    request_id=context.request_id,
                )

            if not can_manage_target(actor_role, target_role):
                raise_api_error(
                    status_code=status.HTTP_403_FORBIDDEN,
                    message="You cannot modify a member with an equal or higher role.",
                    code="ROLE_MANAGEMENT_BLOCKED",
                    request_id=context.request_id,
                )

            if not can_manage_target(actor_role, new_role):
                raise_api_error(
                    status_code=status.HTTP_403_FORBIDDEN,
                    message="You cannot assign an equal or higher role.",
                    code="ROLE_ESCALATION_BLOCKED",
                    request_id=context.request_id,
                )

            security_result = await security_review(
                {
                    "type": "workspace_member_role_update",
                    "actor_user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "target_user_id": target_user_id,
                    "from_role": target_role,
                    "to_role": new_role,
                    "request_id": context.request_id,
                    "created_at": utc_now(),
                }
            )

            if not security_approved(security_result):
                raise_api_error(
                    status_code=status.HTTP_403_FORBIDDEN,
                    message="Member role update was blocked by Security Agent.",
                    code="SECURITY_AGENT_DENIED",
                    request_id=context.request_id,
                    details=security_result,
                )

            updated = WORKSPACE_STORE.update_member(
                user_id=target_user_id,
                workspace_id=context.workspace_id,
                role=new_role,
                permissions=payload.permissions or DEFAULT_PERMISSIONS_BY_ROLE.get(new_role, []),
            )

            audit = write_workspace_audit(
                request=request,
                context=context,
                event_type="workspace_member_role_update",
                action="update_member_role",
                result="success",
                target_user_id=target_user_id,
                status_code=status.HTTP_200_OK,
                metadata={
                    "from_role": target_role,
                    "to_role": new_role,
                    "security_result": security_result,
                },
            )

            memory_result = await emit_memory_context(
                {
                    "type": "workspace_member_role_update",
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "request_id": context.request_id,
                    "content": {
                        "event": "workspace_member_role_updated",
                        "target_user_id": target_user_id,
                        "from_role": target_role,
                        "to_role": new_role,
                    },
                    "created_at": utc_now(),
                }
            )

            verification_result = await prepare_verification(
                {
                    "type": "workspace_member_role_update_confirmation",
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "request_id": context.request_id,
                    "result": "success",
                    "target_user_id": target_user_id,
                    "created_at": utc_now(),
                }
            )

            return api_success(
                message="Workspace member role updated successfully.",
                data={
                    "membership": safe_membership(updated),
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
                code="MEMBER_ROLE_UPDATE_FAILED",
                request_id=context.request_id,
            )

    async def update_member_access(
        self,
        target_user_id: str,
        payload: MemberAccessUpdateRequest,
        request: Request,
        context: AuthContext = Depends(require_auth_role(Role.ADMIN.value)),
    ) -> Dict[str, Any]:
        try:
            actor_membership = WORKSPACE_STORE.require_membership(context.user_id, context.workspace_id)
            target_membership = WORKSPACE_STORE.require_membership(target_user_id, context.workspace_id)

            actor_role = safe_membership(actor_membership)["role"]
            target_role = safe_membership(target_membership)["role"]

            if not can_manage_target(actor_role, target_role) and target_user_id != context.user_id:
                raise_api_error(
                    status_code=status.HTTP_403_FORBIDDEN,
                    message="You cannot update access for a member with an equal or higher role.",
                    code="ACCESS_MANAGEMENT_BLOCKED",
                    request_id=context.request_id,
                )

            security_result = await security_review(
                {
                    "type": "workspace_member_access_update",
                    "actor_user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "target_user_id": target_user_id,
                    "permissions": payload.permissions,
                    "is_active": payload.is_active,
                    "request_id": context.request_id,
                    "created_at": utc_now(),
                }
            )

            if not security_approved(security_result):
                raise_api_error(
                    status_code=status.HTTP_403_FORBIDDEN,
                    message="Member access update was blocked by Security Agent.",
                    code="SECURITY_AGENT_DENIED",
                    request_id=context.request_id,
                    details=security_result,
                )

            updated = WORKSPACE_STORE.update_member(
                user_id=target_user_id,
                workspace_id=context.workspace_id,
                permissions=payload.permissions,
                is_active=payload.is_active,
            )

            audit = write_workspace_audit(
                request=request,
                context=context,
                event_type="workspace_member_access_update",
                action="update_member_access",
                result="success",
                target_user_id=target_user_id,
                status_code=status.HTTP_200_OK,
                metadata={
                    "permissions": payload.permissions,
                    "is_active": payload.is_active,
                    "security_result": security_result,
                },
            )

            verification_result = await prepare_verification(
                {
                    "type": "workspace_member_access_update_confirmation",
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "request_id": context.request_id,
                    "result": "success",
                    "target_user_id": target_user_id,
                    "created_at": utc_now(),
                }
            )

            return api_success(
                message="Workspace member access updated successfully.",
                data={
                    "membership": safe_membership(updated),
                    "audit": audit,
                    "verification_result": verification_result,
                },
                request_id=context.request_id,
            )

        except ValueError as exc:
            raise_api_error(
                status_code=status.HTTP_404_NOT_FOUND,
                message=str(exc),
                code="MEMBER_ACCESS_UPDATE_FAILED",
                request_id=context.request_id,
            )

    async def remove_member(
        self,
        target_user_id: str,
        request: Request,
        context: AuthContext = Depends(require_auth_role(Role.ADMIN.value)),
    ) -> Dict[str, Any]:
        try:
            actor_membership = WORKSPACE_STORE.require_membership(context.user_id, context.workspace_id)
            target_membership = WORKSPACE_STORE.require_membership(target_user_id, context.workspace_id)

            actor_role = safe_membership(actor_membership)["role"]
            target_role = safe_membership(target_membership)["role"]

            if target_user_id == context.user_id:
                raise_api_error(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    message="You cannot remove yourself from the workspace using this endpoint.",
                    code="SELF_REMOVE_BLOCKED",
                    request_id=context.request_id,
                )

            if target_role == Role.OWNER.value and not WORKSPACE_SETTINGS.allow_owner_removal:
                raise_api_error(
                    status_code=status.HTTP_403_FORBIDDEN,
                    message="Workspace owner removal is disabled by policy.",
                    code="OWNER_REMOVE_BLOCKED",
                    request_id=context.request_id,
                )

            if not can_manage_target(actor_role, target_role):
                raise_api_error(
                    status_code=status.HTTP_403_FORBIDDEN,
                    message="You cannot remove a member with an equal or higher role.",
                    code="REMOVE_MEMBER_BLOCKED",
                    request_id=context.request_id,
                )

            security_result = await security_review(
                {
                    "type": "workspace_member_remove",
                    "actor_user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "target_user_id": target_user_id,
                    "target_role": target_role,
                    "request_id": context.request_id,
                    "created_at": utc_now(),
                }
            )

            if not security_approved(security_result):
                raise_api_error(
                    status_code=status.HTTP_403_FORBIDDEN,
                    message="Member removal was blocked by Security Agent.",
                    code="SECURITY_AGENT_DENIED",
                    request_id=context.request_id,
                    details=security_result,
                )

            updated = WORKSPACE_STORE.update_member(
                user_id=target_user_id,
                workspace_id=context.workspace_id,
                is_active=False,
            )

            audit = write_workspace_audit(
                request=request,
                context=context,
                event_type="workspace_member_remove",
                action="remove_member",
                result="success",
                target_user_id=target_user_id,
                status_code=status.HTTP_200_OK,
                metadata={
                    "target_role": target_role,
                    "security_result": security_result,
                },
            )

            memory_result = await emit_memory_context(
                {
                    "type": "workspace_member_remove",
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "request_id": context.request_id,
                    "content": {
                        "event": "workspace_member_removed",
                        "target_user_id": target_user_id,
                        "target_role": target_role,
                    },
                    "created_at": utc_now(),
                }
            )

            verification_result = await prepare_verification(
                {
                    "type": "workspace_member_remove_confirmation",
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "request_id": context.request_id,
                    "result": "success",
                    "target_user_id": target_user_id,
                    "created_at": utc_now(),
                }
            )

            return api_success(
                message="Workspace member removed successfully.",
                data={
                    "membership": safe_membership(updated),
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
                code="MEMBER_REMOVE_FAILED",
                request_id=context.request_id,
            )

    async def get_workspace_audit(
        self,
        context: AuthContext = Depends(require_auth_role(Role.ADMIN.value)),
    ) -> Dict[str, Any]:
        scoped = [
            event
            for event in WORKSPACE_AUDIT_EVENTS
            if event.get("workspace_id") == context.workspace_id
        ]

        return api_success(
            message="Workspace audit logs loaded.",
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


workspaces = Workspaces()
router = workspaces.router