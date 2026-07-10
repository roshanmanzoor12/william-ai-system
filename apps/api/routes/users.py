"""
apps/api/routes/users.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

User routes with workspace-aware isolation.

Purpose:
- User CRUD
- Profile management
- Workspace-scoped user listing
- Role updates
- Activation/deactivation
- Soft delete/removal from workspace
- Plan visibility
- Audit hooks
- Security Agent approval for sensitive actions
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
import traceback
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Tuple

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field, validator


# =============================================================================
# Logging
# =============================================================================

LOGGER_NAME = "william.api.routes.users"
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


def safe_error_detail(exc: Exception, debug: bool = False) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "type": exc.__class__.__name__,
        "message": str(exc) or "Unexpected error",
    }

    if debug:
        payload["traceback"] = traceback.format_exc()

    return payload


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


def normalize_email(email: str) -> str:
    clean = (email or "").strip().lower()

    if not clean:
        raise ValueError("Email is required.")

    if len(clean) > 254:
        raise ValueError("Email is too long.")

    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", clean):
        raise ValueError("Email format is invalid.")

    return clean


def normalize_text(value: Optional[str], fallback: str = "") -> str:
    clean = (value or fallback).strip()
    return clean


# =============================================================================
# Settings
# =============================================================================

@dataclass(frozen=True)
class UserRouteSettings:
    environment: str = field(default_factory=lambda: os.getenv("WILLIAM_ENV", "development"))
    debug: bool = field(default_factory=lambda: parse_bool(os.getenv("WILLIAM_DEBUG"), False))
    audit_enabled: bool = field(default_factory=lambda: parse_bool(os.getenv("WILLIAM_AUDIT_LOG_ENABLED"), True))
    security_agent_enabled: bool = field(default_factory=lambda: parse_bool(os.getenv("WILLIAM_SECURITY_AGENT_ENABLED"), True))
    memory_agent_enabled: bool = field(default_factory=lambda: parse_bool(os.getenv("WILLIAM_MEMORY_AGENT_ENABLED"), True))
    verification_agent_enabled: bool = field(
        default_factory=lambda: parse_bool(os.getenv("WILLIAM_VERIFICATION_AGENT_ENABLED"), True)
    )
    allow_self_profile_update: bool = field(
        default_factory=lambda: parse_bool(os.getenv("WILLIAM_ALLOW_SELF_PROFILE_UPDATE"), True)
    )
    allow_owner_deactivation: bool = field(
        default_factory=lambda: parse_bool(os.getenv("WILLIAM_ALLOW_OWNER_DEACTIVATION"), False)
    )

    def public_dict(self) -> Dict[str, Any]:
        return asdict(self)


USER_SETTINGS = UserRouteSettings()


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
        raise ValueError("Invalid role.")

    return clean


def normalize_plan(plan: Optional[str]) -> str:
    clean = (plan or Plan.FREE.value).strip().lower()

    if clean not in PLAN_RANK:
        raise ValueError("Invalid plan.")

    return clean


def has_min_role(current_role: str, required_role: str) -> bool:
    return ROLE_RANK.get(current_role, 0) >= ROLE_RANK.get(required_role, 0)


def can_manage_target(actor_role: str, target_role: str) -> bool:
    actor_rank = ROLE_RANK.get(actor_role, 0)
    target_rank = ROLE_RANK.get(target_role, 0)

    if actor_role == Role.OWNER.value:
        return True

    return actor_rank > target_rank


# =============================================================================
# Safe API Responses
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
            "module": "users",
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
                "module": "users",
            },
        },
    )


# =============================================================================
# Auth Compatibility Layer
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


class FallbackRecord(BaseModel):
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


class FallbackUserStore:
    """
    Development fallback store.

    Production should use the AUTH_STORE from apps.api.routes.auth or a database repository.
    This fallback exists only to keep imports safe while the project is being assembled.
    """

    def __init__(self) -> None:
        now = utc_now()
        self.users_by_id: Dict[str, FallbackRecord] = {
            "demo_user": FallbackRecord(
                user_id="demo_user",
                email="dev@example.com",
                full_name="Demo Owner",
                created_at=now,
                updated_at=now,
                is_active=True,
                metadata={"source": "fallback_users_store"},
            )
        }
        self.user_id_by_email: Dict[str, str] = {"dev@example.com": "demo_user"}
        self.workspaces_by_id: Dict[str, FallbackWorkspaceRecord] = {
            "demo_workspace": FallbackWorkspaceRecord(
                workspace_id="demo_workspace",
                name="Demo Workspace",
                owner_user_id="demo_user",
                plan=Plan.FREE.value,
                subscription_status="active",
                created_at=now,
                updated_at=now,
            )
        }
        self.memberships_by_id: Dict[str, FallbackMembershipRecord] = {
            "membership_demo": FallbackMembershipRecord(
                membership_id="membership_demo",
                user_id="demo_user",
                workspace_id="demo_workspace",
                role=Role.OWNER.value,
                plan=Plan.FREE.value,
                permissions=["workspace:read", "user:read", "user:update", "session:manage"],
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
            if membership.workspace_id == workspace_id and membership.is_active:
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
    logger.warning("Auth route import fallback enabled: %s", auth_import_exc)
    AUTH_STORE = FallbackUserStore()
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
            permissions=["workspace:read", "user:read", "user:update"],
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
                logger.info("Loaded optional users hook: %s from %s", self.component_name, self.loaded_from)
                return True

            except Exception as exc:
                self.import_error = f"{module_path}.{attr_name}: {exc}"

        return False

    @staticmethod
    def _instantiate(cls: Any) -> Any:
        attempts = [
            {"settings": USER_SETTINGS},
            {},
        ]

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
                "error": safe_error_detail(exc, USER_SETTINGS.debug),
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
    method_candidates=["approve_user_action", "approve_api_action", "approve_action", "check_permission", "execute", "run"],
)

MEMORY_AGENT = OptionalAgentHook(
    component_name="Memory Agent",
    import_candidates=[
        ("apps.api.services.memory_agent_bridge", "MemoryAgentBridge"),
        ("agents.memory_agent.memory_agent", "MemoryAgent"),
        ("agents.memory.memory_agent", "MemoryAgent"),
    ],
    method_candidates=["record_user_context", "record_api_context", "save_context", "remember", "execute", "run"],
)

VERIFICATION_AGENT = OptionalAgentHook(
    component_name="Verification Agent",
    import_candidates=[
        ("apps.api.services.verification_agent_bridge", "VerificationAgentBridge"),
        ("agents.verification_agent.verification_agent", "VerificationAgent"),
        ("agents.verification.verification_agent", "VerificationAgent"),
    ],
    method_candidates=["prepare_user_confirmation", "prepare_confirmation", "verify_result", "confirm", "execute", "run"],
)


async def security_review(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not USER_SETTINGS.security_agent_enabled:
        return {
            "success": True,
            "message": "Security Agent hook disabled; action allowed by local policy.",
            "data": {"approved": True, "local_policy": True},
            "error": None,
            "metadata": {"timestamp": utc_now()},
        }

    return await SECURITY_AGENT.call(payload)


async def emit_memory_context(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not USER_SETTINGS.memory_agent_enabled:
        return {
            "success": False,
            "message": "Memory Agent hook disabled.",
            "data": {},
            "error": {"code": "MEMORY_HOOK_DISABLED"},
            "metadata": {"timestamp": utc_now()},
        }

    return await MEMORY_AGENT.call(payload)


async def prepare_verification(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not USER_SETTINGS.verification_agent_enabled:
        return {
            "success": False,
            "message": "Verification Agent hook disabled.",
            "data": {},
            "error": {"code": "VERIFICATION_HOOK_DISABLED"},
            "metadata": {"timestamp": utc_now()},
        }

    return await VERIFICATION_AGENT.call(payload)


# =============================================================================
# Local Audit Store
# =============================================================================

USER_AUDIT_EVENTS: List[Dict[str, Any]] = []


def write_user_audit(
    request: Request,
    context: AuthContext,
    event_type: str,
    action: str,
    result: str,
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

    if USER_SETTINGS.audit_enabled:
        USER_AUDIT_EVENTS.append(event)

        if len(USER_AUDIT_EVENTS) > 1000:
            del USER_AUDIT_EVENTS[: len(USER_AUDIT_EVENTS) - 1000]

        logger.info(
            "Users audit | type=%s | action=%s | actor=%s | target=%s | workspace=%s | result=%s",
            event_type,
            action,
            context.user_id,
            target_user_id,
            context.workspace_id,
            result,
        )

    return event


# =============================================================================
# Models
# =============================================================================

class UserCreateRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=254)
    full_name: str = Field(..., min_length=1, max_length=120)
    role: str = Field(default=Role.USER.value)
    plan: Optional[str] = None
    permissions: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @validator("email")
    def validate_email(cls, value: str) -> str:
        return normalize_email(value)

    @validator("role")
    def validate_role(cls, value: str) -> str:
        return normalize_role(value)

    @validator("plan")
    def validate_plan(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value

        return normalize_plan(value)


class UserUpdateRequest(BaseModel):
    full_name: Optional[str] = Field(default=None, min_length=1, max_length=120)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class UserAdminUpdateRequest(BaseModel):
    full_name: Optional[str] = Field(default=None, min_length=1, max_length=120)
    role: Optional[str] = None
    plan: Optional[str] = None
    permissions: Optional[List[str]] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @validator("role")
    def validate_role(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value

        return normalize_role(value)

    @validator("plan")
    def validate_plan(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value

        return normalize_plan(value)


class RoleUpdateRequest(BaseModel):
    role: str = Field(...)

    @validator("role")
    def validate_role(cls, value: str) -> str:
        return normalize_role(value)


class ActivationRequest(BaseModel):
    is_active: bool
    reason: Optional[str] = Field(default=None, max_length=500)


class PlanVisibilityResponse(BaseModel):
    current_plan: str
    subscription_status: str
    visible_features: List[str]
    upgrade_locked_features: List[str]
    limits: Dict[str, Any]


# =============================================================================
# Store Adapter
# =============================================================================

class UserStoreAdapter:
    """
    Adapter over AUTH_STORE.

    Works with the auth.py in-memory store now and can be replaced with
    database repositories later without changing route behavior.
    """

    def __init__(self, auth_store: Any) -> None:
        self.store = auth_store

    def get_user(self, user_id: str) -> Optional[Any]:
        getter = getattr(self.store, "get_user_by_id", None)
        if callable(getter):
            return getter(user_id)

        return getattr(self.store, "users_by_id", {}).get(user_id)

    def get_workspace(self, workspace_id: str) -> Optional[Any]:
        getter = getattr(self.store, "get_workspace", None)
        if callable(getter):
            return getter(workspace_id)

        return getattr(self.store, "workspaces_by_id", {}).get(workspace_id)

    def get_membership(self, user_id: str, workspace_id: str) -> Optional[Any]:
        getter = getattr(self.store, "get_membership", None)
        if callable(getter):
            return getter(user_id, workspace_id)

        memberships = self.list_memberships_for_user(user_id)
        for membership in memberships:
            if getattr(membership, "workspace_id", None) == workspace_id:
                return membership

        return None

    def list_memberships_for_user(self, user_id: str) -> List[Any]:
        getter = getattr(self.store, "list_memberships_for_user", None)
        if callable(getter):
            return getter(user_id)

        ids = getattr(self.store, "membership_ids_by_user", {}).get(user_id, [])
        memberships = getattr(self.store, "memberships_by_id", {})
        return [memberships[item] for item in ids if item in memberships]

    def list_workspace_memberships(self, workspace_id: str) -> List[Any]:
        memberships_by_id = getattr(self.store, "memberships_by_id", {})
        return [
            membership
            for membership in memberships_by_id.values()
            if getattr(membership, "workspace_id", None) == workspace_id and getattr(membership, "is_active", True)
        ]

    def list_workspace_users(self, workspace_id: str) -> List[Tuple[Any, Any]]:
        results: List[Tuple[Any, Any]] = []

        for membership in self.list_workspace_memberships(workspace_id):
            user = self.get_user(getattr(membership, "user_id"))
            if user:
                results.append((user, membership))

        return results

    def create_workspace_user(
        self,
        workspace_id: str,
        email: str,
        full_name: str,
        role: str,
        plan: str,
        permissions: List[str],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Any, Any]:
        normalized_email = normalize_email(email)
        users_by_id = getattr(self.store, "users_by_id", None)
        user_id_by_email = getattr(self.store, "user_id_by_email", None)
        memberships_by_id = getattr(self.store, "memberships_by_id", None)
        membership_ids_by_user = getattr(self.store, "membership_ids_by_user", None)

        if not isinstance(users_by_id, dict) or not isinstance(user_id_by_email, dict):
            raise RuntimeError("Current user store does not support direct user creation.")

        if not isinstance(memberships_by_id, dict) or not isinstance(membership_ids_by_user, dict):
            raise RuntimeError("Current user store does not support direct membership creation.")

        existing_user_id = user_id_by_email.get(normalized_email)
        now = utc_now()

        if existing_user_id:
            user = self.get_user(existing_user_id)
            if not user:
                raise RuntimeError("Email index points to missing user.")

            existing_membership = self.get_membership(existing_user_id, workspace_id)
            if existing_membership and getattr(existing_membership, "is_active", True):
                raise ValueError("User already belongs to this workspace.")
        else:
            user_cls = self._infer_user_class()
            password_hash = "external_invite_no_password_set"

            try:
                user = user_cls(
                    user_id=new_id("user"),
                    email=normalized_email,
                    full_name=full_name.strip(),
                    password_hash=password_hash,
                    created_at=now,
                    updated_at=now,
                    is_active=True,
                    metadata=metadata or {},
                )
            except TypeError:
                user = user_cls(
                    user_id=new_id("user"),
                    email=normalized_email,
                    full_name=full_name.strip(),
                    created_at=now,
                    updated_at=now,
                    is_active=True,
                    metadata=metadata or {},
                )

            users_by_id[getattr(user, "user_id")] = user
            user_id_by_email[normalized_email] = getattr(user, "user_id")

        membership_cls = self._infer_membership_class()
        membership = membership_cls(
            membership_id=new_id("membership"),
            user_id=getattr(user, "user_id"),
            workspace_id=workspace_id,
            role=role,
            plan=plan,
            permissions=permissions,
            created_at=now,
            updated_at=now,
            is_active=True,
        )

        memberships_by_id[getattr(membership, "membership_id")] = membership
        membership_ids_by_user.setdefault(getattr(user, "user_id"), []).append(getattr(membership, "membership_id"))

        return user, membership

    def update_user_profile(
        self,
        user_id: str,
        full_name: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Any:
        user = self.require_user(user_id)
        update_data = {}

        if full_name is not None:
            update_data["full_name"] = full_name.strip()

        if metadata:
            existing_metadata = dict(getattr(user, "metadata", {}) or {})
            existing_metadata.update(metadata)
            update_data["metadata"] = existing_metadata

        update_data["updated_at"] = utc_now()

        return self._replace_record("users_by_id", user_id, user, update_data)

    def update_membership(
        self,
        user_id: str,
        workspace_id: str,
        role: Optional[str] = None,
        plan: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        is_active: Optional[bool] = None,
    ) -> Any:
        membership = self.require_membership(user_id, workspace_id)
        update_data: Dict[str, Any] = {}

        if role is not None:
            update_data["role"] = role

        if plan is not None:
            update_data["plan"] = plan

        if permissions is not None:
            update_data["permissions"] = permissions

        if is_active is not None:
            update_data["is_active"] = is_active

        update_data["updated_at"] = utc_now()

        return self._replace_record("memberships_by_id", getattr(membership, "membership_id"), membership, update_data)

    def update_user_activation(self, user_id: str, is_active: bool) -> Any:
        user = self.require_user(user_id)
        return self._replace_record("users_by_id", user_id, user, {"is_active": is_active, "updated_at": utc_now()})

    def soft_delete_from_workspace(self, user_id: str, workspace_id: str) -> Any:
        return self.update_membership(user_id=user_id, workspace_id=workspace_id, is_active=False)

    def require_user(self, user_id: str) -> Any:
        user = self.get_user(user_id)

        if not user:
            raise ValueError("User not found.")

        return user

    def require_membership(self, user_id: str, workspace_id: str) -> Any:
        membership = self.get_membership(user_id, workspace_id)

        if not membership:
            raise ValueError("User is not a member of this workspace.")

        return membership

    def _replace_record(self, store_attr: str, record_id: str, record: Any, update_data: Dict[str, Any]) -> Any:
        mapping = getattr(self.store, store_attr, None)

        if not isinstance(mapping, dict):
            raise RuntimeError(f"Store does not expose {store_attr}.")

        if hasattr(record, "copy"):
            updated = record.copy(update=update_data)
        elif hasattr(record, "model_copy"):
            updated = record.model_copy(update=update_data)
        else:
            current = model_to_dict(record)
            current.update(update_data)
            updated = current

        mapping[record_id] = updated
        return updated

    def _infer_user_class(self) -> Any:
        users = getattr(self.store, "users_by_id", {})
        for user in users.values():
            return user.__class__

        return FallbackRecord

    def _infer_membership_class(self) -> Any:
        memberships = getattr(self.store, "memberships_by_id", {})
        for membership in memberships.values():
            return membership.__class__

        return FallbackMembershipRecord


USER_STORE = UserStoreAdapter(AUTH_STORE)


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


def safe_user_with_membership(user: Any, membership: Any) -> Dict[str, Any]:
    return {
        "user": safe_user(user),
        "membership": safe_membership(membership),
    }


def plan_features(plan: str) -> Dict[str, Any]:
    normalized = normalize_plan(plan)

    matrix = {
        Plan.FREE.value: {
            "visible_features": [
                "basic_profile",
                "limited_agent_preview",
                "single_workspace_view",
            ],
            "upgrade_locked_features": [
                "agent_execution",
                "dashboard_analytics",
                "team_management",
                "audit_exports",
                "advanced_memory",
            ],
            "limits": {
                "users": 1,
                "workspaces": 1,
                "agent_tasks_per_month": 25,
                "memory_items": 50,
            },
        },
        Plan.STARTER.value: {
            "visible_features": [
                "agent_execution",
                "basic_audit_logs",
                "workspace_sessions",
                "profile_management",
            ],
            "upgrade_locked_features": [
                "advanced_dashboard",
                "multi_team_roles",
                "audit_exports",
                "priority_security_review",
            ],
            "limits": {
                "users": 3,
                "workspaces": 1,
                "agent_tasks_per_month": 500,
                "memory_items": 1000,
            },
        },
        Plan.PRO.value: {
            "visible_features": [
                "dashboard_analytics",
                "team_management",
                "agent_execution",
                "basic_memory",
                "audit_visibility",
            ],
            "upgrade_locked_features": [
                "enterprise_policy_controls",
                "custom_agent_registry",
                "dedicated_worker_nodes",
            ],
            "limits": {
                "users": 10,
                "workspaces": 3,
                "agent_tasks_per_month": 5000,
                "memory_items": 10000,
            },
        },
        Plan.BUSINESS.value: {
            "visible_features": [
                "advanced_dashboard",
                "team_roles",
                "audit_exports",
                "advanced_memory",
                "plugin_agents",
                "security_agent_approval_flows",
            ],
            "upgrade_locked_features": [
                "enterprise_sso",
                "dedicated_infrastructure",
                "custom_contract_limits",
            ],
            "limits": {
                "users": 50,
                "workspaces": 10,
                "agent_tasks_per_month": 50000,
                "memory_items": 100000,
            },
        },
        Plan.ENTERPRISE.value: {
            "visible_features": [
                "enterprise_sso",
                "dedicated_infrastructure",
                "custom_agent_registry",
                "advanced_security_controls",
                "unlimited_dashboard_visibility",
                "custom_limits",
            ],
            "upgrade_locked_features": [],
            "limits": {
                "users": "custom",
                "workspaces": "custom",
                "agent_tasks_per_month": "custom",
                "memory_items": "custom",
            },
        },
    }

    return matrix[normalized]


# =============================================================================
# Users Class / Router
# =============================================================================

class Users:
    """
    Required component name: Users

    Provides workspace-scoped user CRUD, profile, role, activation,
    and plan visibility routes.
    """

    def __init__(self) -> None:
        self.router = APIRouter(tags=["Users"])
        self._register_routes()

    def _register_routes(self) -> None:
        self.router.get("/me")(self.get_my_profile)
        self.router.patch("/me")(self.update_my_profile)
        self.router.get("/plan")(self.get_plan_visibility)
        self.router.get("/audit")(self.get_user_audit)
        self.router.get("")(self.list_users)
        self.router.post("")(self.create_user)
        self.router.get("/{target_user_id}")(self.get_user)
        self.router.patch("/{target_user_id}")(self.update_user)
        self.router.patch("/{target_user_id}/role")(self.update_user_role)
        self.router.patch("/{target_user_id}/activation")(self.update_user_activation)
        self.router.delete("/{target_user_id}")(self.remove_user_from_workspace)

    async def get_my_profile(
        self,
        context: AuthContext = Depends(get_current_auth_context),
    ) -> Dict[str, Any]:
        user = USER_STORE.get_user(context.user_id)
        workspace = USER_STORE.get_workspace(context.workspace_id)
        membership = USER_STORE.get_membership(context.user_id, context.workspace_id)

        if not user or not workspace or not membership:
            raise_api_error(
                status_code=status.HTTP_404_NOT_FOUND,
                message="Current user profile scope could not be loaded.",
                code="PROFILE_SCOPE_NOT_FOUND",
                request_id=context.request_id,
            )

        return api_success(
            message="Current user profile loaded.",
            data={
                "profile": safe_user(user),
                "workspace": safe_workspace(workspace),
                "membership": safe_membership(membership),
                "isolation": {
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                },
            },
            request_id=context.request_id,
        )

    async def update_my_profile(
        self,
        payload: UserUpdateRequest,
        request: Request,
        context: AuthContext = Depends(get_current_auth_context),
    ) -> Dict[str, Any]:
        if not USER_SETTINGS.allow_self_profile_update:
            raise_api_error(
                status_code=status.HTTP_403_FORBIDDEN,
                message="Self profile updates are disabled.",
                code="SELF_PROFILE_UPDATE_DISABLED",
                request_id=context.request_id,
            )

        try:
            updated_user = USER_STORE.update_user_profile(
                user_id=context.user_id,
                full_name=payload.full_name,
                metadata=payload.metadata,
            )

            audit = write_user_audit(
                request=request,
                context=context,
                event_type="user_profile_update",
                action="update_my_profile",
                result="success",
                target_user_id=context.user_id,
                status_code=status.HTTP_200_OK,
            )

            memory_result = await emit_memory_context(
                {
                    "type": "user_profile_update",
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "request_id": context.request_id,
                    "content": {
                        "event": "profile_updated",
                        "target_user_id": context.user_id,
                        "updated_fields": list(model_to_dict(payload).keys()),
                    },
                    "created_at": utc_now(),
                }
            )

            verification_result = await prepare_verification(
                {
                    "type": "user_profile_update_confirmation",
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "request_id": context.request_id,
                    "result": "success",
                    "target_user_id": context.user_id,
                    "created_at": utc_now(),
                }
            )

            return api_success(
                message="Profile updated successfully.",
                data={
                    "profile": safe_user(updated_user),
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
                code="PROFILE_UPDATE_FAILED",
                request_id=context.request_id,
            )

    async def get_plan_visibility(
        self,
        context: AuthContext = Depends(get_current_auth_context),
    ) -> Dict[str, Any]:
        workspace = USER_STORE.get_workspace(context.workspace_id)
        membership = USER_STORE.get_membership(context.user_id, context.workspace_id)

        if not workspace or not membership:
            raise_api_error(
                status_code=status.HTTP_404_NOT_FOUND,
                message="Plan scope could not be loaded.",
                code="PLAN_SCOPE_NOT_FOUND",
                request_id=context.request_id,
            )

        workspace_data = safe_workspace(workspace)
        membership_data = safe_membership(membership)
        current_plan = normalize_plan(membership_data.get("plan") or workspace_data.get("plan"))
        features = plan_features(current_plan)

        return api_success(
            message="Plan visibility loaded.",
            data={
                "current_plan": current_plan,
                "subscription_status": workspace_data.get("subscription_status", "active"),
                "visible_features": features["visible_features"],
                "upgrade_locked_features": features["upgrade_locked_features"],
                "limits": features["limits"],
                "role": membership_data.get("role"),
                "isolation": {
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                },
            },
            request_id=context.request_id,
        )

    async def list_users(
        self,
        q: Optional[str] = None,
        role: Optional[str] = None,
        is_active: Optional[bool] = None,
        limit: int = 50,
        offset: int = 0,
        context: AuthContext = Depends(require_auth_role(Role.MANAGER.value)),
    ) -> Dict[str, Any]:
        safe_limit = max(1, min(limit, 200))
        safe_offset = max(0, offset)
        rows = USER_STORE.list_workspace_users(context.workspace_id)

        filtered: List[Tuple[Any, Any]] = []

        for user, membership in rows:
            user_data = safe_user(user)
            membership_data = safe_membership(membership)

            if q:
                search = q.strip().lower()
                if search not in str(user_data.get("email", "")).lower() and search not in str(user_data.get("full_name", "")).lower():
                    continue

            if role and membership_data.get("role") != normalize_role(role):
                continue

            if is_active is not None and bool(user_data.get("is_active", True)) != is_active:
                continue

            filtered.append((user, membership))

        paginated = filtered[safe_offset : safe_offset + safe_limit]

        return api_success(
            message="Workspace users loaded.",
            data={
                "users": [safe_user_with_membership(user, membership) for user, membership in paginated],
                "pagination": {
                    "total": len(filtered),
                    "limit": safe_limit,
                    "offset": safe_offset,
                    "returned": len(paginated),
                },
                "isolation": {
                    "workspace_id": context.workspace_id,
                    "requested_by_user_id": context.user_id,
                },
            },
            request_id=context.request_id,
        )

    async def create_user(
        self,
        payload: UserCreateRequest,
        request: Request,
        context: AuthContext = Depends(require_auth_role(Role.ADMIN.value)),
    ) -> Dict[str, Any]:
        try:
            requested_role = normalize_role(payload.role)

            if not can_manage_target(context.role, requested_role):
                raise_api_error(
                    status_code=status.HTTP_403_FORBIDDEN,
                    message="You cannot create a user with an equal or higher role.",
                    code="ROLE_ESCALATION_BLOCKED",
                    request_id=context.request_id,
                    details={"actor_role": context.role, "requested_role": requested_role},
                )

            workspace = USER_STORE.get_workspace(context.workspace_id)
            if not workspace:
                raise ValueError("Current workspace not found.")

            workspace_data = safe_workspace(workspace)
            target_plan = normalize_plan(payload.plan or workspace_data.get("plan", Plan.FREE.value))

            security_result = await security_review(
                {
                    "type": "user_create",
                    "actor_user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "target_email": payload.email,
                    "target_role": requested_role,
                    "target_plan": target_plan,
                    "request_id": context.request_id,
                    "created_at": utc_now(),
                }
            )

            if not self._security_approved(security_result):
                raise_api_error(
                    status_code=status.HTTP_403_FORBIDDEN,
                    message="User creation was blocked by Security Agent.",
                    code="SECURITY_AGENT_DENIED",
                    request_id=context.request_id,
                    details=security_result,
                )

            user, membership = USER_STORE.create_workspace_user(
                workspace_id=context.workspace_id,
                email=payload.email,
                full_name=payload.full_name,
                role=requested_role,
                plan=target_plan,
                permissions=payload.permissions,
                metadata={
                    **payload.metadata,
                    "created_by_user_id": context.user_id,
                    "created_from": "users_route",
                },
            )

            audit = write_user_audit(
                request=request,
                context=context,
                event_type="user_create",
                action="create_user",
                result="success",
                target_user_id=getattr(user, "user_id"),
                status_code=status.HTTP_201_CREATED,
                metadata={
                    "target_role": requested_role,
                    "security_result": security_result,
                },
            )

            memory_result = await emit_memory_context(
                {
                    "type": "user_create",
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "request_id": context.request_id,
                    "content": {
                        "event": "workspace_user_created",
                        "target_user_id": getattr(user, "user_id"),
                        "target_email": getattr(user, "email"),
                        "target_role": requested_role,
                    },
                    "created_at": utc_now(),
                }
            )

            verification_result = await prepare_verification(
                {
                    "type": "user_create_confirmation",
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "request_id": context.request_id,
                    "result": "success",
                    "target_user_id": getattr(user, "user_id"),
                    "created_at": utc_now(),
                }
            )

            return api_success(
                message="Workspace user created successfully.",
                data={
                    "user": safe_user(user),
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
                code="USER_CREATE_FAILED",
                request_id=context.request_id,
            )

    async def get_user(
        self,
        target_user_id: str,
        context: AuthContext = Depends(require_auth_role(Role.MANAGER.value)),
    ) -> Dict[str, Any]:
        user = USER_STORE.get_user(target_user_id)
        membership = USER_STORE.get_membership(target_user_id, context.workspace_id)

        if not user or not membership:
            raise_api_error(
                status_code=status.HTTP_404_NOT_FOUND,
                message="User was not found in this workspace.",
                code="USER_NOT_FOUND_IN_WORKSPACE",
                request_id=context.request_id,
            )

        return api_success(
            message="Workspace user loaded.",
            data={
                "user": safe_user(user),
                "membership": safe_membership(membership),
                "isolation": {
                    "target_user_id": target_user_id,
                    "workspace_id": context.workspace_id,
                },
            },
            request_id=context.request_id,
        )

    async def update_user(
        self,
        target_user_id: str,
        payload: UserAdminUpdateRequest,
        request: Request,
        context: AuthContext = Depends(require_auth_role(Role.ADMIN.value)),
    ) -> Dict[str, Any]:
        try:
            target_membership = USER_STORE.require_membership(target_user_id, context.workspace_id)
            target_role = safe_membership(target_membership).get("role", Role.USER.value)

            if not can_manage_target(context.role, target_role) and target_user_id != context.user_id:
                raise_api_error(
                    status_code=status.HTTP_403_FORBIDDEN,
                    message="You cannot update a user with an equal or higher role.",
                    code="ROLE_MANAGEMENT_BLOCKED",
                    request_id=context.request_id,
                )

            if payload.role and not can_manage_target(context.role, payload.role):
                raise_api_error(
                    status_code=status.HTTP_403_FORBIDDEN,
                    message="You cannot assign an equal or higher role.",
                    code="ROLE_ESCALATION_BLOCKED",
                    request_id=context.request_id,
                )

            security_result = await security_review(
                {
                    "type": "user_admin_update",
                    "actor_user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "target_user_id": target_user_id,
                    "updates": model_to_dict(payload),
                    "request_id": context.request_id,
                    "created_at": utc_now(),
                }
            )

            if not self._security_approved(security_result):
                raise_api_error(
                    status_code=status.HTTP_403_FORBIDDEN,
                    message="User update was blocked by Security Agent.",
                    code="SECURITY_AGENT_DENIED",
                    request_id=context.request_id,
                    details=security_result,
                )

            updated_user = USER_STORE.update_user_profile(
                user_id=target_user_id,
                full_name=payload.full_name,
                metadata=payload.metadata,
            )

            updated_membership = target_membership

            if payload.role is not None or payload.plan is not None or payload.permissions is not None:
                updated_membership = USER_STORE.update_membership(
                    user_id=target_user_id,
                    workspace_id=context.workspace_id,
                    role=payload.role,
                    plan=payload.plan,
                    permissions=payload.permissions,
                )

            audit = write_user_audit(
                request=request,
                context=context,
                event_type="user_admin_update",
                action="update_user",
                result="success",
                target_user_id=target_user_id,
                status_code=status.HTTP_200_OK,
                metadata={
                    "updates": model_to_dict(payload),
                    "security_result": security_result,
                },
            )

            memory_result = await emit_memory_context(
                {
                    "type": "user_admin_update",
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "request_id": context.request_id,
                    "content": {
                        "event": "workspace_user_updated",
                        "target_user_id": target_user_id,
                        "updates": model_to_dict(payload),
                    },
                    "created_at": utc_now(),
                }
            )

            verification_result = await prepare_verification(
                {
                    "type": "user_admin_update_confirmation",
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "request_id": context.request_id,
                    "result": "success",
                    "target_user_id": target_user_id,
                    "created_at": utc_now(),
                }
            )

            return api_success(
                message="Workspace user updated successfully.",
                data={
                    "user": safe_user(updated_user),
                    "membership": safe_membership(updated_membership),
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
                code="USER_UPDATE_FAILED",
                request_id=context.request_id,
            )

    async def update_user_role(
        self,
        target_user_id: str,
        payload: RoleUpdateRequest,
        request: Request,
        context: AuthContext = Depends(require_auth_role(Role.ADMIN.value)),
    ) -> Dict[str, Any]:
        try:
            target_membership = USER_STORE.require_membership(target_user_id, context.workspace_id)
            current_target_role = safe_membership(target_membership).get("role", Role.USER.value)

            if not can_manage_target(context.role, current_target_role):
                raise_api_error(
                    status_code=status.HTTP_403_FORBIDDEN,
                    message="You cannot modify the role of a user with an equal or higher role.",
                    code="ROLE_MANAGEMENT_BLOCKED",
                    request_id=context.request_id,
                )

            if not can_manage_target(context.role, payload.role):
                raise_api_error(
                    status_code=status.HTTP_403_FORBIDDEN,
                    message="You cannot assign an equal or higher role.",
                    code="ROLE_ESCALATION_BLOCKED",
                    request_id=context.request_id,
                )

            security_result = await security_review(
                {
                    "type": "user_role_update",
                    "actor_user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "target_user_id": target_user_id,
                    "from_role": current_target_role,
                    "to_role": payload.role,
                    "request_id": context.request_id,
                    "created_at": utc_now(),
                }
            )

            if not self._security_approved(security_result):
                raise_api_error(
                    status_code=status.HTTP_403_FORBIDDEN,
                    message="Role update was blocked by Security Agent.",
                    code="SECURITY_AGENT_DENIED",
                    request_id=context.request_id,
                    details=security_result,
                )

            updated_membership = USER_STORE.update_membership(
                user_id=target_user_id,
                workspace_id=context.workspace_id,
                role=payload.role,
            )

            audit = write_user_audit(
                request=request,
                context=context,
                event_type="user_role_update",
                action="update_user_role",
                result="success",
                target_user_id=target_user_id,
                status_code=status.HTTP_200_OK,
                metadata={
                    "from_role": current_target_role,
                    "to_role": payload.role,
                    "security_result": security_result,
                },
            )

            memory_result = await emit_memory_context(
                {
                    "type": "user_role_update",
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "request_id": context.request_id,
                    "content": {
                        "event": "user_role_updated",
                        "target_user_id": target_user_id,
                        "from_role": current_target_role,
                        "to_role": payload.role,
                    },
                    "created_at": utc_now(),
                }
            )

            verification_result = await prepare_verification(
                {
                    "type": "user_role_update_confirmation",
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "request_id": context.request_id,
                    "result": "success",
                    "target_user_id": target_user_id,
                    "created_at": utc_now(),
                }
            )

            return api_success(
                message="User role updated successfully.",
                data={
                    "membership": safe_membership(updated_membership),
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
                code="ROLE_UPDATE_FAILED",
                request_id=context.request_id,
            )

    async def update_user_activation(
        self,
        target_user_id: str,
        payload: ActivationRequest,
        request: Request,
        context: AuthContext = Depends(require_auth_role(Role.ADMIN.value)),
    ) -> Dict[str, Any]:
        try:
            target_user = USER_STORE.require_user(target_user_id)
            target_membership = USER_STORE.require_membership(target_user_id, context.workspace_id)
            target_role = safe_membership(target_membership).get("role", Role.USER.value)

            if target_user_id == context.user_id and not payload.is_active:
                raise_api_error(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    message="You cannot deactivate your own active session user.",
                    code="SELF_DEACTIVATION_BLOCKED",
                    request_id=context.request_id,
                )

            if target_role == Role.OWNER.value and not USER_SETTINGS.allow_owner_deactivation:
                raise_api_error(
                    status_code=status.HTTP_403_FORBIDDEN,
                    message="Owner deactivation is disabled by policy.",
                    code="OWNER_DEACTIVATION_BLOCKED",
                    request_id=context.request_id,
                )

            if not can_manage_target(context.role, target_role):
                raise_api_error(
                    status_code=status.HTTP_403_FORBIDDEN,
                    message="You cannot change activation for a user with an equal or higher role.",
                    code="ACTIVATION_MANAGEMENT_BLOCKED",
                    request_id=context.request_id,
                )

            security_result = await security_review(
                {
                    "type": "user_activation_update",
                    "actor_user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "target_user_id": target_user_id,
                    "is_active": payload.is_active,
                    "reason": payload.reason,
                    "request_id": context.request_id,
                    "created_at": utc_now(),
                }
            )

            if not self._security_approved(security_result):
                raise_api_error(
                    status_code=status.HTTP_403_FORBIDDEN,
                    message="Activation update was blocked by Security Agent.",
                    code="SECURITY_AGENT_DENIED",
                    request_id=context.request_id,
                    details=security_result,
                )

            updated_user = USER_STORE.update_user_activation(target_user_id, payload.is_active)

            audit = write_user_audit(
                request=request,
                context=context,
                event_type="user_activation_update",
                action="activate_user" if payload.is_active else "deactivate_user",
                result="success",
                target_user_id=target_user_id,
                status_code=status.HTTP_200_OK,
                metadata={
                    "is_active": payload.is_active,
                    "reason": payload.reason,
                    "security_result": security_result,
                },
            )

            memory_result = await emit_memory_context(
                {
                    "type": "user_activation_update",
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "request_id": context.request_id,
                    "content": {
                        "event": "user_activation_updated",
                        "target_user_id": target_user_id,
                        "is_active": payload.is_active,
                        "reason": payload.reason,
                    },
                    "created_at": utc_now(),
                }
            )

            verification_result = await prepare_verification(
                {
                    "type": "user_activation_update_confirmation",
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "request_id": context.request_id,
                    "result": "success",
                    "target_user_id": target_user_id,
                    "created_at": utc_now(),
                }
            )

            return api_success(
                message="User activation updated successfully.",
                data={
                    "user": safe_user(updated_user),
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
                code="ACTIVATION_UPDATE_FAILED",
                request_id=context.request_id,
            )

    async def remove_user_from_workspace(
        self,
        target_user_id: str,
        request: Request,
        context: AuthContext = Depends(require_auth_role(Role.ADMIN.value)),
    ) -> Dict[str, Any]:
        try:
            target_membership = USER_STORE.require_membership(target_user_id, context.workspace_id)
            target_role = safe_membership(target_membership).get("role", Role.USER.value)

            if target_user_id == context.user_id:
                raise_api_error(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    message="You cannot remove yourself from the current workspace through this endpoint.",
                    code="SELF_REMOVE_BLOCKED",
                    request_id=context.request_id,
                )

            if target_role == Role.OWNER.value:
                raise_api_error(
                    status_code=status.HTTP_403_FORBIDDEN,
                    message="Workspace owner cannot be removed through this endpoint.",
                    code="OWNER_REMOVE_BLOCKED",
                    request_id=context.request_id,
                )

            if not can_manage_target(context.role, target_role):
                raise_api_error(
                    status_code=status.HTTP_403_FORBIDDEN,
                    message="You cannot remove a user with an equal or higher role.",
                    code="REMOVE_USER_BLOCKED",
                    request_id=context.request_id,
                )

            security_result = await security_review(
                {
                    "type": "user_remove_from_workspace",
                    "actor_user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "target_user_id": target_user_id,
                    "target_role": target_role,
                    "request_id": context.request_id,
                    "created_at": utc_now(),
                }
            )

            if not self._security_approved(security_result):
                raise_api_error(
                    status_code=status.HTTP_403_FORBIDDEN,
                    message="User removal was blocked by Security Agent.",
                    code="SECURITY_AGENT_DENIED",
                    request_id=context.request_id,
                    details=security_result,
                )

            updated_membership = USER_STORE.soft_delete_from_workspace(target_user_id, context.workspace_id)

            audit = write_user_audit(
                request=request,
                context=context,
                event_type="user_remove_from_workspace",
                action="remove_user_from_workspace",
                result="success",
                target_user_id=target_user_id,
                status_code=status.HTTP_200_OK,
                metadata={
                    "security_result": security_result,
                    "target_role": target_role,
                },
            )

            memory_result = await emit_memory_context(
                {
                    "type": "user_remove_from_workspace",
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "request_id": context.request_id,
                    "content": {
                        "event": "user_removed_from_workspace",
                        "target_user_id": target_user_id,
                        "target_role": target_role,
                    },
                    "created_at": utc_now(),
                }
            )

            verification_result = await prepare_verification(
                {
                    "type": "user_remove_from_workspace_confirmation",
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "request_id": context.request_id,
                    "result": "success",
                    "target_user_id": target_user_id,
                    "created_at": utc_now(),
                }
            )

            return api_success(
                message="User removed from workspace successfully.",
                data={
                    "membership": safe_membership(updated_membership),
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
                code="REMOVE_USER_FAILED",
                request_id=context.request_id,
            )

    async def get_user_audit(
        self,
        context: AuthContext = Depends(require_auth_role(Role.ADMIN.value)),
    ) -> Dict[str, Any]:
        scoped = [
            event
            for event in USER_AUDIT_EVENTS
            if event.get("workspace_id") == context.workspace_id
        ]

        return api_success(
            message="Workspace-scoped user audit logs loaded.",
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

    @staticmethod
    def _security_approved(security_result: Dict[str, Any]) -> bool:
        data = security_result.get("data", {}) if isinstance(security_result, dict) else {}

        return bool(
            security_result.get("success")
            and (
                data.get("approved") is True
                or data.get("allowed") is True
                or data.get("local_policy") is True
            )
        )


users = Users()
router = users.router