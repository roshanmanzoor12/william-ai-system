"""
apps/api/main.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

FastAPI application entrypoint with:
- Middleware
- Request IDs
- CORS
- Auth/context hooks
- Health checks
- Optional router loading
- Role/plan/subscription checks
- Audit logging hooks
- Safe structured errors
- Future-ready Master/Security/Memory/Verification Agent bridges

This file is designed to import safely even when future route files or agent files
are not created yet.
"""

from __future__ import annotations

import importlib
import inspect
import json
import logging
import os
import time
import traceback
import uuid
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Tuple

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field


# =============================================================================
# Logging
# =============================================================================

LOGGER_NAME = "william.api.main"
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

    clean = value.strip().lower()
    return clean in {"1", "true", "yes", "y", "on"}


def parse_csv(value: Optional[str], default: Optional[List[str]] = None) -> List[str]:
    if not value:
        return default or []

    return [item.strip() for item in value.split(",") if item.strip()]


def safe_json(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, default=str)
    except Exception:
        return json.dumps({"error": "Unable to serialize value"}, ensure_ascii=False)


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


def normalize_identifier(value: Optional[str], field_name: str) -> str:
    if value is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "success": False,
                "message": f"{field_name} is required.",
                "error": {"code": f"{field_name.upper()}_REQUIRED"},
            },
        )

    clean = str(value).strip()

    if not clean:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "success": False,
                "message": f"{field_name} cannot be empty.",
                "error": {"code": f"{field_name.upper()}_EMPTY"},
            },
        )

    if len(clean) > 128:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "success": False,
                "message": f"{field_name} is too long.",
                "error": {"code": f"{field_name.upper()}_TOO_LONG"},
            },
        )

    return clean


def normalize_role(value: Optional[str]) -> str:
    clean = (value or "user").strip().lower()

    allowed = {"owner", "admin", "manager", "developer", "analyst", "agent", "user", "viewer"}
    if clean not in allowed:
        return "user"

    return clean


def normalize_plan(value: Optional[str]) -> str:
    clean = (value or "free").strip().lower()

    allowed = {"free", "starter", "pro", "business", "enterprise"}
    if clean not in allowed:
        return "free"

    return clean


# =============================================================================
# Configuration
# =============================================================================

@dataclass(frozen=True)
class Settings:
    app_name: str = field(default_factory=lambda: os.getenv("WILLIAM_APP_NAME", "William / Jarvis API"))
    brand_name: str = field(default_factory=lambda: os.getenv("WILLIAM_BRAND_NAME", "Digital Promotix"))
    environment: str = field(default_factory=lambda: os.getenv("WILLIAM_ENV", "development"))
    version: str = field(default_factory=lambda: os.getenv("WILLIAM_API_VERSION", "1.0.0"))
    debug: bool = field(default_factory=lambda: parse_bool(os.getenv("WILLIAM_DEBUG"), False))

    api_prefix: str = field(default_factory=lambda: os.getenv("WILLIAM_API_PREFIX", "/api/v1"))
    docs_enabled: bool = field(default_factory=lambda: parse_bool(os.getenv("WILLIAM_DOCS_ENABLED"), True))

    allowed_origins: List[str] = field(
        default_factory=lambda: parse_csv(
            os.getenv("WILLIAM_CORS_ORIGINS"),
            [
                "http://localhost:3000",
                "http://localhost:3001",
                "http://localhost:5173",
                "http://127.0.0.1:3000",
                "http://127.0.0.1:3001",
                "http://127.0.0.1:5173",
            ],
        )
    )
    allowed_methods: List[str] = field(
        default_factory=lambda: parse_csv(
            os.getenv("WILLIAM_CORS_METHODS"),
            ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        )
    )
    # Starlette's CORSMiddleware returns its own 400 "Disallowed CORS ..."
    # response (before the request ever reaches routing/auth) whenever a
    # preflight's Origin or Access-Control-Request-Headers isn't covered by
    # these lists. Two rounds of this bug: round 1 was missing Accept/
    # Origin/X-Requested-With, which real browsers/axios always include on
    # preflighted cross-origin requests. Round 2 (this list) was still
    # missing the DASHBOARD'S OWN APP-SPECIFIC custom headers -- grepped
    # directly from apps/dashboard/src/ rather than guessed: several pages'
    # local `apiRequest` helpers (apps/dashboard/src/app/(dashboard)/
    # {dashboard,agents,tasks}/page.tsx) send X-Action/X-Client-App/
    # X-Audit-Enabled/X-Audit-Action/X-Sensitive-Action on every request,
    # none of which were ever in this list, so the browser's preflight
    # Access-Control-Request-Headers always included at least one disallowed
    # header and CORSMiddleware always 400'd -- verified live: `curl -X
    # OPTIONS ... -H "Access-Control-Request-Headers: authorization,
    # content-type,x-action,x-client-app,x-audit-enabled"` reproduced the
    # exact reported 400 "Disallowed CORS headers" before this fix.
    # X-User-ID/X-Workspace-ID/X-User-Role/X-Subscription-Plan stay listed
    # for legacy callers that still send them, but get_current_auth_context()
    # (apps/api/routes/auth.py) never trusts them for identity -- only a
    # verified JWT does.
    allowed_headers: List[str] = field(
        default_factory=lambda: parse_csv(
            os.getenv("WILLIAM_CORS_HEADERS"),
            [
                "Authorization",
                "Content-Type",
                "Accept",
                "Origin",
                "X-Requested-With",
                "X-Request-ID",
                "X-User-ID",
                "X-Workspace-ID",
                "X-User-Role",
                "X-Subscription-Plan",
                "X-Action",
                "X-Client-App",
                "X-Audit-Enabled",
                "X-Audit-Action",
                "X-Sensitive-Action",
            ],
        )
    )

    # Secure by default: a real bearer token is required unless an operator
    # explicitly opts into the header-trust dev fallback (both were the
    # opposite default before -- auth_required=False, dev_auth_enabled=True
    # -- which meant every built-in route accepted a forged X-User-ID by
    # default, in production too, unless someone remembered to flip both).
    auth_required: bool = field(default_factory=lambda: parse_bool(os.getenv("WILLIAM_AUTH_REQUIRED"), True))
    dev_auth_enabled: bool = field(default_factory=lambda: parse_bool(os.getenv("WILLIAM_DEV_AUTH_ENABLED"), False))
    default_user_id: str = field(default_factory=lambda: os.getenv("WILLIAM_DEFAULT_USER_ID", "demo_user"))
    default_workspace_id: str = field(default_factory=lambda: os.getenv("WILLIAM_DEFAULT_WORKSPACE_ID", "demo_workspace"))

    audit_log_enabled: bool = field(default_factory=lambda: parse_bool(os.getenv("WILLIAM_AUDIT_LOG_ENABLED"), True))
    security_agent_required: bool = field(default_factory=lambda: parse_bool(os.getenv("WILLIAM_SECURITY_AGENT_REQUIRED"), True))
    memory_agent_enabled: bool = field(default_factory=lambda: parse_bool(os.getenv("WILLIAM_MEMORY_AGENT_ENABLED"), True))
    verification_agent_enabled: bool = field(default_factory=lambda: parse_bool(os.getenv("WILLIAM_VERIFICATION_AGENT_ENABLED"), True))

    rate_limit_note: str = "External rate limiting should be handled by gateway/proxy for production."

    def as_public_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data.pop("default_user_id", None)
        data.pop("default_workspace_id", None)
        return data


SETTINGS = Settings()


# =============================================================================
# Roles, Plans, Permissions
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

SENSITIVE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

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
    "send_email",
    "send_message",
    "call",
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
}


def has_min_role(user_role: str, required_role: str) -> bool:
    return ROLE_RANK.get(user_role, 0) >= ROLE_RANK.get(required_role, 0)


def has_min_plan(user_plan: str, required_plan: str) -> bool:
    return PLAN_RANK.get(user_plan, 0) >= PLAN_RANK.get(required_plan, 0)


# =============================================================================
# Models
# =============================================================================

class APIResponse(BaseModel):
    success: bool = True
    message: str
    data: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class HealthResponse(BaseModel):
    success: bool
    message: str
    data: Dict[str, Any]
    metadata: Dict[str, Any]


class ExecuteTaskRequest(BaseModel):
    action: str = Field(default="general_request", min_length=1, max_length=128)
    message: str = Field(default="", max_length=20000)
    preferred_agent: Optional[str] = Field(default=None, max_length=128)
    input_data: Dict[str, Any] = Field(default_factory=dict)
    approved_by_security: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AppContext(BaseModel):
    request_id: str
    user_id: str
    workspace_id: str
    role: str
    plan: str
    auth_type: str = "dev_header"
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None

    def isolation_key(self) -> str:
        return f"{self.user_id}:{self.workspace_id}"


class AuditEvent(BaseModel):
    audit_id: str
    request_id: str
    user_id: str
    workspace_id: str
    event_type: str
    action: str
    route: str
    method: str
    result: str
    status_code: Optional[int] = None
    created_at: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


# =============================================================================
# Safe In-Memory Audit Store
# Replace later with database-backed audit_logs table.
# =============================================================================

class AuditStore:
    def __init__(self, max_events: int = 1000) -> None:
        self.max_events = max_events
        self._events: List[AuditEvent] = []

    def add(self, event: AuditEvent) -> AuditEvent:
        self._events.append(event)

        if len(self._events) > self.max_events:
            self._events = self._events[-self.max_events :]

        logger.info(
            "Audit event | type=%s | action=%s | user=%s | workspace=%s | result=%s",
            event.event_type,
            event.action,
            event.user_id,
            event.workspace_id,
            event.result,
        )
        return event

    def list_for_scope(self, user_id: str, workspace_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        scoped = [
            event.model_dump()
            for event in self._events
            if event.user_id == user_id and event.workspace_id == workspace_id
        ]
        return scoped[-limit:]

    def count(self) -> int:
        return len(self._events)


AUDIT_STORE = AuditStore()


# =============================================================================
# Future Agent Bridge
# =============================================================================

class OptionalComponentBridge:
    """
    Imports future components safely.

    Supported patterns:
    - Class with async/sync method
    - Function with async/sync call
    - Missing file/class returns unavailable response
    """

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
        self.import_error: Optional[str] = None
        self.loaded_from: Optional[str] = None

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
                logger.info("Loaded optional component: %s from %s", self.component_name, self.loaded_from)
                return True

            except Exception as exc:
                self.import_error = f"{module_path}.{attr_name}: {exc}"

        return False

    def _instantiate(self, cls: Any) -> Any:
        attempts = [
            {"settings": SETTINGS},
            {},
        ]

        last_error: Optional[Exception] = None
        for kwargs in attempts:
            try:
                return cls(**kwargs)
            except TypeError as exc:
                last_error = exc

        raise last_error or RuntimeError(f"Unable to instantiate {cls}")

    async def call(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        loaded = self.load()

        if not loaded or self.instance is None:
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
                return self._normalize_result(result)

            for method_name in self.method_candidates:
                method = getattr(self.instance, method_name, None)

                if callable(method):
                    result = await maybe_await(method(payload))
                    return self._normalize_result(result)

            return {
                "success": False,
                "message": f"{self.component_name} has no compatible callable method.",
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
                "message": f"{self.component_name} execution failed.",
                "data": {"component": self.component_name},
                "error": safe_error_detail(exc, SETTINGS.debug),
                "metadata": {"timestamp": utc_now()},
            }

    @staticmethod
    def _normalize_result(result: Any) -> Dict[str, Any]:
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


MASTER_AGENT = OptionalComponentBridge(
    component_name="Master Agent",
    import_candidates=[
        ("apps.api.services.master_agent_bridge", "MasterAgentBridge"),
        ("core.master_agent", "MasterAgent"),
        ("agents.master_agent.master_agent", "MasterAgent"),
        ("agents.master.master_agent", "MasterAgent"),
    ],
    method_candidates=["handle_api_task", "handle_request", "execute", "run", "route_task"],
)

SECURITY_AGENT = OptionalComponentBridge(
    component_name="Security Agent",
    import_candidates=[
        ("apps.api.services.security_agent_bridge", "SecurityAgentBridge"),
        ("agents.security_agent.security_agent", "SecurityAgent"),
        ("agents.security.security_agent", "SecurityAgent"),
    ],
    method_candidates=["approve_api_action", "approve_action", "check_permission", "execute", "run"],
)

MEMORY_AGENT = OptionalComponentBridge(
    component_name="Memory Agent",
    import_candidates=[
        ("apps.api.services.memory_agent_bridge", "MemoryAgentBridge"),
        ("agents.memory_agent.memory_agent", "MemoryAgent"),
        ("agents.memory.memory_agent", "MemoryAgent"),
    ],
    method_candidates=["record_api_context", "save_context", "remember", "execute", "run"],
)

VERIFICATION_AGENT = OptionalComponentBridge(
    component_name="Verification Agent",
    import_candidates=[
        ("apps.api.services.verification_agent_bridge", "VerificationAgentBridge"),
        ("agents.verification_agent.verification_agent", "VerificationAgent"),
        ("agents.verification.verification_agent", "VerificationAgent"),
    ],
    method_candidates=["prepare_confirmation", "verify_result", "confirm", "execute", "run"],
)


# =============================================================================
# Response Helpers
# =============================================================================

def response_success(
    message: str,
    data: Optional[Dict[str, Any]] = None,
    request_id: Optional[str] = None,
    extra_metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return {
        "success": True,
        "message": message,
        "data": data or {},
        "error": None,
        "metadata": {
            "request_id": request_id,
            "timestamp": utc_now(),
            "app": SETTINGS.app_name,
            "brand": SETTINGS.brand_name,
            "version": SETTINGS.version,
            **(extra_metadata or {}),
        },
    }


def response_error(
    message: str,
    code: str,
    status_code: int,
    request_id: Optional[str] = None,
    details: Optional[Any] = None,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
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
                "app": SETTINGS.app_name,
                "brand": SETTINGS.brand_name,
                "version": SETTINGS.version,
            },
        },
    )


# =============================================================================
# Auth / Context Dependencies
# =============================================================================

async def get_request_context(
    request: Request,
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
    x_request_id: Optional[str] = Header(default=None, alias="X-Request-ID"),
    x_user_id: Optional[str] = Header(default=None, alias="X-User-ID"),
    x_workspace_id: Optional[str] = Header(default=None, alias="X-Workspace-ID"),
    x_user_role: Optional[str] = Header(default=None, alias="X-User-Role"),
    x_subscription_plan: Optional[str] = Header(default=None, alias="X-Subscription-Plan"),
) -> AppContext:
    """
    Previously: if SETTINGS.auth_required was False (its default) or an
    Authorization header merely existed (never checked for validity), this
    built directly from X-User-ID/X-Workspace-ID/X-User-Role headers --
    identical spoofable-header trust to what apps/api/routes/auth.py's
    real login/register/protected-route flow (Phase 4) replaced. Every
    built-in route using this dependency (/api/v1/system/*,
    /api/v1/agents/execute, /api/v1/agents/status,
    /api/v1/dashboard/summary) was reachable with a forged X-User-ID.

    Now: a real Authorization: Bearer token, if present, is always
    verified through the same TOKEN_SERVICE/AUTH_STORE apps.api.routes.auth
    already uses -- never bypassed by dev_auth_enabled. The X-User-ID-style
    header path only remains as an explicit local-dev fallback, and only
    when auth_required is False (i.e. the operator has explicitly opted
    into unauthenticated local development).
    """
    request_id = x_request_id or getattr(request.state, "request_id", None) or new_id("req")

    if authorization and authorization.lower().startswith("bearer "):
        try:
            from apps.api.routes.auth import AUTH_STORE, TOKEN_SERVICE

            token = authorization.split(" ", 1)[1].strip()
            payload = TOKEN_SERVICE.verify_token(token, expected_type="access")

            if AUTH_STORE.is_jti_revoked(payload["jti"]):
                raise ValueError("Token has been revoked.")

            user = AUTH_STORE.get_user_by_id(payload["sub"])
            if not user or not user.is_active:
                raise ValueError("User account is not active.")

            session = AUTH_STORE.touch_session(payload["session_id"])
            if session.user_id != user.user_id or session.workspace_id != payload["workspace_id"]:
                raise ValueError("Session scope mismatch.")

            membership = AUTH_STORE.get_membership(user.user_id, session.workspace_id)
            if not membership:
                raise ValueError("Workspace access is no longer available.")

            context = AppContext(
                request_id=request_id,
                user_id=user.user_id,
                workspace_id=session.workspace_id,
                role=normalize_role(membership.role),
                plan=normalize_plan(membership.plan),
                auth_type="bearer_token",
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent"),
            )
            request.state.context = context
            return context

        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "success": False,
                    "message": "Invalid or expired access token.",
                    "error": {"code": "INVALID_TOKEN", "details": str(exc)},
                    "metadata": {"request_id": request_id, "timestamp": utc_now()},
                },
            ) from exc

    if SETTINGS.auth_required:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "success": False,
                "message": "A Bearer access token is required.",
                "error": {"code": "AUTH_REQUIRED"},
                "metadata": {"request_id": request_id, "timestamp": utc_now()},
            },
        )

    if not SETTINGS.dev_auth_enabled:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "success": False,
                "message": "A Bearer access token is required.",
                "error": {"code": "AUTH_REQUIRED"},
                "metadata": {"request_id": request_id, "timestamp": utc_now()},
            },
        )

    user_id = normalize_identifier(x_user_id or SETTINGS.default_user_id, "user_id")
    workspace_id = normalize_identifier(x_workspace_id or SETTINGS.default_workspace_id, "workspace_id")

    context = AppContext(
        request_id=request_id,
        user_id=user_id,
        workspace_id=workspace_id,
        role=normalize_role(x_user_role),
        plan=normalize_plan(x_subscription_plan),
        auth_type="dev_header",
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    request.state.context = context
    return context


def require_role(required_role: str) -> Callable[[AppContext], AppContext]:
    async def dependency(context: AppContext = Depends(get_request_context)) -> AppContext:
        if not has_min_role(context.role, required_role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "success": False,
                    "message": f"Role '{required_role}' or higher is required.",
                    "error": {
                        "code": "INSUFFICIENT_ROLE",
                        "required_role": required_role,
                        "current_role": context.role,
                    },
                    "metadata": {"request_id": context.request_id, "timestamp": utc_now()},
                },
            )

        return context

    return dependency


def require_plan(required_plan: str) -> Callable[[AppContext], AppContext]:
    async def dependency(context: AppContext = Depends(get_request_context)) -> AppContext:
        if not has_min_plan(context.plan, required_plan):
            raise HTTPException(
                status_code=status.HTTP_402_PAYMENT_REQUIRED,
                detail={
                    "success": False,
                    "message": f"Plan '{required_plan}' or higher is required.",
                    "error": {
                        "code": "INSUFFICIENT_PLAN",
                        "required_plan": required_plan,
                        "current_plan": context.plan,
                    },
                    "metadata": {"request_id": context.request_id, "timestamp": utc_now()},
                },
            )

        return context

    return dependency


# =============================================================================
# Audit Helpers
# =============================================================================

def is_state_changing(method: str) -> bool:
    return method.upper() in SENSITIVE_METHODS


def looks_sensitive(action: str, message: str = "", payload: Optional[Dict[str, Any]] = None) -> bool:
    payload_text = safe_json(payload or {}).lower()
    combined = f"{action} {message} {payload_text}".lower()
    return any(keyword in combined for keyword in SENSITIVE_ACTION_KEYWORDS)


def write_audit_event(
    context: AppContext,
    event_type: str,
    action: str,
    route: str,
    method: str,
    result: str,
    status_code: Optional[int] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> AuditEvent:
    event = AuditEvent(
        audit_id=new_id("audit"),
        request_id=context.request_id,
        user_id=context.user_id,
        workspace_id=context.workspace_id,
        event_type=event_type,
        action=action,
        route=route,
        method=method.upper(),
        result=result,
        status_code=status_code,
        created_at=utc_now(),
        metadata=metadata or {},
    )

    if SETTINGS.audit_log_enabled:
        return AUDIT_STORE.add(event)

    return event


# =============================================================================
# Middleware
# =============================================================================

async def request_id_middleware(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    request_id = request.headers.get("X-Request-ID") or new_id("req")
    request.state.request_id = request_id

    start = time.perf_counter()

    try:
        response = await call_next(request)
    except Exception as exc:
        logger.exception("Unhandled request error | request_id=%s", request_id)
        return response_error(
            message="Internal server error.",
            code="INTERNAL_SERVER_ERROR",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            request_id=request_id,
            details=safe_error_detail(exc, SETTINGS.debug),
        )

    duration_ms = round((time.perf_counter() - start) * 1000, 2)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Response-Time-MS"] = str(duration_ms)

    return response


async def audit_middleware(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    response = await call_next(request)

    if not SETTINGS.audit_log_enabled:
        return response

    if not is_state_changing(request.method):
        return response

    context = getattr(request.state, "context", None)

    if isinstance(context, AppContext):
        write_audit_event(
            context=context,
            event_type="http_state_change",
            action=f"{request.method.upper()} {request.url.path}",
            route=request.url.path,
            method=request.method,
            result="completed" if response.status_code < 400 else "failed",
            status_code=response.status_code,
            metadata={
                "query": dict(request.query_params),
                "client": context.ip_address,
            },
        )

    return response


# =============================================================================
# Routers
# =============================================================================

health_router = APIRouter(tags=["Health"])
system_router = APIRouter(prefix="/system", tags=["System"])
agents_router = APIRouter(prefix="/agents", tags=["Agents"])
dashboard_router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@health_router.get("/", response_model=APIResponse)
async def root() -> Dict[str, Any]:
    return response_success(
        message="William/Jarvis API is running.",
        data={
            "service": SETTINGS.app_name,
            "brand": SETTINGS.brand_name,
            "environment": SETTINGS.environment,
            "version": SETTINGS.version,
        },
    )


@health_router.get("/health", response_model=HealthResponse)
async def health() -> Dict[str, Any]:
    return {
        "success": True,
        "message": "API health check passed.",
        "data": {
            "status": "healthy",
            "service": SETTINGS.app_name,
            "brand": SETTINGS.brand_name,
            "environment": SETTINGS.environment,
            "version": SETTINGS.version,
            "audit_events": AUDIT_STORE.count(),
        },
        "metadata": {"timestamp": utc_now()},
    }


@health_router.get("/ready", response_model=APIResponse)
async def ready() -> Dict[str, Any]:
    components = {
        "master_agent": MASTER_AGENT.load(),
        "security_agent": SECURITY_AGENT.load(),
        "memory_agent": MEMORY_AGENT.load(),
        "verification_agent": VERIFICATION_AGENT.load(),
    }

    return response_success(
        message="Readiness check completed.",
        data={
            "ready": True,
            "components": components,
            "note": "Missing optional agents do not block API import or boot.",
        },
    )


@system_router.get("/config", response_model=APIResponse)
async def public_config(context: AppContext = Depends(require_role(Role.ADMIN.value))) -> Dict[str, Any]:
    return response_success(
        message="Public API configuration loaded.",
        data={"settings": SETTINGS.as_public_dict()},
        request_id=context.request_id,
    )


@system_router.get("/audit", response_model=APIResponse)
async def scoped_audit_logs(
    limit: int = 100,
    context: AppContext = Depends(require_role(Role.MANAGER.value)),
) -> Dict[str, Any]:
    safe_limit = max(1, min(limit, 500))
    logs = AUDIT_STORE.list_for_scope(
        user_id=context.user_id,
        workspace_id=context.workspace_id,
        limit=safe_limit,
    )

    return response_success(
        message="Scoped audit logs loaded.",
        data={
            "logs": logs,
            "count": len(logs),
            "isolation": {
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
            },
        },
        request_id=context.request_id,
    )


@agents_router.post("/execute", response_model=APIResponse)
async def execute_agent_task(
    payload: ExecuteTaskRequest,
    request: Request,
    context: AppContext = Depends(require_plan(Plan.STARTER.value)),
) -> Dict[str, Any]:
    task_payload = {
        "task_id": new_id("task"),
        "request_id": context.request_id,
        "user_id": context.user_id,
        "workspace_id": context.workspace_id,
        "role": context.role,
        "plan": context.plan,
        "action": payload.action,
        "message": payload.message,
        "preferred_agent": payload.preferred_agent,
        "input_data": payload.input_data,
        "approved_by_security": payload.approved_by_security,
        "metadata": {
            **payload.metadata,
            "route": str(request.url.path),
            "method": request.method,
            "source": "apps/api/main.py",
            "created_at": utc_now(),
        },
    }

    sensitive = looks_sensitive(
        action=payload.action,
        message=payload.message,
        payload=payload.input_data,
    )

    if sensitive and SETTINGS.security_agent_required and not payload.approved_by_security:
        security_result = await SECURITY_AGENT.call(
            {
                "type": "api_security_review",
                "task": task_payload,
                "context": context.model_dump(),
                "created_at": utc_now(),
            }
        )

        approved = bool(
            security_result.get("success")
            and (
                security_result.get("data", {}).get("approved") is True
                or security_result.get("data", {}).get("allowed") is True
            )
        )

        if not approved:
            write_audit_event(
                context=context,
                event_type="security_review",
                action=payload.action,
                route=str(request.url.path),
                method=request.method,
                result="denied",
                status_code=status.HTTP_403_FORBIDDEN,
                metadata={"security_result": security_result},
            )

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "success": False,
                    "message": "Sensitive action requires Security Agent approval.",
                    "data": {"security_result": security_result},
                    "error": {"code": "SECURITY_APPROVAL_REQUIRED"},
                    "metadata": {
                        "request_id": context.request_id,
                        "timestamp": utc_now(),
                    },
                },
            )

        task_payload["approved_by_security"] = True
        task_payload["security_result"] = security_result

    master_result = await MASTER_AGENT.call(task_payload)

    verification_payload = {
        "type": "api_task_verification",
        "task": task_payload,
        "result": master_result,
        "context": context.model_dump(),
        "created_at": utc_now(),
    }

    verification_result: Dict[str, Any] = {
        "success": False,
        "message": "Verification Agent is disabled.",
        "data": {},
        "error": {"code": "VERIFICATION_DISABLED"},
        "metadata": {"timestamp": utc_now()},
    }

    if SETTINGS.verification_agent_enabled:
        verification_result = await VERIFICATION_AGENT.call(verification_payload)

    memory_payload = {
        "type": "api_context_memory",
        "context": context.model_dump(),
        "content": {
            "task_id": task_payload["task_id"],
            "action": payload.action,
            "preferred_agent": payload.preferred_agent,
            "result_success": master_result.get("success"),
            "result_message": master_result.get("message"),
        },
        "created_at": utc_now(),
    }

    memory_result: Dict[str, Any] = {
        "success": False,
        "message": "Memory Agent is disabled.",
        "data": {},
        "error": {"code": "MEMORY_DISABLED"},
        "metadata": {"timestamp": utc_now()},
    }

    if SETTINGS.memory_agent_enabled:
        memory_result = await MEMORY_AGENT.call(memory_payload)

    write_audit_event(
        context=context,
        event_type="agent_task",
        action=payload.action,
        route=str(request.url.path),
        method=request.method,
        result="completed" if master_result.get("success") else "failed",
        status_code=status.HTTP_200_OK if master_result.get("success") else status.HTTP_500_INTERNAL_SERVER_ERROR,
        metadata={
            "task_id": task_payload["task_id"],
            "preferred_agent": payload.preferred_agent,
            "sensitive": sensitive,
            "master_success": master_result.get("success"),
        },
    )

    return response_success(
        message="Agent task routed through API entrypoint.",
        data={
            "task": task_payload,
            "result": master_result,
            "verification_payload": verification_payload,
            "verification_result": verification_result,
            "memory_payload": memory_payload,
            "memory_result": memory_result,
            "isolation": {
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
            },
        },
        request_id=context.request_id,
        extra_metadata={"component": "agent_execute"},
    )


@agents_router.get("/status", response_model=APIResponse)
async def agent_status(context: AppContext = Depends(get_request_context)) -> Dict[str, Any]:
    components = {
        "master_agent": {
            "loaded": MASTER_AGENT.load(),
            "source": MASTER_AGENT.loaded_from,
            "error": MASTER_AGENT.import_error,
        },
        "security_agent": {
            "loaded": SECURITY_AGENT.load(),
            "source": SECURITY_AGENT.loaded_from,
            "error": SECURITY_AGENT.import_error,
        },
        "memory_agent": {
            "loaded": MEMORY_AGENT.load(),
            "source": MEMORY_AGENT.loaded_from,
            "error": MEMORY_AGENT.import_error,
        },
        "verification_agent": {
            "loaded": VERIFICATION_AGENT.load(),
            "source": VERIFICATION_AGENT.loaded_from,
            "error": VERIFICATION_AGENT.import_error,
        },
    }

    return response_success(
        message="Agent bridge status loaded.",
        data={
            "components": components,
            "isolation": {
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
            },
        },
        request_id=context.request_id,
    )


@dashboard_router.get("/summary", response_model=APIResponse)
async def dashboard_summary(
    context: AppContext = Depends(require_plan(Plan.PRO.value)),
) -> Dict[str, Any]:
    logs = AUDIT_STORE.list_for_scope(
        user_id=context.user_id,
        workspace_id=context.workspace_id,
        limit=100,
    )

    state_changes = [event for event in logs if event.get("event_type") == "http_state_change"]
    agent_tasks = [event for event in logs if event.get("event_type") == "agent_task"]

    return response_success(
        message="Dashboard summary loaded.",
        data={
            "scope": {
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
                "role": context.role,
                "plan": context.plan,
            },
            "analytics": {
                "audit_events": len(logs),
                "state_changing_requests": len(state_changes),
                "agent_tasks": len(agent_tasks),
            },
            "recent_activity": logs[-10:],
        },
        request_id=context.request_id,
    )


# =============================================================================
# Optional External Router Loading
# =============================================================================

OPTIONAL_ROUTERS: List[Tuple[str, str, str]] = [
    ("apps.api.routes.auth", "router", "/auth"),
    ("apps.api.routes.users", "router", "/users"),
    ("apps.api.routes.workspaces", "router", "/workspaces"),
    ("apps.api.routes.agents", "router", "/agents"),
    ("apps.api.routes.tasks", "router", "/tasks"),
    ("apps.api.routes.memory", "router", "/memory"),
    ("apps.api.routes.security", "router", "/security"),
    ("apps.api.routes.workflows", "router", "/workflows"),
    ("apps.api.routes.audit", "router", "/audit"),
    ("apps.api.routes.analytics", "router", "/analytics"),
    ("apps.api.routes.billing", "router", "/billing"),
    ("apps.api.routes.subscriptions", "router", "/subscriptions"),
    ("apps.api.routes.files", "router", "/files"),
    ("apps.api.routes.voice", "router", "/voice"),
    ("apps.api.routes.agent_permissions", "router", "/agent-permissions"),
    ("apps.api.routes.admin", "router", "/admin"),
    ("apps.api.routes.system_worker", "router", "/system"),
    ("apps.api.routes.capabilities", "router", "/system"),
    ("apps.api.routes.assistant", "router", "/assistant"),
    # No apps.api.routes.devices entry: no device-pairing concept exists
    # anywhere else in this codebase (no model, no agent, no worker
    # protocol for it) to build a real router against -- inventing one
    # would violate the "no fake implementation" rule. Tracked as an
    # honest out-of-scope gap in the final production-readiness report.
    # WEBSOCKET_PATH already carries the full "/ws/agent-events" path
    # itself (see that module), so no extra path segment here beyond
    # the shared API prefix.
    ("apps.api.websockets.agent_events", "router", ""),
]


def include_optional_routers(app: FastAPI) -> List[Dict[str, Any]]:
    loaded: List[Dict[str, Any]] = []

    for module_path, attr_name, default_prefix in OPTIONAL_ROUTERS:
        record = {
            "module": module_path,
            "attr": attr_name,
            "prefix": default_prefix,
            "loaded": False,
            "error": None,
        }

        try:
            module = importlib.import_module(module_path)
            router = getattr(module, attr_name)

            if not isinstance(router, APIRouter):
                record["error"] = "Attribute is not an APIRouter instance."
                loaded.append(record)
                continue

            # Previously this branched on whether any of the router's own
            # (relative) paths happened to string-match an already-mounted
            # absolute path, on the theory that a match meant "this router
            # already bakes in its own prefix, don't add default_prefix
            # too." That heuristic was wrong: apps.api.routes.agents has a
            # bare "/health" endpoint that coincidentally matches the
            # top-level health-check route's "/health" path even though
            # agents.py has no self-prefix at all, so it silently mounted
            # at just SETTINGS.api_prefix (e.g. "/api/v1") instead of
            # "/api/v1/agents" -- every one of its 12 real endpoints ended
            # up unreachable at their intended path (and some, like
            # "/audit", collided with and shadowed a different router's
            # route at the same accidental path). Every router in
            # OPTIONAL_ROUTERS is now written without a self-prefix
            # (memory.py/billing.py/security.py/workflows.py had one and
            # were fixed to match agents.py/tasks.py's convention), so
            # default_prefix is always the correct and only prefix to add.
            app.include_router(router, prefix=f"{SETTINGS.api_prefix}{default_prefix}")

            record["loaded"] = True

        except ModuleNotFoundError as exc:
            record["error"] = f"Module not available yet: {exc.name}"
        except Exception as exc:
            record["error"] = str(exc)
            logger.warning("Optional router failed to load: %s | %s", module_path, exc)

        loaded.append(record)

    return loaded


# =============================================================================
# Error Handlers
# =============================================================================

async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    request_id = getattr(request.state, "request_id", None)

    if isinstance(exc.detail, dict):
        content = exc.detail
        content.setdefault("metadata", {})
        content["metadata"].setdefault("request_id", request_id)
        content["metadata"].setdefault("timestamp", utc_now())
        return JSONResponse(status_code=exc.status_code, content=content)

    return response_error(
        message=str(exc.detail),
        code="HTTP_EXCEPTION",
        status_code=exc.status_code,
        request_id=request_id,
    )


SENSITIVE_FIELD_NAME_MARKERS = (
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "credential",
    "private_key",
)


def _redact_sensitive_value(value: Any) -> Any:
    """
    Redact a validation error's echoed input, recursing into dicts/lists.

    Sensitive keys are dropped entirely rather than replaced with a
    "***REDACTED***" placeholder -- a placeholder value still leaves a key
    literally named "password" in the response body, which is itself an
    implementation-detail leak worth avoiding, not just the value.
    """

    if isinstance(value, dict):
        redacted: Dict[str, Any] = {}
        for key, item in value.items():
            key_lower = str(key).lower()
            if any(marker in key_lower for marker in SENSITIVE_FIELD_NAME_MARKERS):
                continue
            redacted[key] = _redact_sensitive_value(item)
        return redacted

    if isinstance(value, list):
        return [_redact_sensitive_value(item) for item in value]

    if isinstance(value, BaseException):
        # Pydantic v2 puts the raised exception instance itself (not a
        # string) in "ctx"/"ctx.error" for custom @field_validator/@model_
        # validator failures -- e.g. a `raise ValueError("invalid email")`
        # inside a validator ends up as ctx={"error": ValueError(...)},
        # which JSONResponse cannot serialize and turns a real 422 into an
        # unhandled 500 (confirmed: this crashed on `email: "not-an-email"`
        # in test_register_requires_email_password_and_workspace_context).
        return str(value)

    if isinstance(value, (str, int, float, bool)) or value is None:
        return value

    return safe_json(value)


def sanitize_validation_errors(errors: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Pydantic's default RequestValidationError.errors() includes the raw
    submitted value for every failing field under "input" -- for a field
    like "password" that means a 422 response echoes the caller's actual
    plaintext password back to them (and into logs/proxies) whenever it
    fails validation (too short, wrong type, etc). This also happens for
    body-level errors (e.g. a missing required field elsewhere): "loc" is
    something like ("body",) and "input" is the ENTIRE submitted payload
    dict, password and all, not just the one field that failed -- so
    checking only whether the failing field's own name looks sensitive
    isn't enough; the echoed input itself has to be scanned recursively.
    """

    sanitized: List[Dict[str, Any]] = []

    for error in errors:
        entry = dict(error)
        location = entry.get("loc") or ()
        field_name = str(location[-1]) if location else ""
        field_is_sensitive = any(marker in field_name.lower() for marker in SENSITIVE_FIELD_NAME_MARKERS)

        if field_is_sensitive:
            if "input" in entry:
                entry["input"] = "***REDACTED***"
            if "ctx" in entry:
                entry["ctx"] = "***REDACTED***"
        else:
            if "input" in entry:
                entry["input"] = _redact_sensitive_value(entry["input"])
            if "ctx" in entry:
                entry["ctx"] = _redact_sensitive_value(entry["ctx"])

        sanitized.append(entry)

    return sanitized


async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    request_id = getattr(request.state, "request_id", None)

    return response_error(
        message="Request validation failed.",
        code="VALIDATION_ERROR",
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        request_id=request_id,
        details=sanitize_validation_errors(exc.errors()),
    )


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    request_id = getattr(request.state, "request_id", None)
    logger.exception("Unhandled exception | request_id=%s", request_id)

    return response_error(
        message="Unexpected server error.",
        code="UNHANDLED_EXCEPTION",
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        request_id=request_id,
        details=safe_error_detail(exc, SETTINGS.debug),
    )


# =============================================================================
# Main Application Class
# =============================================================================

class Main:
    """
    FastAPI application builder for William/Jarvis.

    Required component name: Main
    """

    def __init__(self, settings: Settings = SETTINGS) -> None:
        self.settings = settings
        self.loaded_optional_routers: List[Dict[str, Any]] = []

    def create_app(self) -> FastAPI:
        docs_url = "/docs" if self.settings.docs_enabled else None
        redoc_url = "/redoc" if self.settings.docs_enabled else None
        openapi_url = "/openapi.json" if self.settings.docs_enabled else None

        app = FastAPI(
            title=self.settings.app_name,
            description=(
                "William/Jarvis Multi-Agent AI SaaS API by Digital Promotix. "
                "Built for user/workspace isolation, secure agent routing, audit logs, "
                "memory compatibility, and verification payloads."
            ),
            version=self.settings.version,
            docs_url=docs_url,
            redoc_url=redoc_url,
            openapi_url=openapi_url,
        )

        app.state.settings = self.settings
        app.state.started_at = utc_now()
        app.state.audit_store = AUDIT_STORE

        self._initialize_database()

        self._add_middleware(app)
        self._add_exception_handlers(app)
        self._add_builtin_routers(app)

        self.loaded_optional_routers = include_optional_routers(app)
        app.state.optional_routers = self.loaded_optional_routers

        logger.info(
            "William/Jarvis API created | env=%s | version=%s | optional_routers=%s",
            self.settings.environment,
            self.settings.version,
            safe_json(self.loaded_optional_routers),
        )

        return app

    def _initialize_database(self) -> None:
        """
        Ensure every model's table exists before the app starts serving
        requests.

        Root cause this fixes: nothing in this app's boot path ever
        imported the model modules or called Base.metadata.create_all() --
        tests/conftest.py and database/migrations/env.py each had their own
        copy of that "import every model, then create_all" pattern, but the
        real app never did. A fresh or deleted-and-recreated SQLite dev
        database therefore had zero tables until something else (a manual
        Alembic run, or the test suite happening to run first and sharing
        no state with the real app anyway) populated it, so a clean
        `DELETE william.db && restart` produced "no such table: users" on
        the very first request.

        Only auto-creates for the SQLite dev fallback -- a real Postgres
        deployment must go through `python -m alembic upgrade head`, which
        stays authoritative there (this never runs a migration, only
        `create_all()`, which is additive/idempotent and a poor substitute
        for real migrations on a shared production database). Safe to call
        on every boot: `create_all()` only creates tables that don't
        already exist, so this is a no-op once Alembic (or a previous boot)
        has already built the schema.
        """
        try:
            from database.db import Base, db_manager
            from database.models import MODEL_MODULES, import_all_models

            import_all_models(MODEL_MODULES)

            if db_manager.engine.dialect.name == "sqlite":
                Base.metadata.create_all(bind=db_manager.engine)
                logger.info(
                    "SQLite dev database ensured at startup | tables=%d | db_path=%s",
                    len(Base.metadata.tables),
                    db_manager.engine.url.render_as_string(hide_password=True),
                )
        except Exception:
            logger.exception(
                "Database auto-initialization failed at startup; routes touching "
                "the database may error until this is resolved."
            )

    def _add_middleware(self, app: FastAPI) -> None:
        # Middleware registration order matters: Starlette wraps each
        # subsequently-added middleware AROUND the previous stack, so the
        # LAST middleware added ends up OUTERMOST (it sees every request
        # first and every response last) -- verified empirically, not just
        # from docs, since this is easy to get backwards. Registering
        # request_id_middleware and audit_middleware first, then
        # CORSMiddleware last via add_middleware(), already puts CORS
        # outermost correctly: it is the first thing every request hits and
        # can short-circuit a disallowed preflight before request_id/audit
        # bookkeeping or routing/auth ever run. (The actual root cause of
        # the reported CORS 400s was never middleware order -- it was
        # Settings.allowed_headers being incomplete, see above -- but CORS
        # being outermost is still the correct, intentional order and is
        # kept that way here.)
        app.middleware("http")(request_id_middleware)
        app.middleware("http")(audit_middleware)

        app.add_middleware(
            CORSMiddleware,
            allow_origins=self.settings.allowed_origins,
            allow_credentials=True,
            allow_methods=self.settings.allowed_methods,
            allow_headers=self.settings.allowed_headers,
            expose_headers=["X-Request-ID", "X-Response-Time-MS"],
        )

    def _add_exception_handlers(self, app: FastAPI) -> None:
        app.add_exception_handler(HTTPException, http_exception_handler)
        app.add_exception_handler(RequestValidationError, validation_exception_handler)
        app.add_exception_handler(Exception, unhandled_exception_handler)

    def _add_builtin_routers(self, app: FastAPI) -> None:
        app.include_router(health_router)
        app.include_router(system_router, prefix=self.settings.api_prefix)
        app.include_router(agents_router, prefix=self.settings.api_prefix)
        app.include_router(dashboard_router, prefix=self.settings.api_prefix)


def create_app(testing: bool = False) -> FastAPI:
    """
    Module-level app factory.

    Used both for the real production app below (`create_app()`) and by
    tests/conftest.py's `app` fixture (`create_app(testing=True)`), which
    previously called a module-level `create_app` that didn't exist here --
    only `Main.create_app(self)`, an instance method with no `testing`
    parameter -- so the import always failed and every test using the
    `app`/`client`/`async_client` fixtures silently ran against a fake stub
    app instead of the real routed one.

    `testing=True` forces the auth flags that gate the spoofable
    X-User-ID/X-Workspace-ID header-trust fallback back to their secure
    defaults (auth required, dev-auth-header-trust disabled) regardless of
    whatever a developer's ambient .env has set -- a stray
    WILLIAM_DEV_AUTH_ENABLED=true must never leak into a test run just
    because pytest imported this module.
    """
    settings = SETTINGS
    if testing:
        settings = replace(SETTINGS, auth_required=True, dev_auth_enabled=False, debug=False)

    application = Main(settings=settings).create_app()
    application.state.testing = testing
    return application


main = Main()
app = create_app()


# =============================================================================
# Local Development Entrypoint
# =============================================================================

def run_dev() -> None:
    import uvicorn

    uvicorn.run(
        "apps.api.main:app",
        host=os.getenv("WILLIAM_API_HOST", "0.0.0.0"),
        port=int(os.getenv("WILLIAM_API_PORT", "8000")),
        reload=parse_bool(os.getenv("WILLIAM_API_RELOAD"), SETTINGS.environment == "development"),
        log_level=os.getenv("WILLIAM_UVICORN_LOG_LEVEL", "info"),
    )


if __name__ == "__main__":
    run_dev()