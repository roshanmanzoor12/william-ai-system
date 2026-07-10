"""
apps/api/routes/auth.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Authentication routes with workspace-aware sessions.

Endpoints:
- POST /register
- POST /login
- POST /refresh
- POST /logout
- GET  /me
- GET  /sessions
- POST /sessions/revoke
- POST /workspaces/switch

Design goals:
- SaaS-ready user/workspace isolation
- Safe import even when future files are missing
- No hardcoded production secrets
- Structured responses and safe errors
- Audit logging hooks
- Future-ready Security Agent, Memory Agent, and Verification Agent hooks
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import importlib
import inspect
import json
import logging
import os
import re
import secrets
import time
import traceback
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Tuple

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator


# =============================================================================
# Logging
# =============================================================================

LOGGER_NAME = "william.api.routes.auth"
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


def unix_now() -> int:
    return int(time.time())


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


def model_to_dict(model: Any) -> Dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump()

    if hasattr(model, "dict"):
        return model.dict()

    if isinstance(model, dict):
        return model

    return {"value": model}


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


def normalize_email(email: str) -> str:
    clean = (email or "").strip().lower()

    if not clean:
        raise ValueError("Email is required.")

    if len(clean) > 254:
        raise ValueError("Email is too long.")

    pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
    if not re.match(pattern, clean):
        raise ValueError("Email format is invalid.")

    return clean


def normalize_identifier(value: Optional[str], field_name: str) -> str:
    clean = (value or "").strip()

    if not clean:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "success": False,
                "message": f"{field_name} is required.",
                "error": {"code": f"{field_name.upper()}_REQUIRED"},
                "metadata": {"timestamp": utc_now()},
            },
        )

    if len(clean) > 128:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "success": False,
                "message": f"{field_name} is too long.",
                "error": {"code": f"{field_name.upper()}_TOO_LONG"},
                "metadata": {"timestamp": utc_now()},
            },
        )

    return clean


def constant_time_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


# =============================================================================
# Settings
# =============================================================================

@dataclass(frozen=True)
class AuthSettings:
    environment: str = field(default_factory=lambda: os.getenv("WILLIAM_ENV", "development"))
    debug: bool = field(default_factory=lambda: parse_bool(os.getenv("WILLIAM_DEBUG"), False))

    issuer: str = field(default_factory=lambda: os.getenv("WILLIAM_AUTH_ISSUER", "william-jarvis-api"))
    audience: str = field(default_factory=lambda: os.getenv("WILLIAM_AUTH_AUDIENCE", "william-jarvis-saas"))

    jwt_secret: str = field(default_factory=lambda: os.getenv("WILLIAM_JWT_SECRET", ""))
    access_token_ttl_seconds: int = field(
        default_factory=lambda: parse_int(os.getenv("WILLIAM_ACCESS_TOKEN_TTL_SECONDS"), 900)
    )
    refresh_token_ttl_seconds: int = field(
        default_factory=lambda: parse_int(os.getenv("WILLIAM_REFRESH_TOKEN_TTL_SECONDS"), 60 * 60 * 24 * 30)
    )

    password_iterations: int = field(
        default_factory=lambda: parse_int(os.getenv("WILLIAM_PASSWORD_HASH_ITERATIONS"), 390000)
    )
    password_min_length: int = field(
        default_factory=lambda: parse_int(os.getenv("WILLIAM_PASSWORD_MIN_LENGTH"), 8)
    )

    allow_dev_secret: bool = field(default_factory=lambda: parse_bool(os.getenv("WILLIAM_ALLOW_DEV_AUTH_SECRET"), True))
    audit_enabled: bool = field(default_factory=lambda: parse_bool(os.getenv("WILLIAM_AUDIT_LOG_ENABLED"), True))

    security_agent_enabled: bool = field(default_factory=lambda: parse_bool(os.getenv("WILLIAM_SECURITY_AGENT_ENABLED"), True))
    memory_agent_enabled: bool = field(default_factory=lambda: parse_bool(os.getenv("WILLIAM_MEMORY_AGENT_ENABLED"), True))
    verification_agent_enabled: bool = field(
        default_factory=lambda: parse_bool(os.getenv("WILLIAM_VERIFICATION_AGENT_ENABLED"), True)
    )

    default_plan: str = field(default_factory=lambda: os.getenv("WILLIAM_DEFAULT_PLAN", "free"))

    def effective_secret(self) -> str:
        if self.jwt_secret:
            return self.jwt_secret

        if self.environment.lower() in {"production", "prod"}:
            raise RuntimeError("WILLIAM_JWT_SECRET is required in production.")

        if not self.allow_dev_secret:
            raise RuntimeError("WILLIAM_JWT_SECRET is required when dev secret fallback is disabled.")

        return "dev-only-change-me-william-jarvis-auth-secret"

    def public_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["jwt_secret"] = "***"
        return data


AUTH_SETTINGS = AuthSettings()


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
        return Role.USER.value

    return clean


def normalize_plan(plan: Optional[str]) -> str:
    clean = (plan or AUTH_SETTINGS.default_plan).strip().lower()

    if clean not in PLAN_RANK:
        return Plan.FREE.value

    return clean


def has_min_role(current_role: str, required_role: str) -> bool:
    return ROLE_RANK.get(current_role, 0) >= ROLE_RANK.get(required_role, 0)


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
            "module": "auth",
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
                "module": "auth",
            },
        },
    )


# =============================================================================
# Models
# =============================================================================

class RegisterRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=254)
    password: str = Field(..., min_length=8, max_length=256)
    full_name: str = Field(..., min_length=1, max_length=120)
    workspace_name: str = Field(default="My Workspace", min_length=1, max_length=120)
    invite_code: Optional[str] = Field(default=None, max_length=128)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @validator("email")
    def validate_email(cls, value: str) -> str:
        return normalize_email(value)

    @validator("password")
    def validate_password(cls, value: str) -> str:
        validate_password_strength(value)
        return value


class LoginRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=254)
    password: str = Field(..., min_length=1, max_length=256)
    workspace_id: Optional[str] = Field(default=None, max_length=128)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @validator("email")
    def validate_email(cls, value: str) -> str:
        return normalize_email(value)


class RefreshRequest(BaseModel):
    refresh_token: str = Field(..., min_length=20)
    workspace_id: Optional[str] = Field(default=None, max_length=128)


class LogoutRequest(BaseModel):
    refresh_token: Optional[str] = Field(default=None)
    logout_all_sessions: bool = False


class RevokeSessionRequest(BaseModel):
    session_id: str = Field(..., min_length=1, max_length=128)


class SwitchWorkspaceRequest(BaseModel):
    refresh_token: str = Field(..., min_length=20)
    workspace_id: str = Field(..., min_length=1, max_length=128)


class UserRecord(BaseModel):
    user_id: str
    email: str
    full_name: str
    password_hash: str
    created_at: str
    updated_at: str
    is_active: bool = True
    metadata: Dict[str, Any] = Field(default_factory=dict)


class WorkspaceRecord(BaseModel):
    workspace_id: str
    name: str
    owner_user_id: str
    plan: str = Plan.FREE.value
    subscription_status: str = "active"
    created_at: str
    updated_at: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class MembershipRecord(BaseModel):
    membership_id: str
    user_id: str
    workspace_id: str
    role: str
    plan: str
    permissions: List[str] = Field(default_factory=list)
    created_at: str
    updated_at: str
    is_active: bool = True


class SessionRecord(BaseModel):
    session_id: str
    user_id: str
    workspace_id: str
    role: str
    plan: str
    refresh_jti: str
    created_at: str
    expires_at: int
    last_seen_at: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    is_active: bool = True
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AuthContext(BaseModel):
    request_id: str
    user_id: str
    workspace_id: str
    session_id: str
    role: str
    plan: str
    email: str
    permissions: List[str] = Field(default_factory=list)
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None


# =============================================================================
# Password Hashing
# =============================================================================

def validate_password_strength(password: str) -> None:
    if len(password) < AUTH_SETTINGS.password_min_length:
        raise ValueError(f"Password must be at least {AUTH_SETTINGS.password_min_length} characters.")

    if len(password) > 256:
        raise ValueError("Password is too long.")

    has_letter = bool(re.search(r"[A-Za-z]", password))
    has_number = bool(re.search(r"\d", password))

    if not has_letter or not has_number:
        raise ValueError("Password must include at least one letter and one number.")


def hash_password(password: str) -> str:
    validate_password_strength(password)

    salt = secrets.token_bytes(32)
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        AUTH_SETTINGS.password_iterations,
    )

    return (
        f"pbkdf2_sha256"
        f"${AUTH_SETTINGS.password_iterations}"
        f"${base64.urlsafe_b64encode(salt).decode('utf-8')}"
        f"${base64.urlsafe_b64encode(derived).decode('utf-8')}"
    )


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, iterations_raw, salt_raw, hash_raw = stored_hash.split("$", 3)

        if algorithm != "pbkdf2_sha256":
            return False

        iterations = int(iterations_raw)
        salt = base64.urlsafe_b64decode(salt_raw.encode("utf-8"))
        expected_hash = base64.urlsafe_b64decode(hash_raw.encode("utf-8"))

        actual_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
        )

        return hmac.compare_digest(actual_hash, expected_hash)

    except Exception:
        return False


# =============================================================================
# Token Service
# =============================================================================

class TokenService:
    def __init__(self, settings: AuthSettings) -> None:
        self.settings = settings

    @staticmethod
    def _b64encode_json(payload: Dict[str, Any]) -> str:
        raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")

    @staticmethod
    def _b64decode_json(payload: str) -> Dict[str, Any]:
        padded = payload + "=" * (-len(payload) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("utf-8"))
        data = json.loads(raw.decode("utf-8"))

        if not isinstance(data, dict):
            raise ValueError("Token payload must be an object.")

        return data

    @staticmethod
    def _b64encode_bytes(payload: bytes) -> str:
        return base64.urlsafe_b64encode(payload).decode("utf-8").rstrip("=")

    def _sign(self, signing_input: str) -> str:
        secret = self.settings.effective_secret().encode("utf-8")
        signature = hmac.new(secret, signing_input.encode("utf-8"), hashlib.sha256).digest()
        return self._b64encode_bytes(signature)

    def create_token(
        self,
        token_type: str,
        user_id: str,
        workspace_id: str,
        session_id: str,
        role: str,
        plan: str,
        email: str,
        ttl_seconds: int,
        refresh_jti: Optional[str] = None,
    ) -> Tuple[str, str, int]:
        now = unix_now()
        expires_at = now + ttl_seconds
        jti = new_id("jti")

        payload = {
            "iss": self.settings.issuer,
            "aud": self.settings.audience,
            "sub": user_id,
            "email": email,
            "workspace_id": workspace_id,
            "session_id": session_id,
            "role": role,
            "plan": plan,
            "type": token_type,
            "iat": now,
            "exp": expires_at,
            "jti": refresh_jti or jti,
        }

        header = {"alg": "HS256", "typ": "JWT"}
        signing_input = f"{self._b64encode_json(header)}.{self._b64encode_json(payload)}"
        signature = self._sign(signing_input)
        token = f"{signing_input}.{signature}"

        return token, payload["jti"], expires_at

    def verify_token(self, token: str, expected_type: Optional[str] = None) -> Dict[str, Any]:
        try:
            parts = token.split(".")

            if len(parts) != 3:
                raise ValueError("Token must have 3 parts.")

            header_raw, payload_raw, signature = parts
            signing_input = f"{header_raw}.{payload_raw}"
            expected_signature = self._sign(signing_input)

            if not constant_time_equal(signature, expected_signature):
                raise ValueError("Token signature is invalid.")

            header = self._b64decode_json(header_raw)
            payload = self._b64decode_json(payload_raw)

            if header.get("alg") != "HS256":
                raise ValueError("Token algorithm is not supported.")

            if payload.get("iss") != self.settings.issuer:
                raise ValueError("Token issuer is invalid.")

            if payload.get("aud") != self.settings.audience:
                raise ValueError("Token audience is invalid.")

            if expected_type and payload.get("type") != expected_type:
                raise ValueError("Token type is invalid.")

            if int(payload.get("exp", 0)) < unix_now():
                raise ValueError("Token expired.")

            required_fields = ["sub", "workspace_id", "session_id", "role", "plan", "jti"]
            missing = [field_name for field_name in required_fields if not payload.get(field_name)]

            if missing:
                raise ValueError(f"Token is missing required fields: {', '.join(missing)}")

            return payload

        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "success": False,
                    "message": "Invalid or expired token.",
                    "data": {},
                    "error": {
                        "code": "INVALID_TOKEN",
                        "details": str(exc),
                    },
                    "metadata": {"timestamp": utc_now(), "module": "auth"},
                },
            ) from exc


TOKEN_SERVICE = TokenService(AUTH_SETTINGS)


# =============================================================================
# In-Memory Auth Store
# Replace later with database-backed users/workspaces/sessions repositories.
# =============================================================================

class InMemoryAuthStore:
    def __init__(self) -> None:
        self.users_by_id: Dict[str, UserRecord] = {}
        self.user_id_by_email: Dict[str, str] = {}
        self.workspaces_by_id: Dict[str, WorkspaceRecord] = {}
        self.memberships_by_id: Dict[str, MembershipRecord] = {}
        self.membership_ids_by_user: Dict[str, List[str]] = {}
        self.session_by_id: Dict[str, SessionRecord] = {}
        self.session_ids_by_user: Dict[str, List[str]] = {}
        self.revoked_jti: Dict[str, int] = {}

    def create_user_with_workspace(
        self,
        email: str,
        password: str,
        full_name: str,
        workspace_name: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[UserRecord, WorkspaceRecord, MembershipRecord]:
        normalized_email = normalize_email(email)

        if normalized_email in self.user_id_by_email:
            raise ValueError("Email is already registered.")

        now = utc_now()
        user = UserRecord(
            user_id=new_id("user"),
            email=normalized_email,
            full_name=full_name.strip(),
            password_hash=hash_password(password),
            created_at=now,
            updated_at=now,
            is_active=True,
            metadata=metadata or {},
        )

        workspace = WorkspaceRecord(
            workspace_id=new_id("workspace"),
            name=workspace_name.strip(),
            owner_user_id=user.user_id,
            plan=normalize_plan(AUTH_SETTINGS.default_plan),
            subscription_status="active",
            created_at=now,
            updated_at=now,
            metadata={},
        )

        membership = MembershipRecord(
            membership_id=new_id("membership"),
            user_id=user.user_id,
            workspace_id=workspace.workspace_id,
            role=Role.OWNER.value,
            plan=workspace.plan,
            permissions=[
                "workspace:read",
                "workspace:update",
                "agent:execute",
                "session:manage",
                "billing:read",
            ],
            created_at=now,
            updated_at=now,
            is_active=True,
        )

        self.users_by_id[user.user_id] = user
        self.user_id_by_email[user.email] = user.user_id
        self.workspaces_by_id[workspace.workspace_id] = workspace
        self.memberships_by_id[membership.membership_id] = membership
        self.membership_ids_by_user.setdefault(user.user_id, []).append(membership.membership_id)

        return user, workspace, membership

    def get_user_by_email(self, email: str) -> Optional[UserRecord]:
        user_id = self.user_id_by_email.get(normalize_email(email))

        if not user_id:
            return None

        return self.users_by_id.get(user_id)

    def get_user_by_id(self, user_id: str) -> Optional[UserRecord]:
        return self.users_by_id.get(user_id)

    def get_workspace(self, workspace_id: str) -> Optional[WorkspaceRecord]:
        return self.workspaces_by_id.get(workspace_id)

    def list_memberships_for_user(self, user_id: str) -> List[MembershipRecord]:
        membership_ids = self.membership_ids_by_user.get(user_id, [])
        return [
            self.memberships_by_id[membership_id]
            for membership_id in membership_ids
            if membership_id in self.memberships_by_id and self.memberships_by_id[membership_id].is_active
        ]

    def get_membership(self, user_id: str, workspace_id: str) -> Optional[MembershipRecord]:
        for membership in self.list_memberships_for_user(user_id):
            if membership.workspace_id == workspace_id:
                return membership

        return None

    def choose_membership(self, user_id: str, workspace_id: Optional[str] = None) -> MembershipRecord:
        memberships = self.list_memberships_for_user(user_id)

        if not memberships:
            raise ValueError("User has no active workspace membership.")

        if workspace_id:
            selected = self.get_membership(user_id, workspace_id)

            if not selected:
                raise ValueError("User does not have access to this workspace.")

            return selected

        return memberships[0]

    def create_session(
        self,
        user: UserRecord,
        membership: MembershipRecord,
        refresh_jti: str,
        refresh_expires_at: int,
        ip_address: Optional[str],
        user_agent: Optional[str],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SessionRecord:
        now = utc_now()
        session = SessionRecord(
            session_id=new_id("session"),
            user_id=user.user_id,
            workspace_id=membership.workspace_id,
            role=membership.role,
            plan=membership.plan,
            refresh_jti=refresh_jti,
            created_at=now,
            expires_at=refresh_expires_at,
            last_seen_at=now,
            ip_address=ip_address,
            user_agent=user_agent,
            is_active=True,
            metadata=metadata or {},
        )

        self.session_by_id[session.session_id] = session
        self.session_ids_by_user.setdefault(user.user_id, []).append(session.session_id)

        return session

    def update_session_refresh(
        self,
        session_id: str,
        refresh_jti: str,
        expires_at: int,
    ) -> SessionRecord:
        session = self.require_session(session_id)
        updated = session.copy(update={
            "refresh_jti": refresh_jti,
            "expires_at": expires_at,
            "last_seen_at": utc_now(),
        })
        self.session_by_id[session_id] = updated
        return updated

    def require_session(self, session_id: str) -> SessionRecord:
        session = self.session_by_id.get(session_id)

        if not session:
            raise ValueError("Session not found.")

        if not session.is_active:
            raise ValueError("Session is inactive.")

        if session.expires_at < unix_now():
            raise ValueError("Session expired.")

        return session

    def touch_session(self, session_id: str) -> SessionRecord:
        session = self.require_session(session_id)
        updated = session.copy(update={"last_seen_at": utc_now()})
        self.session_by_id[session_id] = updated
        return updated

    def revoke_session(self, session_id: str) -> SessionRecord:
        session = self.session_by_id.get(session_id)

        if not session:
            raise ValueError("Session not found.")

        self.revoked_jti[session.refresh_jti] = unix_now()
        updated = session.copy(update={"is_active": False, "last_seen_at": utc_now()})
        self.session_by_id[session_id] = updated
        return updated

    def revoke_all_user_sessions(self, user_id: str) -> int:
        count = 0

        for session_id in self.session_ids_by_user.get(user_id, []):
            session = self.session_by_id.get(session_id)

            if session and session.is_active:
                self.revoke_session(session_id)
                count += 1

        return count

    def revoke_jti(self, jti: str) -> None:
        self.revoked_jti[jti] = unix_now()

    def is_jti_revoked(self, jti: str) -> bool:
        return jti in self.revoked_jti

    def list_sessions_for_user_workspace(self, user_id: str, workspace_id: str) -> List[SessionRecord]:
        sessions: List[SessionRecord] = []

        for session_id in self.session_ids_by_user.get(user_id, []):
            session = self.session_by_id.get(session_id)

            if session and session.workspace_id == workspace_id:
                sessions.append(session)

        return sessions


AUTH_STORE = InMemoryAuthStore()


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
                logger.info("Loaded optional auth hook: %s from %s", self.component_name, self.loaded_from)
                return True

            except Exception as exc:
                self.import_error = f"{module_path}.{attr_name}: {exc}"

        return False

    @staticmethod
    def _instantiate(cls: Any) -> Any:
        attempts = [
            {"settings": AUTH_SETTINGS},
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
                "error": safe_error_detail(exc, AUTH_SETTINGS.debug),
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
    method_candidates=["approve_auth_action", "approve_api_action", "approve_action", "check_permission", "execute", "run"],
)

MEMORY_AGENT = OptionalAgentHook(
    component_name="Memory Agent",
    import_candidates=[
        ("apps.api.services.memory_agent_bridge", "MemoryAgentBridge"),
        ("agents.memory_agent.memory_agent", "MemoryAgent"),
        ("agents.memory.memory_agent", "MemoryAgent"),
    ],
    method_candidates=["record_auth_context", "record_api_context", "save_context", "remember", "execute", "run"],
)

VERIFICATION_AGENT = OptionalAgentHook(
    component_name="Verification Agent",
    import_candidates=[
        ("apps.api.services.verification_agent_bridge", "VerificationAgentBridge"),
        ("agents.verification_agent.verification_agent", "VerificationAgent"),
        ("agents.verification.verification_agent", "VerificationAgent"),
    ],
    method_candidates=["prepare_auth_confirmation", "prepare_confirmation", "verify_result", "confirm", "execute", "run"],
)


# =============================================================================
# Audit
# =============================================================================

AUTH_AUDIT_EVENTS: List[Dict[str, Any]] = []


def write_auth_audit(
    request: Request,
    event_type: str,
    action: str,
    result: str,
    user_id: Optional[str] = None,
    workspace_id: Optional[str] = None,
    request_id: Optional[str] = None,
    status_code: Optional[int] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    event = {
        "audit_id": new_id("audit"),
        "event_type": event_type,
        "action": action,
        "result": result,
        "user_id": user_id,
        "workspace_id": workspace_id,
        "request_id": request_id or getattr(request.state, "request_id", None) or request.headers.get("X-Request-ID") or new_id("req"),
        "route": str(request.url.path),
        "method": request.method,
        "status_code": status_code,
        "ip_address": request.client.host if request.client else None,
        "user_agent": request.headers.get("user-agent"),
        "created_at": utc_now(),
        "metadata": metadata or {},
    }

    if AUTH_SETTINGS.audit_enabled:
        AUTH_AUDIT_EVENTS.append(event)

        if len(AUTH_AUDIT_EVENTS) > 1000:
            del AUTH_AUDIT_EVENTS[: len(AUTH_AUDIT_EVENTS) - 1000]

        logger.info(
            "Auth audit | type=%s | action=%s | user=%s | workspace=%s | result=%s",
            event_type,
            action,
            user_id,
            workspace_id,
            result,
        )

    return event


async def emit_memory_context(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not AUTH_SETTINGS.memory_agent_enabled:
        return {
            "success": False,
            "message": "Memory Agent hook disabled.",
            "data": {},
            "error": {"code": "MEMORY_HOOK_DISABLED"},
            "metadata": {"timestamp": utc_now()},
        }

    return await MEMORY_AGENT.call(payload)


async def prepare_verification(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not AUTH_SETTINGS.verification_agent_enabled:
        return {
            "success": False,
            "message": "Verification Agent hook disabled.",
            "data": {},
            "error": {"code": "VERIFICATION_HOOK_DISABLED"},
            "metadata": {"timestamp": utc_now()},
        }

    return await VERIFICATION_AGENT.call(payload)


async def security_review(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not AUTH_SETTINGS.security_agent_enabled:
        return {
            "success": True,
            "message": "Security Agent hook disabled; action allowed by local policy.",
            "data": {"approved": True, "local_policy": True},
            "error": None,
            "metadata": {"timestamp": utc_now()},
        }

    return await SECURITY_AGENT.call(payload)


# =============================================================================
# Auth Dependency
# =============================================================================

async def get_current_auth_context(
    request: Request,
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
    x_request_id: Optional[str] = Header(default=None, alias="X-Request-ID"),
) -> AuthContext:
    request_id = x_request_id or getattr(request.state, "request_id", None) or new_id("req")

    if not authorization or not authorization.lower().startswith("bearer "):
        raise_api_error(
            status_code=status.HTTP_401_UNAUTHORIZED,
            message="Bearer access token is required.",
            code="ACCESS_TOKEN_REQUIRED",
            request_id=request_id,
        )

    token = authorization.split(" ", 1)[1].strip()
    payload = TOKEN_SERVICE.verify_token(token, expected_type="access")

    if AUTH_STORE.is_jti_revoked(payload["jti"]):
        raise_api_error(
            status_code=status.HTTP_401_UNAUTHORIZED,
            message="Token has been revoked.",
            code="TOKEN_REVOKED",
            request_id=request_id,
        )

    user = AUTH_STORE.get_user_by_id(payload["sub"])

    if not user or not user.is_active:
        raise_api_error(
            status_code=status.HTTP_401_UNAUTHORIZED,
            message="User account is not active.",
            code="USER_INACTIVE",
            request_id=request_id,
        )

    try:
        session = AUTH_STORE.touch_session(payload["session_id"])
    except Exception as exc:
        raise_api_error(
            status_code=status.HTTP_401_UNAUTHORIZED,
            message="Session is invalid or expired.",
            code="SESSION_INVALID",
            request_id=request_id,
            details=str(exc),
        )

    if session.user_id != user.user_id or session.workspace_id != payload["workspace_id"]:
        raise_api_error(
            status_code=status.HTTP_403_FORBIDDEN,
            message="Session scope mismatch.",
            code="SESSION_SCOPE_MISMATCH",
            request_id=request_id,
        )

    membership = AUTH_STORE.get_membership(user.user_id, session.workspace_id)

    if not membership:
        raise_api_error(
            status_code=status.HTTP_403_FORBIDDEN,
            message="Workspace access is no longer available.",
            code="WORKSPACE_ACCESS_REVOKED",
            request_id=request_id,
        )

    context = AuthContext(
        request_id=request_id,
        user_id=user.user_id,
        workspace_id=session.workspace_id,
        session_id=session.session_id,
        role=membership.role,
        plan=membership.plan,
        email=user.email,
        permissions=membership.permissions,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    request.state.auth_context = context
    return context


def require_auth_role(required_role: str) -> Callable[[AuthContext], Awaitable[AuthContext]]:
    async def dependency(context: AuthContext = Depends(get_current_auth_context)) -> AuthContext:
        if not has_min_role(context.role, required_role):
            raise_api_error(
                status_code=status.HTTP_403_FORBIDDEN,
                message=f"Role '{required_role}' or higher is required.",
                code="INSUFFICIENT_ROLE",
                request_id=context.request_id,
                details={
                    "required_role": required_role,
                    "current_role": context.role,
                },
            )

        return context

    return dependency


# =============================================================================
# Auth Class / Router
# =============================================================================

class Auth:
    """
    Required component name: Auth

    Provides workspace-aware authentication and session endpoints.
    """

    def __init__(self) -> None:
        self.router = APIRouter(tags=["Auth"])
        self._register_routes()

    def _register_routes(self) -> None:
        self.router.post("/register")(self.register)
        self.router.post("/login")(self.login)
        self.router.post("/refresh")(self.refresh)
        self.router.post("/logout")(self.logout)
        self.router.get("/me")(self.me)
        self.router.get("/sessions")(self.sessions)
        self.router.post("/sessions/revoke")(self.revoke_session)
        self.router.post("/workspaces/switch")(self.switch_workspace)
        self.router.get("/audit")(self.audit)

    async def register(self, payload: RegisterRequest, request: Request) -> Dict[str, Any]:
        request_id = request.headers.get("X-Request-ID") or getattr(request.state, "request_id", None) or new_id("req")

        try:
            user, workspace, membership = AUTH_STORE.create_user_with_workspace(
                email=payload.email,
                password=payload.password,
                full_name=payload.full_name,
                workspace_name=payload.workspace_name,
                metadata={
                    **payload.metadata,
                    "registered_from": "api",
                    "invite_code_used": bool(payload.invite_code),
                },
            )

            pre_refresh_token, refresh_jti, refresh_expires_at = TOKEN_SERVICE.create_token(
                token_type="refresh",
                user_id=user.user_id,
                workspace_id=workspace.workspace_id,
                session_id="pending",
                role=membership.role,
                plan=membership.plan,
                email=user.email,
                ttl_seconds=AUTH_SETTINGS.refresh_token_ttl_seconds,
            )

            session = AUTH_STORE.create_session(
                user=user,
                membership=membership,
                refresh_jti=refresh_jti,
                refresh_expires_at=refresh_expires_at,
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent"),
                metadata={"auth_flow": "register"},
            )

            access_token, access_jti, access_expires_at = TOKEN_SERVICE.create_token(
                token_type="access",
                user_id=user.user_id,
                workspace_id=workspace.workspace_id,
                session_id=session.session_id,
                role=membership.role,
                plan=membership.plan,
                email=user.email,
                ttl_seconds=AUTH_SETTINGS.access_token_ttl_seconds,
            )

            refresh_token, refresh_jti, refresh_expires_at = TOKEN_SERVICE.create_token(
                token_type="refresh",
                user_id=user.user_id,
                workspace_id=workspace.workspace_id,
                session_id=session.session_id,
                role=membership.role,
                plan=membership.plan,
                email=user.email,
                ttl_seconds=AUTH_SETTINGS.refresh_token_ttl_seconds,
            )

            AUTH_STORE.revoke_jti(access_jti) if False else None
            AUTH_STORE.revoke_jti(pre_refresh_token) if False else None
            AUTH_STORE.update_session_refresh(session.session_id, refresh_jti, refresh_expires_at)

            audit = write_auth_audit(
                request=request,
                event_type="auth_register",
                action="register",
                result="success",
                user_id=user.user_id,
                workspace_id=workspace.workspace_id,
                request_id=request_id,
                status_code=status.HTTP_201_CREATED,
                metadata={"session_id": session.session_id},
            )

            memory_result = await emit_memory_context(
                {
                    "type": "auth_register",
                    "user_id": user.user_id,
                    "workspace_id": workspace.workspace_id,
                    "request_id": request_id,
                    "content": {
                        "event": "user_registered",
                        "email": user.email,
                        "workspace_name": workspace.name,
                        "role": membership.role,
                        "plan": membership.plan,
                    },
                    "created_at": utc_now(),
                }
            )

            verification_result = await prepare_verification(
                {
                    "type": "auth_register_confirmation",
                    "user_id": user.user_id,
                    "workspace_id": workspace.workspace_id,
                    "request_id": request_id,
                    "result": "success",
                    "created_at": utc_now(),
                }
            )

            return api_success(
                message="User registered and workspace session created.",
                data={
                    "user": self._safe_user(user),
                    "workspace": self._safe_workspace(workspace),
                    "membership": self._safe_membership(membership),
                    "session": self._safe_session(session),
                    "tokens": {
                        "access_token": access_token,
                        "refresh_token": refresh_token,
                        "token_type": "bearer",
                        "access_expires_at": access_expires_at,
                        "refresh_expires_at": refresh_expires_at,
                    },
                    "audit": audit,
                    "memory_result": memory_result,
                    "verification_result": verification_result,
                },
                request_id=request_id,
            )

        except ValueError as exc:
            write_auth_audit(
                request=request,
                event_type="auth_register",
                action="register",
                result="failed",
                request_id=request_id,
                status_code=status.HTTP_400_BAD_REQUEST,
                metadata={"error": str(exc)},
            )
            raise_api_error(
                status_code=status.HTTP_400_BAD_REQUEST,
                message=str(exc),
                code="REGISTER_FAILED",
                request_id=request_id,
            )

        except Exception as exc:
            logger.exception("Registration failed.")
            write_auth_audit(
                request=request,
                event_type="auth_register",
                action="register",
                result="error",
                request_id=request_id,
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                metadata={"error": safe_error_detail(exc, AUTH_SETTINGS.debug)},
            )
            raise_api_error(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                message="Registration failed.",
                code="REGISTER_ERROR",
                request_id=request_id,
                details=safe_error_detail(exc, AUTH_SETTINGS.debug),
            )

    async def login(self, payload: LoginRequest, request: Request) -> Dict[str, Any]:
        request_id = request.headers.get("X-Request-ID") or getattr(request.state, "request_id", None) or new_id("req")

        user = AUTH_STORE.get_user_by_email(payload.email)

        if not user or not verify_password(payload.password, user.password_hash):
            write_auth_audit(
                request=request,
                event_type="auth_login",
                action="login",
                result="failed",
                request_id=request_id,
                status_code=status.HTTP_401_UNAUTHORIZED,
                metadata={"email": payload.email},
            )
            raise_api_error(
                status_code=status.HTTP_401_UNAUTHORIZED,
                message="Invalid email or password.",
                code="INVALID_CREDENTIALS",
                request_id=request_id,
            )

        if not user.is_active:
            write_auth_audit(
                request=request,
                event_type="auth_login",
                action="login",
                result="blocked",
                user_id=user.user_id,
                request_id=request_id,
                status_code=status.HTTP_403_FORBIDDEN,
            )
            raise_api_error(
                status_code=status.HTTP_403_FORBIDDEN,
                message="User account is inactive.",
                code="USER_INACTIVE",
                request_id=request_id,
            )

        try:
            membership = AUTH_STORE.choose_membership(user.user_id, payload.workspace_id)
            workspace = AUTH_STORE.get_workspace(membership.workspace_id)

            if not workspace:
                raise ValueError("Workspace not found.")

            if workspace.subscription_status not in {"active", "trialing"}:
                raise ValueError("Workspace subscription is not active.")

            refresh_preview_token, refresh_jti, refresh_expires_at = TOKEN_SERVICE.create_token(
                token_type="refresh",
                user_id=user.user_id,
                workspace_id=membership.workspace_id,
                session_id="pending",
                role=membership.role,
                plan=membership.plan,
                email=user.email,
                ttl_seconds=AUTH_SETTINGS.refresh_token_ttl_seconds,
            )

            session = AUTH_STORE.create_session(
                user=user,
                membership=membership,
                refresh_jti=refresh_jti,
                refresh_expires_at=refresh_expires_at,
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent"),
                metadata={
                    "auth_flow": "login",
                    "login_metadata": payload.metadata,
                    "refresh_preview_created": bool(refresh_preview_token),
                },
            )

            access_token, access_jti, access_expires_at = TOKEN_SERVICE.create_token(
                token_type="access",
                user_id=user.user_id,
                workspace_id=membership.workspace_id,
                session_id=session.session_id,
                role=membership.role,
                plan=membership.plan,
                email=user.email,
                ttl_seconds=AUTH_SETTINGS.access_token_ttl_seconds,
            )

            refresh_token, refresh_jti, refresh_expires_at = TOKEN_SERVICE.create_token(
                token_type="refresh",
                user_id=user.user_id,
                workspace_id=membership.workspace_id,
                session_id=session.session_id,
                role=membership.role,
                plan=membership.plan,
                email=user.email,
                ttl_seconds=AUTH_SETTINGS.refresh_token_ttl_seconds,
            )

            AUTH_STORE.update_session_refresh(session.session_id, refresh_jti, refresh_expires_at)

            audit = write_auth_audit(
                request=request,
                event_type="auth_login",
                action="login",
                result="success",
                user_id=user.user_id,
                workspace_id=membership.workspace_id,
                request_id=request_id,
                status_code=status.HTTP_200_OK,
                metadata={
                    "session_id": session.session_id,
                    "access_jti": access_jti,
                },
            )

            memory_result = await emit_memory_context(
                {
                    "type": "auth_login",
                    "user_id": user.user_id,
                    "workspace_id": membership.workspace_id,
                    "request_id": request_id,
                    "content": {
                        "event": "user_logged_in",
                        "session_id": session.session_id,
                        "role": membership.role,
                        "plan": membership.plan,
                    },
                    "created_at": utc_now(),
                }
            )

            verification_result = await prepare_verification(
                {
                    "type": "auth_login_confirmation",
                    "user_id": user.user_id,
                    "workspace_id": membership.workspace_id,
                    "request_id": request_id,
                    "result": "success",
                    "created_at": utc_now(),
                }
            )

            return api_success(
                message="Login successful.",
                data={
                    "user": self._safe_user(user),
                    "workspace": self._safe_workspace(workspace),
                    "membership": self._safe_membership(membership),
                    "session": self._safe_session(session),
                    "tokens": {
                        "access_token": access_token,
                        "refresh_token": refresh_token,
                        "token_type": "bearer",
                        "access_expires_at": access_expires_at,
                        "refresh_expires_at": refresh_expires_at,
                    },
                    "audit": audit,
                    "memory_result": memory_result,
                    "verification_result": verification_result,
                },
                request_id=request_id,
            )

        except ValueError as exc:
            write_auth_audit(
                request=request,
                event_type="auth_login",
                action="login",
                result="failed",
                user_id=user.user_id,
                request_id=request_id,
                status_code=status.HTTP_403_FORBIDDEN,
                metadata={"error": str(exc)},
            )
            raise_api_error(
                status_code=status.HTTP_403_FORBIDDEN,
                message=str(exc),
                code="WORKSPACE_LOGIN_FAILED",
                request_id=request_id,
            )

    async def refresh(self, payload: RefreshRequest, request: Request) -> Dict[str, Any]:
        request_id = request.headers.get("X-Request-ID") or getattr(request.state, "request_id", None) or new_id("req")
        token_payload = TOKEN_SERVICE.verify_token(payload.refresh_token, expected_type="refresh")

        if AUTH_STORE.is_jti_revoked(token_payload["jti"]):
            raise_api_error(
                status_code=status.HTTP_401_UNAUTHORIZED,
                message="Refresh token has been revoked.",
                code="REFRESH_TOKEN_REVOKED",
                request_id=request_id,
            )

        try:
            session = AUTH_STORE.require_session(token_payload["session_id"])

            if session.refresh_jti != token_payload["jti"]:
                raise ValueError("Refresh token does not match active session.")

            if payload.workspace_id and payload.workspace_id != session.workspace_id:
                raise ValueError("Use /workspaces/switch to change workspace scope.")

            user = AUTH_STORE.get_user_by_id(session.user_id)

            if not user or not user.is_active:
                raise ValueError("User is inactive.")

            membership = AUTH_STORE.get_membership(user.user_id, session.workspace_id)

            if not membership:
                raise ValueError("Workspace membership no longer exists.")

            AUTH_STORE.revoke_jti(token_payload["jti"])

            new_refresh_token, new_refresh_jti, refresh_expires_at = TOKEN_SERVICE.create_token(
                token_type="refresh",
                user_id=user.user_id,
                workspace_id=session.workspace_id,
                session_id=session.session_id,
                role=membership.role,
                plan=membership.plan,
                email=user.email,
                ttl_seconds=AUTH_SETTINGS.refresh_token_ttl_seconds,
            )

            AUTH_STORE.update_session_refresh(session.session_id, new_refresh_jti, refresh_expires_at)

            access_token, access_jti, access_expires_at = TOKEN_SERVICE.create_token(
                token_type="access",
                user_id=user.user_id,
                workspace_id=session.workspace_id,
                session_id=session.session_id,
                role=membership.role,
                plan=membership.plan,
                email=user.email,
                ttl_seconds=AUTH_SETTINGS.access_token_ttl_seconds,
            )

            audit = write_auth_audit(
                request=request,
                event_type="auth_refresh",
                action="refresh",
                result="success",
                user_id=user.user_id,
                workspace_id=session.workspace_id,
                request_id=request_id,
                status_code=status.HTTP_200_OK,
                metadata={
                    "session_id": session.session_id,
                    "access_jti": access_jti,
                },
            )

            verification_result = await prepare_verification(
                {
                    "type": "auth_refresh_confirmation",
                    "user_id": user.user_id,
                    "workspace_id": session.workspace_id,
                    "request_id": request_id,
                    "result": "success",
                    "created_at": utc_now(),
                }
            )

            return api_success(
                message="Token refreshed successfully.",
                data={
                    "tokens": {
                        "access_token": access_token,
                        "refresh_token": new_refresh_token,
                        "token_type": "bearer",
                        "access_expires_at": access_expires_at,
                        "refresh_expires_at": refresh_expires_at,
                    },
                    "session": self._safe_session(AUTH_STORE.require_session(session.session_id)),
                    "audit": audit,
                    "verification_result": verification_result,
                },
                request_id=request_id,
            )

        except ValueError as exc:
            write_auth_audit(
                request=request,
                event_type="auth_refresh",
                action="refresh",
                result="failed",
                user_id=token_payload.get("sub"),
                workspace_id=token_payload.get("workspace_id"),
                request_id=request_id,
                status_code=status.HTTP_401_UNAUTHORIZED,
                metadata={"error": str(exc)},
            )
            raise_api_error(
                status_code=status.HTTP_401_UNAUTHORIZED,
                message=str(exc),
                code="REFRESH_FAILED",
                request_id=request_id,
            )

    async def logout(
        self,
        payload: LogoutRequest,
        request: Request,
        context: AuthContext = Depends(get_current_auth_context),
    ) -> Dict[str, Any]:
        security_result = await security_review(
            {
                "type": "auth_logout",
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
                "session_id": context.session_id,
                "logout_all_sessions": payload.logout_all_sessions,
                "created_at": utc_now(),
            }
        )

        approved = bool(
            security_result.get("success")
            and (
                security_result.get("data", {}).get("approved") is True
                or security_result.get("data", {}).get("allowed") is True
                or security_result.get("data", {}).get("local_policy") is True
            )
        )

        if not approved:
            raise_api_error(
                status_code=status.HTTP_403_FORBIDDEN,
                message="Logout was blocked by Security Agent.",
                code="SECURITY_AGENT_DENIED",
                request_id=context.request_id,
                details=security_result,
            )

        revoked_count = AUTH_STORE.revoke_all_user_sessions(context.user_id) if payload.logout_all_sessions else 0

        if not payload.logout_all_sessions:
            AUTH_STORE.revoke_session(context.session_id)
            revoked_count = 1

        if payload.refresh_token:
            try:
                refresh_payload = TOKEN_SERVICE.verify_token(payload.refresh_token, expected_type="refresh")
                AUTH_STORE.revoke_jti(refresh_payload["jti"])
            except HTTPException:
                logger.info("Logout received invalid refresh token; active session already revoked.")

        audit = write_auth_audit(
            request=request,
            event_type="auth_logout",
            action="logout_all" if payload.logout_all_sessions else "logout",
            result="success",
            user_id=context.user_id,
            workspace_id=context.workspace_id,
            request_id=context.request_id,
            status_code=status.HTTP_200_OK,
            metadata={
                "session_id": context.session_id,
                "revoked_count": revoked_count,
                "security_result": security_result,
            },
        )

        verification_result = await prepare_verification(
            {
                "type": "auth_logout_confirmation",
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
                "request_id": context.request_id,
                "result": "success",
                "revoked_count": revoked_count,
                "created_at": utc_now(),
            }
        )

        return api_success(
            message="Logout successful.",
            data={
                "revoked_sessions": revoked_count,
                "audit": audit,
                "verification_result": verification_result,
            },
            request_id=context.request_id,
        )

    async def me(
        self,
        context: AuthContext = Depends(get_current_auth_context),
    ) -> Dict[str, Any]:
        user = AUTH_STORE.get_user_by_id(context.user_id)
        workspace = AUTH_STORE.get_workspace(context.workspace_id)
        membership = AUTH_STORE.get_membership(context.user_id, context.workspace_id)
        session = AUTH_STORE.require_session(context.session_id)

        if not user or not workspace or not membership:
            raise_api_error(
                status_code=status.HTTP_404_NOT_FOUND,
                message="Current auth scope could not be loaded.",
                code="AUTH_SCOPE_NOT_FOUND",
                request_id=context.request_id,
            )

        return api_success(
            message="Current authenticated user loaded.",
            data={
                "user": self._safe_user(user),
                "workspace": self._safe_workspace(workspace),
                "membership": self._safe_membership(membership),
                "session": self._safe_session(session),
                "isolation": {
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                },
            },
            request_id=context.request_id,
        )

    async def sessions(
        self,
        context: AuthContext = Depends(get_current_auth_context),
    ) -> Dict[str, Any]:
        sessions = AUTH_STORE.list_sessions_for_user_workspace(
            user_id=context.user_id,
            workspace_id=context.workspace_id,
        )

        return api_success(
            message="Workspace-scoped sessions loaded.",
            data={
                "sessions": [self._safe_session(session) for session in sessions],
                "count": len(sessions),
                "isolation": {
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                },
            },
            request_id=context.request_id,
        )

    async def revoke_session(
        self,
        payload: RevokeSessionRequest,
        request: Request,
        context: AuthContext = Depends(require_auth_role(Role.ADMIN.value)),
    ) -> Dict[str, Any]:
        try:
            target_session = AUTH_STORE.require_session(payload.session_id)

            if target_session.user_id != context.user_id or target_session.workspace_id != context.workspace_id:
                raise_api_error(
                    status_code=status.HTTP_403_FORBIDDEN,
                    message="Cannot revoke a session outside your current user/workspace scope.",
                    code="SESSION_SCOPE_VIOLATION",
                    request_id=context.request_id,
                )

            security_result = await security_review(
                {
                    "type": "auth_revoke_session",
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "target_session_id": payload.session_id,
                    "actor_session_id": context.session_id,
                    "created_at": utc_now(),
                }
            )

            approved = bool(
                security_result.get("success")
                and (
                    security_result.get("data", {}).get("approved") is True
                    or security_result.get("data", {}).get("allowed") is True
                    or security_result.get("data", {}).get("local_policy") is True
                )
            )

            if not approved:
                raise_api_error(
                    status_code=status.HTTP_403_FORBIDDEN,
                    message="Session revocation was blocked by Security Agent.",
                    code="SECURITY_AGENT_DENIED",
                    request_id=context.request_id,
                    details=security_result,
                )

            revoked = AUTH_STORE.revoke_session(payload.session_id)

            audit = write_auth_audit(
                request=request,
                event_type="auth_revoke_session",
                action="revoke_session",
                result="success",
                user_id=context.user_id,
                workspace_id=context.workspace_id,
                request_id=context.request_id,
                status_code=status.HTTP_200_OK,
                metadata={
                    "target_session_id": payload.session_id,
                    "security_result": security_result,
                },
            )

            verification_result = await prepare_verification(
                {
                    "type": "auth_revoke_session_confirmation",
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "request_id": context.request_id,
                    "result": "success",
                    "target_session_id": payload.session_id,
                    "created_at": utc_now(),
                }
            )

            return api_success(
                message="Session revoked successfully.",
                data={
                    "session": self._safe_session(revoked),
                    "audit": audit,
                    "verification_result": verification_result,
                },
                request_id=context.request_id,
            )

        except ValueError as exc:
            raise_api_error(
                status_code=status.HTTP_404_NOT_FOUND,
                message=str(exc),
                code="SESSION_NOT_FOUND",
                request_id=context.request_id,
            )

    async def switch_workspace(self, payload: SwitchWorkspaceRequest, request: Request) -> Dict[str, Any]:
        request_id = request.headers.get("X-Request-ID") or getattr(request.state, "request_id", None) or new_id("req")
        token_payload = TOKEN_SERVICE.verify_token(payload.refresh_token, expected_type="refresh")

        if AUTH_STORE.is_jti_revoked(token_payload["jti"]):
            raise_api_error(
                status_code=status.HTTP_401_UNAUTHORIZED,
                message="Refresh token has been revoked.",
                code="REFRESH_TOKEN_REVOKED",
                request_id=request_id,
            )

        try:
            old_session = AUTH_STORE.require_session(token_payload["session_id"])
            user = AUTH_STORE.get_user_by_id(old_session.user_id)

            if not user or not user.is_active:
                raise ValueError("User is inactive.")

            target_membership = AUTH_STORE.get_membership(user.user_id, payload.workspace_id)

            if not target_membership:
                raise ValueError("User does not have access to target workspace.")

            target_workspace = AUTH_STORE.get_workspace(target_membership.workspace_id)

            if not target_workspace:
                raise ValueError("Target workspace not found.")

            if target_workspace.subscription_status not in {"active", "trialing"}:
                raise ValueError("Target workspace subscription is not active.")

            AUTH_STORE.revoke_jti(token_payload["jti"])
            AUTH_STORE.revoke_session(old_session.session_id)

            refresh_token, refresh_jti, refresh_expires_at = TOKEN_SERVICE.create_token(
                token_type="refresh",
                user_id=user.user_id,
                workspace_id=target_membership.workspace_id,
                session_id="pending",
                role=target_membership.role,
                plan=target_membership.plan,
                email=user.email,
                ttl_seconds=AUTH_SETTINGS.refresh_token_ttl_seconds,
            )

            new_session = AUTH_STORE.create_session(
                user=user,
                membership=target_membership,
                refresh_jti=refresh_jti,
                refresh_expires_at=refresh_expires_at,
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent"),
                metadata={
                    "auth_flow": "switch_workspace",
                    "previous_workspace_id": old_session.workspace_id,
                    "previous_session_id": old_session.session_id,
                },
            )

            refresh_token, refresh_jti, refresh_expires_at = TOKEN_SERVICE.create_token(
                token_type="refresh",
                user_id=user.user_id,
                workspace_id=target_membership.workspace_id,
                session_id=new_session.session_id,
                role=target_membership.role,
                plan=target_membership.plan,
                email=user.email,
                ttl_seconds=AUTH_SETTINGS.refresh_token_ttl_seconds,
            )

            AUTH_STORE.update_session_refresh(new_session.session_id, refresh_jti, refresh_expires_at)

            access_token, access_jti, access_expires_at = TOKEN_SERVICE.create_token(
                token_type="access",
                user_id=user.user_id,
                workspace_id=target_membership.workspace_id,
                session_id=new_session.session_id,
                role=target_membership.role,
                plan=target_membership.plan,
                email=user.email,
                ttl_seconds=AUTH_SETTINGS.access_token_ttl_seconds,
            )

            audit = write_auth_audit(
                request=request,
                event_type="auth_switch_workspace",
                action="switch_workspace",
                result="success",
                user_id=user.user_id,
                workspace_id=target_membership.workspace_id,
                request_id=request_id,
                status_code=status.HTTP_200_OK,
                metadata={
                    "previous_workspace_id": old_session.workspace_id,
                    "new_workspace_id": target_membership.workspace_id,
                    "new_session_id": new_session.session_id,
                    "access_jti": access_jti,
                },
            )

            memory_result = await emit_memory_context(
                {
                    "type": "auth_switch_workspace",
                    "user_id": user.user_id,
                    "workspace_id": target_membership.workspace_id,
                    "request_id": request_id,
                    "content": {
                        "event": "workspace_switched",
                        "previous_workspace_id": old_session.workspace_id,
                        "new_workspace_id": target_membership.workspace_id,
                    },
                    "created_at": utc_now(),
                }
            )

            verification_result = await prepare_verification(
                {
                    "type": "auth_switch_workspace_confirmation",
                    "user_id": user.user_id,
                    "workspace_id": target_membership.workspace_id,
                    "request_id": request_id,
                    "result": "success",
                    "created_at": utc_now(),
                }
            )

            return api_success(
                message="Workspace switched successfully.",
                data={
                    "user": self._safe_user(user),
                    "workspace": self._safe_workspace(target_workspace),
                    "membership": self._safe_membership(target_membership),
                    "session": self._safe_session(AUTH_STORE.require_session(new_session.session_id)),
                    "tokens": {
                        "access_token": access_token,
                        "refresh_token": refresh_token,
                        "token_type": "bearer",
                        "access_expires_at": access_expires_at,
                        "refresh_expires_at": refresh_expires_at,
                    },
                    "audit": audit,
                    "memory_result": memory_result,
                    "verification_result": verification_result,
                },
                request_id=request_id,
            )

        except ValueError as exc:
            write_auth_audit(
                request=request,
                event_type="auth_switch_workspace",
                action="switch_workspace",
                result="failed",
                user_id=token_payload.get("sub"),
                workspace_id=payload.workspace_id,
                request_id=request_id,
                status_code=status.HTTP_403_FORBIDDEN,
                metadata={"error": str(exc)},
            )
            raise_api_error(
                status_code=status.HTTP_403_FORBIDDEN,
                message=str(exc),
                code="WORKSPACE_SWITCH_FAILED",
                request_id=request_id,
            )

    async def audit(
        self,
        context: AuthContext = Depends(require_auth_role(Role.ADMIN.value)),
    ) -> Dict[str, Any]:
        scoped = [
            event
            for event in AUTH_AUDIT_EVENTS
            if event.get("user_id") == context.user_id and event.get("workspace_id") == context.workspace_id
        ]

        return api_success(
            message="Auth audit logs loaded for current user/workspace scope.",
            data={
                "logs": scoped[-100:],
                "count": len(scoped[-100:]),
                "isolation": {
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                },
            },
            request_id=context.request_id,
        )

    @staticmethod
    def _safe_user(user: UserRecord) -> Dict[str, Any]:
        return {
            "user_id": user.user_id,
            "email": user.email,
            "full_name": user.full_name,
            "created_at": user.created_at,
            "updated_at": user.updated_at,
            "is_active": user.is_active,
            "metadata": user.metadata,
        }

    @staticmethod
    def _safe_workspace(workspace: WorkspaceRecord) -> Dict[str, Any]:
        return {
            "workspace_id": workspace.workspace_id,
            "name": workspace.name,
            "owner_user_id": workspace.owner_user_id,
            "plan": workspace.plan,
            "subscription_status": workspace.subscription_status,
            "created_at": workspace.created_at,
            "updated_at": workspace.updated_at,
            "metadata": workspace.metadata,
        }

    @staticmethod
    def _safe_membership(membership: MembershipRecord) -> Dict[str, Any]:
        return {
            "membership_id": membership.membership_id,
            "user_id": membership.user_id,
            "workspace_id": membership.workspace_id,
            "role": membership.role,
            "plan": membership.plan,
            "permissions": membership.permissions,
            "created_at": membership.created_at,
            "updated_at": membership.updated_at,
            "is_active": membership.is_active,
        }

    @staticmethod
    def _safe_session(session: SessionRecord) -> Dict[str, Any]:
        return {
            "session_id": session.session_id,
            "user_id": session.user_id,
            "workspace_id": session.workspace_id,
            "role": session.role,
            "plan": session.plan,
            "created_at": session.created_at,
            "expires_at": session.expires_at,
            "last_seen_at": session.last_seen_at,
            "ip_address": session.ip_address,
            "user_agent": session.user_agent,
            "is_active": session.is_active,
            "metadata": session.metadata,
        }


auth = Auth()
router = auth.router


# =============================================================================
# Optional standalone error handler helper
# =============================================================================

def auth_http_exception_response(exc: HTTPException) -> JSONResponse:
    if isinstance(exc.detail, dict):
        return JSONResponse(status_code=exc.status_code, content=exc.detail)

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "message": str(exc.detail),
            "data": {},
            "error": {"code": "AUTH_HTTP_EXCEPTION"},
            "metadata": {"timestamp": utc_now(), "module": "auth"},
        },
    )