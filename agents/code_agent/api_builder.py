"""
agents/code_agent/api_builder.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    APIBuilder generates REST API scaffolds, authentication routes, CRUD routers,
    webhook handlers, Flask blueprints, FastAPI routers, route manifests, and
    API documentation metadata for the William/Jarvis Code Agent.

Architecture Compatibility:
    - BaseAgent compatible
    - Master Agent routing compatible
    - Agent Registry / Agent Loader safe
    - SaaS user_id / workspace_id isolation aware
    - Security Agent approval hooks included
    - Verification Agent payload hooks included
    - Memory Agent payload hooks included
    - Dashboard/API structured result compatible

Safety:
    This file does not execute external services or destructive operations.
    It generates code strings and optional files only after context validation.
    File writing is treated as a sensitive action and routed through the
    security approval hook.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import logging
import os
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union


# ---------------------------------------------------------------------
# Safe optional imports for William/Jarvis architecture compatibility
# ---------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:
    class BaseAgent:
        """
        Fallback BaseAgent stub.

        This keeps the file import-safe before the real William/Jarvis
        BaseAgent exists.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_type = kwargs.get("agent_type", "code_agent")
            self.logger = logging.getLogger(self.agent_name)

        def run(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent run() called.",
                "data": {},
                "error": None,
                "metadata": {},
            }


# ---------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------

LOGGER = logging.getLogger("APIBuilder")
if not LOGGER.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

SUPPORTED_FRAMEWORKS = {"flask", "fastapi"}

SUPPORTED_ROUTE_TYPES = {
    "crud",
    "auth",
    "webhook",
    "health",
    "custom",
}

SENSITIVE_ACTIONS = {
    "write_file",
    "generate_project_api",
    "generate_auth_router",
    "generate_crud_router",
    "generate_webhook_router",
    "generate_flask_blueprint",
    "generate_fastapi_router",
}

DEFAULT_CRUD_ACTIONS = ["list", "get", "create", "update", "delete"]

RESERVED_PYTHON_WORDS = {
    "False", "None", "True", "and", "as", "assert", "async", "await",
    "break", "class", "continue", "def", "del", "elif", "else", "except",
    "finally", "for", "from", "global", "if", "import", "in", "is",
    "lambda", "nonlocal", "not", "or", "pass", "raise", "return",
    "try", "while", "with", "yield",
}


# ---------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------

def utc_now_iso() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def sha256_text(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()


def safe_slug(value: str, default: str = "resource") -> str:
    """
    Converts a string into a safe API/path slug.
    """
    value = str(value or "").strip().lower()
    value = re.sub(r"[^a-z0-9_\\-\\s]", "", value)
    value = re.sub(r"[\\s_]+", "-", value)
    value = value.strip("-")
    return value or default


def safe_identifier(value: str, default: str = "resource") -> str:
    """
    Converts a string into a safe Python identifier.
    """
    value = str(value or "").strip().lower()
    value = re.sub(r"[^a-z0-9_\\s]", "", value)
    value = re.sub(r"[\\s\\-]+", "_", value)
    value = value.strip("_")

    if not value:
        value = default

    if value[0].isdigit():
        value = f"{default}_{value}"

    if value in RESERVED_PYTHON_WORDS:
        value = f"{value}_resource"

    return value


def pascal_case(value: str, default: str = "Resource") -> str:
    cleaned = safe_identifier(value, default=default.lower())
    return "".join(part.capitalize() for part in cleaned.split("_")) or default


def pluralize_simple(value: str) -> str:
    value = value.strip()
    if value.endswith("y") and len(value) > 1 and value[-2].lower() not in "aeiou":
        return value[:-1] + "ies"
    if value.endswith(("s", "x", "z", "ch", "sh")):
        return value + "es"
    return value + "s"


def ensure_directory(path: Union[str, Path]) -> Path:
    resolved = Path(path).expanduser().resolve()
    resolved.mkdir(parents=True, exist_ok=True)
    return resolved


def safe_write_text(path: Union[str, Path], content: str) -> None:
    target = Path(path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def indent_text(text: str, spaces: int = 4) -> str:
    prefix = " " * spaces
    return "\n".join(prefix + line if line.strip() else line for line in text.splitlines())


# ---------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------

@dataclass
class APIRouteSpec:
    """
    Represents one API route to generate or document.
    """

    name: str
    method: str
    path: str
    handler_name: str
    route_type: str = "custom"
    auth_required: bool = True
    workspace_required: bool = True
    request_schema: Optional[str] = None
    response_schema: Optional[str] = None
    description: Optional[str] = None
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CRUDResourceSpec:
    """
    Represents a CRUD resource used to generate API routers.
    """

    resource_name: str
    table_name: Optional[str] = None
    model_name: Optional[str] = None
    route_prefix: Optional[str] = None
    fields: Dict[str, str] = field(default_factory=dict)
    actions: List[str] = field(default_factory=lambda: DEFAULT_CRUD_ACTIONS.copy())
    auth_required: bool = True
    workspace_required: bool = True
    soft_delete: bool = True
    owner_field: str = "user_id"
    workspace_field: str = "workspace_id"

    def normalized(self) -> "CRUDResourceSpec":
        resource_identifier = safe_identifier(self.resource_name)
        route_slug = safe_slug(self.route_prefix or pluralize_simple(resource_identifier))
        model = self.model_name or pascal_case(resource_identifier)
        table = self.table_name or pluralize_simple(resource_identifier)

        return CRUDResourceSpec(
            resource_name=resource_identifier,
            table_name=table,
            model_name=model,
            route_prefix=route_slug,
            fields=self.fields or {},
            actions=self.actions or DEFAULT_CRUD_ACTIONS.copy(),
            auth_required=self.auth_required,
            workspace_required=self.workspace_required,
            soft_delete=self.soft_delete,
            owner_field=self.owner_field,
            workspace_field=self.workspace_field,
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AuthConfig:
    """
    Auth route generation configuration.
    """

    include_signup: bool = True
    include_login: bool = True
    include_logout: bool = True
    include_me: bool = True
    include_refresh: bool = True
    include_forgot_password: bool = True
    include_reset_password: bool = True
    token_strategy: str = "jwt"
    password_hashing: str = "werkzeug"
    user_model_name: str = "User"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class WebhookSpec:
    """
    Represents a webhook router generation spec.
    """

    name: str
    path: Optional[str] = None
    secret_header: str = "X-Webhook-Signature"
    event_field: str = "event"
    verify_signature: bool = True
    auth_required: bool = False
    workspace_required: bool = False
    allowed_events: List[str] = field(default_factory=list)

    def normalized(self) -> "WebhookSpec":
        ident = safe_identifier(self.name, default="webhook")
        return WebhookSpec(
            name=ident,
            path=self.path or f"/webhooks/{safe_slug(ident)}",
            secret_header=self.secret_header,
            event_field=self.event_field,
            verify_signature=self.verify_signature,
            auth_required=self.auth_required,
            workspace_required=self.workspace_required,
            allowed_events=self.allowed_events,
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class GeneratedAPIFile:
    """
    Represents generated API code output.
    """

    file_name: str
    file_path: str
    content: str
    framework: str
    route_type: str
    sha256: str
    written: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------
# APIBuilder
# ---------------------------------------------------------------------

class APIBuilder(BaseAgent):
    """
    Code Agent helper for generating API files.

    Main responsibilities:
        - Generate Flask blueprints
        - Generate FastAPI routers
        - Generate auth route scaffolds
        - Generate CRUD route scaffolds
        - Generate webhook handlers
        - Generate route manifests
        - Generate API helper utilities
        - Prepare Memory, Verification, Audit, Security, and Dashboard payloads

    This class generates code safely. Writing files is gated by the security
    approval hook, and all public methods return structured dict results.
    """

    VERSION = "1.0.0"

    def __init__(
        self,
        agent_name: str = "APIBuilder",
        agent_type: str = "code_agent",
        default_output_dir: Optional[Union[str, Path]] = None,
        logger: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name=agent_name, agent_type=agent_type, **kwargs)

        self.agent_name = agent_name
        self.agent_type = agent_type
        self.default_output_dir = Path(default_output_dir).expanduser().resolve() if default_output_dir else None
        self.logger = logger or LOGGER

    # -----------------------------------------------------------------
    # Result helpers
    # -----------------------------------------------------------------

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": {
                "agent": self.agent_name,
                "agent_type": self.agent_type,
                "timestamp": utc_now_iso(),
                **(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Union[str, Exception]] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": str(error) if error else message,
            "metadata": {
                "agent": self.agent_name,
                "agent_type": self.agent_type,
                "timestamp": utc_now_iso(),
                **(metadata or {}),
            },
        }

    # -----------------------------------------------------------------
    # William/Jarvis compatibility hooks
    # -----------------------------------------------------------------

    def _validate_task_context(
        self,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        action: str,
        framework: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Validates SaaS task context.

        API generation is user/workspace specific in William/Jarvis because
        generated files, logs, task history, and dashboard analytics must never
        mix between tenants.
        """
        if user_id is None or str(user_id).strip() == "":
            return False, "Missing user_id. API generation requires SaaS user isolation."

        if workspace_id is None or str(workspace_id).strip() == "":
            return False, "Missing workspace_id. API generation requires workspace isolation."

        if not action or not isinstance(action, str):
            return False, "Missing or invalid action."

        if framework is not None and framework not in SUPPORTED_FRAMEWORKS:
            return False, f"Unsupported framework '{framework}'. Supported: {sorted(SUPPORTED_FRAMEWORKS)}"

        return True, None

    def _requires_security_check(
        self,
        action: str,
        write_files: bool = False,
        route_type: Optional[str] = None,
    ) -> bool:
        """
        Determines whether Security Agent approval is required.
        """
        action = str(action or "").strip().lower()

        if action in SENSITIVE_ACTIONS:
            return True

        if write_files:
            return True

        if route_type in {"auth", "webhook"}:
            return True

        return False

    def _request_security_approval(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        action: str,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Security Agent compatibility hook.

        In the full system, this should call Security Agent. This import-safe
        implementation returns a structured security request. It does not
        auto-approve sensitive file-writing or auth/webhook generation.
        """
        write_files = bool(payload.get("write_files", False))
        route_type = payload.get("route_type")

        required = self._requires_security_check(
            action=action,
            write_files=write_files,
            route_type=route_type,
        )

        return {
            "required": required,
            "approved": not required,
            "message": (
                "Security approval required before writing files or generating sensitive API routes."
                if required
                else "Security approval not required for this planning action."
            ),
            "security_payload": {
                "user_id": user_id,
                "workspace_id": workspace_id,
                "agent": self.agent_name,
                "action": action,
                "payload": payload,
                "timestamp": utc_now_iso(),
            },
        }

    def _prepare_verification_payload(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        action: str,
        result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepares Verification Agent payload.
        """
        data = result.get("data", {})
        generated_files = data.get("generated_files", [])

        return {
            "verification_type": "api_generation",
            "user_id": user_id,
            "workspace_id": workspace_id,
            "agent": self.agent_name,
            "action": action,
            "success": result.get("success", False),
            "message": result.get("message"),
            "generated_file_count": len(generated_files),
            "data_hash": sha256_text(json.dumps(data, sort_keys=True, default=str)),
            "timestamp": utc_now_iso(),
        }

    def _prepare_memory_payload(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        action: str,
        result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepares Memory Agent payload.

        Stores API generation summary only. No secrets are included.
        """
        data = result.get("data", {})

        return {
            "memory_type": "code_api_generation_context",
            "user_id": user_id,
            "workspace_id": workspace_id,
            "agent": self.agent_name,
            "summary": {
                "action": action,
                "framework": data.get("framework"),
                "route_type": data.get("route_type"),
                "resource": data.get("resource"),
                "generated_files": [
                    {
                        "file_name": item.get("file_name"),
                        "file_path": item.get("file_path"),
                        "sha256": item.get("sha256"),
                    }
                    for item in data.get("generated_files", [])
                ],
            },
            "timestamp": utc_now_iso(),
        }

    def _emit_agent_event(
        self,
        event_name: str,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Dashboard/API/Registry event compatibility hook.
        """
        event = {
            "event_name": event_name,
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "payload": payload or {},
            "timestamp": utc_now_iso(),
        }

        self.logger.info("Agent event emitted: %s", event_name)
        return event

    def _log_audit_event(
        self,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        action: str,
        status: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Audit log compatibility hook.

        In full SaaS production, this should write to the audit log table.
        """
        audit = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "agent": self.agent_name,
            "action": action,
            "status": status,
            "details": details or {},
            "timestamp": utc_now_iso(),
        }

        self.logger.info("Audit event: action=%s status=%s", action, status)
        return audit

    # -----------------------------------------------------------------
    # Master Agent compatible router
    # -----------------------------------------------------------------

    def run(
        self,
        action: str,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        framework: str = "fastapi",
        write_files: bool = False,
        output_dir: Optional[Union[str, Path]] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Master Agent / Agent Router compatible entrypoint.

        Supported actions:
            - generate_health_router
            - generate_auth_router
            - generate_crud_router
            - generate_webhook_router
            - generate_project_api
            - generate_route_manifest
            - generate_api_utils
        """
        action = str(action or "").strip().lower()
        framework = str(framework or "fastapi").strip().lower()

        valid, error = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            action=action,
            framework=framework,
        )
        if not valid:
            return self._error_result(error or "Invalid task context.")

        assert user_id is not None
        assert workspace_id is not None

        self._emit_agent_event(
            "api_builder.started",
            user_id=user_id,
            workspace_id=workspace_id,
            payload={
                "action": action,
                "framework": framework,
                "write_files": write_files,
            },
        )

        try:
            if action == "generate_health_router":
                result = self.generate_health_router(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    framework=framework,
                    output_dir=output_dir,
                    write_files=write_files,
                )

            elif action == "generate_auth_router":
                result = self.generate_auth_router(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    framework=framework,
                    auth_config=kwargs.get("auth_config"),
                    output_dir=output_dir,
                    write_files=write_files,
                )

            elif action == "generate_crud_router":
                result = self.generate_crud_router(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    framework=framework,
                    resource=kwargs.get("resource"),
                    output_dir=output_dir,
                    write_files=write_files,
                )

            elif action == "generate_webhook_router":
                result = self.generate_webhook_router(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    framework=framework,
                    webhook=kwargs.get("webhook"),
                    output_dir=output_dir,
                    write_files=write_files,
                )

            elif action == "generate_project_api":
                result = self.generate_project_api(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    framework=framework,
                    resources=kwargs.get("resources") or [],
                    webhooks=kwargs.get("webhooks") or [],
                    include_auth=bool(kwargs.get("include_auth", True)),
                    include_health=bool(kwargs.get("include_health", True)),
                    output_dir=output_dir,
                    write_files=write_files,
                )

            elif action == "generate_route_manifest":
                result = self.generate_route_manifest(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    framework=framework,
                    resources=kwargs.get("resources") or [],
                    webhooks=kwargs.get("webhooks") or [],
                    include_auth=bool(kwargs.get("include_auth", True)),
                    include_health=bool(kwargs.get("include_health", True)),
                )

            elif action == "generate_api_utils":
                result = self.generate_api_utils(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    framework=framework,
                    output_dir=output_dir,
                    write_files=write_files,
                )

            else:
                result = self._error_result(
                    f"Unsupported APIBuilder action: {action}",
                    data={"supported_actions": self.supported_actions()},
                )

            verification_payload = self._prepare_verification_payload(
                user_id=user_id,
                workspace_id=workspace_id,
                action=action,
                result=result,
            )
            memory_payload = self._prepare_memory_payload(
                user_id=user_id,
                workspace_id=workspace_id,
                action=action,
                result=result,
            )

            result.setdefault("metadata", {})
            result["metadata"]["verification_payload"] = verification_payload
            result["metadata"]["memory_payload"] = memory_payload

            self._log_audit_event(
                user_id=user_id,
                workspace_id=workspace_id,
                action=action,
                status="success" if result.get("success") else "failed",
                details={
                    "framework": framework,
                    "write_files": write_files,
                    "message": result.get("message"),
                },
            )

            return result

        except Exception as exc:
            self.logger.exception("APIBuilder action failed.")
            return self._error_result(
                "APIBuilder action failed.",
                error=exc,
                metadata={
                    "action": action,
                    "framework": framework,
                },
            )

    def supported_actions(self) -> List[str]:
        return [
            "generate_health_router",
            "generate_auth_router",
            "generate_crud_router",
            "generate_webhook_router",
            "generate_project_api",
            "generate_route_manifest",
            "generate_api_utils",
        ]

    # -----------------------------------------------------------------
    # Output/file helpers
    # -----------------------------------------------------------------

    def _resolve_output_dir(self, output_dir: Optional[Union[str, Path]]) -> Path:
        if output_dir:
            return Path(output_dir).expanduser().resolve()
        if self.default_output_dir:
            return self.default_output_dir
        return Path.cwd().resolve()

    def _build_generated_file(
        self,
        file_name: str,
        file_path: Union[str, Path],
        content: str,
        framework: str,
        route_type: str,
        written: bool = False,
    ) -> GeneratedAPIFile:
        return GeneratedAPIFile(
            file_name=file_name,
            file_path=str(file_path),
            content=content,
            framework=framework,
            route_type=route_type,
            sha256=sha256_text(content),
            written=written,
        )

    def _maybe_write_generated_file(
        self,
        generated_file: GeneratedAPIFile,
        write_files: bool,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        action: str,
        route_type: str,
    ) -> Tuple[GeneratedAPIFile, Dict[str, Any]]:
        security = self._request_security_approval(
            user_id=user_id,
            workspace_id=workspace_id,
            action=action,
            payload={
                "write_files": write_files,
                "route_type": route_type,
                "file_path": generated_file.file_path,
                "file_name": generated_file.file_name,
                "sha256": generated_file.sha256,
            },
        )

        if write_files:
            if security.get("required") and not security.get("approved"):
                generated_file.written = False
                return generated_file, security

            safe_write_text(generated_file.file_path, generated_file.content)
            generated_file.written = True

        return generated_file, security

    # -----------------------------------------------------------------
    # Health router generation
    # -----------------------------------------------------------------

    def generate_health_router(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        framework: str = "fastapi",
        output_dir: Optional[Union[str, Path]] = None,
        write_files: bool = False,
    ) -> Dict[str, Any]:
        framework = framework.lower()
        if framework not in SUPPORTED_FRAMEWORKS:
            return self._error_result(f"Unsupported framework: {framework}")

        output = self._resolve_output_dir(output_dir)
        file_name = "health_router.py" if framework == "fastapi" else "health_blueprint.py"
        file_path = output / file_name

        content = (
            self._generate_fastapi_health_router_code()
            if framework == "fastapi"
            else self._generate_flask_health_blueprint_code()
        )

        generated = self._build_generated_file(
            file_name=file_name,
            file_path=file_path,
            content=content,
            framework=framework,
            route_type="health",
        )

        generated, security = self._maybe_write_generated_file(
            generated_file=generated,
            write_files=write_files,
            user_id=user_id,
            workspace_id=workspace_id,
            action="generate_health_router",
            route_type="health",
        )

        return self._safe_result(
            "Health API router generated.",
            data={
                "framework": framework,
                "route_type": "health",
                "generated_files": [generated.to_dict()],
                "security": security,
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )

    def _generate_fastapi_health_router_code(self) -> str:
        return '''"""
Generated FastAPI health router for William/Jarvis.

This router is safe to import and can be included with:
    app.include_router(router)
"""

from __future__ import annotations

import datetime
from typing import Any, Dict

try:
    from fastapi import APIRouter
except Exception:
    APIRouter = None


if APIRouter is not None:
    router = APIRouter(prefix="/health", tags=["health"])
else:
    router = None


def utc_now_iso() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def api_response(success: bool, message: str, data: Dict[str, Any] | None = None, error: str | None = None) -> Dict[str, Any]:
    return {
        "success": success,
        "message": message,
        "data": data or {},
        "error": error,
        "metadata": {
            "timestamp": utc_now_iso(),
            "service": "william-jarvis-api",
        },
    }


if router is not None:
    @router.get("/")
    async def health_check() -> Dict[str, Any]:
        return api_response(
            success=True,
            message="API service is healthy.",
            data={"status": "ok"},
        )


    @router.get("/ready")
    async def readiness_check() -> Dict[str, Any]:
        return api_response(
            success=True,
            message="API service is ready.",
            data={"status": "ready"},
        )
'''

    def _generate_flask_health_blueprint_code(self) -> str:
        return '''"""
Generated Flask health blueprint for William/Jarvis.

Register with:
    app.register_blueprint(health_bp)
"""

from __future__ import annotations

import datetime
from typing import Any, Dict

try:
    from flask import Blueprint, jsonify
except Exception:
    Blueprint = None
    jsonify = None


if Blueprint is not None:
    health_bp = Blueprint("health_bp", __name__, url_prefix="/health")
else:
    health_bp = None


def utc_now_iso() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def api_response(success: bool, message: str, data: Dict[str, Any] | None = None, error: str | None = None) -> Dict[str, Any]:
    return {
        "success": success,
        "message": message,
        "data": data or {},
        "error": error,
        "metadata": {
            "timestamp": utc_now_iso(),
            "service": "william-jarvis-api",
        },
    }


if health_bp is not None:
    @health_bp.get("/")
    def health_check():
        return jsonify(api_response(
            success=True,
            message="API service is healthy.",
            data={"status": "ok"},
        ))


    @health_bp.get("/ready")
    def readiness_check():
        return jsonify(api_response(
            success=True,
            message="API service is ready.",
            data={"status": "ready"},
        ))
'''

    # -----------------------------------------------------------------
    # Auth router generation
    # -----------------------------------------------------------------

    def generate_auth_router(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        framework: str = "fastapi",
        auth_config: Optional[Union[AuthConfig, Dict[str, Any]]] = None,
        output_dir: Optional[Union[str, Path]] = None,
        write_files: bool = False,
    ) -> Dict[str, Any]:
        framework = framework.lower()
        if framework not in SUPPORTED_FRAMEWORKS:
            return self._error_result(f"Unsupported framework: {framework}")

        config = self._normalize_auth_config(auth_config)
        output = self._resolve_output_dir(output_dir)
        file_name = "auth_router.py" if framework == "fastapi" else "auth_blueprint.py"
        file_path = output / file_name

        content = (
            self._generate_fastapi_auth_router_code(config)
            if framework == "fastapi"
            else self._generate_flask_auth_blueprint_code(config)
        )

        generated = self._build_generated_file(
            file_name=file_name,
            file_path=file_path,
            content=content,
            framework=framework,
            route_type="auth",
        )

        generated, security = self._maybe_write_generated_file(
            generated_file=generated,
            write_files=write_files,
            user_id=user_id,
            workspace_id=workspace_id,
            action="generate_auth_router",
            route_type="auth",
        )

        return self._safe_result(
            "Auth API router generated.",
            data={
                "framework": framework,
                "route_type": "auth",
                "auth_config": config.to_dict(),
                "generated_files": [generated.to_dict()],
                "security": security,
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )

    def _normalize_auth_config(self, auth_config: Optional[Union[AuthConfig, Dict[str, Any]]]) -> AuthConfig:
        if auth_config is None:
            return AuthConfig()

        if isinstance(auth_config, AuthConfig):
            return auth_config

        if isinstance(auth_config, dict):
            allowed = AuthConfig().__dict__.keys()
            clean = {key: value for key, value in auth_config.items() if key in allowed}
            return AuthConfig(**clean)

        return AuthConfig()

    def _generate_fastapi_auth_router_code(self, config: AuthConfig) -> str:
        routes: List[str] = []

        if config.include_signup:
            routes.append('''
@router.post("/signup")
async def signup(payload: Dict[str, Any]) -> Dict[str, Any]:
    email = str(payload.get("email", "")).strip().lower()
    password = str(payload.get("password", ""))

    if not email or not password:
        return api_response(False, "Email and password are required.", error="validation_error")

    # Connect this section to your real User model and database service.
    user_payload = {
        "email": email,
        "workspace_id": payload.get("workspace_id"),
        "role": payload.get("role", "owner"),
    }

    return api_response(True, "Signup request accepted.", data={"user": user_payload})
''')

        if config.include_login:
            routes.append('''
@router.post("/login")
async def login(payload: Dict[str, Any]) -> Dict[str, Any]:
    email = str(payload.get("email", "")).strip().lower()
    password = str(payload.get("password", ""))

    if not email or not password:
        return api_response(False, "Email and password are required.", error="validation_error")

    # Replace token generation with your TokenService/JWT service.
    token_payload = {
        "access_token": "generated_access_token_replace_with_token_service",
        "refresh_token": "generated_refresh_token_replace_with_token_service",
        "token_type": "bearer",
    }

    return api_response(True, "Login successful.", data=token_payload)
''')

        if config.include_logout:
            routes.append('''
@router.post("/logout")
async def logout(context: RequestContext = Depends(get_request_context)) -> Dict[str, Any]:
    return api_response(True, "Logout successful.", data={"user_id": context.user_id})
''')

        if config.include_me:
            routes.append('''
@router.get("/me")
async def me(context: RequestContext = Depends(get_request_context)) -> Dict[str, Any]:
    return api_response(
        True,
        "Current user context loaded.",
        data={
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "role": context.role,
        },
    )
''')

        if config.include_refresh:
            routes.append('''
@router.post("/refresh")
async def refresh_token(payload: Dict[str, Any]) -> Dict[str, Any]:
    refresh = str(payload.get("refresh_token", "")).strip()

    if not refresh:
        return api_response(False, "refresh_token is required.", error="validation_error")

    return api_response(
        True,
        "Token refresh accepted.",
        data={
            "access_token": "new_generated_access_token_replace_with_token_service",
            "token_type": "bearer",
        },
    )
''')

        if config.include_forgot_password:
            routes.append('''
@router.post("/forgot-password")
async def forgot_password(payload: Dict[str, Any]) -> Dict[str, Any]:
    email = str(payload.get("email", "")).strip().lower()

    if not email:
        return api_response(False, "Email is required.", error="validation_error")

    return api_response(
        True,
        "Password reset request accepted.",
        data={"email": email, "delivery": "email_service"},
    )
''')

        if config.include_reset_password:
            routes.append('''
@router.post("/reset-password")
async def reset_password(payload: Dict[str, Any]) -> Dict[str, Any]:
    token = str(payload.get("token", "")).strip()
    new_password = str(payload.get("new_password", ""))

    if not token or not new_password:
        return api_response(False, "Token and new_password are required.", error="validation_error")

    return api_response(True, "Password reset accepted.", data={"reset": True})
''')

        joined_routes = "\n".join(routes)

        return f'''"""
Generated FastAPI auth router for William/Jarvis.

Security notes:
    - Replace demo token strings with TokenService/JWT integration.
    - Replace demo user handling with real User model and database service.
    - Keep user_id/workspace_id isolation enforced in all protected routes.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass
from typing import Any, Dict, Optional

try:
    from fastapi import APIRouter, Depends, Header
except Exception:
    APIRouter = None
    Depends = None
    Header = None


if APIRouter is not None:
    router = APIRouter(prefix="/auth", tags=["auth"])
else:
    router = None


@dataclass
class RequestContext:
    user_id: Optional[str] = None
    workspace_id: Optional[str] = None
    role: str = "user"


def utc_now_iso() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def api_response(success: bool, message: str, data: Dict[str, Any] | None = None, error: str | None = None) -> Dict[str, Any]:
    return {{
        "success": success,
        "message": message,
        "data": data or {{}},
        "error": error,
        "metadata": {{
            "timestamp": utc_now_iso(),
            "service": "william-jarvis-api",
        }},
    }}


async def get_request_context(
    x_user_id: Optional[str] = Header(default=None),
    x_workspace_id: Optional[str] = Header(default=None),
    x_role: Optional[str] = Header(default="user"),
) -> RequestContext:
    return RequestContext(
        user_id=x_user_id,
        workspace_id=x_workspace_id,
        role=x_role or "user",
    )


if router is not None:
{indent_text(joined_routes, 4)}
'''

    def _generate_flask_auth_blueprint_code(self, config: AuthConfig) -> str:
        routes: List[str] = []

        if config.include_signup:
            routes.append('''
@auth_bp.post("/signup")
def signup():
    payload = request.get_json(silent=True) or {}
    email = str(payload.get("email", "")).strip().lower()
    password = str(payload.get("password", ""))

    if not email or not password:
        return jsonify(api_response(False, "Email and password are required.", error="validation_error")), 400

    user_payload = {
        "email": email,
        "workspace_id": payload.get("workspace_id"),
        "role": payload.get("role", "owner"),
    }

    return jsonify(api_response(True, "Signup request accepted.", data={"user": user_payload}))
''')

        if config.include_login:
            routes.append('''
@auth_bp.post("/login")
def login():
    payload = request.get_json(silent=True) or {}
    email = str(payload.get("email", "")).strip().lower()
    password = str(payload.get("password", ""))

    if not email or not password:
        return jsonify(api_response(False, "Email and password are required.", error="validation_error")), 400

    token_payload = {
        "access_token": "generated_access_token_replace_with_token_service",
        "refresh_token": "generated_refresh_token_replace_with_token_service",
        "token_type": "bearer",
    }

    return jsonify(api_response(True, "Login successful.", data=token_payload))
''')

        if config.include_logout:
            routes.append('''
@auth_bp.post("/logout")
def logout():
    context = get_request_context()
    return jsonify(api_response(True, "Logout successful.", data={"user_id": context.get("user_id")}))
''')

        if config.include_me:
            routes.append('''
@auth_bp.get("/me")
def me():
    context = get_request_context()
    return jsonify(api_response(True, "Current user context loaded.", data=context))
''')

        if config.include_refresh:
            routes.append('''
@auth_bp.post("/refresh")
def refresh_token():
    payload = request.get_json(silent=True) or {}
    refresh = str(payload.get("refresh_token", "")).strip()

    if not refresh:
        return jsonify(api_response(False, "refresh_token is required.", error="validation_error")), 400

    return jsonify(api_response(
        True,
        "Token refresh accepted.",
        data={
            "access_token": "new_generated_access_token_replace_with_token_service",
            "token_type": "bearer",
        },
    ))
''')

        if config.include_forgot_password:
            routes.append('''
@auth_bp.post("/forgot-password")
def forgot_password():
    payload = request.get_json(silent=True) or {}
    email = str(payload.get("email", "")).strip().lower()

    if not email:
        return jsonify(api_response(False, "Email is required.", error="validation_error")), 400

    return jsonify(api_response(
        True,
        "Password reset request accepted.",
        data={"email": email, "delivery": "email_service"},
    ))
''')

        if config.include_reset_password:
            routes.append('''
@auth_bp.post("/reset-password")
def reset_password():
    payload = request.get_json(silent=True) or {}
    token = str(payload.get("token", "")).strip()
    new_password = str(payload.get("new_password", ""))

    if not token or not new_password:
        return jsonify(api_response(False, "Token and new_password are required.", error="validation_error")), 400

    return jsonify(api_response(True, "Password reset accepted.", data={"reset": True}))
''')

        joined_routes = "\n".join(routes)

        return f'''"""
Generated Flask auth blueprint for William/Jarvis.

Security notes:
    - Replace demo token strings with TokenService/JWT integration.
    - Replace demo user handling with real User model and database service.
    - Keep user_id/workspace_id isolation enforced in all protected routes.
"""

from __future__ import annotations

import datetime
from typing import Any, Dict

try:
    from flask import Blueprint, jsonify, request
except Exception:
    Blueprint = None
    jsonify = None
    request = None


if Blueprint is not None:
    auth_bp = Blueprint("auth_bp", __name__, url_prefix="/auth")
else:
    auth_bp = None


def utc_now_iso() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def api_response(success: bool, message: str, data: Dict[str, Any] | None = None, error: str | None = None) -> Dict[str, Any]:
    return {{
        "success": success,
        "message": message,
        "data": data or {{}},
        "error": error,
        "metadata": {{
            "timestamp": utc_now_iso(),
            "service": "william-jarvis-api",
        }},
    }}


def get_request_context() -> Dict[str, Any]:
    return {{
        "user_id": request.headers.get("X-User-ID") if request else None,
        "workspace_id": request.headers.get("X-Workspace-ID") if request else None,
        "role": request.headers.get("X-Role", "user") if request else "user",
    }}


if auth_bp is not None:
{indent_text(joined_routes, 4)}
'''

    # -----------------------------------------------------------------
    # CRUD router generation
    # -----------------------------------------------------------------

    def generate_crud_router(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        framework: str = "fastapi",
        resource: Optional[Union[CRUDResourceSpec, Dict[str, Any], str]] = None,
        output_dir: Optional[Union[str, Path]] = None,
        write_files: bool = False,
    ) -> Dict[str, Any]:
        framework = framework.lower()
        if framework not in SUPPORTED_FRAMEWORKS:
            return self._error_result(f"Unsupported framework: {framework}")

        spec = self._normalize_crud_resource(resource)
        output = self._resolve_output_dir(output_dir)

        file_name = f"{spec.resource_name}_router.py" if framework == "fastapi" else f"{spec.resource_name}_blueprint.py"
        file_path = output / file_name

        content = (
            self._generate_fastapi_crud_router_code(spec)
            if framework == "fastapi"
            else self._generate_flask_crud_blueprint_code(spec)
        )

        generated = self._build_generated_file(
            file_name=file_name,
            file_path=file_path,
            content=content,
            framework=framework,
            route_type="crud",
        )

        generated, security = self._maybe_write_generated_file(
            generated_file=generated,
            write_files=write_files,
            user_id=user_id,
            workspace_id=workspace_id,
            action="generate_crud_router",
            route_type="crud",
        )

        routes = self._crud_routes_manifest(spec)

        return self._safe_result(
            "CRUD API router generated.",
            data={
                "framework": framework,
                "route_type": "crud",
                "resource": spec.to_dict(),
                "routes": [route.to_dict() for route in routes],
                "generated_files": [generated.to_dict()],
                "security": security,
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )

    def _normalize_crud_resource(
        self,
        resource: Optional[Union[CRUDResourceSpec, Dict[str, Any], str]],
    ) -> CRUDResourceSpec:
        if resource is None:
            return CRUDResourceSpec(resource_name="item").normalized()

        if isinstance(resource, CRUDResourceSpec):
            return resource.normalized()

        if isinstance(resource, str):
            return CRUDResourceSpec(resource_name=resource).normalized()

        if isinstance(resource, dict):
            allowed = CRUDResourceSpec(resource_name="item").__dict__.keys()
            clean = {key: value for key, value in resource.items() if key in allowed}
            return CRUDResourceSpec(**clean).normalized()

        return CRUDResourceSpec(resource_name="item").normalized()

    def _crud_routes_manifest(self, spec: CRUDResourceSpec) -> List[APIRouteSpec]:
        base = f"/{spec.route_prefix}"
        routes: List[APIRouteSpec] = []

        if "list" in spec.actions:
            routes.append(APIRouteSpec(
                name=f"list_{spec.resource_name}",
                method="GET",
                path=base,
                handler_name=f"list_{spec.resource_name}",
                route_type="crud",
                auth_required=spec.auth_required,
                workspace_required=spec.workspace_required,
                description=f"List {spec.resource_name} records.",
                tags=[spec.resource_name],
            ))

        if "get" in spec.actions:
            routes.append(APIRouteSpec(
                name=f"get_{spec.resource_name}",
                method="GET",
                path=f"{base}/{{item_id}}",
                handler_name=f"get_{spec.resource_name}",
                route_type="crud",
                auth_required=spec.auth_required,
                workspace_required=spec.workspace_required,
                description=f"Get one {spec.resource_name} record.",
                tags=[spec.resource_name],
            ))

        if "create" in spec.actions:
            routes.append(APIRouteSpec(
                name=f"create_{spec.resource_name}",
                method="POST",
                path=base,
                handler_name=f"create_{spec.resource_name}",
                route_type="crud",
                auth_required=spec.auth_required,
                workspace_required=spec.workspace_required,
                description=f"Create one {spec.resource_name} record.",
                tags=[spec.resource_name],
            ))

        if "update" in spec.actions:
            routes.append(APIRouteSpec(
                name=f"update_{spec.resource_name}",
                method="PUT",
                path=f"{base}/{{item_id}}",
                handler_name=f"update_{spec.resource_name}",
                route_type="crud",
                auth_required=spec.auth_required,
                workspace_required=spec.workspace_required,
                description=f"Update one {spec.resource_name} record.",
                tags=[spec.resource_name],
            ))

        if "delete" in spec.actions:
            routes.append(APIRouteSpec(
                name=f"delete_{spec.resource_name}",
                method="DELETE",
                path=f"{base}/{{item_id}}",
                handler_name=f"delete_{spec.resource_name}",
                route_type="crud",
                auth_required=spec.auth_required,
                workspace_required=spec.workspace_required,
                description=f"Delete one {spec.resource_name} record.",
                tags=[spec.resource_name],
            ))

        return routes

    def _generate_fastapi_crud_router_code(self, spec: CRUDResourceSpec) -> str:
        fields_doc = json.dumps(spec.fields, indent=4)
        route_prefix = f"/{spec.route_prefix}"

        route_blocks: List[str] = []

        if "list" in spec.actions:
            route_blocks.append(f'''
@router.get("/")
async def list_{spec.resource_name}(context: RequestContext = Depends(get_request_context)) -> Dict[str, Any]:
    if not context.user_id or not context.workspace_id:
        return api_response(False, "Missing user or workspace context.", error="unauthorized")

    filters = {{
        "{spec.owner_field}": context.user_id,
        "{spec.workspace_field}": context.workspace_id,
    }}

    return api_response(
        True,
        "{spec.model_name} list loaded.",
        data={{
            "items": [],
            "filters": filters,
            "note": "Connect this handler to your database service.",
        }},
    )
''')

        if "get" in spec.actions:
            route_blocks.append(f'''
@router.get("/{{item_id}}")
async def get_{spec.resource_name}(item_id: int, context: RequestContext = Depends(get_request_context)) -> Dict[str, Any]:
    if not context.user_id or not context.workspace_id:
        return api_response(False, "Missing user or workspace context.", error="unauthorized")

    return api_response(
        True,
        "{spec.model_name} loaded.",
        data={{
            "id": item_id,
            "{spec.owner_field}": context.user_id,
            "{spec.workspace_field}": context.workspace_id,
            "note": "Connect this handler to your database service.",
        }},
    )
''')

        if "create" in spec.actions:
            route_blocks.append(f'''
@router.post("/")
async def create_{spec.resource_name}(payload: Dict[str, Any], context: RequestContext = Depends(get_request_context)) -> Dict[str, Any]:
    if not context.user_id or not context.workspace_id:
        return api_response(False, "Missing user or workspace context.", error="unauthorized")

    record = {{
        **payload,
        "{spec.owner_field}": context.user_id,
        "{spec.workspace_field}": context.workspace_id,
    }}

    return api_response(
        True,
        "{spec.model_name} create request accepted.",
        data={{"record": record}},
    )
''')

        if "update" in spec.actions:
            route_blocks.append(f'''
@router.put("/{{item_id}}")
async def update_{spec.resource_name}(item_id: int, payload: Dict[str, Any], context: RequestContext = Depends(get_request_context)) -> Dict[str, Any]:
    if not context.user_id or not context.workspace_id:
        return api_response(False, "Missing user or workspace context.", error="unauthorized")

    record = {{
        **payload,
        "id": item_id,
        "{spec.owner_field}": context.user_id,
        "{spec.workspace_field}": context.workspace_id,
    }}

    return api_response(
        True,
        "{spec.model_name} update request accepted.",
        data={{"record": record}},
    )
''')

        if "delete" in spec.actions:
            delete_message = "soft delete request accepted" if spec.soft_delete else "delete request accepted"
            route_blocks.append(f'''
@router.delete("/{{item_id}}")
async def delete_{spec.resource_name}(item_id: int, context: RequestContext = Depends(get_request_context)) -> Dict[str, Any]:
    if not context.user_id or not context.workspace_id:
        return api_response(False, "Missing user or workspace context.", error="unauthorized")

    return api_response(
        True,
        "{spec.model_name} {delete_message}.",
        data={{
            "id": item_id,
            "soft_delete": {str(spec.soft_delete)},
            "{spec.owner_field}": context.user_id,
            "{spec.workspace_field}": context.workspace_id,
        }},
    )
''')

        routes_joined = "\n".join(route_blocks)

        return f'''"""
Generated FastAPI CRUD router for {spec.model_name}.

William/Jarvis SaaS isolation:
    - Every protected route reads X-User-ID and X-Workspace-ID.
    - Replace demo handlers with your database service.
    - Keep owner/workspace filters on every query.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass
from typing import Any, Dict, Optional

try:
    from fastapi import APIRouter, Depends, Header
except Exception:
    APIRouter = None
    Depends = None
    Header = None


RESOURCE_FIELDS = {fields_doc}


if APIRouter is not None:
    router = APIRouter(prefix="{route_prefix}", tags=["{spec.resource_name}"])
else:
    router = None


@dataclass
class RequestContext:
    user_id: Optional[str] = None
    workspace_id: Optional[str] = None
    role: str = "user"


def utc_now_iso() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def api_response(success: bool, message: str, data: Dict[str, Any] | None = None, error: str | None = None) -> Dict[str, Any]:
    return {{
        "success": success,
        "message": message,
        "data": data or {{}},
        "error": error,
        "metadata": {{
            "timestamp": utc_now_iso(),
            "resource": "{spec.resource_name}",
        }},
    }}


async def get_request_context(
    x_user_id: Optional[str] = Header(default=None),
    x_workspace_id: Optional[str] = Header(default=None),
    x_role: Optional[str] = Header(default="user"),
) -> RequestContext:
    return RequestContext(
        user_id=x_user_id,
        workspace_id=x_workspace_id,
        role=x_role or "user",
    )


if router is not None:
{indent_text(routes_joined, 4)}
'''

    def _generate_flask_crud_blueprint_code(self, spec: CRUDResourceSpec) -> str:
        fields_doc = json.dumps(spec.fields, indent=4)
        route_prefix = f"/{spec.route_prefix}"
        blueprint_name = f"{spec.resource_name}_bp"

        route_blocks: List[str] = []

        if "list" in spec.actions:
            route_blocks.append(f'''
@{blueprint_name}.get("/")
def list_{spec.resource_name}():
    context = get_request_context()
    if not context.get("user_id") or not context.get("workspace_id"):
        return jsonify(api_response(False, "Missing user or workspace context.", error="unauthorized")), 401

    filters = {{
        "{spec.owner_field}": context.get("user_id"),
        "{spec.workspace_field}": context.get("workspace_id"),
    }}

    return jsonify(api_response(
        True,
        "{spec.model_name} list loaded.",
        data={{
            "items": [],
            "filters": filters,
            "note": "Connect this handler to your database service.",
        }},
    ))
''')

        if "get" in spec.actions:
            route_blocks.append(f'''
@{blueprint_name}.get("/<int:item_id>")
def get_{spec.resource_name}(item_id: int):
    context = get_request_context()
    if not context.get("user_id") or not context.get("workspace_id"):
        return jsonify(api_response(False, "Missing user or workspace context.", error="unauthorized")), 401

    return jsonify(api_response(
        True,
        "{spec.model_name} loaded.",
        data={{
            "id": item_id,
            "{spec.owner_field}": context.get("user_id"),
            "{spec.workspace_field}": context.get("workspace_id"),
            "note": "Connect this handler to your database service.",
        }},
    ))
''')

        if "create" in spec.actions:
            route_blocks.append(f'''
@{blueprint_name}.post("/")
def create_{spec.resource_name}():
    context = get_request_context()
    if not context.get("user_id") or not context.get("workspace_id"):
        return jsonify(api_response(False, "Missing user or workspace context.", error="unauthorized")), 401

    payload = request.get_json(silent=True) or {{}}
    record = {{
        **payload,
        "{spec.owner_field}": context.get("user_id"),
        "{spec.workspace_field}": context.get("workspace_id"),
    }}

    return jsonify(api_response(
        True,
        "{spec.model_name} create request accepted.",
        data={{"record": record}},
    ))
''')

        if "update" in spec.actions:
            route_blocks.append(f'''
@{blueprint_name}.put("/<int:item_id>")
def update_{spec.resource_name}(item_id: int):
    context = get_request_context()
    if not context.get("user_id") or not context.get("workspace_id"):
        return jsonify(api_response(False, "Missing user or workspace context.", error="unauthorized")), 401

    payload = request.get_json(silent=True) or {{}}
    record = {{
        **payload,
        "id": item_id,
        "{spec.owner_field}": context.get("user_id"),
        "{spec.workspace_field}": context.get("workspace_id"),
    }}

    return jsonify(api_response(
        True,
        "{spec.model_name} update request accepted.",
        data={{"record": record}},
    ))
''')

        if "delete" in spec.actions:
            delete_message = "soft delete request accepted" if spec.soft_delete else "delete request accepted"
            route_blocks.append(f'''
@{blueprint_name}.delete("/<int:item_id>")
def delete_{spec.resource_name}(item_id: int):
    context = get_request_context()
    if not context.get("user_id") or not context.get("workspace_id"):
        return jsonify(api_response(False, "Missing user or workspace context.", error="unauthorized")), 401

    return jsonify(api_response(
        True,
        "{spec.model_name} {delete_message}.",
        data={{
            "id": item_id,
            "soft_delete": {str(spec.soft_delete)},
            "{spec.owner_field}": context.get("user_id"),
            "{spec.workspace_field}": context.get("workspace_id"),
        }},
    ))
''')

        routes_joined = "\n".join(route_blocks)

        return f'''"""
Generated Flask CRUD blueprint for {spec.model_name}.

William/Jarvis SaaS isolation:
    - Every protected route reads X-User-ID and X-Workspace-ID.
    - Replace demo handlers with your database service.
    - Keep owner/workspace filters on every query.
"""

from __future__ import annotations

import datetime
from typing import Any, Dict

try:
    from flask import Blueprint, jsonify, request
except Exception:
    Blueprint = None
    jsonify = None
    request = None


RESOURCE_FIELDS = {fields_doc}


if Blueprint is not None:
    {blueprint_name} = Blueprint("{blueprint_name}", __name__, url_prefix="{route_prefix}")
else:
    {blueprint_name} = None


def utc_now_iso() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def api_response(success: bool, message: str, data: Dict[str, Any] | None = None, error: str | None = None) -> Dict[str, Any]:
    return {{
        "success": success,
        "message": message,
        "data": data or {{}},
        "error": error,
        "metadata": {{
            "timestamp": utc_now_iso(),
            "resource": "{spec.resource_name}",
        }},
    }}


def get_request_context() -> Dict[str, Any]:
    return {{
        "user_id": request.headers.get("X-User-ID") if request else None,
        "workspace_id": request.headers.get("X-Workspace-ID") if request else None,
        "role": request.headers.get("X-Role", "user") if request else "user",
    }}


if {blueprint_name} is not None:
{indent_text(routes_joined, 4)}
'''

    # -----------------------------------------------------------------
    # Webhook router generation
    # -----------------------------------------------------------------

    def generate_webhook_router(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        framework: str = "fastapi",
        webhook: Optional[Union[WebhookSpec, Dict[str, Any], str]] = None,
        output_dir: Optional[Union[str, Path]] = None,
        write_files: bool = False,
    ) -> Dict[str, Any]:
        framework = framework.lower()
        if framework not in SUPPORTED_FRAMEWORKS:
            return self._error_result(f"Unsupported framework: {framework}")

        spec = self._normalize_webhook(webhook)
        output = self._resolve_output_dir(output_dir)

        file_name = f"{spec.name}_webhook_router.py" if framework == "fastapi" else f"{spec.name}_webhook_blueprint.py"
        file_path = output / file_name

        content = (
            self._generate_fastapi_webhook_router_code(spec)
            if framework == "fastapi"
            else self._generate_flask_webhook_blueprint_code(spec)
        )

        generated = self._build_generated_file(
            file_name=file_name,
            file_path=file_path,
            content=content,
            framework=framework,
            route_type="webhook",
        )

        generated, security = self._maybe_write_generated_file(
            generated_file=generated,
            write_files=write_files,
            user_id=user_id,
            workspace_id=workspace_id,
            action="generate_webhook_router",
            route_type="webhook",
        )

        return self._safe_result(
            "Webhook API router generated.",
            data={
                "framework": framework,
                "route_type": "webhook",
                "webhook": spec.to_dict(),
                "generated_files": [generated.to_dict()],
                "security": security,
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )

    def _normalize_webhook(
        self,
        webhook: Optional[Union[WebhookSpec, Dict[str, Any], str]],
    ) -> WebhookSpec:
        if webhook is None:
            return WebhookSpec(name="default").normalized()

        if isinstance(webhook, WebhookSpec):
            return webhook.normalized()

        if isinstance(webhook, str):
            return WebhookSpec(name=webhook).normalized()

        if isinstance(webhook, dict):
            allowed = WebhookSpec(name="default").__dict__.keys()
            clean = {key: value for key, value in webhook.items() if key in allowed}
            return WebhookSpec(**clean).normalized()

        return WebhookSpec(name="default").normalized()

    def _generate_fastapi_webhook_router_code(self, spec: WebhookSpec) -> str:
        allowed_events = json.dumps(spec.allowed_events, indent=4)

        return f'''"""
Generated FastAPI webhook router for {spec.name}.

Security notes:
    - Store webhook secrets in environment variables or secret manager.
    - Never hardcode webhook secrets.
    - Signature verification is scaffolded for safe integration.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import os
from typing import Any, Dict, Optional

try:
    from fastapi import APIRouter, Header, Request
except Exception:
    APIRouter = None
    Header = None
    Request = None


ALLOWED_EVENTS = {allowed_events}
WEBHOOK_SECRET_ENV = "{spec.name.upper()}_WEBHOOK_SECRET"


if APIRouter is not None:
    router = APIRouter(prefix="{spec.path}", tags=["webhooks", "{spec.name}"])
else:
    router = None


def utc_now_iso() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def api_response(success: bool, message: str, data: Dict[str, Any] | None = None, error: str | None = None) -> Dict[str, Any]:
    return {{
        "success": success,
        "message": message,
        "data": data or {{}},
        "error": error,
        "metadata": {{
            "timestamp": utc_now_iso(),
            "webhook": "{spec.name}",
        }},
    }}


def verify_signature(raw_body: bytes, signature: Optional[str]) -> bool:
    secret = os.getenv(WEBHOOK_SECRET_ENV, "")
    if not secret:
        return False

    if not signature:
        return False

    digest = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    expected = f"sha256={{digest}}"

    return hmac.compare_digest(expected, signature) or hmac.compare_digest(digest, signature)


if router is not None:
    @router.post("/")
    async def receive_{spec.name}_webhook(
        request: Request,
        signature: Optional[str] = Header(default=None, alias="{spec.secret_header}"),
    ) -> Dict[str, Any]:
        raw_body = await request.body()

        if {str(spec.verify_signature)} and not verify_signature(raw_body, signature):
            return api_response(False, "Invalid webhook signature.", error="invalid_signature")

        try:
            payload = await request.json()
        except Exception:
            return api_response(False, "Invalid JSON payload.", error="invalid_json")

        event_name = payload.get("{spec.event_field}")

        if ALLOWED_EVENTS and event_name not in ALLOWED_EVENTS:
            return api_response(
                False,
                "Webhook event is not allowed.",
                error="event_not_allowed",
                data={{"event": event_name}},
            )

        return api_response(
            True,
            "Webhook received.",
            data={{
                "event": event_name,
                "payload": payload,
                "note": "Connect this handler to Workflow Agent or task queue.",
            }},
        )
'''

    def _generate_flask_webhook_blueprint_code(self, spec: WebhookSpec) -> str:
        allowed_events = json.dumps(spec.allowed_events, indent=4)
        bp_name = f"{spec.name}_webhook_bp"

        return f'''"""
Generated Flask webhook blueprint for {spec.name}.

Security notes:
    - Store webhook secrets in environment variables or secret manager.
    - Never hardcode webhook secrets.
    - Signature verification is scaffolded for safe integration.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import os
from typing import Any, Dict, Optional

try:
    from flask import Blueprint, jsonify, request
except Exception:
    Blueprint = None
    jsonify = None
    request = None


ALLOWED_EVENTS = {allowed_events}
WEBHOOK_SECRET_ENV = "{spec.name.upper()}_WEBHOOK_SECRET"


if Blueprint is not None:
    {bp_name} = Blueprint("{bp_name}", __name__, url_prefix="{spec.path}")
else:
    {bp_name} = None


def utc_now_iso() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def api_response(success: bool, message: str, data: Dict[str, Any] | None = None, error: str | None = None) -> Dict[str, Any]:
    return {{
        "success": success,
        "message": message,
        "data": data or {{}},
        "error": error,
        "metadata": {{
            "timestamp": utc_now_iso(),
            "webhook": "{spec.name}",
        }},
    }}


def verify_signature(raw_body: bytes, signature: Optional[str]) -> bool:
    secret = os.getenv(WEBHOOK_SECRET_ENV, "")
    if not secret:
        return False

    if not signature:
        return False

    digest = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    expected = f"sha256={{digest}}"

    return hmac.compare_digest(expected, signature) or hmac.compare_digest(digest, signature)


if {bp_name} is not None:
    @{bp_name}.post("/")
    def receive_{spec.name}_webhook():
        raw_body = request.get_data() if request else b""
        signature = request.headers.get("{spec.secret_header}") if request else None

        if {str(spec.verify_signature)} and not verify_signature(raw_body, signature):
            return jsonify(api_response(False, "Invalid webhook signature.", error="invalid_signature")), 401

        payload = request.get_json(silent=True) or {{}}

        event_name = payload.get("{spec.event_field}")

        if ALLOWED_EVENTS and event_name not in ALLOWED_EVENTS:
            return jsonify(api_response(
                False,
                "Webhook event is not allowed.",
                error="event_not_allowed",
                data={{"event": event_name}},
            )), 400

        return jsonify(api_response(
            True,
            "Webhook received.",
            data={{
                "event": event_name,
                "payload": payload,
                "note": "Connect this handler to Workflow Agent or task queue.",
            }},
        ))
'''

    # -----------------------------------------------------------------
    # API utils generation
    # -----------------------------------------------------------------

    def generate_api_utils(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        framework: str = "fastapi",
        output_dir: Optional[Union[str, Path]] = None,
        write_files: bool = False,
    ) -> Dict[str, Any]:
        framework = framework.lower()
        if framework not in SUPPORTED_FRAMEWORKS:
            return self._error_result(f"Unsupported framework: {framework}")

        output = self._resolve_output_dir(output_dir)
        file_name = "api_utils.py"
        file_path = output / file_name

        content = self._generate_api_utils_code(framework)

        generated = self._build_generated_file(
            file_name=file_name,
            file_path=file_path,
            content=content,
            framework=framework,
            route_type="utils",
        )

        generated, security = self._maybe_write_generated_file(
            generated_file=generated,
            write_files=write_files,
            user_id=user_id,
            workspace_id=workspace_id,
            action="generate_api_utils",
            route_type="utils",
        )

        return self._safe_result(
            "API utilities generated.",
            data={
                "framework": framework,
                "route_type": "utils",
                "generated_files": [generated.to_dict()],
                "security": security,
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )

    def _generate_api_utils_code(self, framework: str) -> str:
        return f'''"""
Generated API utilities for William/Jarvis.

Framework target: {framework}

These helpers are safe to import and can be shared by generated routers.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class RequestContext:
    user_id: Optional[str] = None
    workspace_id: Optional[str] = None
    role: str = "user"
    subscription_status: Optional[str] = None


def utc_now_iso() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def api_response(
    success: bool,
    message: str,
    data: Dict[str, Any] | None = None,
    error: str | None = None,
    metadata: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    return {{
        "success": success,
        "message": message,
        "data": data or {{}},
        "error": error,
        "metadata": {{
            "timestamp": utc_now_iso(),
            **(metadata or {{}}),
        }},
    }}


def require_context(context: RequestContext) -> Optional[Dict[str, Any]]:
    if not context.user_id:
        return api_response(False, "Missing user context.", error="missing_user_id")

    if not context.workspace_id:
        return api_response(False, "Missing workspace context.", error="missing_workspace_id")

    return None


def workspace_filter(context: RequestContext) -> Dict[str, Any]:
    return {{
        "user_id": context.user_id,
        "workspace_id": context.workspace_id,
    }}


def audit_payload(
    action: str,
    context: RequestContext,
    status: str,
    details: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    return {{
        "action": action,
        "user_id": context.user_id,
        "workspace_id": context.workspace_id,
        "role": context.role,
        "status": status,
        "details": details or {{}},
        "timestamp": utc_now_iso(),
    }}
'''

    # -----------------------------------------------------------------
    # Project API generation
    # -----------------------------------------------------------------

    def generate_project_api(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        framework: str = "fastapi",
        resources: List[Union[CRUDResourceSpec, Dict[str, Any], str]] = None,
        webhooks: List[Union[WebhookSpec, Dict[str, Any], str]] = None,
        include_auth: bool = True,
        include_health: bool = True,
        output_dir: Optional[Union[str, Path]] = None,
        write_files: bool = False,
    ) -> Dict[str, Any]:
        framework = framework.lower()
        if framework not in SUPPORTED_FRAMEWORKS:
            return self._error_result(f"Unsupported framework: {framework}")

        resources = resources or []
        webhooks = webhooks or []

        generated_files: List[Dict[str, Any]] = []
        security_payloads: List[Dict[str, Any]] = []

        utils_result = self.generate_api_utils(
            user_id=user_id,
            workspace_id=workspace_id,
            framework=framework,
            output_dir=output_dir,
            write_files=write_files,
        )
        generated_files.extend(utils_result.get("data", {}).get("generated_files", []))
        security_payloads.append(utils_result.get("data", {}).get("security", {}))

        if include_health:
            health_result = self.generate_health_router(
                user_id=user_id,
                workspace_id=workspace_id,
                framework=framework,
                output_dir=output_dir,
                write_files=write_files,
            )
            generated_files.extend(health_result.get("data", {}).get("generated_files", []))
            security_payloads.append(health_result.get("data", {}).get("security", {}))

        if include_auth:
            auth_result = self.generate_auth_router(
                user_id=user_id,
                workspace_id=workspace_id,
                framework=framework,
                output_dir=output_dir,
                write_files=write_files,
            )
            generated_files.extend(auth_result.get("data", {}).get("generated_files", []))
            security_payloads.append(auth_result.get("data", {}).get("security", {}))

        for resource in resources:
            crud_result = self.generate_crud_router(
                user_id=user_id,
                workspace_id=workspace_id,
                framework=framework,
                resource=resource,
                output_dir=output_dir,
                write_files=write_files,
            )
            generated_files.extend(crud_result.get("data", {}).get("generated_files", []))
            security_payloads.append(crud_result.get("data", {}).get("security", {}))

        for webhook in webhooks:
            webhook_result = self.generate_webhook_router(
                user_id=user_id,
                workspace_id=workspace_id,
                framework=framework,
                webhook=webhook,
                output_dir=output_dir,
                write_files=write_files,
            )
            generated_files.extend(webhook_result.get("data", {}).get("generated_files", []))
            security_payloads.append(webhook_result.get("data", {}).get("security", {}))

        manifest_result = self.generate_route_manifest(
            user_id=user_id,
            workspace_id=workspace_id,
            framework=framework,
            resources=resources,
            webhooks=webhooks,
            include_auth=include_auth,
            include_health=include_health,
        )

        return self._safe_result(
            "Project API generated.",
            data={
                "framework": framework,
                "route_type": "project_api",
                "generated_files": generated_files,
                "generated_file_count": len(generated_files),
                "route_manifest": manifest_result.get("data", {}).get("manifest", {}),
                "security": security_payloads,
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )

    # -----------------------------------------------------------------
    # Route manifest generation
    # -----------------------------------------------------------------

    def generate_route_manifest(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        framework: str = "fastapi",
        resources: List[Union[CRUDResourceSpec, Dict[str, Any], str]] = None,
        webhooks: List[Union[WebhookSpec, Dict[str, Any], str]] = None,
        include_auth: bool = True,
        include_health: bool = True,
    ) -> Dict[str, Any]:
        framework = framework.lower()
        resources = resources or []
        webhooks = webhooks or []

        route_specs: List[APIRouteSpec] = []

        if include_health:
            route_specs.extend([
                APIRouteSpec(
                    name="health_check",
                    method="GET",
                    path="/health/",
                    handler_name="health_check",
                    route_type="health",
                    auth_required=False,
                    workspace_required=False,
                    description="Health check route.",
                    tags=["health"],
                ),
                APIRouteSpec(
                    name="readiness_check",
                    method="GET",
                    path="/health/ready",
                    handler_name="readiness_check",
                    route_type="health",
                    auth_required=False,
                    workspace_required=False,
                    description="Readiness check route.",
                    tags=["health"],
                ),
            ])

        if include_auth:
            route_specs.extend([
                APIRouteSpec("signup", "POST", "/auth/signup", "signup", "auth", False, False, description="Create account.", tags=["auth"]),
                APIRouteSpec("login", "POST", "/auth/login", "login", "auth", False, False, description="Login user.", tags=["auth"]),
                APIRouteSpec("logout", "POST", "/auth/logout", "logout", "auth", True, True, description="Logout user.", tags=["auth"]),
                APIRouteSpec("me", "GET", "/auth/me", "me", "auth", True, True, description="Get current user.", tags=["auth"]),
                APIRouteSpec("refresh_token", "POST", "/auth/refresh", "refresh_token", "auth", False, False, description="Refresh token.", tags=["auth"]),
            ])

        for resource in resources:
            spec = self._normalize_crud_resource(resource)
            route_specs.extend(self._crud_routes_manifest(spec))

        for webhook in webhooks:
            spec = self._normalize_webhook(webhook)
            route_specs.append(APIRouteSpec(
                name=f"receive_{spec.name}_webhook",
                method="POST",
                path=spec.path or f"/webhooks/{spec.name}",
                handler_name=f"receive_{spec.name}_webhook",
                route_type="webhook",
                auth_required=spec.auth_required,
                workspace_required=spec.workspace_required,
                description=f"Receive {spec.name} webhook.",
                tags=["webhooks", spec.name],
            ))

        manifest = {
            "framework": framework,
            "generated_at": utc_now_iso(),
            "route_count": len(route_specs),
            "routes": [route.to_dict() for route in route_specs],
        }

        return self._safe_result(
            "Route manifest generated.",
            data={
                "framework": framework,
                "route_type": "manifest",
                "manifest": manifest,
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )


# ---------------------------------------------------------------------
# Public module helpers
# ---------------------------------------------------------------------

def create_api_builder(
    default_output_dir: Optional[Union[str, Path]] = None,
) -> APIBuilder:
    """
    Factory helper for Agent Loader / Registry.
    """
    return APIBuilder(default_output_dir=default_output_dir)


def get_agent_metadata() -> Dict[str, Any]:
    """
    Agent Registry compatible metadata.
    """
    return {
        "agent_name": "APIBuilder",
        "agent_type": "code_agent",
        "class_name": "APIBuilder",
        "version": APIBuilder.VERSION,
        "file_path": "agents/code_agent/api_builder.py",
        "description": "Generates REST APIs, auth routes, CRUD routers, webhooks, Flask blueprints, and FastAPI routers.",
        "supports_user_workspace_isolation": True,
        "requires_security_for_file_writes": True,
        "compatible_with_master_agent": True,
        "compatible_with_registry": True,
        "compatible_with_dashboard": True,
        "supported_frameworks": sorted(SUPPORTED_FRAMEWORKS),
        "supported_actions": APIBuilder().supported_actions(),
    }


__all__ = [
    "APIBuilder",
    "APIRouteSpec",
    "CRUDResourceSpec",
    "AuthConfig",
    "WebhookSpec",
    "GeneratedAPIFile",
    "create_api_builder",
    "get_agent_metadata",
    "safe_slug",
    "safe_identifier",
    "pascal_case",
]