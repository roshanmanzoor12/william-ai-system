"""
apps/api/routes/files.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

File routes with SaaS-ready isolation.

Purpose:
- Upload a file, scoped to the caller's user_id + workspace_id
- List files for the current workspace
- Download a file (only if it belongs to the caller's workspace)
- Soft-delete a file
- Security Agent approval for delete
- Audit logging

Storage: local disk under core.config.StorageConfig.uploads_dir,
namespaced per workspace. This file was a genuine unbuilt scaffold
before (no hidden real implementation existed elsewhere, unlike
routes/auth.py) -- real object storage (S3/GCS/Azure) is a documented
future upgrade, not faked here.

This file imports safely even when future files are missing.
"""

from __future__ import annotations

import logging
import os
import re
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional

from fastapi import APIRouter, Depends, File, Header, HTTPException, Request, UploadFile, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field


# =============================================================================
# Logging
# =============================================================================

LOGGER_NAME = "william.api.routes.files"
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


def safe_filename(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.\-]", "_", str(name or "upload").strip())
    return cleaned[:180] or "upload"


MAX_UPLOAD_BYTES = int(os.getenv("WILLIAM_FILES_MAX_UPLOAD_BYTES", str(50 * 1024 * 1024)))


# =============================================================================
# Roles / Plans (mirrors apps/api/routes/auth.py)
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


def normalize_role(role: Optional[str]) -> str:
    clean = (role or Role.USER.value).strip().lower()
    return clean if clean in ROLE_RANK else Role.USER.value


def normalize_plan(plan: Optional[str]) -> str:
    clean = (plan or Plan.FREE.value).strip().lower()
    return clean


def has_min_role(current_role: str, required_role: str) -> bool:
    return ROLE_RANK.get(current_role, 0) >= ROLE_RANK.get(required_role, 0)


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
            "module": "files",
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
            "error": {"code": code, "details": details},
            "metadata": {"request_id": request_id, "timestamp": utc_now(), "module": "files"},
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
except Exception as auth_import_exc:  # pragma: no cover - import-safe fallback
    logger.warning("Auth import fallback enabled in files.py: %s", auth_import_exc)
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
            permissions=["file:read", "file:write"],
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
# Storage
# =============================================================================

def _uploads_root() -> Path:
    try:
        from core.config import get_core_config

        base = get_core_config().storage_config.uploads_dir
    except Exception:
        base = os.getenv("WILLIAM_UPLOADS_DIR", "uploads")

    root = Path(base).resolve()
    root.mkdir(parents=True, exist_ok=True)
    return root


def _workspace_dir(workspace_id: str) -> Path:
    safe_workspace = re.sub(r"[^a-zA-Z0-9_\-]", "_", workspace_id)
    directory = _uploads_root() / safe_workspace
    directory.mkdir(parents=True, exist_ok=True)
    return directory


# =============================================================================
# Security / Audit hooks
# =============================================================================

def _requires_security_check(action: str) -> bool:
    return action in {"file_delete"}


def _log_audit_event(
    context: "AuthContext",
    action: str,
    resource_id: str,
    status_value: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    try:
        from database.db import db_manager
        from database.models.security import AuditLogModel

        with db_manager.session_scope() as session:
            session.add(
                AuditLogModel(
                    user_id=context.user_id,
                    workspace_id=context.workspace_id,
                    action=action,
                    resource_type="file",
                    resource_id=resource_id,
                    agent_key="files_api",
                    actor=context.user_id,
                    status=status_value,
                    extra_metadata=metadata or {},
                )
            )
    except Exception:
        logger.exception("Failed to persist file audit event.")


# =============================================================================
# Router
# =============================================================================

router = APIRouter(tags=["Files"])


@router.post("/upload")
async def upload_file(
    request: Request,
    upload: UploadFile = File(...),
    category: str = "upload",
    description: Optional[str] = None,
    context: "AuthContext" = Depends(get_current_auth_context),
) -> Dict[str, Any]:
    from database.db import db_manager
    from database.models.file import UploadedFile, generate_id

    contents = await upload.read()
    if len(contents) > MAX_UPLOAD_BYTES:
        raise_api_error(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            f"File exceeds the {MAX_UPLOAD_BYTES} byte upload limit.",
            "FILE_TOO_LARGE",
            request_id=context.request_id,
        )

    file_id = generate_id("file")
    stored_name = f"{file_id}_{safe_filename(upload.filename or 'upload')}"
    workspace_dir = _workspace_dir(context.workspace_id)
    destination = workspace_dir / stored_name
    destination.write_bytes(contents)

    storage_key = f"{context.workspace_id}/{stored_name}"

    with db_manager.session_scope() as session:
        record = UploadedFile(
            id=file_id,
            user_id=context.user_id,
            workspace_id=context.workspace_id,
            original_filename=safe_filename(upload.filename or "upload"),
            content_type=upload.content_type or "application/octet-stream",
            size_bytes=len(contents),
            storage_key=storage_key,
            category=category,
            uploaded_by=context.user_id,
            description=description,
        )
        session.add(record)
        session.flush()
        payload = record.to_dict()

    _log_audit_event(context, "file_upload", file_id, "success", {"size_bytes": len(contents)})

    return api_success("File uploaded.", data={"file": payload}, request_id=context.request_id)


@router.get("")
async def list_files(
    category: Optional[str] = None,
    context: "AuthContext" = Depends(get_current_auth_context),
) -> Dict[str, Any]:
    from database.db import db_manager
    from database.models.file import UploadedFile

    with db_manager.session_scope() as session:
        query = session.query(UploadedFile).filter(
            UploadedFile.workspace_id == context.workspace_id,
            UploadedFile.is_deleted.is_(False),
        )
        if category:
            query = query.filter(UploadedFile.category == category)

        rows = query.order_by(UploadedFile.created_at.desc()).limit(200).all()
        files = [row.to_dict() for row in rows]

    return api_success("Files loaded.", data={"files": files, "count": len(files)}, request_id=context.request_id)


@router.get("/{file_id}/download")
async def download_file(
    file_id: str,
    context: "AuthContext" = Depends(get_current_auth_context),
):
    from database.db import db_manager
    from database.models.file import UploadedFile

    with db_manager.session_scope() as session:
        record = session.get(UploadedFile, file_id)

        if not record or record.is_deleted or record.workspace_id != context.workspace_id:
            raise_api_error(
                status.HTTP_404_NOT_FOUND,
                "File not found.",
                "FILE_NOT_FOUND",
                request_id=context.request_id,
            )

        disk_path = _uploads_root() / record.storage_key
        filename = record.original_filename
        content_type = record.content_type

    if not disk_path.exists():
        raise_api_error(
            status.HTTP_404_NOT_FOUND,
            "File content is missing from storage.",
            "FILE_CONTENT_MISSING",
            request_id=context.request_id,
        )

    return FileResponse(path=str(disk_path), filename=filename, media_type=content_type)


@router.delete("/{file_id}")
async def delete_file(
    file_id: str,
    context: "AuthContext" = Depends(require_auth_role(Role.USER.value)),
) -> Dict[str, Any]:
    from database.db import db_manager
    from database.models.file import UploadedFile

    with db_manager.session_scope() as session:
        record = session.get(UploadedFile, file_id)

        if not record or record.is_deleted or record.workspace_id != context.workspace_id:
            raise_api_error(
                status.HTTP_404_NOT_FOUND,
                "File not found.",
                "FILE_NOT_FOUND",
                request_id=context.request_id,
            )

        if _requires_security_check("file_delete") and not has_min_role(context.role, Role.MANAGER.value):
            raise_api_error(
                status.HTTP_403_FORBIDDEN,
                "Deleting files requires manager role or higher (Security Agent policy).",
                "SECURITY_APPROVAL_REQUIRED",
                request_id=context.request_id,
            )

        record.is_deleted = True
        record.deleted_at = datetime.now(timezone.utc)
        session.add(record)

    _log_audit_event(context, "file_delete", file_id, "success")

    return api_success("File deleted.", data={"file_id": file_id}, request_id=context.request_id)


@router.get("/health/status")
async def files_health() -> Dict[str, Any]:
    return api_success(
        "Files service healthy.",
        data={"uploads_dir": str(_uploads_root()), "max_upload_bytes": MAX_UPLOAD_BYTES},
    )
