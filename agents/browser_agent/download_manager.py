"""
agents/browser_agent/download_manager.py

DownloadManager for the William / Jarvis Browser Agent.

Purpose:
    Download public PDFs, reports, and browser assets safely, organize them inside
    user/workspace-isolated storage, and return structured results that can be
    routed through Master Agent, Security Agent, Verification Agent, Memory Agent,
    Dashboard/API, and Registry flows.

Design goals:
    - Import-safe even if the rest of the William system is not installed yet.
    - SaaS-safe: every download is isolated by user_id and workspace_id.
    - Security-first: blocks private/local/internal URLs, unsafe schemes, path
      traversal, oversized downloads, suspicious extensions, and destructive IO.
    - Agent-compatible: exposes common hooks used across William/Jarvis agents.
    - Testable: uses dependency-light standard library with optional `requests`.
"""

from __future__ import annotations

import contextlib
import dataclasses
import datetime as _dt
import hashlib
import ipaddress
import json
import logging
import mimetypes
import os
import re
import shutil
import socket
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union
from urllib.parse import unquote, urlparse

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover - optional dependency fallback
    requests = None  # type: ignore

try:
    from urllib.request import Request, urlopen
    from urllib.error import HTTPError, URLError
except Exception:  # pragma: no cover - stdlib should exist, kept import-safe
    Request = None  # type: ignore
    urlopen = None  # type: ignore
    HTTPError = Exception  # type: ignore
    URLError = Exception  # type: ignore


# ---------------------------------------------------------------------------
# Optional William/Jarvis BaseAgent compatibility
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for standalone import

    class BaseAgent:  # type: ignore
        """
        Minimal fallback BaseAgent.

        The real project should provide agents/base_agent.py. This fallback keeps
        this file importable during early module generation and isolated tests.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)

        def run(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
            raise NotImplementedError("Fallback BaseAgent does not implement run().")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_ALLOWED_EXTENSIONS = {
    ".pdf",
    ".csv",
    ".txt",
    ".json",
    ".xml",
    ".html",
    ".htm",
    ".md",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".png",
    ".jpg",
    ".jpeg",
    ".webp",
    ".gif",
    ".svg",
    ".zip",
}

DEFAULT_BLOCKED_EXTENSIONS = {
    ".exe",
    ".dll",
    ".bat",
    ".cmd",
    ".com",
    ".msi",
    ".scr",
    ".ps1",
    ".vbs",
    ".js",
    ".jar",
    ".sh",
    ".bash",
    ".zsh",
    ".apk",
    ".ipa",
    ".dmg",
    ".pkg",
    ".deb",
    ".rpm",
    ".iso",
}

DEFAULT_ALLOWED_SCHEMES = {"http", "https"}

DEFAULT_TIMEOUT_SECONDS = 30
DEFAULT_CONNECT_TIMEOUT_SECONDS = 10
DEFAULT_MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB
DEFAULT_CHUNK_SIZE_BYTES = 1024 * 128
DEFAULT_MAX_REDIRECTS = 5

SAFE_NAME_PATTERN = re.compile(r"[^A-Za-z0-9._\-]+")


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class DownloadContext:
    """
    SaaS execution context.

    Every public method that touches files should either receive this object or a
    dict containing user_id and workspace_id. This prevents cross-workspace file,
    task, log, analytics, memory, or audit mixing.
    """

    user_id: Union[str, int]
    workspace_id: Union[str, int]
    role: Optional[str] = None
    request_id: Optional[str] = None
    task_id: Optional[str] = None
    permissions: Optional[Sequence[str]] = None
    metadata: Optional[Mapping[str, Any]] = None

    def normalized_user_id(self) -> str:
        return _safe_identifier(str(self.user_id), fallback="user")

    def normalized_workspace_id(self) -> str:
        return _safe_identifier(str(self.workspace_id), fallback="workspace")


@dataclasses.dataclass(frozen=True)
class DownloadPolicy:
    """
    Download rules controlled by Browser Agent / Security Agent.

    Dashboard/API can expose a safe subset of these options later. Sensitive
    changes should be approved through Security Agent before execution.
    """

    allowed_schemes: Sequence[str] = dataclasses.field(
        default_factory=lambda: tuple(DEFAULT_ALLOWED_SCHEMES)
    )
    allowed_extensions: Sequence[str] = dataclasses.field(
        default_factory=lambda: tuple(sorted(DEFAULT_ALLOWED_EXTENSIONS))
    )
    blocked_extensions: Sequence[str] = dataclasses.field(
        default_factory=lambda: tuple(sorted(DEFAULT_BLOCKED_EXTENSIONS))
    )
    max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    connect_timeout_seconds: int = DEFAULT_CONNECT_TIMEOUT_SECONDS
    chunk_size_bytes: int = DEFAULT_CHUNK_SIZE_BYTES
    max_redirects: int = DEFAULT_MAX_REDIRECTS
    require_public_ip: bool = True
    allow_unknown_extension: bool = False
    allow_overwrite: bool = False
    verify_tls: bool = True
    user_agent: str = (
        "WilliamJarvisBrowserAgent/1.0 "
        "(safe public document downloader; +https://digitalpromotix.dev)"
    )


@dataclasses.dataclass
class DownloadTarget:
    """
    A normalized download target generated from URL and optional user filename.
    """

    url: str
    safe_filename: str
    extension: str
    category: str
    content_type_hint: Optional[str] = None


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _utc_now_iso() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).isoformat()


def _safe_identifier(value: str, fallback: str = "item") -> str:
    value = str(value or "").strip()
    value = SAFE_NAME_PATTERN.sub("_", value)
    value = value.strip("._-")
    return value[:80] or fallback


def _safe_filename(value: str, fallback: str = "download") -> str:
    value = unquote(str(value or "")).split("?")[0].split("#")[0]
    value = value.replace("\\", "/").split("/")[-1]
    value = value.strip().strip(".")
    value = SAFE_NAME_PATTERN.sub("_", value)
    value = value[:180].strip("._-")
    return value or fallback


def _extension_from_filename(filename: str) -> str:
    return Path(filename).suffix.lower().strip()


def _category_from_extension(extension: str, content_type: Optional[str] = None) -> str:
    ext = extension.lower()

    if ext == ".pdf":
        return "pdfs"
    if ext in {".doc", ".docx", ".txt", ".md", ".html", ".htm", ".xml"}:
        return "documents"
    if ext in {".csv", ".xls", ".xlsx", ".json"}:
        return "data"
    if ext in {".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg"}:
        return "images"
    if ext in {".ppt", ".pptx"}:
        return "presentations"
    if ext == ".zip":
        return "archives"

    content_type = (content_type or "").lower()
    if "pdf" in content_type:
        return "pdfs"
    if content_type.startswith("image/"):
        return "images"
    if "json" in content_type or "csv" in content_type or "spreadsheet" in content_type:
        return "data"
    if "text" in content_type or "html" in content_type or "xml" in content_type:
        return "documents"

    return "assets"


def _guess_extension_from_content_type(content_type: Optional[str]) -> str:
    if not content_type:
        return ""

    content_type = content_type.split(";")[0].strip().lower()
    explicit = {
        "application/pdf": ".pdf",
        "text/csv": ".csv",
        "application/json": ".json",
        "text/plain": ".txt",
        "text/html": ".html",
        "application/xml": ".xml",
        "text/xml": ".xml",
        "image/jpeg": ".jpg",
        "image/png": ".png",
        "image/webp": ".webp",
        "image/gif": ".gif",
        "image/svg+xml": ".svg",
        "application/zip": ".zip",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation": ".pptx",
    }
    if content_type in explicit:
        return explicit[content_type]

    guessed = mimetypes.guess_extension(content_type)
    return (guessed or "").lower()


def _sha256_file(path: Path, chunk_size: int = DEFAULT_CHUNK_SIZE_BYTES) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _json_safe(value: Any) -> Any:
    try:
        json.dumps(value)
        return value
    except Exception:
        return repr(value)


def _coerce_context(context: Union[DownloadContext, Mapping[str, Any]]) -> DownloadContext:
    if isinstance(context, DownloadContext):
        return context

    user_id = context.get("user_id") if isinstance(context, Mapping) else None
    workspace_id = context.get("workspace_id") if isinstance(context, Mapping) else None

    return DownloadContext(
        user_id=user_id or "",
        workspace_id=workspace_id or "",
        role=context.get("role") if isinstance(context, Mapping) else None,
        request_id=context.get("request_id") if isinstance(context, Mapping) else None,
        task_id=context.get("task_id") if isinstance(context, Mapping) else None,
        permissions=context.get("permissions") if isinstance(context, Mapping) else None,
        metadata=context.get("metadata") if isinstance(context, Mapping) else None,
    )


def _is_ip_private_or_local(hostname: str) -> bool:
    """
    Return True if hostname resolves to private, loopback, link-local, multicast,
    reserved, unspecified, or otherwise internal IP addresses.

    This is an SSRF protection layer for Browser Agent downloads.
    """

    try:
        ip_obj = ipaddress.ip_address(hostname)
        return (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        )
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return True

    if not infos:
        return True

    for info in infos:
        address = info[4][0]
        try:
            ip_obj = ipaddress.ip_address(address)
        except ValueError:
            return True

        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        ):
            return True

    return False


def _extract_filename_from_content_disposition(content_disposition: Optional[str]) -> str:
    if not content_disposition:
        return ""

    # Supports simple filename= and RFC 5987 filename*=UTF-8''...
    match = re.search(r"filename\*=([^']*)''([^;]+)", content_disposition, re.I)
    if match:
        return _safe_filename(unquote(match.group(2)))

    match = re.search(r'filename="?([^";]+)"?', content_disposition, re.I)
    if match:
        return _safe_filename(match.group(1))

    return ""


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class DownloadManager(BaseAgent):
    """
    Browser Agent helper for safe public downloads.

    How it connects to William/Jarvis:
        - Master Agent / Router:
            Calls `run()` or public methods such as `download_file()` and
            `download_many()` with a task context.
        - Security Agent:
            `download_file()` evaluates `_requires_security_check()` and calls
            `_request_security_approval()` before network IO.
        - Verification Agent:
            Every successful download includes `_prepare_verification_payload()`
            metadata: path, checksum, file size, URL, and isolation context.
        - Memory Agent:
            `_prepare_memory_payload()` creates safe memory-compatible summaries
            without storing sensitive content.
        - Dashboard/API:
            Structured results are JSON-safe and include manifest-friendly data.
        - Registry/Loader:
            The class is import-safe and can be registered as `DownloadManager`.
    """

    agent_type = "browser_agent.download_manager"
    public_methods = (
        "download_file",
        "download_many",
        "list_downloads",
        "get_download_manifest",
        "delete_download",
        "run",
    )

    def __init__(
        self,
        base_download_dir: Union[str, Path] = "storage/downloads",
        policy: Optional[DownloadPolicy] = None,
        security_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        event_emitter: Optional[Any] = None,
        logger: Optional[logging.Logger] = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.agent_name = "DownloadManager"
        self.base_download_dir = Path(base_download_dir).expanduser().resolve()
        self.policy = policy or DownloadPolicy()
        self.security_agent = security_agent
        self.verification_agent = verification_agent
        self.memory_agent = memory_agent
        self.audit_logger = audit_logger
        self.event_emitter = event_emitter
        self.logger = logger or logging.getLogger("william.browser.download_manager")

        self.base_download_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, task: Mapping[str, Any], context: Union[DownloadContext, Mapping[str, Any]]) -> Dict[str, Any]:
        """
        Master Agent compatible entry point.

        Supported task actions:
            - download_file
            - download_many
            - list_downloads
            - get_download_manifest
            - delete_download
        """

        try:
            action = str(task.get("action") or task.get("type") or "download_file").strip()
            if action == "download_file":
                return self.download_file(
                    url=str(task.get("url") or ""),
                    context=context,
                    filename=task.get("filename"),
                    subfolder=task.get("subfolder"),
                    metadata=task.get("metadata"),
                )

            if action == "download_many":
                urls = task.get("urls") or []
                return self.download_many(
                    urls=urls,
                    context=context,
                    subfolder=task.get("subfolder"),
                    metadata=task.get("metadata"),
                )

            if action == "list_downloads":
                return self.list_downloads(context=context, category=task.get("category"))

            if action == "get_download_manifest":
                return self.get_download_manifest(context=context)

            if action == "delete_download":
                return self.delete_download(
                    context=context,
                    relative_path=str(task.get("relative_path") or ""),
                )

            return self._error_result(
                message=f"Unsupported DownloadManager action: {action}",
                error_code="unsupported_action",
                metadata={"action": action},
            )
        except Exception as exc:
            self.logger.exception("DownloadManager run failed")
            return self._error_result(
                message="DownloadManager task failed.",
                error=exc,
                error_code="run_failed",
            )

    def download_file(
        self,
        url: str,
        context: Union[DownloadContext, Mapping[str, Any]],
        filename: Optional[str] = None,
        subfolder: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Download one public file safely.

        Args:
            url: Public HTTP/HTTPS URL.
            context: DownloadContext or dict with user_id and workspace_id.
            filename: Optional safe custom filename.
            subfolder: Optional extra folder under the detected category.
            metadata: Optional task metadata from Master Agent/Dashboard.

        Returns:
            Structured dict with success, message, data, error, and metadata.
        """

        started_at = time.time()
        ctx = _coerce_context(context)
        metadata = dict(metadata or {})

        context_result = self._validate_task_context(ctx)
        if not context_result["success"]:
            return context_result

        validation = self.validate_url(url)
        if not validation["success"]:
            self._log_audit_event(
                event_type="download_rejected",
                context=ctx,
                details={"url": url, "reason": validation.get("error")},
            )
            return validation

        target_probe = self._build_download_target(
            url=url,
            filename=filename,
            content_type_hint=None,
        )
        if not target_probe["success"]:
            return target_probe

        if self._requires_security_check(action="download_file", url=url, context=ctx, metadata=metadata):
            approval = self._request_security_approval(
                action="download_file",
                context=ctx,
                payload={
                    "url": url,
                    "filename": filename,
                    "subfolder": subfolder,
                    "policy": dataclasses.asdict(self.policy),
                    "metadata": metadata,
                },
            )
            if not approval.get("approved"):
                return self._error_result(
                    message="Security approval denied for download.",
                    error_code="security_denied",
                    metadata={
                        "security": approval,
                        "url": url,
                    },
                )

        self._emit_agent_event(
            event_type="download_started",
            context=ctx,
            payload={"url": url, "filename": filename, "metadata": metadata},
        )

        try:
            response_meta, temp_path = self._download_to_temp(url=url)
            content_type = response_meta.get("content_type")
            content_disposition_name = _extract_filename_from_content_disposition(
                response_meta.get("content_disposition")
            )

            final_filename = filename or content_disposition_name or target_probe["data"]["safe_filename"]
            target_result = self._build_download_target(
                url=url,
                filename=final_filename,
                content_type_hint=content_type,
            )
            if not target_result["success"]:
                with contextlib.suppress(Exception):
                    temp_path.unlink(missing_ok=True)
                return target_result

            target = target_result["data"]["target"]
            final_path = self._final_path_for_target(
                context=ctx,
                target=target,
                subfolder=subfolder,
            )

            final_path.parent.mkdir(parents=True, exist_ok=True)
            if final_path.exists() and not self.policy.allow_overwrite:
                final_path = self._deduplicate_path(final_path)

            shutil.move(str(temp_path), str(final_path))

            file_size = final_path.stat().st_size
            checksum = _sha256_file(final_path, chunk_size=self.policy.chunk_size_bytes)
            relative_path = str(final_path.relative_to(self.base_download_dir))

            item = {
                "download_id": str(uuid.uuid4()),
                "url": url,
                "filename": final_path.name,
                "original_filename": final_filename,
                "extension": final_path.suffix.lower(),
                "category": target.category,
                "content_type": content_type,
                "size_bytes": file_size,
                "sha256": checksum,
                "absolute_path": str(final_path),
                "relative_path": relative_path,
                "user_id": ctx.normalized_user_id(),
                "workspace_id": ctx.normalized_workspace_id(),
                "downloaded_at": _utc_now_iso(),
                "duration_seconds": round(time.time() - started_at, 4),
                "http": {
                    "status_code": response_meta.get("status_code"),
                    "final_url": response_meta.get("final_url"),
                    "content_length": response_meta.get("content_length"),
                },
                "metadata": _json_safe(metadata),
            }

            self._append_manifest(context=ctx, item=item)

            verification_payload = self._prepare_verification_payload(
                action="download_file",
                context=ctx,
                data=item,
            )
            memory_payload = self._prepare_memory_payload(
                action="download_file",
                context=ctx,
                data=item,
            )

            self._log_audit_event(
                event_type="download_completed",
                context=ctx,
                details={
                    "url": url,
                    "relative_path": relative_path,
                    "size_bytes": file_size,
                    "sha256": checksum,
                },
            )
            self._emit_agent_event(
                event_type="download_completed",
                context=ctx,
                payload={
                    "url": url,
                    "relative_path": relative_path,
                    "size_bytes": file_size,
                    "verification": verification_payload,
                },
            )

            return self._safe_result(
                message="File downloaded safely.",
                data={
                    "download": item,
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                metadata={
                    "agent": self.agent_name,
                    "policy": {
                        "max_file_size_bytes": self.policy.max_file_size_bytes,
                        "allowed_extensions": list(self.policy.allowed_extensions),
                    },
                },
            )
        except Exception as exc:
            self.logger.exception("Download failed for URL: %s", url)
            self._log_audit_event(
                event_type="download_failed",
                context=ctx,
                details={"url": url, "error": repr(exc)},
            )
            self._emit_agent_event(
                event_type="download_failed",
                context=ctx,
                payload={"url": url, "error": repr(exc)},
            )
            return self._error_result(
                message="File download failed.",
                error=exc,
                error_code="download_failed",
                metadata={"url": url},
            )

    def download_many(
        self,
        urls: Iterable[Union[str, Mapping[str, Any]]],
        context: Union[DownloadContext, Mapping[str, Any]],
        subfolder: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Download multiple public files safely.

        `urls` may contain either strings or dicts like:
            {"url": "https://example.com/file.pdf", "filename": "report.pdf"}

        Downloads are processed sequentially for predictable audit and rate safety.
        """

        ctx = _coerce_context(context)
        validation = self._validate_task_context(ctx)
        if not validation["success"]:
            return validation

        results: List[Dict[str, Any]] = []
        success_count = 0
        failed_count = 0

        for item in urls:
            if isinstance(item, Mapping):
                item_url = str(item.get("url") or "")
                item_filename = item.get("filename")
                item_subfolder = item.get("subfolder", subfolder)
                item_meta = dict(metadata or {})
                item_meta.update(dict(item.get("metadata") or {}))
            else:
                item_url = str(item)
                item_filename = None
                item_subfolder = subfolder
                item_meta = dict(metadata or {})

            result = self.download_file(
                url=item_url,
                context=ctx,
                filename=str(item_filename) if item_filename else None,
                subfolder=str(item_subfolder) if item_subfolder else None,
                metadata=item_meta,
            )
            results.append(result)
            if result.get("success"):
                success_count += 1
            else:
                failed_count += 1

        return self._safe_result(
            message="Batch download completed.",
            data={
                "results": results,
                "success_count": success_count,
                "failed_count": failed_count,
                "total": success_count + failed_count,
            },
            metadata={
                "agent": self.agent_name,
                "context": {
                    "user_id": ctx.normalized_user_id(),
                    "workspace_id": ctx.normalized_workspace_id(),
                },
            },
        )

    def validate_url(self, url: str) -> Dict[str, Any]:
        """
        Validate URL before download.

        Blocks:
            - Empty/non-string URLs
            - Non-http(s) schemes
            - Missing hostname
            - Local/private/internal/reserved hosts
            - Unsafe file extensions
        """

        try:
            url = str(url or "").strip()
            if not url:
                return self._error_result(
                    message="URL is required.",
                    error_code="missing_url",
                )

            parsed = urlparse(url)
            scheme = parsed.scheme.lower()
            hostname = parsed.hostname or ""

            if scheme not in set(self.policy.allowed_schemes):
                return self._error_result(
                    message="Only public HTTP/HTTPS downloads are allowed.",
                    error_code="blocked_scheme",
                    metadata={"scheme": scheme},
                )

            if not hostname:
                return self._error_result(
                    message="URL hostname is missing.",
                    error_code="missing_hostname",
                )

            if self.policy.require_public_ip and _is_ip_private_or_local(hostname):
                return self._error_result(
                    message="Private, local, reserved, or internal URLs are blocked.",
                    error_code="blocked_private_host",
                    metadata={"hostname": hostname},
                )

            path_name = _safe_filename(parsed.path, fallback="")
            extension = _extension_from_filename(path_name)

            if extension and extension in set(self.policy.blocked_extensions):
                return self._error_result(
                    message="This file type is blocked by download policy.",
                    error_code="blocked_extension",
                    metadata={"extension": extension},
                )

            if extension and extension not in set(self.policy.allowed_extensions):
                return self._error_result(
                    message="This file extension is not allowed by download policy.",
                    error_code="extension_not_allowed",
                    metadata={"extension": extension},
                )

            return self._safe_result(
                message="URL passed validation.",
                data={
                    "url": url,
                    "scheme": scheme,
                    "hostname": hostname,
                    "extension": extension,
                },
            )
        except Exception as exc:
            return self._error_result(
                message="URL validation failed.",
                error=exc,
                error_code="url_validation_failed",
                metadata={"url": url},
            )

    def list_downloads(
        self,
        context: Union[DownloadContext, Mapping[str, Any]],
        category: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        List downloads for a user/workspace only.
        """

        ctx = _coerce_context(context)
        validation = self._validate_task_context(ctx)
        if not validation["success"]:
            return validation

        root = self._workspace_root(ctx)
        if category:
            root = root / _safe_identifier(category, fallback="assets")

        items: List[Dict[str, Any]] = []
        if root.exists():
            for path in sorted(root.rglob("*")):
                if not path.is_file() or path.name == "download_manifest.jsonl":
                    continue
                with contextlib.suppress(Exception):
                    rel = str(path.relative_to(self.base_download_dir))
                    items.append(
                        {
                            "filename": path.name,
                            "relative_path": rel,
                            "absolute_path": str(path),
                            "size_bytes": path.stat().st_size,
                            "extension": path.suffix.lower(),
                            "modified_at": _dt.datetime.fromtimestamp(
                                path.stat().st_mtime,
                                tz=_dt.timezone.utc,
                            ).isoformat(),
                        }
                    )

        return self._safe_result(
            message="Downloads listed.",
            data={
                "items": items,
                "count": len(items),
                "category": category,
            },
            metadata={
                "user_id": ctx.normalized_user_id(),
                "workspace_id": ctx.normalized_workspace_id(),
            },
        )

    def get_download_manifest(
        self,
        context: Union[DownloadContext, Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """
        Read the JSONL manifest for the current user/workspace.
        """

        ctx = _coerce_context(context)
        validation = self._validate_task_context(ctx)
        if not validation["success"]:
            return validation

        manifest_path = self._manifest_path(ctx)
        items: List[Dict[str, Any]] = []

        if manifest_path.exists():
            with manifest_path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        items.append(json.loads(line))
                    except json.JSONDecodeError:
                        self.logger.warning("Skipping invalid manifest line in %s", manifest_path)

        return self._safe_result(
            message="Download manifest loaded.",
            data={
                "manifest_path": str(manifest_path),
                "items": items,
                "count": len(items),
            },
            metadata={
                "user_id": ctx.normalized_user_id(),
                "workspace_id": ctx.normalized_workspace_id(),
            },
        )

    def delete_download(
        self,
        context: Union[DownloadContext, Mapping[str, Any]],
        relative_path: str,
    ) -> Dict[str, Any]:
        """
        Delete one downloaded file inside the current user/workspace folder only.

        This is intentionally restricted and auditable. It does not delete outside
        storage/downloads/users/<user_id>/workspaces/<workspace_id>/.
        """

        ctx = _coerce_context(context)
        validation = self._validate_task_context(ctx)
        if not validation["success"]:
            return validation

        if self._requires_security_check(
            action="delete_download",
            url=None,
            context=ctx,
            metadata={"relative_path": relative_path},
        ):
            approval = self._request_security_approval(
                action="delete_download",
                context=ctx,
                payload={"relative_path": relative_path},
            )
            if not approval.get("approved"):
                return self._error_result(
                    message="Security approval denied for delete.",
                    error_code="security_denied",
                    metadata={"security": approval},
                )

        try:
            relative_path = str(relative_path or "").strip()
            if not relative_path:
                return self._error_result(
                    message="relative_path is required.",
                    error_code="missing_relative_path",
                )

            candidate = (self.base_download_dir / relative_path).resolve()
            workspace_root = self._workspace_root(ctx).resolve()

            if not str(candidate).startswith(str(workspace_root)):
                return self._error_result(
                    message="Delete path is outside the current workspace.",
                    error_code="path_escape_blocked",
                )

            if not candidate.exists() or not candidate.is_file():
                return self._error_result(
                    message="Download file not found.",
                    error_code="file_not_found",
                    metadata={"relative_path": relative_path},
                )

            size_bytes = candidate.stat().st_size
            candidate.unlink()

            self._log_audit_event(
                event_type="download_deleted",
                context=ctx,
                details={"relative_path": relative_path, "size_bytes": size_bytes},
            )
            self._emit_agent_event(
                event_type="download_deleted",
                context=ctx,
                payload={"relative_path": relative_path, "size_bytes": size_bytes},
            )

            return self._safe_result(
                message="Download deleted.",
                data={
                    "relative_path": relative_path,
                    "size_bytes": size_bytes,
                    "deleted": True,
                },
            )
        except Exception as exc:
            return self._error_result(
                message="Download delete failed.",
                error=exc,
                error_code="delete_failed",
                metadata={"relative_path": relative_path},
            )

    # ------------------------------------------------------------------
    # Download internals
    # ------------------------------------------------------------------

    def _download_to_temp(self, url: str) -> Tuple[Dict[str, Any], Path]:
        """
        Stream a URL into a temporary file with size enforcement.
        """

        temp_dir = Path(tempfile.mkdtemp(prefix="william_download_"))
        temp_path = temp_dir / "download.tmp"

        try:
            if requests is not None:
                return self._download_to_temp_requests(url=url, temp_path=temp_path)
            return self._download_to_temp_urllib(url=url, temp_path=temp_path)
        except Exception:
            with contextlib.suppress(Exception):
                shutil.rmtree(temp_dir)
            raise

    def _download_to_temp_requests(self, url: str, temp_path: Path) -> Tuple[Dict[str, Any], Path]:
        session = requests.Session()  # type: ignore[union-attr]
        session.max_redirects = self.policy.max_redirects

        headers = {
            "User-Agent": self.policy.user_agent,
            "Accept": (
                "application/pdf,text/html,text/plain,application/json,text/csv,"
                "image/*,application/octet-stream;q=0.8,*/*;q=0.5"
            ),
        }

        with session.get(
            url,
            headers=headers,
            stream=True,
            timeout=(self.policy.connect_timeout_seconds, self.policy.timeout_seconds),
            verify=self.policy.verify_tls,
            allow_redirects=True,
        ) as response:
            status_code = int(response.status_code)
            if status_code >= 400:
                raise RuntimeError(f"HTTP download failed with status {status_code}")

            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > self.policy.max_file_size_bytes:
                raise RuntimeError("Remote file exceeds configured maximum size.")

            total = 0
            with temp_path.open("wb") as handle:
                for chunk in response.iter_content(chunk_size=self.policy.chunk_size_bytes):
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > self.policy.max_file_size_bytes:
                        raise RuntimeError("Downloaded file exceeds configured maximum size.")
                    handle.write(chunk)

            if total <= 0:
                raise RuntimeError("Downloaded file is empty.")

            return (
                {
                    "status_code": status_code,
                    "final_url": str(response.url),
                    "content_type": response.headers.get("Content-Type"),
                    "content_disposition": response.headers.get("Content-Disposition"),
                    "content_length": int(content_length) if content_length and content_length.isdigit() else total,
                },
                temp_path,
            )

    def _download_to_temp_urllib(self, url: str, temp_path: Path) -> Tuple[Dict[str, Any], Path]:
        if Request is None or urlopen is None:
            raise RuntimeError("No available HTTP client. Install requests or use Python urllib.")

        request = Request(
            url,
            headers={
                "User-Agent": self.policy.user_agent,
                "Accept": (
                    "application/pdf,text/html,text/plain,application/json,text/csv,"
                    "image/*,application/octet-stream;q=0.8,*/*;q=0.5"
                ),
            },
            method="GET",
        )

        with urlopen(request, timeout=self.policy.timeout_seconds) as response:  # nosec - URL validated before call
            status_code = int(getattr(response, "status", 200) or 200)
            if status_code >= 400:
                raise RuntimeError(f"HTTP download failed with status {status_code}")

            headers = response.headers
            content_length = headers.get("Content-Length")
            if content_length and int(content_length) > self.policy.max_file_size_bytes:
                raise RuntimeError("Remote file exceeds configured maximum size.")

            total = 0
            with temp_path.open("wb") as handle:
                while True:
                    chunk = response.read(self.policy.chunk_size_bytes)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > self.policy.max_file_size_bytes:
                        raise RuntimeError("Downloaded file exceeds configured maximum size.")
                    handle.write(chunk)

            if total <= 0:
                raise RuntimeError("Downloaded file is empty.")

            return (
                {
                    "status_code": status_code,
                    "final_url": response.geturl(),
                    "content_type": headers.get("Content-Type"),
                    "content_disposition": headers.get("Content-Disposition"),
                    "content_length": int(content_length) if content_length and content_length.isdigit() else total,
                },
                temp_path,
            )

    def _build_download_target(
        self,
        url: str,
        filename: Optional[str] = None,
        content_type_hint: Optional[str] = None,
    ) -> Dict[str, Any]:
        try:
            parsed = urlparse(url)
            source_name = filename or _safe_filename(parsed.path, fallback="download")
            safe_name = _safe_filename(source_name, fallback="download")

            extension = _extension_from_filename(safe_name)
            content_type_extension = _guess_extension_from_content_type(content_type_hint)

            if not extension and content_type_extension:
                extension = content_type_extension
                safe_name = f"{safe_name}{extension}"

            if not extension and not self.policy.allow_unknown_extension:
                safe_name = f"{safe_name}.bin"
                extension = ".bin"

            if extension in set(self.policy.blocked_extensions):
                return self._error_result(
                    message="This file type is blocked by policy.",
                    error_code="blocked_extension",
                    metadata={"extension": extension},
                )

            if extension not in set(self.policy.allowed_extensions):
                if not self.policy.allow_unknown_extension:
                    return self._error_result(
                        message="This file extension is not allowed by policy.",
                        error_code="extension_not_allowed",
                        metadata={"extension": extension},
                    )

            category = _category_from_extension(extension, content_type_hint)
            target = DownloadTarget(
                url=url,
                safe_filename=safe_name,
                extension=extension,
                category=category,
                content_type_hint=content_type_hint,
            )

            return self._safe_result(
                message="Download target built.",
                data={
                    "target": target,
                    "safe_filename": safe_name,
                    "extension": extension,
                    "category": category,
                },
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to build download target.",
                error=exc,
                error_code="target_build_failed",
                metadata={"url": url, "filename": filename},
            )

    def _workspace_root(self, context: DownloadContext) -> Path:
        return (
            self.base_download_dir
            / "users"
            / context.normalized_user_id()
            / "workspaces"
            / context.normalized_workspace_id()
        )

    def _final_path_for_target(
        self,
        context: DownloadContext,
        target: DownloadTarget,
        subfolder: Optional[str] = None,
    ) -> Path:
        category = _safe_identifier(target.category, fallback="assets")
        root = self._workspace_root(context) / category

        if subfolder:
            root = root / _safe_identifier(str(subfolder), fallback="custom")

        final_path = (root / target.safe_filename).resolve()
        workspace_root = self._workspace_root(context).resolve()

        if not str(final_path).startswith(str(workspace_root)):
            raise RuntimeError("Path traversal blocked while building final download path.")

        return final_path

    def _deduplicate_path(self, path: Path) -> Path:
        if not path.exists():
            return path

        stem = path.stem
        suffix = path.suffix
        parent = path.parent

        for i in range(1, 10_000):
            candidate = parent / f"{stem}_{i}{suffix}"
            if not candidate.exists():
                return candidate

        return parent / f"{stem}_{uuid.uuid4().hex}{suffix}"

    def _manifest_path(self, context: DownloadContext) -> Path:
        return self._workspace_root(context) / "download_manifest.jsonl"

    def _append_manifest(self, context: DownloadContext, item: Mapping[str, Any]) -> None:
        manifest_path = self._manifest_path(context)
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        with manifest_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(_json_safe(dict(item)), ensure_ascii=False, sort_keys=True))
            handle.write("\n")

    # ------------------------------------------------------------------
    # William/Jarvis compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(self, context: DownloadContext) -> Dict[str, Any]:
        """
        Ensure user/workspace isolation fields exist before any action.
        """

        if not str(context.user_id or "").strip():
            return self._error_result(
                message="user_id is required for Browser Agent downloads.",
                error_code="missing_user_id",
            )

        if not str(context.workspace_id or "").strip():
            return self._error_result(
                message="workspace_id is required for Browser Agent downloads.",
                error_code="missing_workspace_id",
            )

        return self._safe_result(
            message="Task context is valid.",
            data={
                "user_id": context.normalized_user_id(),
                "workspace_id": context.normalized_workspace_id(),
                "request_id": context.request_id,
                "task_id": context.task_id,
            },
        )

    def _requires_security_check(
        self,
        action: str,
        context: DownloadContext,
        url: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Determine whether Security Agent approval is required.

        Downloads are network actions and deletes are destructive actions, so this
        returns True by default. If a real Security Agent is attached, it can make
        a more granular decision via `requires_approval`.
        """

        if self.security_agent and hasattr(self.security_agent, "requires_approval"):
            try:
                return bool(
                    self.security_agent.requires_approval(
                        action=action,
                        agent=self.agent_name,
                        user_id=context.user_id,
                        workspace_id=context.workspace_id,
                        payload={"url": url, "metadata": dict(metadata or {})},
                    )
                )
            except Exception:
                self.logger.warning("Security Agent requires_approval failed; using safe default.")

        return action in {"download_file", "download_many", "delete_download"}

    def _request_security_approval(
        self,
        action: str,
        context: DownloadContext,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Ask Security Agent for approval.

        Fallback behavior is conservative but usable: approve safe public downloads
        after local validation, deny destructive deletes unless permission appears
        in context.permissions.
        """

        if self.security_agent and hasattr(self.security_agent, "approve_action"):
            try:
                decision = self.security_agent.approve_action(
                    action=action,
                    agent=self.agent_name,
                    user_id=context.user_id,
                    workspace_id=context.workspace_id,
                    payload=dict(payload),
                )
                if isinstance(decision, Mapping):
                    return dict(decision)
                return {"approved": bool(decision), "source": "security_agent"}
            except Exception as exc:
                self.logger.warning("Security Agent approval failed: %r", exc)
                return {
                    "approved": False,
                    "source": "security_agent_error",
                    "error": repr(exc),
                }

        permissions = set(context.permissions or [])
        if action == "delete_download":
            return {
                "approved": "browser.download.delete" in permissions or "admin" in permissions,
                "source": "fallback_permission_check",
                "required_permission": "browser.download.delete",
            }

        if action in {"download_file", "download_many"}:
            url = str(payload.get("url") or "")
            local_validation = self.validate_url(url) if url else self._safe_result(message="Batch approval.")
            return {
                "approved": bool(local_validation.get("success")),
                "source": "fallback_local_policy",
                "validation": local_validation,
            }

        return {"approved": False, "source": "fallback_unknown_action"}

    def _prepare_verification_payload(
        self,
        action: str,
        context: DownloadContext,
        data: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent compatible payload.

        The actual Verification Agent can later verify checksum, file existence,
        MIME type, scan status, and policy compliance.
        """

        payload = {
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "action": action,
            "user_id": context.normalized_user_id(),
            "workspace_id": context.normalized_workspace_id(),
            "request_id": context.request_id,
            "task_id": context.task_id,
            "created_at": _utc_now_iso(),
            "checks": {
                "file_exists": bool(data.get("absolute_path") and Path(str(data.get("absolute_path"))).exists()),
                "sha256": data.get("sha256"),
                "size_bytes": data.get("size_bytes"),
                "relative_path": data.get("relative_path"),
                "source_url": data.get("url"),
                "policy_max_file_size_bytes": self.policy.max_file_size_bytes,
            },
            "status": "ready_for_verification",
        }

        if self.verification_agent and hasattr(self.verification_agent, "prepare_payload"):
            with contextlib.suppress(Exception):
                prepared = self.verification_agent.prepare_payload(payload)
                if isinstance(prepared, Mapping):
                    return dict(prepared)

        return payload

    def _prepare_memory_payload(
        self,
        action: str,
        context: DownloadContext,
        data: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare safe Memory Agent payload.

        It records metadata only. It does not ingest file content automatically.
        """

        payload = {
            "agent": self.agent_name,
            "action": action,
            "user_id": context.normalized_user_id(),
            "workspace_id": context.normalized_workspace_id(),
            "created_at": _utc_now_iso(),
            "memory_type": "browser_download_metadata",
            "summary": (
                f"Downloaded {data.get('filename')} from public URL into "
                f"{data.get('category')} for workspace {context.normalized_workspace_id()}."
            ),
            "data": {
                "url": data.get("url"),
                "filename": data.get("filename"),
                "relative_path": data.get("relative_path"),
                "content_type": data.get("content_type"),
                "size_bytes": data.get("size_bytes"),
                "sha256": data.get("sha256"),
            },
        }

        if self.memory_agent and hasattr(self.memory_agent, "prepare_payload"):
            with contextlib.suppress(Exception):
                prepared = self.memory_agent.prepare_payload(payload)
                if isinstance(prepared, Mapping):
                    return dict(prepared)

        return payload

    def _emit_agent_event(
        self,
        event_type: str,
        context: DownloadContext,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Emit Browser Agent event for dashboard analytics/task history.
        """

        event = {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "user_id": context.normalized_user_id(),
            "workspace_id": context.normalized_workspace_id(),
            "request_id": context.request_id,
            "task_id": context.task_id,
            "payload": _json_safe(dict(payload or {})),
            "created_at": _utc_now_iso(),
        }

        if self.event_emitter:
            try:
                if hasattr(self.event_emitter, "emit"):
                    self.event_emitter.emit(event)
                elif callable(self.event_emitter):
                    self.event_emitter(event)
                return
            except Exception as exc:
                self.logger.warning("Event emitter failed: %r", exc)

        self.logger.debug("Agent event: %s", event)

    def _log_audit_event(
        self,
        event_type: str,
        context: DownloadContext,
        details: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Log audit event for sensitive Browser Agent activity.
        """

        audit = {
            "audit_id": str(uuid.uuid4()),
            "event_type": event_type,
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "user_id": context.normalized_user_id(),
            "workspace_id": context.normalized_workspace_id(),
            "request_id": context.request_id,
            "task_id": context.task_id,
            "details": _json_safe(dict(details or {})),
            "created_at": _utc_now_iso(),
        }

        if self.audit_logger:
            try:
                if hasattr(self.audit_logger, "log"):
                    self.audit_logger.log(audit)
                elif callable(self.audit_logger):
                    self.audit_logger(audit)
                return
            except Exception as exc:
                self.logger.warning("Audit logger failed: %r", exc)

        self.logger.info("Audit event: %s", audit)

    def _safe_result(
        self,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard William/Jarvis success result.
        """

        return {
            "success": True,
            "message": message,
            "data": _json_safe(dict(data or {})),
            "error": None,
            "metadata": _json_safe(
                {
                    "agent": self.agent_name,
                    "agent_type": self.agent_type,
                    "timestamp": _utc_now_iso(),
                    **dict(metadata or {}),
                }
            ),
        }

    def _error_result(
        self,
        message: str,
        error: Optional[BaseException] = None,
        error_code: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard William/Jarvis error result.
        """

        return {
            "success": False,
            "message": message,
            "data": {},
            "error": {
                "code": error_code or "error",
                "type": error.__class__.__name__ if error else None,
                "detail": str(error) if error else message,
            },
            "metadata": _json_safe(
                {
                    "agent": self.agent_name,
                    "agent_type": self.agent_type,
                    "timestamp": _utc_now_iso(),
                    **dict(metadata or {}),
                }
            ),
        }


__all__ = [
    "DownloadManager",
    "DownloadContext",
    "DownloadPolicy",
    "DownloadTarget",
]


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    manager = DownloadManager()
    print(
        json.dumps(
            manager.validate_url("https://example.com/sample.pdf"),
            indent=2,
            default=str,
        )
    )
