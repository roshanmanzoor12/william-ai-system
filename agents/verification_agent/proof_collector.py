"""
agents/verification_agent/proof_collector.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Collects verification proof artifacts including screenshots, logs, process status,
    API responses, and timestamps.

Architecture Role:
    - Verification Agent helper/component.
    - Used by Master Agent or Verification Agent after a task/action completes.
    - Produces structured proof bundles for dashboard/API, audit logs, task history,
      Verification Agent payloads, and Memory Agent compatible summaries.
    - Enforces SaaS user/workspace isolation through explicit task context validation.
    - Routes sensitive proof collection actions through security approval hooks.

Import Safety:
    This file is safe to import even if the rest of the William/Jarvis system is not
    created yet. Optional integrations use fallback stubs.

Security Notes:
    - Does not hardcode secrets.
    - Does not perform destructive actions.
    - Screenshots, local log reads, process inspection, and API calls can reveal
      sensitive data, so they are guarded by security-check hooks.
    - File reads are constrained to configured allowed log directories unless
      explicitly overridden by policy.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import mimetypes
import os
import platform
import socket
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# =============================================================================
# Optional imports with safe fallbacks
# =============================================================================

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    psutil = None  # type: ignore

try:
    from PIL import ImageGrab  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    ImageGrab = None  # type: ignore


# =============================================================================
# Optional William/Jarvis imports with fallback stubs
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - project may not exist yet

    class BaseAgent:  # type: ignore
        """
        Minimal fallback BaseAgent.

        This keeps proof_collector.py import-safe before the full William/Jarvis
        codebase exists. When the real BaseAgent is available, it will be used.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())


try:
    from agents.security_agent.security_agent import SecurityAgent  # type: ignore
except Exception:  # pragma: no cover - project may not exist yet

    class SecurityAgent:  # type: ignore
        """
        Minimal fallback SecurityAgent.

        The fallback denies high-risk actions only when explicitly configured by
        ProofCollector policy. It exists to prevent import crashes, not to replace
        the real Security Agent.
        """

        def approve_action(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
            return {
                "success": True,
                "approved": True,
                "message": "Fallback security approval granted by safe default policy.",
                "data": {
                    "source": "fallback_security_agent",
                    "risk_level": payload.get("risk_level", "low"),
                },
                "error": None,
                "metadata": {},
            }


# =============================================================================
# Logging
# =============================================================================

LOGGER = logging.getLogger("william.verification.proof_collector")
if not LOGGER.handlers:
    logging.basicConfig(level=logging.INFO)


# =============================================================================
# Data structures
# =============================================================================

JsonDict = Dict[str, Any]
SecurityApprovalCallable = Callable[[Mapping[str, Any]], Mapping[str, Any]]
EventEmitterCallable = Callable[[str, Mapping[str, Any]], None]
AuditLoggerCallable = Callable[[Mapping[str, Any]], None]


@dataclass
class TaskContext:
    """
    SaaS-safe execution context.

    Every proof collection request that relates to a user/workspace must include
    user_id and workspace_id. This prevents mixing screenshots, files, logs,
    process data, audit events, memory summaries, and task history across tenants.
    """

    user_id: str
    workspace_id: str
    task_id: Optional[str] = None
    run_id: Optional[str] = None
    agent_id: Optional[str] = None
    source_agent: Optional[str] = None
    requested_by: Optional[str] = None
    role: Optional[str] = None
    permissions: Sequence[str] = field(default_factory=list)
    metadata: JsonDict = field(default_factory=dict)

    def to_dict(self) -> JsonDict:
        return asdict(self)


@dataclass
class ProofCollectorConfig:
    """
    Runtime configuration for proof collection.

    Defaults are conservative and import-safe. Integrators can pass stricter
    config from Verification Agent, Dashboard/API, or Agent Registry.
    """

    proof_root_dir: str = "runtime/proofs"
    allowed_log_dirs: Sequence[str] = field(
        default_factory=lambda: (
            "logs",
            "runtime/logs",
            "storage/logs",
            "var/log/william",
        )
    )
    max_log_bytes: int = 512_000
    max_log_lines: int = 500
    max_api_response_bytes: int = 256_000
    api_timeout_seconds: float = 10.0
    screenshot_enabled: bool = True
    screenshot_format: str = "png"
    store_screenshot_file: bool = True
    include_screenshot_base64: bool = False
    collect_environment_summary: bool = True
    process_scan_limit: int = 300
    require_security_for_screenshot: bool = True
    require_security_for_log_read: bool = True
    require_security_for_process_scan: bool = False
    require_security_for_api_call: bool = True
    allow_api_private_hosts: bool = False
    allow_log_path_outside_allowed_dirs: bool = False
    redact_sensitive_values: bool = True
    sensitive_key_fragments: Sequence[str] = field(
        default_factory=lambda: (
            "password",
            "passwd",
            "secret",
            "token",
            "api_key",
            "apikey",
            "authorization",
            "cookie",
            "set-cookie",
            "private_key",
            "access_key",
            "refresh",
            "bearer",
        )
    )
    blocked_log_extensions: Sequence[str] = field(
        default_factory=lambda: (
            ".db",
            ".sqlite",
            ".sqlite3",
            ".pem",
            ".key",
            ".p12",
            ".pfx",
            ".env",
        )
    )


@dataclass
class ProofArtifact:
    """
    Standard proof artifact shape.

    Artifacts are returned inside a proof bundle and can be stored in task history,
    dashboard evidence, audit trails, or verification reports.
    """

    artifact_type: str
    success: bool
    message: str
    data: JsonDict = field(default_factory=dict)
    error: Optional[JsonDict] = None
    metadata: JsonDict = field(default_factory=dict)

    def to_dict(self) -> JsonDict:
        return asdict(self)


# =============================================================================
# Helper functions
# =============================================================================

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_iso() -> str:
    return _utc_now().isoformat()


def _safe_str(value: Any, max_length: int = 3000) -> str:
    try:
        text = str(value)
    except Exception:
        text = repr(value)
    if len(text) > max_length:
        return text[: max_length - 20] + "...[truncated]"
    return text


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _ensure_list(value: Optional[Union[str, Sequence[str]]]) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return [str(item) for item in value]


def _normalize_path(path: Union[str, Path]) -> Path:
    return Path(path).expanduser().resolve()


def _is_subpath(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _safe_mkdir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _redact_mapping(
    value: Any,
    sensitive_fragments: Sequence[str],
    replacement: str = "[REDACTED]",
) -> Any:
    """
    Recursively redact likely secret values by key name.

    This is used before emitting proof to dashboard/API, audit logs, memory, or
    Master Agent routes.
    """
    if isinstance(value, Mapping):
        clean: JsonDict = {}
        for key, item in value.items():
            key_text = str(key).lower()
            if any(fragment.lower() in key_text for fragment in sensitive_fragments):
                clean[str(key)] = replacement
            else:
                clean[str(key)] = _redact_mapping(item, sensitive_fragments, replacement)
        return clean

    if isinstance(value, list):
        return [_redact_mapping(item, sensitive_fragments, replacement) for item in value]

    if isinstance(value, tuple):
        return tuple(_redact_mapping(item, sensitive_fragments, replacement) for item in value)

    return value


def _redact_text(text: str) -> str:
    """
    Lightweight line-based secret redaction for logs.

    Avoids expensive regex-heavy processing while masking common secret patterns.
    """
    sensitive_markers = (
        "password=",
        "passwd=",
        "secret=",
        "token=",
        "api_key=",
        "apikey=",
        "authorization:",
        "cookie:",
        "set-cookie:",
        "bearer ",
    )

    redacted_lines: List[str] = []
    for line in text.splitlines():
        low = line.lower()
        if any(marker in low for marker in sensitive_markers):
            redacted_lines.append("[REDACTED SENSITIVE LOG LINE]")
        else:
            redacted_lines.append(line)
    return "\n".join(redacted_lines)


def _is_private_or_local_host(url: str) -> bool:
    """
    Best-effort local/private host detector for API proof collection.

    This protects against accidental SSRF-style internal calls when the collector
    is connected to dashboard/API input.
    """
    try:
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname
        if not host:
            return True

        host_lower = host.lower()
        if host_lower in {"localhost", "127.0.0.1", "0.0.0.0", "::1"}:
            return True

        ip = socket.gethostbyname(host)
        parts = [int(part) for part in ip.split(".")]
        if parts[0] == 10:
            return True
        if parts[0] == 127:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        if parts[0] == 192 and parts[1] == 168:
            return True
        if parts[0] == 169 and parts[1] == 254:
            return True

        return False
    except Exception:
        return True


def _valid_http_url(url: str) -> bool:
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.scheme in {"http", "https"} and bool(parsed.netloc)
    except Exception:
        return False


# =============================================================================
# ProofCollector
# =============================================================================

class ProofCollector(BaseAgent):
    """
    Collects proof artifacts for Verification Agent.

    Public methods:
        - collect_proof_bundle()
        - collect_timestamp()
        - collect_screenshot()
        - collect_logs()
        - collect_process_status()
        - collect_api_response()
        - build_verification_payload()
        - build_memory_payload()

    Integration points:
        Master Agent:
            Can call collect_proof_bundle() after action execution to receive
            structured evidence for routing and dashboard display.

        Security Agent:
            Sensitive proof collection actions call _request_security_approval().

        Memory Agent:
            build_memory_payload() prepares a safe, compact summary without raw
            sensitive proof content.

        Verification Agent:
            build_verification_payload() returns evidence suitable for proof reports,
            result validation, retries, and task completion confirmation.

        Dashboard/API:
            All outputs are structured dicts with success, message, data, error,
            and metadata fields.
    """

    def __init__(
        self,
        config: Optional[Union[ProofCollectorConfig, Mapping[str, Any]]] = None,
        security_agent: Optional[Any] = None,
        event_emitter: Optional[EventEmitterCallable] = None,
        audit_logger: Optional[AuditLoggerCallable] = None,
        logger: Optional[logging.Logger] = None,
        agent_name: str = "ProofCollector",
        agent_id: str = "verification.proof_collector",
    ) -> None:
        super().__init__(agent_name=agent_name, agent_id=agent_id)
        self.agent_name = agent_name
        self.agent_id = agent_id
        self.logger = logger or LOGGER
        self.security_agent = security_agent or SecurityAgent()
        self.event_emitter = event_emitter
        self.audit_logger = audit_logger
        self.config = self._coerce_config(config)

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    def collect_proof_bundle(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        *,
        include_timestamp: bool = True,
        screenshot: bool = False,
        log_paths: Optional[Sequence[Union[str, Path]]] = None,
        process_names: Optional[Sequence[str]] = None,
        process_pids: Optional[Sequence[int]] = None,
        api_requests: Optional[Sequence[Mapping[str, Any]]] = None,
        extra_evidence: Optional[Mapping[str, Any]] = None,
        proof_label: Optional[str] = None,
    ) -> JsonDict:
        """
        Collect multiple proof artifacts in one SaaS-safe bundle.

        Args:
            context:
                Must include user_id and workspace_id.
            include_timestamp:
                Adds UTC/local/platform timestamp artifact.
            screenshot:
                Capture current screen if supported and security-approved.
            log_paths:
                Optional log files to read safely.
            process_names:
                Optional process names to inspect.
            process_pids:
                Optional process IDs to inspect.
            api_requests:
                Optional list of API request specs:
                    {
                        "url": "https://example.com/health",
                        "method": "GET",
                        "headers": {"X-Request-ID": "..."},
                        "body": null,
                        "timeout_seconds": 5
                    }
            extra_evidence:
                Caller-provided proof/evidence to attach after redaction.
            proof_label:
                Human-readable bundle label.

        Returns:
            Structured William/Jarvis result dict.
        """
        started = time.monotonic()
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        ctx = ctx_result["data"]["context"]
        bundle_id = self._make_bundle_id(ctx, proof_label)

        self._emit_agent_event(
            "proof_collection_started",
            {
                "bundle_id": bundle_id,
                "context": self._safe_context_public(ctx),
                "proof_label": proof_label,
            },
        )

        artifacts: List[JsonDict] = []

        if include_timestamp:
            artifacts.append(self.collect_timestamp(ctx).get("data", {}).get("artifact", {}))

        if screenshot:
            artifacts.append(
                self.collect_screenshot(
                    ctx,
                    bundle_id=bundle_id,
                    label=proof_label or "verification_screenshot",
                ).get("data", {}).get("artifact", {})
            )

        for log_path in log_paths or []:
            artifacts.append(
                self.collect_logs(
                    ctx,
                    log_path=log_path,
                    bundle_id=bundle_id,
                ).get("data", {}).get("artifact", {})
            )

        if process_names or process_pids:
            artifacts.append(
                self.collect_process_status(
                    ctx,
                    process_names=process_names,
                    process_pids=process_pids,
                ).get("data", {}).get("artifact", {})
            )

        for request_spec in api_requests or []:
            artifacts.append(
                self.collect_api_response(
                    ctx,
                    request_spec=request_spec,
                ).get("data", {}).get("artifact", {})
            )

        if extra_evidence is not None:
            artifacts.append(
                self._build_extra_evidence_artifact(
                    extra_evidence=extra_evidence,
                    context=ctx,
                    bundle_id=bundle_id,
                ).to_dict()
            )

        cleaned_artifacts = [artifact for artifact in artifacts if artifact]
        successful_count = sum(1 for item in cleaned_artifacts if item.get("success") is True)
        failed_count = sum(1 for item in cleaned_artifacts if item.get("success") is False)

        duration_ms = round((time.monotonic() - started) * 1000, 3)

        data = {
            "bundle": {
                "bundle_id": bundle_id,
                "proof_label": proof_label,
                "context": self._safe_context_public(ctx),
                "artifacts": cleaned_artifacts,
                "summary": {
                    "total_artifacts": len(cleaned_artifacts),
                    "successful_artifacts": successful_count,
                    "failed_artifacts": failed_count,
                    "duration_ms": duration_ms,
                    "collected_at": _utc_iso(),
                },
            },
            "verification_payload": self._prepare_verification_payload(
                ctx,
                {
                    "bundle_id": bundle_id,
                    "artifacts": cleaned_artifacts,
                    "proof_label": proof_label,
                },
            ),
            "memory_payload": self._prepare_memory_payload(
                ctx,
                {
                    "bundle_id": bundle_id,
                    "artifacts": cleaned_artifacts,
                    "proof_label": proof_label,
                },
            ),
        }

        result = self._safe_result(
            message="Proof bundle collected.",
            data=data,
            metadata={
                "agent_id": self.agent_id,
                "agent_name": self.agent_name,
                "duration_ms": duration_ms,
            },
        )

        self._log_audit_event(
            {
                "event_type": "verification.proof_bundle_collected",
                "context": self._safe_context_public(ctx),
                "bundle_id": bundle_id,
                "artifact_count": len(cleaned_artifacts),
                "failed_artifact_count": failed_count,
                "duration_ms": duration_ms,
            }
        )

        self._emit_agent_event(
            "proof_collection_completed",
            {
                "bundle_id": bundle_id,
                "context": self._safe_context_public(ctx),
                "artifact_count": len(cleaned_artifacts),
                "failed_artifact_count": failed_count,
            },
        )

        return result

    def collect_timestamp(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
    ) -> JsonDict:
        """
        Collect timestamp and environment proof.

        This is low-risk and does not require a security check by default.
        """
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx = ctx_result["data"]["context"]

        now_utc = _utc_now()
        local_now = datetime.now().astimezone()

        data: JsonDict = {
            "utc_iso": now_utc.isoformat(),
            "utc_epoch_seconds": now_utc.timestamp(),
            "local_iso": local_now.isoformat(),
            "timezone": str(local_now.tzinfo),
            "monotonic_seconds": time.monotonic(),
        }

        if self.config.collect_environment_summary:
            data["environment"] = {
                "platform": platform.platform(),
                "system": platform.system(),
                "release": platform.release(),
                "python_version": platform.python_version(),
                "machine": platform.machine(),
                "hostname_hash": _sha256_text(socket.gethostname()),
            }

        artifact = ProofArtifact(
            artifact_type="timestamp",
            success=True,
            message="Timestamp proof collected.",
            data=data,
            metadata={
                "context": self._safe_context_public(ctx),
                "collected_at": _utc_iso(),
            },
        )

        return self._safe_result(
            message="Timestamp proof collected.",
            data={"artifact": artifact.to_dict()},
            metadata={"agent_id": self.agent_id},
        )

    def collect_screenshot(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        *,
        bundle_id: Optional[str] = None,
        label: str = "verification_screenshot",
    ) -> JsonDict:
        """
        Capture current screen as proof.

        Uses PIL.ImageGrab when available. On headless servers this may fail safely
        and return a structured error artifact instead of raising.
        """
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx = ctx_result["data"]["context"]

        approval = self._request_if_required(
            ctx,
            action="collect_screenshot",
            risk_level="medium",
            required=self.config.require_security_for_screenshot,
            details={"label": label, "bundle_id": bundle_id},
        )
        if not approval["success"]:
            artifact = self._failed_artifact(
                artifact_type="screenshot",
                message="Screenshot proof blocked by security approval.",
                error=approval.get("error") or {
                    "code": "SECURITY_APPROVAL_DENIED",
                    "details": approval.get("message"),
                },
                context=ctx,
            )
            return self._safe_result(
                message="Screenshot proof blocked by security approval.",
                data={"artifact": artifact.to_dict()},
                metadata={"agent_id": self.agent_id},
            )

        if not self.config.screenshot_enabled:
            artifact = self._failed_artifact(
                artifact_type="screenshot",
                message="Screenshot collection is disabled by configuration.",
                error={"code": "SCREENSHOT_DISABLED"},
                context=ctx,
            )
            return self._safe_result(
                message="Screenshot collection is disabled by configuration.",
                data={"artifact": artifact.to_dict()},
                metadata={"agent_id": self.agent_id},
            )

        if ImageGrab is None:
            artifact = self._failed_artifact(
                artifact_type="screenshot",
                message="Screenshot dependency is unavailable. Install pillow to enable screenshots.",
                error={"code": "DEPENDENCY_UNAVAILABLE", "dependency": "Pillow.ImageGrab"},
                context=ctx,
            )
            return self._safe_result(
                message="Screenshot dependency unavailable.",
                data={"artifact": artifact.to_dict()},
                metadata={"agent_id": self.agent_id},
            )

        try:
            image = ImageGrab.grab()
            fmt = self.config.screenshot_format.lower().strip(".") or "png"
            bundle_id = bundle_id or self._make_bundle_id(ctx, label)
            proof_dir = self._proof_dir_for_context(ctx, bundle_id)
            _safe_mkdir(proof_dir)

            timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%S%fZ")
            filename = f"{self._safe_filename(label)}_{timestamp}.{fmt}"
            file_path = proof_dir / filename

            metadata: JsonDict = {
                "context": self._safe_context_public(ctx),
                "bundle_id": bundle_id,
                "label": label,
                "format": fmt,
                "size": getattr(image, "size", None),
                "mode": getattr(image, "mode", None),
                "collected_at": _utc_iso(),
            }

            data: JsonDict = {
                "screenshot_available": True,
                "stored_file": False,
                "file_path": None,
                "file_sha256": None,
                "mime_type": mimetypes.guess_type(str(file_path))[0] or f"image/{fmt}",
                "width": image.size[0] if getattr(image, "size", None) else None,
                "height": image.size[1] if getattr(image, "size", None) else None,
            }

            if self.config.store_screenshot_file:
                image.save(str(file_path))
                raw = file_path.read_bytes()
                data["stored_file"] = True
                data["file_path"] = str(file_path)
                data["file_sha256"] = _sha256_bytes(raw)
                data["file_size_bytes"] = len(raw)

                if self.config.include_screenshot_base64:
                    data["base64"] = base64.b64encode(raw).decode("ascii")

            artifact = ProofArtifact(
                artifact_type="screenshot",
                success=True,
                message="Screenshot proof collected.",
                data=data,
                metadata=metadata,
            )

            self._log_audit_event(
                {
                    "event_type": "verification.screenshot_collected",
                    "context": self._safe_context_public(ctx),
                    "bundle_id": bundle_id,
                    "stored_file": data.get("stored_file"),
                    "file_sha256": data.get("file_sha256"),
                }
            )

            return self._safe_result(
                message="Screenshot proof collected.",
                data={"artifact": artifact.to_dict()},
                metadata={"agent_id": self.agent_id},
            )

        except Exception as exc:
            artifact = self._failed_artifact(
                artifact_type="screenshot",
                message="Screenshot collection failed.",
                error=self._exception_error(exc),
                context=ctx,
            )
            return self._safe_result(
                message="Screenshot collection failed.",
                data={"artifact": artifact.to_dict()},
                metadata={"agent_id": self.agent_id},
            )

    def collect_logs(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        *,
        log_path: Union[str, Path],
        bundle_id: Optional[str] = None,
        tail_lines: Optional[int] = None,
        max_bytes: Optional[int] = None,
    ) -> JsonDict:
        """
        Collect tail of a log file as proof.

        The method reads only up to max_bytes and tail_lines. It redacts common
        secrets and blocks dangerous file extensions by default.
        """
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx = ctx_result["data"]["context"]

        path_check = self._validate_log_path(log_path)
        if not path_check["success"]:
            artifact = self._failed_artifact(
                artifact_type="log",
                message="Log path validation failed.",
                error=path_check["error"],
                context=ctx,
                data={"requested_path": _safe_str(log_path)},
            )
            return self._safe_result(
                message="Log path validation failed.",
                data={"artifact": artifact.to_dict()},
                metadata={"agent_id": self.agent_id},
            )

        safe_path = Path(path_check["data"]["path"])

        approval = self._request_if_required(
            ctx,
            action="collect_logs",
            risk_level="medium",
            required=self.config.require_security_for_log_read,
            details={"log_path": str(safe_path), "bundle_id": bundle_id},
        )
        if not approval["success"]:
            artifact = self._failed_artifact(
                artifact_type="log",
                message="Log collection blocked by security approval.",
                error=approval.get("error") or {
                    "code": "SECURITY_APPROVAL_DENIED",
                    "details": approval.get("message"),
                },
                context=ctx,
                data={"log_path": str(safe_path)},
            )
            return self._safe_result(
                message="Log collection blocked by security approval.",
                data={"artifact": artifact.to_dict()},
                metadata={"agent_id": self.agent_id},
            )

        try:
            max_bytes_final = int(max_bytes or self.config.max_log_bytes)
            tail_lines_final = int(tail_lines or self.config.max_log_lines)
            raw = self._read_file_tail_bytes(safe_path, max_bytes_final)
            text = raw.decode("utf-8", errors="replace")

            lines = text.splitlines()
            if tail_lines_final > 0 and len(lines) > tail_lines_final:
                lines = lines[-tail_lines_final:]
            text = "\n".join(lines)

            if self.config.redact_sensitive_values:
                text = _redact_text(text)

            stat = safe_path.stat()

            artifact = ProofArtifact(
                artifact_type="log",
                success=True,
                message="Log proof collected.",
                data={
                    "log_path": str(safe_path),
                    "exists": True,
                    "file_size_bytes": stat.st_size,
                    "modified_at_epoch": stat.st_mtime,
                    "modified_at_utc": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
                    "tail_line_count": len(lines),
                    "max_bytes_requested": max_bytes_final,
                    "content_sha256": _sha256_text(text),
                    "content": text,
                },
                metadata={
                    "context": self._safe_context_public(ctx),
                    "bundle_id": bundle_id,
                    "collected_at": _utc_iso(),
                    "redacted": self.config.redact_sensitive_values,
                },
            )

            self._log_audit_event(
                {
                    "event_type": "verification.log_collected",
                    "context": self._safe_context_public(ctx),
                    "bundle_id": bundle_id,
                    "log_path": str(safe_path),
                    "content_sha256": artifact.data.get("content_sha256"),
                }
            )

            return self._safe_result(
                message="Log proof collected.",
                data={"artifact": artifact.to_dict()},
                metadata={"agent_id": self.agent_id},
            )

        except Exception as exc:
            artifact = self._failed_artifact(
                artifact_type="log",
                message="Log collection failed.",
                error=self._exception_error(exc),
                context=ctx,
                data={"log_path": str(safe_path)},
            )
            return self._safe_result(
                message="Log collection failed.",
                data={"artifact": artifact.to_dict()},
                metadata={"agent_id": self.agent_id},
            )

    def collect_process_status(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        *,
        process_names: Optional[Sequence[str]] = None,
        process_pids: Optional[Sequence[int]] = None,
    ) -> JsonDict:
        """
        Collect process status proof.

        Supports process name matching and PID matching. Uses psutil when available.
        """
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx = ctx_result["data"]["context"]

        names = [name.lower().strip() for name in _ensure_list(process_names) if name.strip()]
        pids = [int(pid) for pid in (process_pids or []) if str(pid).isdigit() or isinstance(pid, int)]

        approval = self._request_if_required(
            ctx,
            action="collect_process_status",
            risk_level="low",
            required=self.config.require_security_for_process_scan,
            details={"process_names": names, "process_pids": pids},
        )
        if not approval["success"]:
            artifact = self._failed_artifact(
                artifact_type="process_status",
                message="Process status collection blocked by security approval.",
                error=approval.get("error") or {
                    "code": "SECURITY_APPROVAL_DENIED",
                    "details": approval.get("message"),
                },
                context=ctx,
            )
            return self._safe_result(
                message="Process status collection blocked by security approval.",
                data={"artifact": artifact.to_dict()},
                metadata={"agent_id": self.agent_id},
            )

        if psutil is None:
            artifact = self._failed_artifact(
                artifact_type="process_status",
                message="Process inspection dependency is unavailable. Install psutil to enable process proof.",
                error={"code": "DEPENDENCY_UNAVAILABLE", "dependency": "psutil"},
                context=ctx,
            )
            return self._safe_result(
                message="Process inspection dependency unavailable.",
                data={"artifact": artifact.to_dict()},
                metadata={"agent_id": self.agent_id},
            )

        try:
            matches: List[JsonDict] = []
            scanned = 0
            wanted_pids = set(pids)

            for proc in psutil.process_iter(["pid", "name", "status", "create_time", "username", "cmdline"]):
                if scanned >= self.config.process_scan_limit:
                    break
                scanned += 1

                try:
                    info = proc.info
                    pid = int(info.get("pid"))
                    proc_name = str(info.get("name") or "")
                    proc_name_low = proc_name.lower()

                    name_match = any(name in proc_name_low for name in names) if names else False
                    pid_match = pid in wanted_pids if wanted_pids else False

                    if names or wanted_pids:
                        if not name_match and not pid_match:
                            continue

                    cmdline = info.get("cmdline") or []
                    cmdline_text = " ".join([_safe_str(part, 500) for part in cmdline])
                    if self.config.redact_sensitive_values:
                        cmdline_text = _redact_text(cmdline_text)

                    create_time = info.get("create_time")
                    create_time_iso = None
                    if create_time:
                        create_time_iso = datetime.fromtimestamp(float(create_time), timezone.utc).isoformat()

                    matches.append(
                        {
                            "pid": pid,
                            "name": proc_name,
                            "status": info.get("status"),
                            "username_hash": _sha256_text(str(info.get("username"))) if info.get("username") else None,
                            "create_time_utc": create_time_iso,
                            "cmdline": cmdline_text,
                            "matched_by": {
                                "name": name_match,
                                "pid": pid_match,
                            },
                        }
                    )
                except Exception:
                    continue

            artifact = ProofArtifact(
                artifact_type="process_status",
                success=True,
                message="Process status proof collected.",
                data={
                    "requested_process_names": names,
                    "requested_pids": pids,
                    "matches": matches,
                    "match_count": len(matches),
                    "scanned_count": scanned,
                    "scan_limit": self.config.process_scan_limit,
                },
                metadata={
                    "context": self._safe_context_public(ctx),
                    "collected_at": _utc_iso(),
                    "psutil_available": True,
                    "redacted": self.config.redact_sensitive_values,
                },
            )

            self._log_audit_event(
                {
                    "event_type": "verification.process_status_collected",
                    "context": self._safe_context_public(ctx),
                    "requested_process_names": names,
                    "requested_pids": pids,
                    "match_count": len(matches),
                }
            )

            return self._safe_result(
                message="Process status proof collected.",
                data={"artifact": artifact.to_dict()},
                metadata={"agent_id": self.agent_id},
            )

        except Exception as exc:
            artifact = self._failed_artifact(
                artifact_type="process_status",
                message="Process status collection failed.",
                error=self._exception_error(exc),
                context=ctx,
            )
            return self._safe_result(
                message="Process status collection failed.",
                data={"artifact": artifact.to_dict()},
                metadata={"agent_id": self.agent_id},
            )

    def collect_api_response(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        *,
        request_spec: Mapping[str, Any],
    ) -> JsonDict:
        """
        Collect API response proof.

        Supports GET, HEAD, and POST. Response body is capped by
        max_api_response_bytes. Headers are redacted before returning.
        """
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx = ctx_result["data"]["context"]

        spec = dict(request_spec or {})
        url = str(spec.get("url") or "").strip()
        method = str(spec.get("method") or "GET").upper().strip()
        headers = dict(spec.get("headers") or {})
        body = spec.get("body")
        timeout = float(spec.get("timeout_seconds") or self.config.api_timeout_seconds)

        validation_error = self._validate_api_request(url=url, method=method)
        if validation_error:
            artifact = self._failed_artifact(
                artifact_type="api_response",
                message="API request validation failed.",
                error=validation_error,
                context=ctx,
                data={"url": url, "method": method},
            )
            return self._safe_result(
                message="API request validation failed.",
                data={"artifact": artifact.to_dict()},
                metadata={"agent_id": self.agent_id},
            )

        approval = self._request_if_required(
            ctx,
            action="collect_api_response",
            risk_level="medium",
            required=self.config.require_security_for_api_call,
            details={
                "url": url,
                "method": method,
                "timeout_seconds": timeout,
            },
        )
        if not approval["success"]:
            artifact = self._failed_artifact(
                artifact_type="api_response",
                message="API response collection blocked by security approval.",
                error=approval.get("error") or {
                    "code": "SECURITY_APPROVAL_DENIED",
                    "details": approval.get("message"),
                },
                context=ctx,
                data={"url": url, "method": method},
            )
            return self._safe_result(
                message="API response collection blocked by security approval.",
                data={"artifact": artifact.to_dict()},
                metadata={"agent_id": self.agent_id},
            )

        started = time.monotonic()
        request_headers = self._redact_if_needed(headers)

        try:
            encoded_body: Optional[bytes] = None
            if body is not None:
                if isinstance(body, bytes):
                    encoded_body = body
                elif isinstance(body, (dict, list)):
                    encoded_body = json.dumps(body).encode("utf-8")
                    headers.setdefault("Content-Type", "application/json")
                else:
                    encoded_body = str(body).encode("utf-8")

            req = urllib.request.Request(
                url=url,
                data=encoded_body,
                headers=headers,
                method=method,
            )

            status_code: Optional[int] = None
            response_headers: JsonDict = {}
            response_body = b""
            response_error: Optional[JsonDict] = None

            try:
                with urllib.request.urlopen(req, timeout=timeout) as response:
                    status_code = int(getattr(response, "status", response.getcode()))
                    response_headers = dict(response.headers.items())
                    response_body = response.read(self.config.max_api_response_bytes + 1)
            except urllib.error.HTTPError as http_exc:
                status_code = int(http_exc.code)
                response_headers = dict(http_exc.headers.items()) if http_exc.headers else {}
                response_body = http_exc.read(self.config.max_api_response_bytes + 1)
                response_error = {
                    "code": "HTTP_ERROR",
                    "status_code": status_code,
                    "reason": _safe_str(http_exc.reason),
                }

            duration_ms = round((time.monotonic() - started) * 1000, 3)
            truncated = len(response_body) > self.config.max_api_response_bytes
            if truncated:
                response_body = response_body[: self.config.max_api_response_bytes]

            body_text = response_body.decode("utf-8", errors="replace")
            if self.config.redact_sensitive_values:
                body_text = _redact_text(body_text)

            artifact_success = response_error is None and status_code is not None and 200 <= status_code <= 399

            artifact = ProofArtifact(
                artifact_type="api_response",
                success=artifact_success,
                message="API response proof collected." if artifact_success else "API response collected with non-success status.",
                data={
                    "url": url,
                    "method": method,
                    "request_headers": request_headers,
                    "status_code": status_code,
                    "response_headers": self._redact_if_needed(response_headers),
                    "response_body": body_text,
                    "response_body_sha256": _sha256_text(body_text),
                    "response_body_bytes": len(response_body),
                    "response_body_truncated": truncated,
                    "duration_ms": duration_ms,
                },
                error=response_error,
                metadata={
                    "context": self._safe_context_public(ctx),
                    "collected_at": _utc_iso(),
                    "timeout_seconds": timeout,
                    "redacted": self.config.redact_sensitive_values,
                },
            )

            self._log_audit_event(
                {
                    "event_type": "verification.api_response_collected",
                    "context": self._safe_context_public(ctx),
                    "url": url,
                    "method": method,
                    "status_code": status_code,
                    "duration_ms": duration_ms,
                    "success": artifact_success,
                }
            )

            return self._safe_result(
                message=artifact.message,
                data={"artifact": artifact.to_dict()},
                metadata={"agent_id": self.agent_id},
            )

        except Exception as exc:
            duration_ms = round((time.monotonic() - started) * 1000, 3)
            artifact = self._failed_artifact(
                artifact_type="api_response",
                message="API response collection failed.",
                error=self._exception_error(exc),
                context=ctx,
                data={
                    "url": url,
                    "method": method,
                    "request_headers": request_headers,
                    "duration_ms": duration_ms,
                },
            )
            return self._safe_result(
                message="API response collection failed.",
                data={"artifact": artifact.to_dict()},
                metadata={"agent_id": self.agent_id, "duration_ms": duration_ms},
            )

    def build_verification_payload(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        proof_bundle: Mapping[str, Any],
    ) -> JsonDict:
        """
        Public wrapper for Verification Agent payload preparation.
        """
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx = ctx_result["data"]["context"]

        payload = self._prepare_verification_payload(ctx, proof_bundle)
        return self._safe_result(
            message="Verification payload prepared.",
            data={"verification_payload": payload},
            metadata={"agent_id": self.agent_id},
        )

    def build_memory_payload(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        proof_bundle: Mapping[str, Any],
    ) -> JsonDict:
        """
        Public wrapper for Memory Agent compatible payload preparation.
        """
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx = ctx_result["data"]["context"]

        payload = self._prepare_memory_payload(ctx, proof_bundle)
        return self._safe_result(
            message="Memory payload prepared.",
            data={"memory_payload": payload},
            metadata={"agent_id": self.agent_id},
        )

    # -------------------------------------------------------------------------
    # Required compatibility hooks
    # -------------------------------------------------------------------------

    def _validate_task_context(
        self,
        context: Union[TaskContext, Mapping[str, Any], None],
    ) -> JsonDict:
        """
        Required compatibility hook.

        Validates user_id and workspace_id for SaaS tenant isolation.
        """
        if context is None:
            return self._error_result(
                message="Task context is required.",
                error={
                    "code": "MISSING_CONTEXT",
                    "details": "Proof collection requires user_id and workspace_id.",
                },
            )

        if isinstance(context, TaskContext):
            ctx = context
        elif isinstance(context, Mapping):
            ctx = TaskContext(
                user_id=str(context.get("user_id") or "").strip(),
                workspace_id=str(context.get("workspace_id") or "").strip(),
                task_id=self._optional_str(context.get("task_id")),
                run_id=self._optional_str(context.get("run_id")),
                agent_id=self._optional_str(context.get("agent_id")),
                source_agent=self._optional_str(context.get("source_agent")),
                requested_by=self._optional_str(context.get("requested_by")),
                role=self._optional_str(context.get("role")),
                permissions=tuple(str(x) for x in context.get("permissions", []) or []),
                metadata=dict(context.get("metadata") or {}),
            )
        else:
            return self._error_result(
                message="Invalid task context type.",
                error={
                    "code": "INVALID_CONTEXT_TYPE",
                    "details": f"Expected TaskContext or Mapping, got {type(context).__name__}.",
                },
            )

        missing = []
        if not ctx.user_id:
            missing.append("user_id")
        if not ctx.workspace_id:
            missing.append("workspace_id")

        if missing:
            return self._error_result(
                message="Task context validation failed.",
                error={
                    "code": "INVALID_CONTEXT",
                    "missing_fields": missing,
                    "details": "user_id and workspace_id are required for tenant isolation.",
                },
            )

        return self._safe_result(
            message="Task context validated.",
            data={"context": ctx},
            metadata={"agent_id": self.agent_id},
        )

    def _requires_security_check(
        self,
        action: str,
        risk_level: str = "low",
        details: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Required compatibility hook.

        Determines whether an action must route through Security Agent.
        """
        action = (action or "").lower()

        if action == "collect_screenshot":
            return self.config.require_security_for_screenshot
        if action == "collect_logs":
            return self.config.require_security_for_log_read
        if action == "collect_process_status":
            return self.config.require_security_for_process_scan
        if action == "collect_api_response":
            return self.config.require_security_for_api_call

        return risk_level.lower() in {"medium", "high", "critical"}

    def _request_security_approval(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        action: str,
        risk_level: str = "low",
        details: Optional[Mapping[str, Any]] = None,
    ) -> JsonDict:
        """
        Required compatibility hook.

        Calls Security Agent if available. The fallback SecurityAgent is import-safe.
        """
        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx = ctx_result["data"]["context"]

        payload = {
            "action": action,
            "risk_level": risk_level,
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "context": self._safe_context_public(ctx),
            "details": self._redact_if_needed(dict(details or {})),
            "requested_at": _utc_iso(),
        }

        try:
            if hasattr(self.security_agent, "approve_action"):
                approval = self.security_agent.approve_action(payload)
            elif hasattr(self.security_agent, "request_approval"):
                approval = self.security_agent.request_approval(payload)
            else:
                approval = {
                    "success": True,
                    "approved": True,
                    "message": "Security agent has no approval method; fallback allowed.",
                    "data": {"source": "proof_collector_local_fallback"},
                    "error": None,
                    "metadata": {},
                }

            approved = bool(
                approval.get("approved")
                if isinstance(approval, Mapping)
                else False
            )
            success = bool(
                approval.get("success", approved)
                if isinstance(approval, Mapping)
                else False
            )

            if success and approved:
                return self._safe_result(
                    message="Security approval granted.",
                    data={"approval": dict(approval)},
                    metadata={"agent_id": self.agent_id},
                )

            return self._error_result(
                message="Security approval denied.",
                error={
                    "code": "SECURITY_APPROVAL_DENIED",
                    "approval": dict(approval) if isinstance(approval, Mapping) else _safe_str(approval),
                },
                metadata={"agent_id": self.agent_id},
            )

        except Exception as exc:
            return self._error_result(
                message="Security approval request failed.",
                error=self._exception_error(exc),
                metadata={"agent_id": self.agent_id},
            )

    def _prepare_verification_payload(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        proof_data: Mapping[str, Any],
    ) -> JsonDict:
        """
        Required compatibility hook.

        Creates a Verification Agent payload with proof artifact summaries.
        """
        ctx = context if isinstance(context, TaskContext) else self._validate_task_context(context)["data"]["context"]
        artifacts = list(proof_data.get("artifacts", []) or [])

        artifact_summaries: List[JsonDict] = []
        for artifact in artifacts:
            if not isinstance(artifact, Mapping):
                continue
            artifact_summaries.append(
                {
                    "artifact_type": artifact.get("artifact_type"),
                    "success": artifact.get("success"),
                    "message": artifact.get("message"),
                    "error_code": (artifact.get("error") or {}).get("code")
                    if isinstance(artifact.get("error"), Mapping)
                    else None,
                    "collected_at": (artifact.get("metadata") or {}).get("collected_at")
                    if isinstance(artifact.get("metadata"), Mapping)
                    else None,
                }
            )

        return {
            "payload_type": "verification_proof",
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "user_id": ctx.user_id,
            "workspace_id": ctx.workspace_id,
            "task_id": ctx.task_id,
            "run_id": ctx.run_id,
            "bundle_id": proof_data.get("bundle_id"),
            "proof_label": proof_data.get("proof_label"),
            "artifact_count": len(artifact_summaries),
            "successful_artifact_count": sum(1 for item in artifact_summaries if item.get("success") is True),
            "failed_artifact_count": sum(1 for item in artifact_summaries if item.get("success") is False),
            "artifacts": artifact_summaries,
            "created_at": _utc_iso(),
        }

    def _prepare_memory_payload(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        proof_data: Mapping[str, Any],
    ) -> JsonDict:
        """
        Required compatibility hook.

        Creates a compact safe summary for Memory Agent. It avoids storing raw
        screenshot image bytes, raw logs, API bodies, cookies, tokens, or secrets.
        """
        ctx = context if isinstance(context, TaskContext) else self._validate_task_context(context)["data"]["context"]
        artifacts = list(proof_data.get("artifacts", []) or [])

        safe_summary: List[JsonDict] = []
        for artifact in artifacts:
            if not isinstance(artifact, Mapping):
                continue

            data = artifact.get("data") if isinstance(artifact.get("data"), Mapping) else {}
            safe_data: JsonDict = {}

            artifact_type = artifact.get("artifact_type")
            if artifact_type == "screenshot":
                safe_data = {
                    "screenshot_available": data.get("screenshot_available"),
                    "stored_file": data.get("stored_file"),
                    "file_sha256": data.get("file_sha256"),
                    "width": data.get("width"),
                    "height": data.get("height"),
                }
            elif artifact_type == "log":
                safe_data = {
                    "log_path": data.get("log_path"),
                    "file_size_bytes": data.get("file_size_bytes"),
                    "modified_at_utc": data.get("modified_at_utc"),
                    "content_sha256": data.get("content_sha256"),
                    "tail_line_count": data.get("tail_line_count"),
                }
            elif artifact_type == "api_response":
                safe_data = {
                    "url": data.get("url"),
                    "method": data.get("method"),
                    "status_code": data.get("status_code"),
                    "response_body_sha256": data.get("response_body_sha256"),
                    "duration_ms": data.get("duration_ms"),
                    "response_body_truncated": data.get("response_body_truncated"),
                }
            elif artifact_type == "process_status":
                safe_data = {
                    "requested_process_names": data.get("requested_process_names"),
                    "requested_pids": data.get("requested_pids"),
                    "match_count": data.get("match_count"),
                    "scanned_count": data.get("scanned_count"),
                }
            else:
                safe_data = {
                    "data_keys": sorted(list(data.keys())) if isinstance(data, Mapping) else [],
                }

            safe_summary.append(
                {
                    "artifact_type": artifact_type,
                    "success": artifact.get("success"),
                    "message": artifact.get("message"),
                    "safe_data": self._redact_if_needed(safe_data),
                }
            )

        return {
            "payload_type": "verification_proof_memory_summary",
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "user_id": ctx.user_id,
            "workspace_id": ctx.workspace_id,
            "task_id": ctx.task_id,
            "run_id": ctx.run_id,
            "bundle_id": proof_data.get("bundle_id"),
            "proof_label": proof_data.get("proof_label"),
            "summary": safe_summary,
            "created_at": _utc_iso(),
        }

    def _emit_agent_event(
        self,
        event_name: str,
        payload: Mapping[str, Any],
    ) -> None:
        """
        Required compatibility hook.

        Emits lifecycle events for Master Agent, Dashboard/API, Agent Registry,
        or observability layer when an emitter is injected.
        """
        try:
            clean_payload = self._redact_if_needed(dict(payload))
            if self.event_emitter:
                self.event_emitter(event_name, clean_payload)
            else:
                self.logger.debug("Agent event: %s %s", event_name, clean_payload)
        except Exception:
            self.logger.debug("Failed to emit agent event: %s", event_name, exc_info=True)

    def _log_audit_event(
        self,
        event: Mapping[str, Any],
    ) -> None:
        """
        Required compatibility hook.

        Sends audit events to injected audit logger. Falls back to standard logging.
        """
        try:
            clean_event = self._redact_if_needed(dict(event))
            clean_event.setdefault("agent_id", self.agent_id)
            clean_event.setdefault("agent_name", self.agent_name)
            clean_event.setdefault("timestamp", _utc_iso())

            if self.audit_logger:
                self.audit_logger(clean_event)
            else:
                self.logger.info("Audit event: %s", json.dumps(clean_event, default=str))
        except Exception:
            self.logger.debug("Failed to log audit event.", exc_info=True)

    def _safe_result(
        self,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> JsonDict:
        """
        Required compatibility hook.

        Standard success result format.
        """
        clean_data = dict(data or {})
        clean_metadata = dict(metadata or {})
        if self.config.redact_sensitive_values:
            clean_data = self._redact_if_needed(clean_data)
            clean_metadata = self._redact_if_needed(clean_metadata)

        return {
            "success": True,
            "message": message,
            "data": clean_data,
            "error": None,
            "metadata": clean_metadata,
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Mapping[str, Any]] = None,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> JsonDict:
        """
        Required compatibility hook.

        Standard error result format.
        """
        clean_error = dict(error or {"code": "UNKNOWN_ERROR"})
        clean_data = dict(data or {})
        clean_metadata = dict(metadata or {})
        if self.config.redact_sensitive_values:
            clean_error = self._redact_if_needed(clean_error)
            clean_data = self._redact_if_needed(clean_data)
            clean_metadata = self._redact_if_needed(clean_metadata)

        return {
            "success": False,
            "message": message,
            "data": clean_data,
            "error": clean_error,
            "metadata": clean_metadata,
        }

    # -------------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------------

    def _coerce_config(
        self,
        config: Optional[Union[ProofCollectorConfig, Mapping[str, Any]]],
    ) -> ProofCollectorConfig:
        if config is None:
            return ProofCollectorConfig()
        if isinstance(config, ProofCollectorConfig):
            return config
        if isinstance(config, Mapping):
            base = ProofCollectorConfig()
            for key, value in config.items():
                if hasattr(base, str(key)):
                    setattr(base, str(key), value)
            return base
        return ProofCollectorConfig()

    def _request_if_required(
        self,
        context: TaskContext,
        *,
        action: str,
        risk_level: str,
        required: bool,
        details: Optional[Mapping[str, Any]] = None,
    ) -> JsonDict:
        if not required and not self._requires_security_check(action, risk_level, details):
            return self._safe_result(
                message="Security approval not required.",
                data={"approval": {"approved": True, "source": "policy_not_required"}},
            )
        return self._request_security_approval(
            context=context,
            action=action,
            risk_level=risk_level,
            details=details,
        )

    def _validate_log_path(self, log_path: Union[str, Path]) -> JsonDict:
        try:
            path = _normalize_path(log_path)

            if not path.exists():
                return self._error_result(
                    message="Log file does not exist.",
                    error={"code": "LOG_FILE_NOT_FOUND", "path": str(path)},
                )

            if not path.is_file():
                return self._error_result(
                    message="Log path is not a file.",
                    error={"code": "LOG_PATH_NOT_FILE", "path": str(path)},
                )

            if path.suffix.lower() in {ext.lower() for ext in self.config.blocked_log_extensions}:
                return self._error_result(
                    message="Log file extension is blocked by safety policy.",
                    error={
                        "code": "BLOCKED_LOG_EXTENSION",
                        "path": str(path),
                        "extension": path.suffix,
                    },
                )

            if not self.config.allow_log_path_outside_allowed_dirs:
                allowed = [_normalize_path(item) for item in self.config.allowed_log_dirs]
                in_allowed_dir = any(_is_subpath(path, allowed_dir) for allowed_dir in allowed)
                if not in_allowed_dir:
                    return self._error_result(
                        message="Log path is outside allowed log directories.",
                        error={
                            "code": "LOG_PATH_OUTSIDE_ALLOWED_DIRS",
                            "path": str(path),
                            "allowed_log_dirs": [str(item) for item in allowed],
                        },
                    )

            return self._safe_result(
                message="Log path validated.",
                data={"path": str(path)},
            )

        except Exception as exc:
            return self._error_result(
                message="Log path validation failed.",
                error=self._exception_error(exc),
            )

    def _validate_api_request(self, *, url: str, method: str) -> Optional[JsonDict]:
        if not url:
            return {"code": "MISSING_API_URL", "details": "request_spec.url is required."}

        if not _valid_http_url(url):
            return {
                "code": "INVALID_API_URL",
                "details": "Only valid http/https URLs are allowed.",
                "url": url,
            }

        if method not in {"GET", "HEAD", "POST"}:
            return {
                "code": "UNSUPPORTED_API_METHOD",
                "details": "Only GET, HEAD, and POST are supported for proof collection.",
                "method": method,
            }

        if not self.config.allow_api_private_hosts and _is_private_or_local_host(url):
            return {
                "code": "PRIVATE_OR_LOCAL_API_HOST_BLOCKED",
                "details": "Private/local API hosts are blocked by default to reduce SSRF risk.",
                "url": url,
            }

        return None

    def _read_file_tail_bytes(self, path: Path, max_bytes: int) -> bytes:
        size = path.stat().st_size
        with path.open("rb") as handle:
            if size > max_bytes:
                handle.seek(max(0, size - max_bytes))
            return handle.read(max_bytes)

    def _build_extra_evidence_artifact(
        self,
        *,
        extra_evidence: Mapping[str, Any],
        context: TaskContext,
        bundle_id: str,
    ) -> ProofArtifact:
        evidence = dict(extra_evidence or {})
        if self.config.redact_sensitive_values:
            evidence = self._redact_if_needed(evidence)

        return ProofArtifact(
            artifact_type="extra_evidence",
            success=True,
            message="Extra evidence attached.",
            data={
                "evidence": evidence,
                "evidence_sha256": _sha256_text(json.dumps(evidence, sort_keys=True, default=str)),
            },
            metadata={
                "context": self._safe_context_public(context),
                "bundle_id": bundle_id,
                "collected_at": _utc_iso(),
                "redacted": self.config.redact_sensitive_values,
            },
        )

    def _failed_artifact(
        self,
        *,
        artifact_type: str,
        message: str,
        error: Mapping[str, Any],
        context: TaskContext,
        data: Optional[Mapping[str, Any]] = None,
    ) -> ProofArtifact:
        return ProofArtifact(
            artifact_type=artifact_type,
            success=False,
            message=message,
            data=dict(data or {}),
            error=dict(error),
            metadata={
                "context": self._safe_context_public(context),
                "collected_at": _utc_iso(),
            },
        )

    def _exception_error(self, exc: BaseException) -> JsonDict:
        return {
            "code": exc.__class__.__name__.upper(),
            "message": _safe_str(exc),
            "traceback": traceback.format_exc(limit=5),
        }

    def _proof_dir_for_context(self, context: TaskContext, bundle_id: str) -> Path:
        root = _normalize_path(self.config.proof_root_dir)
        user_hash = _sha256_text(context.user_id)[:16]
        workspace_hash = _sha256_text(context.workspace_id)[:16]
        return root / user_hash / workspace_hash / self._safe_filename(bundle_id)

    def _make_bundle_id(
        self,
        context: TaskContext,
        proof_label: Optional[str] = None,
    ) -> str:
        raw = {
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "task_id": context.task_id,
            "run_id": context.run_id,
            "proof_label": proof_label,
            "timestamp": _utc_iso(),
            "nonce": time.monotonic_ns(),
        }
        digest = _sha256_text(json.dumps(raw, sort_keys=True, default=str))[:20]
        label = self._safe_filename(proof_label or "proof_bundle")
        return f"{label}_{digest}"

    def _safe_filename(self, value: str) -> str:
        safe = []
        for char in str(value):
            if char.isalnum() or char in {"-", "_", "."}:
                safe.append(char)
            else:
                safe.append("_")
        result = "".join(safe).strip("._")
        return result[:120] or "proof"

    def _safe_context_public(self, context: TaskContext) -> JsonDict:
        """
        Public context representation.

        Keeps tenant identifiers because routing requires them, but avoids dumping
        all metadata blindly.
        """
        return {
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "task_id": context.task_id,
            "run_id": context.run_id,
            "agent_id": context.agent_id,
            "source_agent": context.source_agent,
            "requested_by": context.requested_by,
            "role": context.role,
        }

    def _redact_if_needed(self, value: Any) -> Any:
        if not self.config.redact_sensitive_values:
            return value
        return _redact_mapping(value, self.config.sensitive_key_fragments)

    def _optional_str(self, value: Any) -> Optional[str]:
        if value is None:
            return None
        text = str(value).strip()
        return text or None


# =============================================================================
# Factory and module metadata
# =============================================================================

def create_proof_collector(
    config: Optional[Union[ProofCollectorConfig, Mapping[str, Any]]] = None,
    security_agent: Optional[Any] = None,
    event_emitter: Optional[EventEmitterCallable] = None,
    audit_logger: Optional[AuditLoggerCallable] = None,
) -> ProofCollector:
    """
    Factory helper for Agent Loader / Agent Registry.

    This keeps construction consistent and avoids direct dependency on the full
    application container during early development.
    """
    return ProofCollector(
        config=config,
        security_agent=security_agent,
        event_emitter=event_emitter,
        audit_logger=audit_logger,
    )


AGENT_MODULE_METADATA: JsonDict = {
    "module": "agents.verification_agent.proof_collector",
    "file_name": "proof_collector.py",
    "class_name": "ProofCollector",
    "agent_module": "Verification Agent",
    "purpose": "Collects screenshots, logs, process status, API responses, timestamps.",
    "version": "1.0.0",
    "safe_to_import": True,
    "requires_user_workspace_context": True,
    "public_methods": [
        "collect_proof_bundle",
        "collect_timestamp",
        "collect_screenshot",
        "collect_logs",
        "collect_process_status",
        "collect_api_response",
        "build_verification_payload",
        "build_memory_payload",
    ],
    "compatibility_hooks": [
        "_validate_task_context",
        "_requires_security_check",
        "_request_security_approval",
        "_prepare_verification_payload",
        "_prepare_memory_payload",
        "_emit_agent_event",
        "_log_audit_event",
        "_safe_result",
        "_error_result",
    ],
    "optional_dependencies": {
        "psutil": "Required for process status proof.",
        "Pillow": "Required for screenshot proof through PIL.ImageGrab.",
    },
}


__all__ = [
    "ProofCollector",
    "ProofCollectorConfig",
    "ProofArtifact",
    "TaskContext",
    "create_proof_collector",
    "AGENT_MODULE_METADATA",
]


if __name__ == "__main__":
    # Lightweight smoke test. Does not capture screenshots, read logs, or call APIs.
    collector = ProofCollector()
    smoke_context = {
        "user_id": "demo_user",
        "workspace_id": "demo_workspace",
        "task_id": "demo_task",
        "run_id": "demo_run",
    }
    result = collector.collect_proof_bundle(
        smoke_context,
        include_timestamp=True,
        screenshot=False,
        extra_evidence={"status": "smoke_test_ok"},
        proof_label="smoke_test",
    )
    print(json.dumps(result, indent=2, default=str))