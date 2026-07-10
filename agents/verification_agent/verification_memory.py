"""
agents/verification_agent/verification_memory.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Stores success signals and verification patterns for apps/sites/projects.

This module helps the Verification Agent remember what "success" usually looks like
for a given user/workspace/project/resource. It stores reusable verification patterns
such as:
    - Expected page titles, URLs, visible text, DOM selectors
    - Expected files/folders/processes/ports/services
    - Expected app/window/device/browser states
    - Known success signals from previous completed tasks
    - Failure indicators and anti-patterns
    - Confidence statistics for repeated verification outcomes

Architecture compatibility:
    - Import-safe even if BaseAgent or other William modules are not present yet.
    - Compatible with Master Agent routing and Agent Registry discovery.
    - Compatible with SaaS multi-tenant user/workspace isolation.
    - Provides structured dict/JSON style results.
    - Prepares Memory Agent payloads for useful verification learning.
    - Prepares Verification Agent payloads for completed actions.
    - Includes Security Agent hooks for sensitive or cross-scope operations.
    - Ready for future FastAPI/dashboard integration.

Important:
    This file does not execute browser/device/system/destructive actions.
    It only stores, retrieves, scores, and exports verification memory data.
"""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
import logging
import os
import re
import threading
import time
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, ClassVar, Dict, Iterable, List, Mapping, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Safe optional imports / fallbacks
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for standalone import safety
    class BaseAgent:  # type: ignore
        """
        Minimal fallback BaseAgent stub.

        Real William deployments should provide agents.base_agent.BaseAgent.
        This fallback keeps the file import-safe during early development,
        tests, code generation, and isolated module loading.
        """

        agent_name: str = "base_agent_fallback"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.config = kwargs.get("config", {}) or {}

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            return None

        def log_audit(self, action: str, payload: Dict[str, Any]) -> None:
            return None


try:
    from agents.security_agent.security_agent import SecurityAgent  # type: ignore
except Exception:  # pragma: no cover
    SecurityAgent = None  # type: ignore


try:
    from agents.memory_agent.memory_agent import MemoryAgent  # type: ignore
except Exception:  # pragma: no cover
    MemoryAgent = None  # type: ignore


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
if not logger.handlers:
    logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

UTC = timezone.utc

VERIFICATION_MEMORY_SCHEMA_VERSION = "1.0.0"

DEFAULT_MAX_PATTERNS_PER_SCOPE = 5000
DEFAULT_MAX_SIGNALS_PER_PATTERN = 100
DEFAULT_MIN_CONFIDENCE = 0.0
DEFAULT_MAX_CONFIDENCE = 1.0
DEFAULT_RETENTION_DAYS = 365
DEFAULT_RECENT_MATCH_LIMIT = 20

SENSITIVE_CONTEXT_KEYS = {
    "password",
    "token",
    "secret",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "session",
    "credential",
    "private_key",
    "access_key",
    "refresh_token",
    "bearer",
}

SAFE_PATTERN_TYPES = {
    "app",
    "browser",
    "code",
    "device",
    "file",
    "folder",
    "service",
    "port",
    "site",
    "ui",
    "api",
    "workflow",
    "task",
    "custom",
}

SAFE_SIGNAL_TYPES = {
    "url",
    "title",
    "text",
    "selector",
    "status_code",
    "file_exists",
    "folder_exists",
    "process_running",
    "service_running",
    "port_open",
    "api_response",
    "json_field",
    "log_contains",
    "screenshot_observation",
    "ui_element",
    "device_state",
    "code_test",
    "build_status",
    "custom",
}

RISKY_OPERATION_NAMES = {
    "delete_pattern",
    "delete_scope",
    "clear_workspace_memory",
    "import_patterns",
    "overwrite_patterns",
    "cross_workspace_read",
    "cross_user_read",
    "cross_workspace_write",
    "cross_user_write",
}


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _utc_now() -> datetime:
    return datetime.now(tz=UTC)


def _utc_now_iso() -> str:
    return _utc_now().isoformat()


def _safe_uuid(prefix: str = "vmem") -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def _normalize_str(value: Any, max_len: int = 500) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    text = re.sub(r"\s+", " ", text)
    return text[:max_len]


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _stable_json_hash(payload: Mapping[str, Any]) -> str:
    safe_payload = json.dumps(payload, sort_keys=True, default=str, ensure_ascii=False)
    return _sha256_text(safe_payload)


def _coerce_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _clamp_float(value: Any, minimum: float = 0.0, maximum: float = 1.0) -> float:
    number = _coerce_float(value, minimum)
    return max(minimum, min(maximum, number))


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _deepcopy_json_safe(value: Any) -> Any:
    try:
        return json.loads(json.dumps(value, default=str))
    except Exception:
        return copy.deepcopy(value)


def _redact_sensitive(value: Any) -> Any:
    """
    Redact sensitive keys recursively.

    The Verification Memory should store patterns and signals, not credentials.
    """
    if isinstance(value, Mapping):
        redacted: Dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key).lower()
            if any(sensitive in key_text for sensitive in SENSITIVE_CONTEXT_KEYS):
                redacted[str(key)] = "[REDACTED]"
            else:
                redacted[str(key)] = _redact_sensitive(item)
        return redacted

    if isinstance(value, list):
        return [_redact_sensitive(item) for item in value]

    if isinstance(value, tuple):
        return tuple(_redact_sensitive(item) for item in value)

    if isinstance(value, str):
        text = value
        text = re.sub(
            r"(?i)(bearer\s+)[a-z0-9._\-+/=]+",
            r"\1[REDACTED]",
            text,
        )
        text = re.sub(
            r"(?i)(api[_-]?key\s*[:=]\s*)[a-z0-9._\-+/=]+",
            r"\1[REDACTED]",
            text,
        )
        text = re.sub(
            r"(?i)(password\s*[:=]\s*)\S+",
            r"\1[REDACTED]",
            text,
        )
        return text

    return value


def _safe_slug(value: str, fallback: str = "default") -> str:
    text = _normalize_str(value, max_len=120).lower()
    text = re.sub(r"[^a-z0-9._-]+", "_", text)
    text = text.strip("._-")
    return text or fallback


def _parse_iso_datetime(value: Any) -> Optional[datetime]:
    if not value:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class VerificationSignal:
    """
    A reusable success/failure signal.

    Examples:
        - title contains "Dashboard"
        - URL contains "/dashboard"
        - file exists at "dist/index.html"
        - API response JSON field "success" equals true
        - UI selector "#submit-button" is visible
    """

    signal_id: str
    signal_type: str
    name: str
    expected: Any
    operator: str = "contains"
    weight: float = 1.0
    confidence: float = 0.7
    positive: bool = True
    source: str = "verification_memory"
    description: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=_utc_now_iso)
    updated_at: str = field(default_factory=_utc_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "signal_id": self.signal_id,
            "signal_type": self.signal_type,
            "name": self.name,
            "expected": _redact_sensitive(self.expected),
            "operator": self.operator,
            "weight": self.weight,
            "confidence": self.confidence,
            "positive": self.positive,
            "source": self.source,
            "description": self.description,
            "metadata": _redact_sensitive(self.metadata),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "VerificationSignal":
        signal_type = _normalize_str(payload.get("signal_type") or "custom", 80)
        if signal_type not in SAFE_SIGNAL_TYPES:
            signal_type = "custom"

        return cls(
            signal_id=_normalize_str(payload.get("signal_id") or _safe_uuid("sig"), 120),
            signal_type=signal_type,
            name=_normalize_str(payload.get("name") or signal_type, 200),
            expected=_redact_sensitive(payload.get("expected")),
            operator=_normalize_str(payload.get("operator") or "contains", 60),
            weight=max(0.0, _coerce_float(payload.get("weight"), 1.0)),
            confidence=_clamp_float(payload.get("confidence"), 0.0, 1.0),
            positive=bool(payload.get("positive", True)),
            source=_normalize_str(payload.get("source") or "verification_memory", 120),
            description=_normalize_str(payload.get("description") or "", 1000),
            metadata=_redact_sensitive(dict(payload.get("metadata") or {})),
            created_at=_normalize_str(payload.get("created_at") or _utc_now_iso(), 80),
            updated_at=_normalize_str(payload.get("updated_at") or _utc_now_iso(), 80),
        )


@dataclass
class VerificationPattern:
    """
    A grouped set of signals for a project/resource/task.

    A pattern can be matched later against an observed state to estimate whether
    a new task completed successfully.
    """

    pattern_id: str
    user_id: str
    workspace_id: str
    pattern_type: str
    name: str
    project_id: Optional[str] = None
    resource_key: Optional[str] = None
    task_type: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    success_signals: List[VerificationSignal] = field(default_factory=list)
    failure_signals: List[VerificationSignal] = field(default_factory=list)
    confidence: float = 0.7
    success_count: int = 0
    failure_count: int = 0
    last_matched_at: Optional[str] = None
    source: str = "verification_memory"
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=_utc_now_iso)
    updated_at: str = field(default_factory=_utc_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "pattern_type": self.pattern_type,
            "name": self.name,
            "project_id": self.project_id,
            "resource_key": self.resource_key,
            "task_type": self.task_type,
            "tags": list(self.tags),
            "success_signals": [signal.to_dict() for signal in self.success_signals],
            "failure_signals": [signal.to_dict() for signal in self.failure_signals],
            "confidence": self.confidence,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "last_matched_at": self.last_matched_at,
            "source": self.source,
            "metadata": _redact_sensitive(self.metadata),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "VerificationPattern":
        pattern_type = _normalize_str(payload.get("pattern_type") or "custom", 80)
        if pattern_type not in SAFE_PATTERN_TYPES:
            pattern_type = "custom"

        return cls(
            pattern_id=_normalize_str(payload.get("pattern_id") or _safe_uuid("vpat"), 120),
            user_id=_normalize_str(payload.get("user_id"), 120),
            workspace_id=_normalize_str(payload.get("workspace_id"), 120),
            pattern_type=pattern_type,
            name=_normalize_str(payload.get("name") or pattern_type, 200),
            project_id=_normalize_str(payload.get("project_id"), 160) or None,
            resource_key=_normalize_str(payload.get("resource_key"), 300) or None,
            task_type=_normalize_str(payload.get("task_type"), 160) or None,
            tags=[
                _safe_slug(str(tag), "tag")
                for tag in list(payload.get("tags") or [])
                if _normalize_str(tag)
            ],
            success_signals=[
                VerificationSignal.from_dict(signal)
                for signal in list(payload.get("success_signals") or [])
                if isinstance(signal, Mapping)
            ],
            failure_signals=[
                VerificationSignal.from_dict(signal)
                for signal in list(payload.get("failure_signals") or [])
                if isinstance(signal, Mapping)
            ],
            confidence=_clamp_float(payload.get("confidence"), 0.0, 1.0),
            success_count=max(0, _coerce_int(payload.get("success_count"), 0)),
            failure_count=max(0, _coerce_int(payload.get("failure_count"), 0)),
            last_matched_at=_normalize_str(payload.get("last_matched_at"), 80) or None,
            source=_normalize_str(payload.get("source") or "verification_memory", 120),
            metadata=_redact_sensitive(dict(payload.get("metadata") or {})),
            created_at=_normalize_str(payload.get("created_at") or _utc_now_iso(), 80),
            updated_at=_normalize_str(payload.get("updated_at") or _utc_now_iso(), 80),
        )


@dataclass
class VerificationMemoryConfig:
    """
    Runtime configuration.

    storage_path:
        Optional JSON file path. If omitted, the memory is in-process only.
        For production, this can later be replaced with a database repository.
    """

    storage_path: Optional[str] = None
    autosave: bool = True
    max_patterns_per_scope: int = DEFAULT_MAX_PATTERNS_PER_SCOPE
    max_signals_per_pattern: int = DEFAULT_MAX_SIGNALS_PER_PATTERN
    retention_days: int = DEFAULT_RETENTION_DAYS
    allow_cross_workspace_admin: bool = False
    redact_sensitive_data: bool = True
    enable_audit_log: bool = True
    enable_agent_events: bool = True
    enable_memory_payloads: bool = True
    default_confidence: float = 0.7

    @classmethod
    def from_mapping(cls, payload: Optional[Mapping[str, Any]]) -> "VerificationMemoryConfig":
        payload = payload or {}
        return cls(
            storage_path=(
                _normalize_str(payload.get("storage_path"), 1000) or None
            ),
            autosave=bool(payload.get("autosave", True)),
            max_patterns_per_scope=max(
                1,
                _coerce_int(payload.get("max_patterns_per_scope"), DEFAULT_MAX_PATTERNS_PER_SCOPE),
            ),
            max_signals_per_pattern=max(
                1,
                _coerce_int(payload.get("max_signals_per_pattern"), DEFAULT_MAX_SIGNALS_PER_PATTERN),
            ),
            retention_days=max(
                1,
                _coerce_int(payload.get("retention_days"), DEFAULT_RETENTION_DAYS),
            ),
            allow_cross_workspace_admin=bool(payload.get("allow_cross_workspace_admin", False)),
            redact_sensitive_data=bool(payload.get("redact_sensitive_data", True)),
            enable_audit_log=bool(payload.get("enable_audit_log", True)),
            enable_agent_events=bool(payload.get("enable_agent_events", True)),
            enable_memory_payloads=bool(payload.get("enable_memory_payloads", True)),
            default_confidence=_clamp_float(payload.get("default_confidence"), 0.0, 1.0),
        )


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class VerificationMemory(BaseAgent):
    """
    Stores success signals and verification patterns for apps/sites/projects.

    Public methods:
        - remember_success()
        - remember_failure()
        - store_pattern()
        - update_pattern()
        - get_pattern()
        - find_patterns()
        - match_observation()
        - learn_from_verification_result()
        - record_match_outcome()
        - delete_pattern()
        - export_memory()
        - import_memory()
        - prune_memory()
        - get_stats()
        - health_check()

    Master Agent / Router:
        The Master Agent can route "remember verification pattern", "find success
        signal", or "match current state" tasks to this class.

    Security Agent:
        Sensitive operations such as delete/import/cross-scope access call
        _requires_security_check() and _request_security_approval().

    Memory Agent:
        Useful learned verification patterns are converted into
        _prepare_memory_payload() output for long-term memory compatibility.

    Dashboard/API:
        Methods return structured dict/JSON style responses for easy FastAPI
        endpoint wrapping later.
    """

    agent_name: ClassVar[str] = "verification_memory"
    agent_type: ClassVar[str] = "verification_agent_helper"
    registry_name: ClassVar[str] = "VerificationMemory"
    version: ClassVar[str] = VERIFICATION_MEMORY_SCHEMA_VERSION

    def __init__(
        self,
        config: Optional[Mapping[str, Any]] = None,
        *,
        security_agent: Any = None,
        memory_agent: Any = None,
        audit_logger: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        event_emitter: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    ) -> None:
        super().__init__(config=dict(config or {}))
        self.memory_config = VerificationMemoryConfig.from_mapping(config)
        self.security_agent = security_agent
        self.memory_agent = memory_agent
        self.audit_logger = audit_logger
        self.event_emitter = event_emitter

        self._lock = threading.RLock()
        self._patterns: Dict[str, VerificationPattern] = {}
        self._scope_index: Dict[Tuple[str, str], set[str]] = defaultdict(set)
        self._project_index: Dict[Tuple[str, str, str], set[str]] = defaultdict(set)
        self._resource_index: Dict[Tuple[str, str, str], set[str]] = defaultdict(set)
        self._tag_index: Dict[Tuple[str, str, str], set[str]] = defaultdict(set)

        self._load_from_disk_safely()

    # ------------------------------------------------------------------
    # Required compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(
        self,
        context: Optional[Mapping[str, Any]],
        *,
        require_user_workspace: bool = True,
    ) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """
        Validate SaaS isolation context.

        Every user-specific verification memory operation must include user_id
        and workspace_id. This prevents cross-tenant pattern leakage.
        """
        safe_context = dict(context or {})
        user_id = _normalize_str(safe_context.get("user_id"), 120)
        workspace_id = _normalize_str(safe_context.get("workspace_id"), 120)

        if require_user_workspace and not user_id:
            return False, "Missing required user_id for verification memory operation.", safe_context

        if require_user_workspace and not workspace_id:
            return False, "Missing required workspace_id for verification memory operation.", safe_context

        safe_context["user_id"] = user_id
        safe_context["workspace_id"] = workspace_id

        return True, None, safe_context

    def _requires_security_check(self, operation: str, context: Optional[Mapping[str, Any]] = None) -> bool:
        """
        Determine whether a memory operation needs Security Agent approval.
        """
        operation_name = _normalize_str(operation, 120).lower()
        context = context or {}

        if operation_name in RISKY_OPERATION_NAMES:
            return True

        if context.get("cross_workspace") or context.get("cross_user"):
            return True

        if context.get("admin_override"):
            return True

        return False

    def _request_security_approval(
        self,
        operation: str,
        context: Optional[Mapping[str, Any]] = None,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request approval from Security Agent if available.

        Fallback behavior:
            Safe local deny for risky operation unless explicitly marked
            security_approved=True in trusted context.
        """
        safe_context = dict(context or {})
        safe_payload = _redact_sensitive(dict(payload or {}))
        operation_name = _normalize_str(operation, 120)

        if not self._requires_security_check(operation_name, safe_context):
            return self._safe_result(
                True,
                "Security approval not required.",
                data={"approved": True, "reason": "not_required"},
                metadata={"operation": operation_name},
            )

        if bool(safe_context.get("security_approved")):
            return self._safe_result(
                True,
                "Security approval accepted from trusted context.",
                data={"approved": True, "reason": "trusted_context"},
                metadata={"operation": operation_name},
            )

        agent = self.security_agent
        if agent is None and SecurityAgent is not None:
            try:
                agent = SecurityAgent()
            except Exception:
                agent = None

        if agent is not None:
            try:
                if hasattr(agent, "approve_action"):
                    decision = agent.approve_action(
                        action=operation_name,
                        context=safe_context,
                        payload=safe_payload,
                    )
                elif hasattr(agent, "request_approval"):
                    decision = agent.request_approval(
                        operation=operation_name,
                        context=safe_context,
                        payload=safe_payload,
                    )
                else:
                    decision = {"approved": False, "reason": "security_agent_missing_approval_method"}

                approved = bool(
                    decision.get("approved")
                    if isinstance(decision, Mapping)
                    else decision
                )
                return self._safe_result(
                    approved,
                    "Security approval granted." if approved else "Security approval denied.",
                    data={
                        "approved": approved,
                        "decision": _redact_sensitive(decision),
                    },
                    metadata={"operation": operation_name},
                )
            except Exception as exc:
                logger.exception("Security approval request failed.")
                return self._error_result(
                    "Security approval request failed.",
                    error=exc,
                    metadata={"operation": operation_name},
                )

        return self._safe_result(
            False,
            "Security approval required but no Security Agent approval is available.",
            data={"approved": False, "reason": "approval_unavailable"},
            metadata={"operation": operation_name},
        )

    def _prepare_verification_payload(
        self,
        action: str,
        context: Optional[Mapping[str, Any]] = None,
        data: Optional[Mapping[str, Any]] = None,
        success: bool = True,
        confidence: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Prepare a Verification Agent compatible payload.
        """
        safe_context = _redact_sensitive(dict(context or {}))
        safe_data = _redact_sensitive(dict(data or {}))

        return {
            "agent": self.agent_name,
            "action": action,
            "success": bool(success),
            "confidence": _clamp_float(
                self.memory_config.default_confidence if confidence is None else confidence,
                0.0,
                1.0,
            ),
            "user_id": safe_context.get("user_id"),
            "workspace_id": safe_context.get("workspace_id"),
            "data": safe_data,
            "timestamp": _utc_now_iso(),
            "schema_version": self.version,
        }

    def _prepare_memory_payload(
        self,
        action: str,
        context: Optional[Mapping[str, Any]] = None,
        pattern: Optional[VerificationPattern] = None,
        data: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare a Memory Agent compatible payload.

        This payload can be stored by the Memory Agent as useful context about
        how a user/workspace/project normally verifies successful completion.
        """
        safe_context = _redact_sensitive(dict(context or {}))
        safe_data = _redact_sensitive(dict(data or {}))

        payload = {
            "memory_type": "verification_pattern",
            "source_agent": self.agent_name,
            "action": action,
            "user_id": safe_context.get("user_id"),
            "workspace_id": safe_context.get("workspace_id"),
            "project_id": safe_context.get("project_id"),
            "importance": "medium",
            "content": {},
            "tags": ["verification", "success_signals", "patterns"],
            "created_at": _utc_now_iso(),
            "schema_version": self.version,
        }

        if pattern is not None:
            payload["project_id"] = pattern.project_id or payload.get("project_id")
            payload["content"] = {
                "pattern_id": pattern.pattern_id,
                "pattern_type": pattern.pattern_type,
                "name": pattern.name,
                "resource_key": pattern.resource_key,
                "task_type": pattern.task_type,
                "confidence": pattern.confidence,
                "success_signal_count": len(pattern.success_signals),
                "failure_signal_count": len(pattern.failure_signals),
                "success_count": pattern.success_count,
                "failure_count": pattern.failure_count,
            }
            payload["tags"].extend(pattern.tags[:10])
        else:
            payload["content"] = safe_data

        return payload

    def _emit_agent_event(
        self,
        event_name: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Emit Agent Registry / Dashboard compatible events.
        """
        if not self.memory_config.enable_agent_events:
            return

        safe_payload = _redact_sensitive(dict(payload or {}))
        safe_payload.setdefault("agent", self.agent_name)
        safe_payload.setdefault("timestamp", _utc_now_iso())

        try:
            if self.event_emitter:
                self.event_emitter(event_name, safe_payload)
                return

            if hasattr(self, "emit_event"):
                self.emit_event(event_name, safe_payload)  # type: ignore[attr-defined]
        except Exception:
            logger.debug("Agent event emission failed.", exc_info=True)

    def _log_audit_event(
        self,
        action: str,
        context: Optional[Mapping[str, Any]] = None,
        data: Optional[Mapping[str, Any]] = None,
        success: bool = True,
    ) -> None:
        """
        Log audit events without leaking sensitive data.
        """
        if not self.memory_config.enable_audit_log:
            return

        payload = {
            "agent": self.agent_name,
            "action": action,
            "success": bool(success),
            "context": _redact_sensitive(dict(context or {})),
            "data": _redact_sensitive(dict(data or {})),
            "timestamp": _utc_now_iso(),
        }

        try:
            if self.audit_logger:
                self.audit_logger(action, payload)
                return

            if hasattr(self, "log_audit"):
                self.log_audit(action, payload)  # type: ignore[attr-defined]
        except Exception:
            logger.debug("Audit logging failed.", exc_info=True)

    def _safe_result(
        self,
        success: bool,
        message: str,
        *,
        data: Optional[Mapping[str, Any]] = None,
        error: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard result wrapper used across William/Jarvis agents.
        """
        return {
            "success": bool(success),
            "message": str(message),
            "data": _redact_sensitive(dict(data or {})),
            "error": self._serialize_error(error) if error else None,
            "metadata": {
                "agent": self.agent_name,
                "schema_version": self.version,
                "timestamp": _utc_now_iso(),
                **_redact_sensitive(dict(metadata or {})),
            },
        }

    def _error_result(
        self,
        message: str,
        *,
        error: Optional[Any] = None,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self._safe_result(
            False,
            message,
            data=data,
            error=error,
            metadata=metadata,
        )

    @staticmethod
    def _serialize_error(error: Any) -> Dict[str, Any]:
        if error is None:
            return {}
        if isinstance(error, Mapping):
            return _redact_sensitive(dict(error))
        return {
            "type": error.__class__.__name__,
            "message": str(error),
        }

    # ------------------------------------------------------------------
    # Public API: storing memory
    # ------------------------------------------------------------------

    def remember_success(
        self,
        context: Mapping[str, Any],
        *,
        name: str,
        pattern_type: str = "custom",
        success_signals: Optional[List[Mapping[str, Any]]] = None,
        project_id: Optional[str] = None,
        resource_key: Optional[str] = None,
        task_type: Optional[str] = None,
        tags: Optional[List[str]] = None,
        confidence: Optional[float] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Store a successful verification pattern.

        Example:
            remember_success(
                {"user_id": "u1", "workspace_id": "w1"},
                name="Dashboard loaded",
                pattern_type="browser",
                success_signals=[
                    {"signal_type": "url", "name": "dashboard url", "expected": "/dashboard"},
                    {"signal_type": "title", "name": "page title", "expected": "Dashboard"},
                ],
            )
        """
        valid, error_message, safe_context = self._validate_task_context(context)
        if not valid:
            return self._error_result(error_message or "Invalid context.")

        pattern_payload = {
            "user_id": safe_context["user_id"],
            "workspace_id": safe_context["workspace_id"],
            "pattern_type": pattern_type,
            "name": name,
            "project_id": project_id or safe_context.get("project_id"),
            "resource_key": resource_key,
            "task_type": task_type,
            "tags": tags or [],
            "success_signals": success_signals or [],
            "failure_signals": [],
            "confidence": self.memory_config.default_confidence if confidence is None else confidence,
            "success_count": 1,
            "failure_count": 0,
            "source": "remember_success",
            "metadata": metadata or {},
        }

        result = self.store_pattern(safe_context, pattern_payload)

        if result.get("success"):
            pattern_data = result.get("data", {}).get("pattern", {})
            self._emit_memory_payload(
                "remember_success",
                safe_context,
                VerificationPattern.from_dict(pattern_data) if pattern_data else None,
            )

        return result

    def remember_failure(
        self,
        context: Mapping[str, Any],
        *,
        name: str,
        pattern_type: str = "custom",
        failure_signals: Optional[List[Mapping[str, Any]]] = None,
        project_id: Optional[str] = None,
        resource_key: Optional[str] = None,
        task_type: Optional[str] = None,
        tags: Optional[List[str]] = None,
        confidence: Optional[float] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Store a known failure pattern or anti-pattern.

        Failure patterns improve future checks by reducing confidence when
        matching bad states such as 404 pages, permission errors, build failures,
        blank screens, or crash indicators.
        """
        valid, error_message, safe_context = self._validate_task_context(context)
        if not valid:
            return self._error_result(error_message or "Invalid context.")

        pattern_payload = {
            "user_id": safe_context["user_id"],
            "workspace_id": safe_context["workspace_id"],
            "pattern_type": pattern_type,
            "name": name,
            "project_id": project_id or safe_context.get("project_id"),
            "resource_key": resource_key,
            "task_type": task_type,
            "tags": tags or [],
            "success_signals": [],
            "failure_signals": failure_signals or [],
            "confidence": self.memory_config.default_confidence if confidence is None else confidence,
            "success_count": 0,
            "failure_count": 1,
            "source": "remember_failure",
            "metadata": metadata or {},
        }

        return self.store_pattern(safe_context, pattern_payload)

    def store_pattern(
        self,
        context: Mapping[str, Any],
        pattern: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Store a verification pattern.

        If pattern_id already exists, this method updates it only within the same
        user/workspace scope.
        """
        valid, error_message, safe_context = self._validate_task_context(context)
        if not valid:
            return self._error_result(error_message or "Invalid context.")

        try:
            pattern_payload = dict(pattern)
            pattern_payload["user_id"] = safe_context["user_id"]
            pattern_payload["workspace_id"] = safe_context["workspace_id"]
            pattern_payload.setdefault("pattern_id", self._build_pattern_id(pattern_payload))

            pattern_obj = VerificationPattern.from_dict(pattern_payload)
            validation_result = self._validate_pattern_scope(pattern_obj, safe_context)
            if not validation_result["success"]:
                return validation_result

            pattern_obj.success_signals = pattern_obj.success_signals[: self.memory_config.max_signals_per_pattern]
            pattern_obj.failure_signals = pattern_obj.failure_signals[: self.memory_config.max_signals_per_pattern]
            pattern_obj.updated_at = _utc_now_iso()

            with self._lock:
                self._enforce_scope_limit(pattern_obj.user_id, pattern_obj.workspace_id)
                existing = self._patterns.get(pattern_obj.pattern_id)

                if existing:
                    if (
                        existing.user_id != pattern_obj.user_id
                        or existing.workspace_id != pattern_obj.workspace_id
                    ):
                        return self._error_result(
                            "Pattern ID belongs to a different user/workspace scope.",
                            metadata={"pattern_id": pattern_obj.pattern_id},
                        )

                    pattern_obj.created_at = existing.created_at
                    pattern_obj.success_count = max(pattern_obj.success_count, existing.success_count)
                    pattern_obj.failure_count = max(pattern_obj.failure_count, existing.failure_count)

                self._patterns[pattern_obj.pattern_id] = pattern_obj
                self._rebuild_indexes_locked()
                self._save_to_disk_safely()

            data = {
                "pattern": pattern_obj.to_dict(),
                "verification_payload": self._prepare_verification_payload(
                    "store_pattern",
                    safe_context,
                    {"pattern_id": pattern_obj.pattern_id},
                    success=True,
                    confidence=pattern_obj.confidence,
                ),
                "memory_payload": self._prepare_memory_payload(
                    "store_pattern",
                    safe_context,
                    pattern_obj,
                ),
            }

            self._log_audit_event(
                "store_pattern",
                safe_context,
                {"pattern_id": pattern_obj.pattern_id, "pattern_type": pattern_obj.pattern_type},
                success=True,
            )
            self._emit_agent_event(
                "verification_memory.pattern_stored",
                {
                    "user_id": safe_context["user_id"],
                    "workspace_id": safe_context["workspace_id"],
                    "pattern_id": pattern_obj.pattern_id,
                    "pattern_type": pattern_obj.pattern_type,
                },
            )

            return self._safe_result(
                True,
                "Verification pattern stored successfully.",
                data=data,
                metadata={"pattern_id": pattern_obj.pattern_id},
            )

        except Exception as exc:
            logger.exception("Failed to store verification pattern.")
            self._log_audit_event("store_pattern", safe_context, {"error": str(exc)}, success=False)
            return self._error_result("Failed to store verification pattern.", error=exc)

    def update_pattern(
        self,
        context: Mapping[str, Any],
        pattern_id: str,
        updates: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Update an existing pattern within the same user/workspace scope.
        """
        valid, error_message, safe_context = self._validate_task_context(context)
        if not valid:
            return self._error_result(error_message or "Invalid context.")

        pattern_id = _normalize_str(pattern_id, 120)
        if not pattern_id:
            return self._error_result("Missing pattern_id.")

        try:
            with self._lock:
                existing = self._patterns.get(pattern_id)
                if not existing:
                    return self._error_result("Pattern not found.", metadata={"pattern_id": pattern_id})

                if not self._scope_matches(existing, safe_context):
                    return self._error_result("Pattern access denied for this user/workspace scope.")

                payload = existing.to_dict()
                blocked_fields = {"user_id", "workspace_id", "pattern_id", "created_at"}
                for key, value in dict(updates).items():
                    if key in blocked_fields:
                        continue
                    payload[key] = value

                payload["updated_at"] = _utc_now_iso()
                updated = VerificationPattern.from_dict(payload)

                validation_result = self._validate_pattern_scope(updated, safe_context)
                if not validation_result["success"]:
                    return validation_result

                self._patterns[pattern_id] = updated
                self._rebuild_indexes_locked()
                self._save_to_disk_safely()

            self._log_audit_event("update_pattern", safe_context, {"pattern_id": pattern_id}, success=True)
            self._emit_agent_event(
                "verification_memory.pattern_updated",
                {
                    "user_id": safe_context["user_id"],
                    "workspace_id": safe_context["workspace_id"],
                    "pattern_id": pattern_id,
                },
            )

            return self._safe_result(
                True,
                "Verification pattern updated successfully.",
                data={"pattern": updated.to_dict()},
                metadata={"pattern_id": pattern_id},
            )

        except Exception as exc:
            logger.exception("Failed to update verification pattern.")
            return self._error_result("Failed to update verification pattern.", error=exc)

    def learn_from_verification_result(
        self,
        context: Mapping[str, Any],
        verification_result: Mapping[str, Any],
        *,
        project_id: Optional[str] = None,
        resource_key: Optional[str] = None,
        task_type: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Learn a pattern from a completed Verification Agent result.

        This method extracts reusable signals from structured verification output.
        It does not fabricate success. If signals cannot be extracted, it returns
        a safe failure result explaining why.
        """
        valid, error_message, safe_context = self._validate_task_context(context)
        if not valid:
            return self._error_result(error_message or "Invalid context.")

        try:
            result_payload = _redact_sensitive(dict(verification_result))
            success = bool(result_payload.get("success", False))
            confidence = _clamp_float(result_payload.get("confidence"), 0.0, 1.0)

            extracted = self._extract_signals_from_result(result_payload)
            if not extracted:
                return self._safe_result(
                    False,
                    "No reusable verification signals could be extracted from result.",
                    data={"extracted_signal_count": 0},
                )

            pattern_name = _normalize_str(
                result_payload.get("name")
                or result_payload.get("task_name")
                or result_payload.get("message")
                or "Learned verification pattern",
                200,
            )

            if success:
                return self.remember_success(
                    safe_context,
                    name=pattern_name,
                    pattern_type=_normalize_str(result_payload.get("pattern_type") or "task", 80),
                    success_signals=extracted,
                    project_id=project_id or safe_context.get("project_id"),
                    resource_key=resource_key,
                    task_type=task_type or _normalize_str(result_payload.get("task_type"), 160) or None,
                    tags=tags or ["learned", "success"],
                    confidence=confidence or self.memory_config.default_confidence,
                    metadata={
                        "learned_from": "verification_result",
                        "source_result": result_payload.get("result_id") or result_payload.get("task_id"),
                    },
                )

            return self.remember_failure(
                safe_context,
                name=pattern_name,
                pattern_type=_normalize_str(result_payload.get("pattern_type") or "task", 80),
                failure_signals=extracted,
                project_id=project_id or safe_context.get("project_id"),
                resource_key=resource_key,
                task_type=task_type or _normalize_str(result_payload.get("task_type"), 160) or None,
                tags=tags or ["learned", "failure"],
                confidence=max(confidence, 0.5),
                metadata={
                    "learned_from": "verification_result",
                    "source_result": result_payload.get("result_id") or result_payload.get("task_id"),
                },
            )

        except Exception as exc:
            logger.exception("Failed to learn from verification result.")
            return self._error_result("Failed to learn from verification result.", error=exc)

    # ------------------------------------------------------------------
    # Public API: retrieval and search
    # ------------------------------------------------------------------

    def get_pattern(
        self,
        context: Mapping[str, Any],
        pattern_id: str,
    ) -> Dict[str, Any]:
        """
        Retrieve a pattern by ID within the same user/workspace scope.
        """
        valid, error_message, safe_context = self._validate_task_context(context)
        if not valid:
            return self._error_result(error_message or "Invalid context.")

        pattern_id = _normalize_str(pattern_id, 120)
        if not pattern_id:
            return self._error_result("Missing pattern_id.")

        with self._lock:
            pattern = self._patterns.get(pattern_id)
            if not pattern:
                return self._error_result("Pattern not found.", metadata={"pattern_id": pattern_id})

            if not self._scope_matches(pattern, safe_context):
                return self._error_result("Pattern access denied for this user/workspace scope.")

            return self._safe_result(
                True,
                "Verification pattern retrieved successfully.",
                data={"pattern": pattern.to_dict()},
                metadata={"pattern_id": pattern_id},
            )

    def find_patterns(
        self,
        context: Mapping[str, Any],
        *,
        pattern_type: Optional[str] = None,
        project_id: Optional[str] = None,
        resource_key: Optional[str] = None,
        task_type: Optional[str] = None,
        tags: Optional[List[str]] = None,
        query: Optional[str] = None,
        min_confidence: float = 0.0,
        limit: int = 50,
    ) -> Dict[str, Any]:
        """
        Find patterns for a user/workspace scope.

        Supports filtering by type, project, resource, task type, tags, and
        basic text query over pattern name/description/tags.
        """
        valid, error_message, safe_context = self._validate_task_context(context)
        if not valid:
            return self._error_result(error_message or "Invalid context.")

        limit = max(1, min(500, _coerce_int(limit, 50)))
        min_confidence = _clamp_float(min_confidence, 0.0, 1.0)

        with self._lock:
            scope_key = (safe_context["user_id"], safe_context["workspace_id"])
            candidate_ids = set(self._scope_index.get(scope_key, set()))

            if project_id:
                candidate_ids &= set(
                    self._project_index.get(
                        (safe_context["user_id"], safe_context["workspace_id"], _normalize_str(project_id, 160)),
                        set(),
                    )
                )

            if resource_key:
                candidate_ids &= set(
                    self._resource_index.get(
                        (safe_context["user_id"], safe_context["workspace_id"], _normalize_str(resource_key, 300)),
                        set(),
                    )
                )

            normalized_tags = [_safe_slug(tag, "tag") for tag in (tags or []) if _normalize_str(tag)]
            for tag in normalized_tags:
                candidate_ids &= set(
                    self._tag_index.get(
                        (safe_context["user_id"], safe_context["workspace_id"], tag),
                        set(),
                    )
                )

            patterns = []
            query_text = _normalize_str(query, 300).lower()
            normalized_type = _normalize_str(pattern_type, 80)
            normalized_task_type = _normalize_str(task_type, 160)

            for pattern_id in candidate_ids:
                pattern = self._patterns.get(pattern_id)
                if not pattern:
                    continue

                if normalized_type and pattern.pattern_type != normalized_type:
                    continue

                if normalized_task_type and pattern.task_type != normalized_task_type:
                    continue

                if pattern.confidence < min_confidence:
                    continue

                if query_text:
                    searchable = " ".join(
                        [
                            pattern.name,
                            pattern.pattern_type,
                            pattern.resource_key or "",
                            pattern.task_type or "",
                            " ".join(pattern.tags),
                            json.dumps(pattern.metadata, default=str),
                        ]
                    ).lower()
                    if query_text not in searchable:
                        continue

                patterns.append(pattern)

            patterns.sort(
                key=lambda item: (
                    item.confidence,
                    item.success_count - item.failure_count,
                    item.updated_at,
                ),
                reverse=True,
            )

            selected = patterns[:limit]

            return self._safe_result(
                True,
                "Verification patterns found.",
                data={
                    "patterns": [pattern.to_dict() for pattern in selected],
                    "count": len(selected),
                    "total_candidates": len(patterns),
                },
                metadata={"limit": limit},
            )

    # ------------------------------------------------------------------
    # Public API: matching and scoring
    # ------------------------------------------------------------------

    def match_observation(
        self,
        context: Mapping[str, Any],
        observation: Mapping[str, Any],
        *,
        pattern_type: Optional[str] = None,
        project_id: Optional[str] = None,
        resource_key: Optional[str] = None,
        task_type: Optional[str] = None,
        tags: Optional[List[str]] = None,
        limit: int = DEFAULT_RECENT_MATCH_LIMIT,
    ) -> Dict[str, Any]:
        """
        Match current observed state against remembered verification patterns.

        observation can contain keys such as:
            url, title, text, selectors, status_code, files, folders, processes,
            services, ports, api_response, json, logs, screenshot_observations,
            ui_elements, device_state, build_status, tests, custom

        Returns ranked pattern matches with score and confidence.
        """
        valid, error_message, safe_context = self._validate_task_context(context)
        if not valid:
            return self._error_result(error_message or "Invalid context.")

        search_result = self.find_patterns(
            safe_context,
            pattern_type=pattern_type,
            project_id=project_id,
            resource_key=resource_key,
            task_type=task_type,
            tags=tags,
            limit=max(1, min(500, limit * 5)),
        )

        if not search_result.get("success"):
            return search_result

        patterns_payload = search_result.get("data", {}).get("patterns", [])
        observation_safe = _redact_sensitive(dict(observation or {}))
        matches: List[Dict[str, Any]] = []

        for pattern_payload in patterns_payload:
            pattern = VerificationPattern.from_dict(pattern_payload)
            match = self._score_pattern_match(pattern, observation_safe)
            if match["score"] > 0 or match["failure_score"] > 0:
                matches.append(match)

        matches.sort(
            key=lambda item: (
                item.get("final_confidence", 0.0),
                item.get("score", 0.0),
                -item.get("failure_score", 0.0),
            ),
            reverse=True,
        )
        selected = matches[: max(1, min(100, limit))]

        best_match = selected[0] if selected else None
        final_confidence = best_match.get("final_confidence", 0.0) if best_match else 0.0
        inferred_success = bool(
            best_match
            and best_match.get("score", 0.0) >= best_match.get("failure_score", 0.0)
            and final_confidence >= 0.5
        )

        data = {
            "matched": bool(selected),
            "inferred_success": inferred_success,
            "final_confidence": final_confidence,
            "best_match": best_match,
            "matches": selected,
            "observation_hash": _stable_json_hash(observation_safe),
            "verification_payload": self._prepare_verification_payload(
                "match_observation",
                safe_context,
                {
                    "matched": bool(selected),
                    "inferred_success": inferred_success,
                    "best_pattern_id": best_match.get("pattern_id") if best_match else None,
                },
                success=inferred_success,
                confidence=final_confidence,
            ),
        }

        self._emit_agent_event(
            "verification_memory.observation_matched",
            {
                "user_id": safe_context["user_id"],
                "workspace_id": safe_context["workspace_id"],
                "matched": bool(selected),
                "inferred_success": inferred_success,
                "confidence": final_confidence,
            },
        )

        return self._safe_result(
            True,
            "Observation matched against verification memory.",
            data=data,
            metadata={"match_count": len(selected)},
        )

    def record_match_outcome(
        self,
        context: Mapping[str, Any],
        pattern_id: str,
        *,
        actual_success: bool,
        confidence_delta: float = 0.03,
        notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Record whether a previous pattern match was truly successful.

        This improves future confidence over time.
        """
        valid, error_message, safe_context = self._validate_task_context(context)
        if not valid:
            return self._error_result(error_message or "Invalid context.")

        pattern_id = _normalize_str(pattern_id, 120)
        confidence_delta = abs(_coerce_float(confidence_delta, 0.03))
        confidence_delta = min(confidence_delta, 0.25)

        try:
            with self._lock:
                pattern = self._patterns.get(pattern_id)
                if not pattern:
                    return self._error_result("Pattern not found.", metadata={"pattern_id": pattern_id})

                if not self._scope_matches(pattern, safe_context):
                    return self._error_result("Pattern access denied for this user/workspace scope.")

                if actual_success:
                    pattern.success_count += 1
                    pattern.confidence = _clamp_float(pattern.confidence + confidence_delta, 0.0, 1.0)
                else:
                    pattern.failure_count += 1
                    pattern.confidence = _clamp_float(pattern.confidence - confidence_delta, 0.0, 1.0)

                pattern.last_matched_at = _utc_now_iso()
                pattern.updated_at = _utc_now_iso()
                if notes:
                    pattern.metadata.setdefault("outcome_notes", [])
                    pattern.metadata["outcome_notes"] = list(pattern.metadata["outcome_notes"])[-20:]
                    pattern.metadata["outcome_notes"].append(
                        {
                            "notes": _normalize_str(notes, 1000),
                            "actual_success": bool(actual_success),
                            "timestamp": _utc_now_iso(),
                        }
                    )

                self._patterns[pattern_id] = pattern
                self._save_to_disk_safely()

            self._log_audit_event(
                "record_match_outcome",
                safe_context,
                {
                    "pattern_id": pattern_id,
                    "actual_success": actual_success,
                    "confidence": pattern.confidence,
                },
                success=True,
            )

            return self._safe_result(
                True,
                "Pattern match outcome recorded successfully.",
                data={"pattern": pattern.to_dict()},
                metadata={"pattern_id": pattern_id},
            )

        except Exception as exc:
            logger.exception("Failed to record match outcome.")
            return self._error_result("Failed to record match outcome.", error=exc)

    # ------------------------------------------------------------------
    # Public API: delete/import/export/maintenance
    # ------------------------------------------------------------------

    def delete_pattern(
        self,
        context: Mapping[str, Any],
        pattern_id: str,
    ) -> Dict[str, Any]:
        """
        Delete one verification pattern after security approval.
        """
        valid, error_message, safe_context = self._validate_task_context(context)
        if not valid:
            return self._error_result(error_message or "Invalid context.")

        approval = self._request_security_approval(
            "delete_pattern",
            safe_context,
            {"pattern_id": pattern_id},
        )
        if not approval.get("success") or not approval.get("data", {}).get("approved"):
            return self._error_result(
                "Security approval denied for pattern deletion.",
                data={"approval": approval.get("data", {})},
            )

        pattern_id = _normalize_str(pattern_id, 120)
        try:
            with self._lock:
                pattern = self._patterns.get(pattern_id)
                if not pattern:
                    return self._error_result("Pattern not found.", metadata={"pattern_id": pattern_id})

                if not self._scope_matches(pattern, safe_context):
                    return self._error_result("Pattern access denied for this user/workspace scope.")

                deleted = self._patterns.pop(pattern_id)
                self._rebuild_indexes_locked()
                self._save_to_disk_safely()

            self._log_audit_event(
                "delete_pattern",
                safe_context,
                {"pattern_id": pattern_id},
                success=True,
            )
            self._emit_agent_event(
                "verification_memory.pattern_deleted",
                {
                    "user_id": safe_context["user_id"],
                    "workspace_id": safe_context["workspace_id"],
                    "pattern_id": pattern_id,
                },
            )

            return self._safe_result(
                True,
                "Verification pattern deleted successfully.",
                data={"deleted_pattern": deleted.to_dict()},
                metadata={"pattern_id": pattern_id},
            )

        except Exception as exc:
            logger.exception("Failed to delete pattern.")
            return self._error_result("Failed to delete pattern.", error=exc)

    def export_memory(
        self,
        context: Mapping[str, Any],
        *,
        include_patterns: bool = True,
    ) -> Dict[str, Any]:
        """
        Export verification memory for a single user/workspace scope.

        Does not export other users/workspaces.
        """
        valid, error_message, safe_context = self._validate_task_context(context)
        if not valid:
            return self._error_result(error_message or "Invalid context.")

        with self._lock:
            scope_key = (safe_context["user_id"], safe_context["workspace_id"])
            pattern_ids = set(self._scope_index.get(scope_key, set()))
            patterns = [
                self._patterns[pattern_id].to_dict()
                for pattern_id in pattern_ids
                if pattern_id in self._patterns
            ]

        export_payload = {
            "schema_version": self.version,
            "exported_at": _utc_now_iso(),
            "user_id": safe_context["user_id"],
            "workspace_id": safe_context["workspace_id"],
            "pattern_count": len(patterns),
            "patterns": patterns if include_patterns else [],
        }

        return self._safe_result(
            True,
            "Verification memory exported successfully.",
            data={"export": export_payload},
            metadata={"pattern_count": len(patterns)},
        )

    def import_memory(
        self,
        context: Mapping[str, Any],
        memory_payload: Mapping[str, Any],
        *,
        overwrite_existing: bool = False,
    ) -> Dict[str, Any]:
        """
        Import verification patterns into the current user/workspace scope.

        Security approval is required because imports can overwrite useful memory.
        The imported patterns are forcibly scoped to the provided context.
        """
        valid, error_message, safe_context = self._validate_task_context(context)
        if not valid:
            return self._error_result(error_message or "Invalid context.")

        approval = self._request_security_approval(
            "import_patterns" if not overwrite_existing else "overwrite_patterns",
            safe_context,
            {"overwrite_existing": overwrite_existing},
        )
        if not approval.get("success") or not approval.get("data", {}).get("approved"):
            return self._error_result(
                "Security approval denied for memory import.",
                data={"approval": approval.get("data", {})},
            )

        try:
            incoming_patterns = list(memory_payload.get("patterns") or [])
            imported = 0
            skipped = 0
            errors: List[Dict[str, Any]] = []

            with self._lock:
                for item in incoming_patterns:
                    if not isinstance(item, Mapping):
                        skipped += 1
                        continue

                    try:
                        payload = dict(item)
                        payload["user_id"] = safe_context["user_id"]
                        payload["workspace_id"] = safe_context["workspace_id"]

                        pattern = VerificationPattern.from_dict(payload)
                        if pattern.pattern_id in self._patterns and not overwrite_existing:
                            skipped += 1
                            continue

                        self._patterns[pattern.pattern_id] = pattern
                        imported += 1

                    except Exception as item_exc:
                        skipped += 1
                        errors.append(
                            {
                                "error": str(item_exc),
                                "item_hash": _stable_json_hash(dict(item)),
                            }
                        )

                self._rebuild_indexes_locked()
                self._save_to_disk_safely()

            self._log_audit_event(
                "import_memory",
                safe_context,
                {"imported": imported, "skipped": skipped, "overwrite_existing": overwrite_existing},
                success=True,
            )

            return self._safe_result(
                True,
                "Verification memory import completed.",
                data={
                    "imported": imported,
                    "skipped": skipped,
                    "errors": errors[:20],
                },
                metadata={"error_count": len(errors)},
            )

        except Exception as exc:
            logger.exception("Failed to import verification memory.")
            return self._error_result("Failed to import verification memory.", error=exc)

    def prune_memory(
        self,
        context: Mapping[str, Any],
        *,
        older_than_days: Optional[int] = None,
        min_confidence: Optional[float] = None,
        dry_run: bool = True,
    ) -> Dict[str, Any]:
        """
        Prune old or low-confidence patterns for the current user/workspace.

        dry_run=True returns what would be deleted without deleting anything.
        dry_run=False requires security approval.
        """
        valid, error_message, safe_context = self._validate_task_context(context)
        if not valid:
            return self._error_result(error_message or "Invalid context.")

        if not dry_run:
            approval = self._request_security_approval(
                "delete_scope",
                safe_context,
                {
                    "older_than_days": older_than_days,
                    "min_confidence": min_confidence,
                    "dry_run": dry_run,
                },
            )
            if not approval.get("success") or not approval.get("data", {}).get("approved"):
                return self._error_result("Security approval denied for memory prune.")

        older_than_days = (
            max(1, _coerce_int(older_than_days, self.memory_config.retention_days))
            if older_than_days is not None
            else self.memory_config.retention_days
        )
        min_confidence_value = (
            _clamp_float(min_confidence, 0.0, 1.0)
            if min_confidence is not None
            else None
        )

        cutoff_ts = time.time() - (older_than_days * 86400)
        to_delete: List[str] = []

        with self._lock:
            scope_key = (safe_context["user_id"], safe_context["workspace_id"])
            for pattern_id in list(self._scope_index.get(scope_key, set())):
                pattern = self._patterns.get(pattern_id)
                if not pattern:
                    continue

                updated_dt = _parse_iso_datetime(pattern.updated_at)
                updated_ts = updated_dt.timestamp() if updated_dt else time.time()
                old_enough = updated_ts < cutoff_ts
                low_confidence = (
                    min_confidence_value is not None
                    and pattern.confidence < min_confidence_value
                )

                if old_enough or low_confidence:
                    to_delete.append(pattern_id)

            if not dry_run:
                for pattern_id in to_delete:
                    self._patterns.pop(pattern_id, None)
                self._rebuild_indexes_locked()
                self._save_to_disk_safely()

        self._log_audit_event(
            "prune_memory",
            safe_context,
            {
                "dry_run": dry_run,
                "candidate_count": len(to_delete),
                "older_than_days": older_than_days,
                "min_confidence": min_confidence_value,
            },
            success=True,
        )

        return self._safe_result(
            True,
            "Memory prune dry-run completed." if dry_run else "Memory prune completed.",
            data={
                "dry_run": dry_run,
                "candidate_pattern_ids": to_delete,
                "deleted_count": 0 if dry_run else len(to_delete),
            },
            metadata={"candidate_count": len(to_delete)},
        )

    def get_stats(
        self,
        context: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Return verification memory statistics for one user/workspace scope.
        """
        valid, error_message, safe_context = self._validate_task_context(context)
        if not valid:
            return self._error_result(error_message or "Invalid context.")

        with self._lock:
            scope_key = (safe_context["user_id"], safe_context["workspace_id"])
            pattern_ids = list(self._scope_index.get(scope_key, set()))
            patterns = [
                self._patterns[pattern_id]
                for pattern_id in pattern_ids
                if pattern_id in self._patterns
            ]

            type_counts = Counter(pattern.pattern_type for pattern in patterns)
            tag_counts: Counter[str] = Counter()
            signal_type_counts: Counter[str] = Counter()

            confidence_values: List[float] = []
            total_success = 0
            total_failure = 0

            for pattern in patterns:
                tag_counts.update(pattern.tags)
                confidence_values.append(pattern.confidence)
                total_success += pattern.success_count
                total_failure += pattern.failure_count
                signal_type_counts.update(signal.signal_type for signal in pattern.success_signals)
                signal_type_counts.update(signal.signal_type for signal in pattern.failure_signals)

            avg_confidence = (
                sum(confidence_values) / len(confidence_values)
                if confidence_values
                else 0.0
            )

        return self._safe_result(
            True,
            "Verification memory stats generated.",
            data={
                "pattern_count": len(patterns),
                "type_counts": dict(type_counts),
                "top_tags": dict(tag_counts.most_common(20)),
                "signal_type_counts": dict(signal_type_counts),
                "average_confidence": round(avg_confidence, 4),
                "success_count": total_success,
                "failure_count": total_failure,
                "schema_version": self.version,
            },
        )

    def health_check(self) -> Dict[str, Any]:
        """
        Basic health check for dashboard/API/agent loader.
        """
        storage_path = self.memory_config.storage_path
        storage_ok = True
        storage_error = None

        if storage_path:
            try:
                path = Path(storage_path)
                if path.exists():
                    storage_ok = path.is_file()
                else:
                    parent = path.parent
                    storage_ok = parent.exists() and os.access(parent, os.W_OK)
            except Exception as exc:
                storage_ok = False
                storage_error = str(exc)

        with self._lock:
            pattern_count = len(self._patterns)

        return self._safe_result(
            storage_ok,
            "VerificationMemory is healthy." if storage_ok else "VerificationMemory storage is not healthy.",
            data={
                "agent": self.agent_name,
                "version": self.version,
                "pattern_count": pattern_count,
                "storage_path": storage_path,
                "storage_ok": storage_ok,
                "storage_error": storage_error,
            },
        )

    # ------------------------------------------------------------------
    # Internal scoring helpers
    # ------------------------------------------------------------------

    def _score_pattern_match(
        self,
        pattern: VerificationPattern,
        observation: Mapping[str, Any],
    ) -> Dict[str, Any]:
        success_matches = []
        failure_matches = []

        success_total_weight = sum(max(0.0, signal.weight) for signal in pattern.success_signals) or 1.0
        failure_total_weight = sum(max(0.0, signal.weight) for signal in pattern.failure_signals) or 1.0

        success_score_raw = 0.0
        failure_score_raw = 0.0

        for signal in pattern.success_signals:
            matched, details = self._match_signal(signal, observation)
            if matched:
                weighted = max(0.0, signal.weight) * signal.confidence
                success_score_raw += weighted
                success_matches.append(
                    {
                        "signal_id": signal.signal_id,
                        "name": signal.name,
                        "signal_type": signal.signal_type,
                        "weight": signal.weight,
                        "confidence": signal.confidence,
                        "details": details,
                    }
                )

        for signal in pattern.failure_signals:
            matched, details = self._match_signal(signal, observation)
            if matched:
                weighted = max(0.0, signal.weight) * signal.confidence
                failure_score_raw += weighted
                failure_matches.append(
                    {
                        "signal_id": signal.signal_id,
                        "name": signal.name,
                        "signal_type": signal.signal_type,
                        "weight": signal.weight,
                        "confidence": signal.confidence,
                        "details": details,
                    }
                )

        score = _clamp_float(success_score_raw / success_total_weight, 0.0, 1.0)
        failure_score = _clamp_float(failure_score_raw / failure_total_weight, 0.0, 1.0)

        reliability = self._pattern_reliability(pattern)
        final_confidence = _clamp_float(
            (score * pattern.confidence * reliability) - (failure_score * 0.65),
            0.0,
            1.0,
        )

        return {
            "pattern_id": pattern.pattern_id,
            "name": pattern.name,
            "pattern_type": pattern.pattern_type,
            "project_id": pattern.project_id,
            "resource_key": pattern.resource_key,
            "task_type": pattern.task_type,
            "tags": list(pattern.tags),
            "score": round(score, 4),
            "failure_score": round(failure_score, 4),
            "pattern_confidence": pattern.confidence,
            "reliability": round(reliability, 4),
            "final_confidence": round(final_confidence, 4),
            "success_matches": success_matches,
            "failure_matches": failure_matches,
            "success_signal_count": len(pattern.success_signals),
            "failure_signal_count": len(pattern.failure_signals),
        }

    def _match_signal(
        self,
        signal: VerificationSignal,
        observation: Mapping[str, Any],
    ) -> Tuple[bool, Dict[str, Any]]:
        signal_type = signal.signal_type
        expected = signal.expected
        operator = signal.operator.lower().strip()

        observed_value = self._extract_observed_value(signal_type, signal.name, observation)

        matched = self._compare_values(observed_value, expected, operator)
        if not signal.positive:
            matched = not matched

        return matched, {
            "operator": operator,
            "expected": _redact_sensitive(expected),
            "observed": _redact_sensitive(observed_value),
            "positive": signal.positive,
        }

    def _extract_observed_value(
        self,
        signal_type: str,
        name: str,
        observation: Mapping[str, Any],
    ) -> Any:
        direct_keys = [
            signal_type,
            name,
            name.lower(),
            _safe_slug(name),
        ]

        for key in direct_keys:
            if key in observation:
                return observation.get(key)

        aliases = {
            "url": ["current_url", "page_url", "browser_url"],
            "title": ["page_title", "window_title", "app_title"],
            "text": ["content", "body_text", "visible_text"],
            "selector": ["selectors", "dom_selectors", "elements"],
            "status_code": ["http_status", "status"],
            "file_exists": ["files", "file_paths"],
            "folder_exists": ["folders", "folder_paths"],
            "process_running": ["processes", "running_processes"],
            "service_running": ["services", "running_services"],
            "port_open": ["ports", "open_ports"],
            "api_response": ["response", "api", "api_response"],
            "json_field": ["json", "response_json", "api_json"],
            "log_contains": ["logs", "log_text"],
            "screenshot_observation": ["screenshot", "screenshot_observations", "visual_observations"],
            "ui_element": ["ui", "ui_elements", "elements"],
            "device_state": ["device", "device_state"],
            "code_test": ["tests", "test_results"],
            "build_status": ["build", "build_status"],
            "custom": ["custom", "metadata"],
        }

        for key in aliases.get(signal_type, []):
            if key in observation:
                return observation.get(key)

        return None

    def _compare_values(self, observed: Any, expected: Any, operator: str) -> bool:
        if operator in {"exists", "present"}:
            return observed is not None and observed != "" and observed != []

        if operator in {"missing", "not_exists", "absent"}:
            return observed is None or observed == "" or observed == []

        if operator in {"equals", "eq", "is"}:
            return self._value_to_text(observed).lower() == self._value_to_text(expected).lower()

        if operator in {"not_equals", "neq", "not"}:
            return self._value_to_text(observed).lower() != self._value_to_text(expected).lower()

        if operator in {"contains", "includes"}:
            return self._contains_value(observed, expected)

        if operator in {"not_contains", "excludes"}:
            return not self._contains_value(observed, expected)

        if operator in {"starts_with", "prefix"}:
            return self._value_to_text(observed).lower().startswith(self._value_to_text(expected).lower())

        if operator in {"ends_with", "suffix"}:
            return self._value_to_text(observed).lower().endswith(self._value_to_text(expected).lower())

        if operator in {"regex", "matches_regex"}:
            try:
                return re.search(str(expected), self._value_to_text(observed), flags=re.IGNORECASE) is not None
            except re.error:
                return False

        if operator in {"gt", "greater_than"}:
            return _coerce_float(observed, float("-inf")) > _coerce_float(expected, float("inf"))

        if operator in {"gte", "greater_or_equal"}:
            return _coerce_float(observed, float("-inf")) >= _coerce_float(expected, float("inf"))

        if operator in {"lt", "less_than"}:
            return _coerce_float(observed, float("inf")) < _coerce_float(expected, float("-inf"))

        if operator in {"lte", "less_or_equal"}:
            return _coerce_float(observed, float("inf")) <= _coerce_float(expected, float("-inf"))

        if operator in {"in", "one_of"}:
            if isinstance(expected, (list, tuple, set)):
                observed_text = self._value_to_text(observed).lower()
                return any(observed_text == self._value_to_text(item).lower() for item in expected)
            return False

        return self._contains_value(observed, expected)

    @staticmethod
    def _value_to_text(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, str):
            return value
        try:
            return json.dumps(value, sort_keys=True, default=str, ensure_ascii=False)
        except Exception:
            return str(value)

    def _contains_value(self, observed: Any, expected: Any) -> bool:
        if observed is None:
            return False

        if isinstance(observed, Mapping):
            observed_text = self._value_to_text(observed).lower()
            expected_text = self._value_to_text(expected).lower()
            return expected_text in observed_text

        if isinstance(observed, (list, tuple, set)):
            expected_text = self._value_to_text(expected).lower()
            for item in observed:
                if self._value_to_text(item).lower() == expected_text:
                    return True
                if expected_text in self._value_to_text(item).lower():
                    return True
            return False

        return self._value_to_text(expected).lower() in self._value_to_text(observed).lower()

    @staticmethod
    def _pattern_reliability(pattern: VerificationPattern) -> float:
        total = pattern.success_count + pattern.failure_count
        if total <= 0:
            return 0.75

        success_ratio = pattern.success_count / total
        sample_boost = min(0.25, total / 100.0)
        return _clamp_float((0.65 + sample_boost) * success_ratio + 0.2, 0.1, 1.0)

    # ------------------------------------------------------------------
    # Internal extraction helpers
    # ------------------------------------------------------------------

    def _extract_signals_from_result(self, result_payload: Mapping[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract reusable signals from common Verification Agent result shapes.
        """
        signals: List[Dict[str, Any]] = []

        data = result_payload.get("data") if isinstance(result_payload.get("data"), Mapping) else {}
        metadata = result_payload.get("metadata") if isinstance(result_payload.get("metadata"), Mapping) else {}

        candidate_sources = [
            result_payload,
            data,
            metadata,
            data.get("actual") if isinstance(data, Mapping) and isinstance(data.get("actual"), Mapping) else {},
            data.get("observed") if isinstance(data, Mapping) and isinstance(data.get("observed"), Mapping) else {},
            data.get("proof") if isinstance(data, Mapping) and isinstance(data.get("proof"), Mapping) else {},
        ]

        key_to_signal_type = {
            "url": "url",
            "current_url": "url",
            "page_url": "url",
            "title": "title",
            "page_title": "title",
            "text": "text",
            "visible_text": "text",
            "status_code": "status_code",
            "http_status": "status_code",
            "file_path": "file_exists",
            "file_exists": "file_exists",
            "folder_path": "folder_exists",
            "folder_exists": "folder_exists",
            "process": "process_running",
            "process_name": "process_running",
            "service": "service_running",
            "service_name": "service_running",
            "port": "port_open",
            "selector": "selector",
            "ui_element": "ui_element",
            "build_status": "build_status",
            "test_status": "code_test",
        }

        for source in candidate_sources:
            if not isinstance(source, Mapping):
                continue

            for key, signal_type in key_to_signal_type.items():
                value = source.get(key)
                if value is None or value == "":
                    continue

                signals.append(
                    {
                        "signal_type": signal_type,
                        "name": key,
                        "expected": value,
                        "operator": "contains" if isinstance(value, str) else "equals",
                        "confidence": _clamp_float(result_payload.get("confidence"), 0.0, 1.0) or 0.65,
                        "weight": 1.0,
                        "source": "learn_from_verification_result",
                    }
                )

        explicit_signals = result_payload.get("signals")
        if isinstance(explicit_signals, list):
            for item in explicit_signals:
                if isinstance(item, Mapping):
                    signals.append(dict(item))

        if isinstance(data, Mapping):
            for key in ("success_signals", "failure_signals", "verification_signals"):
                explicit = data.get(key)
                if isinstance(explicit, list):
                    for item in explicit:
                        if isinstance(item, Mapping):
                            signals.append(dict(item))

        deduped: Dict[str, Dict[str, Any]] = {}
        for signal in signals:
            signal_safe = _redact_sensitive(signal)
            signal_hash = _stable_json_hash(signal_safe)
            deduped[signal_hash] = signal_safe

        return list(deduped.values())[: self.memory_config.max_signals_per_pattern]

    def _emit_memory_payload(
        self,
        action: str,
        context: Mapping[str, Any],
        pattern: Optional[VerificationPattern],
    ) -> None:
        """
        Send learned verification context to Memory Agent if available.

        This method is safe if Memory Agent does not exist yet.
        """
        if not self.memory_config.enable_memory_payloads:
            return

        payload = self._prepare_memory_payload(action, context, pattern)

        agent = self.memory_agent
        if agent is None and MemoryAgent is not None:
            try:
                agent = MemoryAgent()
            except Exception:
                agent = None

        if agent is None:
            return

        try:
            if hasattr(agent, "store_memory"):
                agent.store_memory(payload)
            elif hasattr(agent, "remember"):
                agent.remember(payload)
            elif hasattr(agent, "save"):
                agent.save(payload)
        except Exception:
            logger.debug("Memory Agent payload emission failed.", exc_info=True)

    # ------------------------------------------------------------------
    # Internal indexing / storage helpers
    # ------------------------------------------------------------------

    def _scope_matches(self, pattern: VerificationPattern, context: Mapping[str, Any]) -> bool:
        return (
            pattern.user_id == _normalize_str(context.get("user_id"), 120)
            and pattern.workspace_id == _normalize_str(context.get("workspace_id"), 120)
        )

    def _validate_pattern_scope(
        self,
        pattern: VerificationPattern,
        context: Mapping[str, Any],
    ) -> Dict[str, Any]:
        if not pattern.user_id or not pattern.workspace_id:
            return self._error_result("Pattern must include user_id and workspace_id.")

        if not self._scope_matches(pattern, context):
            return self._error_result("Pattern scope does not match task context.")

        if not pattern.name:
            return self._error_result("Pattern name is required.")

        if pattern.pattern_type not in SAFE_PATTERN_TYPES:
            return self._error_result(
                "Invalid pattern_type.",
                data={"allowed_pattern_types": sorted(SAFE_PATTERN_TYPES)},
            )

        return self._safe_result(True, "Pattern scope is valid.")

    def _build_pattern_id(self, pattern_payload: Mapping[str, Any]) -> str:
        identity = {
            "user_id": pattern_payload.get("user_id"),
            "workspace_id": pattern_payload.get("workspace_id"),
            "pattern_type": pattern_payload.get("pattern_type"),
            "name": pattern_payload.get("name"),
            "project_id": pattern_payload.get("project_id"),
            "resource_key": pattern_payload.get("resource_key"),
            "task_type": pattern_payload.get("task_type"),
        }
        return f"vpat_{_stable_json_hash(identity)[:24]}"

    def _enforce_scope_limit(self, user_id: str, workspace_id: str) -> None:
        scope_key = (user_id, workspace_id)
        pattern_ids = list(self._scope_index.get(scope_key, set()))
        max_allowed = self.memory_config.max_patterns_per_scope

        if len(pattern_ids) < max_allowed:
            return

        patterns = [
            self._patterns[pattern_id]
            for pattern_id in pattern_ids
            if pattern_id in self._patterns
        ]

        patterns.sort(
            key=lambda pattern: (
                pattern.confidence,
                pattern.success_count - pattern.failure_count,
                pattern.updated_at,
            )
        )

        delete_count = max(1, len(patterns) - max_allowed + 1)
        for pattern in patterns[:delete_count]:
            self._patterns.pop(pattern.pattern_id, None)

        self._rebuild_indexes_locked()

    def _rebuild_indexes_locked(self) -> None:
        self._scope_index.clear()
        self._project_index.clear()
        self._resource_index.clear()
        self._tag_index.clear()

        for pattern_id, pattern in self._patterns.items():
            scope_key = (pattern.user_id, pattern.workspace_id)
            self._scope_index[scope_key].add(pattern_id)

            if pattern.project_id:
                self._project_index[(pattern.user_id, pattern.workspace_id, pattern.project_id)].add(pattern_id)

            if pattern.resource_key:
                self._resource_index[(pattern.user_id, pattern.workspace_id, pattern.resource_key)].add(pattern_id)

            for tag in pattern.tags:
                self._tag_index[(pattern.user_id, pattern.workspace_id, tag)].add(pattern_id)

    def _load_from_disk_safely(self) -> None:
        storage_path = self.memory_config.storage_path
        if not storage_path:
            return

        try:
            path = Path(storage_path)
            if not path.exists():
                return

            with path.open("r", encoding="utf-8") as file:
                payload = json.load(file)

            patterns_payload = payload.get("patterns", [])
            patterns: Dict[str, VerificationPattern] = {}

            for item in patterns_payload:
                if not isinstance(item, Mapping):
                    continue
                pattern = VerificationPattern.from_dict(item)
                if pattern.user_id and pattern.workspace_id:
                    patterns[pattern.pattern_id] = pattern

            with self._lock:
                self._patterns = patterns
                self._rebuild_indexes_locked()

        except Exception:
            logger.exception("Failed to load verification memory from disk.")

    def _save_to_disk_safely(self) -> None:
        if not self.memory_config.autosave:
            return

        storage_path = self.memory_config.storage_path
        if not storage_path:
            return

        try:
            path = Path(storage_path)
            path.parent.mkdir(parents=True, exist_ok=True)

            payload = {
                "schema_version": self.version,
                "saved_at": _utc_now_iso(),
                "patterns": [pattern.to_dict() for pattern in self._patterns.values()],
            }

            temp_path = path.with_suffix(path.suffix + ".tmp")
            with temp_path.open("w", encoding="utf-8") as file:
                json.dump(payload, file, indent=2, ensure_ascii=False, default=str)

            temp_path.replace(path)

        except Exception:
            logger.exception("Failed to save verification memory to disk.")


# ---------------------------------------------------------------------------
# Module-level factory and metadata helpers
# ---------------------------------------------------------------------------

def create_verification_memory(
    config: Optional[Mapping[str, Any]] = None,
    **kwargs: Any,
) -> VerificationMemory:
    """
    Factory used by Agent Loader / Registry.
    """
    return VerificationMemory(config=config, **kwargs)


def get_agent_metadata() -> Dict[str, Any]:
    """
    Agent Registry metadata.

    This allows future registry/loader systems to discover this helper without
    instantiating it first.
    """
    return {
        "agent_name": VerificationMemory.agent_name,
        "registry_name": VerificationMemory.registry_name,
        "agent_type": VerificationMemory.agent_type,
        "version": VerificationMemory.version,
        "class_name": "VerificationMemory",
        "module": "agents.verification_agent.verification_memory",
        "purpose": "Stores success signals and verification patterns for apps/sites/projects.",
        "safe_to_import": True,
        "requires_user_workspace_context": True,
        "supports_security_hooks": True,
        "supports_memory_payloads": True,
        "supports_verification_payloads": True,
        "public_methods": [
            "remember_success",
            "remember_failure",
            "store_pattern",
            "update_pattern",
            "get_pattern",
            "find_patterns",
            "match_observation",
            "learn_from_verification_result",
            "record_match_outcome",
            "delete_pattern",
            "export_memory",
            "import_memory",
            "prune_memory",
            "get_stats",
            "health_check",
        ],
    }


__all__ = [
    "VerificationMemory",
    "VerificationMemoryConfig",
    "VerificationPattern",
    "VerificationSignal",
    "create_verification_memory",
    "get_agent_metadata",
]


if __name__ == "__main__":
    # Safe smoke test only. No system/browser/device/destructive actions.
    demo = VerificationMemory(config={"autosave": False})
    demo_context = {"user_id": "demo_user", "workspace_id": "demo_workspace"}

    store_result = demo.remember_success(
        demo_context,
        name="Demo dashboard loaded",
        pattern_type="browser",
        success_signals=[
            {
                "signal_type": "url",
                "name": "dashboard_url",
                "expected": "/dashboard",
                "operator": "contains",
                "confidence": 0.8,
            },
            {
                "signal_type": "title",
                "name": "dashboard_title",
                "expected": "Dashboard",
                "operator": "contains",
                "confidence": 0.8,
            },
        ],
        project_id="demo_project",
        resource_key="web_dashboard",
        task_type="page_load",
        tags=["demo", "dashboard"],
    )

    match_result = demo.match_observation(
        demo_context,
        {
            "url": "https://example.com/dashboard",
            "title": "Dashboard - Example",
        },
        pattern_type="browser",
        project_id="demo_project",
        resource_key="web_dashboard",
    )

    print(json.dumps({"store_result": store_result, "match_result": match_result}, indent=2, default=str))