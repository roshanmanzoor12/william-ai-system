"""
agents/system_agent/task_recorder.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Records manual workflows and turns them into safe replayable macros.

This module is part of the System Agent and is designed to connect safely with:
    - Master Agent
    - Agent Router
    - Agent Registry
    - Agent Loader
    - Security Agent
    - Verification Agent
    - Memory Agent
    - Dashboard/API layer
    - Future approved executor agents

Important safety rule:
    TaskRecorder DOES NOT directly execute macros.
    It records, sanitizes, validates, stores, exports, imports, and prepares
    replay plans only. Actual replay must be handled by another approved agent
    after Security Agent approval.

SaaS isolation:
    Every user/workspace-specific operation requires user_id and workspace_id.
    Stored sessions/macros are isolated under:
        runtime/task_recorder/user_<user_id>/workspace_<workspace_id>/
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Optional William/Jarvis imports with safe fallback
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:
        """
        Fallback BaseAgent stub.

        This keeps the file import-safe while the rest of the William/Jarvis
        system is still being generated.
        """

        agent_name = "task_recorder"
        agent_type = "system_agent"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.logger = logging.getLogger(self.__class__.__name__)

        async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
            raise NotImplementedError("Fallback BaseAgent does not implement run().")


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger("william.system_agent.task_recorder")
if not logger.handlers:
    logging.basicConfig(
        level=os.getenv("WILLIAM_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc_now_iso() -> str:
    """Return current UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def _new_id(prefix: str) -> str:
    """Create compact unique ID."""
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


def _safe_string(value: Any, max_length: int = 5000) -> str:
    """Convert value to safe string."""
    if value is None:
        return ""
    text = str(value)
    if len(text) > max_length:
        return text[:max_length] + "...[TRUNCATED]"
    return text


def _normalize_action_name(value: Any) -> str:
    """Normalize an action name."""
    text = _safe_string(value, 200).strip().lower()
    text = re.sub(r"[^a-z0-9_.:-]+", "_", text)
    text = re.sub(r"_+", "_", text).strip("_")
    return text or "unknown_action"


def _sanitize_id_part(value: Any) -> str:
    """Sanitize user/workspace ID for file path usage."""
    text = _safe_string(value, 120)
    text = re.sub(r"[^A-Za-z0-9_.-]", "_", text)
    return text or "unknown"


def _json_hash(data: Any) -> str:
    """Create deterministic short hash from JSON-serializable data."""
    raw = json.dumps(data, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def _redact_sensitive_text(text: str) -> str:
    """
    Redact sensitive values from recorded workflow data.

    Redacts:
        - Emails
        - Phone-like long numbers
        - API keys/tokens/password assignments
        - Long token-like strings
        - Credit-card-like numbers
    """
    if not text:
        return text

    redacted = text

    redacted = re.sub(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "[REDACTED_EMAIL]",
        redacted,
    )

    redacted = re.sub(
        r"(?<!\d)(?:\+?\d[\d\s().-]{8,}\d)(?!\d)",
        "[REDACTED_PHONE]",
        redacted,
    )

    redacted = re.sub(
        r"\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|secret|password|passwd|pwd)\s*[:=]\s*[^\s,;]+",
        lambda m: re.split(r"[:=]", m.group(0), maxsplit=1)[0] + "=[REDACTED_SECRET]",
        redacted,
        flags=re.IGNORECASE,
    )

    redacted = re.sub(
        r"\b(?:\d[ -]*?){13,19}\b",
        "[REDACTED_CARD_OR_LONG_NUMBER]",
        redacted,
    )

    redacted = re.sub(
        r"\b[A-Za-z0-9_\-]{32,}\b",
        "[REDACTED_LONG_TOKEN]",
        redacted,
    )

    return redacted


def _redact_sensitive_data(value: Any) -> Any:
    """Recursively redact sensitive values inside JSON-like data."""
    if isinstance(value, str):
        return _redact_sensitive_text(value)

    if isinstance(value, list):
        return [_redact_sensitive_data(item) for item in value]

    if isinstance(value, tuple):
        return tuple(_redact_sensitive_data(item) for item in value)

    if isinstance(value, dict):
        clean: Dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if re.search(
                r"(password|passwd|pwd|secret|token|api[_-]?key|authorization|cookie)",
                key_text,
                re.IGNORECASE,
            ):
                clean[key_text] = "[REDACTED_SECRET]"
            else:
                clean[key_text] = _redact_sensitive_data(item)
        return clean

    return value


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class RecorderAction(str, Enum):
    """Public action names supported by TaskRecorder."""

    HEALTH = "health"
    START_RECORDING = "start_recording"
    RECORD_STEP = "record_step"
    STOP_RECORDING = "stop_recording"
    DISCARD_RECORDING = "discard_recording"
    GET_SESSION = "get_session"
    LIST_SESSIONS = "list_sessions"
    COMPILE_MACRO = "compile_macro"
    VALIDATE_MACRO = "validate_macro"
    SAVE_MACRO = "save_macro"
    GET_MACRO = "get_macro"
    LIST_MACROS = "list_macros"
    DELETE_MACRO = "delete_macro"
    EXPORT_MACRO = "export_macro"
    IMPORT_MACRO = "import_macro"
    PREPARE_REPLAY = "prepare_replay"
    DESCRIBE_MACRO = "describe_macro"


class StepType(str, Enum):
    """Supported recorded workflow step types."""

    OBSERVE = "observe"
    CLICK = "click"
    DOUBLE_CLICK = "double_click"
    RIGHT_CLICK = "right_click"
    TYPE_TEXT = "type_text"
    HOTKEY = "hotkey"
    WAIT = "wait"
    SCROLL = "scroll"
    NAVIGATE = "navigate"
    OPEN_APP = "open_app"
    CLOSE_APP = "close_app"
    SELECT = "select"
    COPY = "copy"
    PASTE = "paste"
    SCREENSHOT = "screenshot"
    OCR_CHECK = "ocr_check"
    CONDITION = "condition"
    NOTE = "note"
    API_CALL = "api_call"
    FILE_ACTION = "file_action"
    SYSTEM_ACTION = "system_action"
    CUSTOM = "custom"


class MacroRisk(str, Enum):
    """Macro safety risk levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    BLOCKED = "blocked"


class SessionStatus(str, Enum):
    """Recording session statuses."""

    RECORDING = "recording"
    STOPPED = "stopped"
    DISCARDED = "discarded"
    COMPILED = "compiled"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class TaskRecorderConfig:
    """
    Runtime configuration for TaskRecorder.

    Defaults are intentionally safe. Macro replay is never directly executed here.
    """

    storage_dir: str = "runtime/task_recorder"
    require_security_for_recording: bool = True
    require_security_for_macro_compile: bool = True
    require_security_for_replay_plan: bool = True
    redact_sensitive_values: bool = True
    max_sessions_per_workspace: int = 200
    max_macros_per_workspace: int = 500
    max_steps_per_session: int = 1000
    max_step_payload_chars: int = 10000
    max_macro_file_bytes: int = 2_000_000
    allow_high_risk_macro_save: bool = False
    allow_blocked_macro_save: bool = False
    default_replay_requires_human_confirmation: bool = True
    allowed_step_types: Tuple[str, ...] = tuple(step.value for step in StepType)
    blocked_step_types: Tuple[str, ...] = (
        StepType.FILE_ACTION.value,
        StepType.SYSTEM_ACTION.value,
        StepType.API_CALL.value,
    )
    high_risk_keywords: Tuple[str, ...] = (
        "delete",
        "remove",
        "erase",
        "format",
        "shutdown",
        "reboot",
        "factory reset",
        "payment",
        "transfer money",
        "send money",
        "wire",
        "purchase",
        "subscribe",
        "unsubscribe",
        "send email",
        "send message",
        "call",
        "sms",
        "credential",
        "password",
        "token",
        "secret",
        "private key",
        "ssh",
        "sudo",
        "admin",
        "registry",
        "firewall",
        "permission",
        "oauth",
    )
    medium_risk_keywords: Tuple[str, ...] = (
        "submit",
        "save",
        "publish",
        "upload",
        "download",
        "install",
        "update",
        "login",
        "sign in",
        "authorize",
        "connect",
        "share",
        "export",
        "import",
    )

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["allowed_step_types"] = list(self.allowed_step_types)
        data["blocked_step_types"] = list(self.blocked_step_types)
        data["high_risk_keywords"] = list(self.high_risk_keywords)
        data["medium_risk_keywords"] = list(self.medium_risk_keywords)
        return data


@dataclass
class RecordedStep:
    """One recorded manual workflow step."""

    step_id: str
    step_index: int
    step_type: str
    action: str
    description: str = ""
    target: Dict[str, Any] = field(default_factory=dict)
    input_data: Dict[str, Any] = field(default_factory=dict)
    expected_result: Dict[str, Any] = field(default_factory=dict)
    safety: Dict[str, Any] = field(default_factory=dict)
    timing: Dict[str, Any] = field(default_factory=dict)
    screenshot_ref: Optional[str] = None
    ocr_text: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=_utc_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RecordingSession:
    """Manual workflow recording session."""

    session_id: str
    user_id: str
    workspace_id: str
    title: str
    status: str
    steps: List[RecordedStep] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    source: str = "manual"
    created_at: str = field(default_factory=_utc_now_iso)
    updated_at: str = field(default_factory=_utc_now_iso)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["steps"] = [step.to_dict() for step in self.steps]
        return data


@dataclass
class MacroDefinition:
    """Replayable macro definition generated from a recording session."""

    macro_id: str
    user_id: str
    workspace_id: str
    title: str
    description: str
    version: str
    source_session_id: Optional[str]
    steps: List[RecordedStep]
    variables: Dict[str, Any] = field(default_factory=dict)
    constraints: Dict[str, Any] = field(default_factory=dict)
    safety: Dict[str, Any] = field(default_factory=dict)
    replay_policy: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    checksum: str = ""
    created_at: str = field(default_factory=_utc_now_iso)
    updated_at: str = field(default_factory=_utc_now_iso)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["steps"] = [step.to_dict() for step in self.steps]
        return data


# ---------------------------------------------------------------------------
# TaskRecorder
# ---------------------------------------------------------------------------

class TaskRecorder(BaseAgent):
    """
    Records manual workflows and turns them into safe replayable macros.

    Main capabilities:
        - Start/stop/discard recording sessions.
        - Record typed/click/wait/navigation/observation steps.
        - Sanitize sensitive values.
        - Compile recorded sessions into macro definitions.
        - Validate macro safety.
        - Save/list/get/delete macros.
        - Export/import macro JSON.
        - Prepare replay plans without executing actions.

    Every result follows:
        {
            "success": bool,
            "message": str,
            "data": dict/list,
            "error": None or dict,
            "metadata": dict
        }
    """

    agent_name = "task_recorder"
    agent_type = "system_agent"
    version = "1.0.0"

    def __init__(
        self,
        config: Optional[Union[TaskRecorderConfig, Dict[str, Any]]] = None,
        security_client: Optional[Any] = None,
        memory_client: Optional[Any] = None,
        verification_client: Optional[Any] = None,
        event_emitter: Optional[Callable[[Dict[str, Any]], Any]] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], Any]] = None,
        logger_instance: Optional[logging.Logger] = None,
    ) -> None:
        super().__init__()

        if isinstance(config, TaskRecorderConfig):
            self.config = config
        elif isinstance(config, dict):
            self.config = self._build_config_from_dict(config)
        else:
            self.config = TaskRecorderConfig()

        self.security_client = security_client
        self.memory_client = memory_client
        self.verification_client = verification_client
        self.event_emitter = event_emitter
        self.audit_logger = audit_logger
        self.logger = logger_instance or logger

        self._active_sessions: Dict[str, RecordingSession] = {}

        Path(self.config.storage_dir).mkdir(parents=True, exist_ok=True)

    # -----------------------------------------------------------------------
    # Config handling
    # -----------------------------------------------------------------------

    def _build_config_from_dict(self, data: Dict[str, Any]) -> TaskRecorderConfig:
        """Build config safely from dict."""
        defaults = TaskRecorderConfig()
        merged = defaults.to_dict()
        merged.update(data or {})

        tuple_fields = {
            "allowed_step_types",
            "blocked_step_types",
            "high_risk_keywords",
            "medium_risk_keywords",
        }

        for field_name in tuple_fields:
            value = merged.get(field_name)
            if isinstance(value, list):
                merged[field_name] = tuple(str(item) for item in value)
            elif isinstance(value, tuple):
                merged[field_name] = value
            else:
                merged[field_name] = getattr(defaults, field_name)

        allowed = set(TaskRecorderConfig.__dataclass_fields__.keys())
        clean = {key: value for key, value in merged.items() if key in allowed}
        return TaskRecorderConfig(**clean)

    # -----------------------------------------------------------------------
    # Required compatibility hooks
    # -----------------------------------------------------------------------

    def _validate_task_context(self, task_context: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Validate SaaS task context.

        Required:
            - user_id
            - workspace_id

        This prevents cross-user/workspace mixing of sessions, macros, logs,
        memory, analytics, and audit records.
        """
        context = task_context or {}
        user_id = context.get("user_id")
        workspace_id = context.get("workspace_id")

        if user_id is None or str(user_id).strip() == "":
            return self._error_result(
                message="Missing required user_id in task context.",
                error_code="MISSING_USER_ID",
                metadata={"hook": "_validate_task_context"},
            )

        if workspace_id is None or str(workspace_id).strip() == "":
            return self._error_result(
                message="Missing required workspace_id in task context.",
                error_code="MISSING_WORKSPACE_ID",
                metadata={"hook": "_validate_task_context"},
            )

        return self._safe_result(
            message="Task context validated.",
            data={
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
                "request_id": str(context.get("request_id") or _new_id("req")),
                "session_id": str(context.get("session_id") or ""),
                "role": str(context.get("role") or ""),
                "permissions": context.get("permissions") or [],
            },
            metadata={"hook": "_validate_task_context"},
        )

    def _requires_security_check(
        self,
        action: str,
        task_context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Decide whether an action requires Security Agent approval.

        Recording workflows and preparing replay plans can expose sensitive UI
        flows or create automatable behavior, so sensitive operations are gated.
        """
        if action in {
            RecorderAction.START_RECORDING.value,
            RecorderAction.RECORD_STEP.value,
            RecorderAction.STOP_RECORDING.value,
            RecorderAction.DISCARD_RECORDING.value,
        }:
            return bool(self.config.require_security_for_recording)

        if action in {
            RecorderAction.COMPILE_MACRO.value,
            RecorderAction.VALIDATE_MACRO.value,
            RecorderAction.SAVE_MACRO.value,
            RecorderAction.IMPORT_MACRO.value,
        }:
            return bool(self.config.require_security_for_macro_compile)

        if action in {
            RecorderAction.PREPARE_REPLAY.value,
            RecorderAction.EXPORT_MACRO.value,
        }:
            return bool(self.config.require_security_for_replay_plan)

        return False

    def _request_security_approval(
        self,
        action: str,
        task_context: Optional[Dict[str, Any]] = None,
        reason: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        If no external Security Agent is injected, this uses local permission
        checks from the task context.
        """
        context_result = self._validate_task_context(task_context)
        if not context_result.get("success"):
            return context_result

        context = context_result["data"]
        permissions = set(str(p).lower() for p in context.get("permissions", []))

        payload = {
            "security_request_id": _new_id("sec"),
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "action": action,
            "reason": reason or "TaskRecorder action requires approval.",
            "risk_level": "medium",
            "user_id": context["user_id"],
            "workspace_id": context["workspace_id"],
            "request_id": context["request_id"],
            "metadata": metadata or {},
            "timestamp": _utc_now_iso(),
        }

        if self.security_client is not None:
            try:
                if hasattr(self.security_client, "approve"):
                    response = self.security_client.approve(payload)
                    return self._normalize_security_response(response, payload)

                if hasattr(self.security_client, "request_approval"):
                    response = self.security_client.request_approval(payload)
                    return self._normalize_security_response(response, payload)

            except Exception as exc:
                return self._error_result(
                    message="Security approval request failed.",
                    error_code="SECURITY_CLIENT_ERROR",
                    error=str(exc),
                    metadata=payload,
                )

        local_allowed = (
            "task_recorder" in permissions
            or "record_workflow" in permissions
            or "macro_manage" in permissions
            or "system_agent" in permissions
            or "admin" in permissions
            or "owner" in permissions
        )

        if local_allowed:
            return self._safe_result(
                message="Local security approval granted from context permissions.",
                data={"approved": True, "source": "local_permission_check"},
                metadata=payload,
            )

        return self._error_result(
            message=(
                "Security approval required. Add one permission: task_recorder, "
                "record_workflow, macro_manage, system_agent, admin, or owner."
            ),
            error_code="SECURITY_PERMISSION_REQUIRED",
            data={"approved": False, "source": "local_permission_check"},
            metadata=payload,
        )

    def _normalize_security_response(
        self,
        response: Any,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Normalize external Security Agent response."""
        if isinstance(response, dict):
            approved = response.get("approved") is True or response.get("success") is True
            if approved:
                return self._safe_result(
                    message="Security approval granted.",
                    data={"approved": True, "source": "security_client"},
                    metadata={**payload, "security_response": response},
                )

            return self._error_result(
                message="Security approval denied.",
                error_code="SECURITY_DENIED",
                data={"approved": False, "source": "security_client"},
                metadata={**payload, "security_response": response},
            )

        if response is True:
            return self._safe_result(
                message="Security approval granted.",
                data={"approved": True, "source": "security_client_bool"},
                metadata=payload,
            )

        return self._error_result(
            message="Security approval denied.",
            error_code="SECURITY_DENIED",
            data={"approved": False, "source": "security_client_unknown"},
            metadata={**payload, "security_response": str(response)},
        )

    def _prepare_verification_payload(
        self,
        action: str,
        result: Dict[str, Any],
        task_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        Verification Agent can review:
            - Whether macro is safe.
            - Whether it requires human confirmation.
            - Whether blocked steps exist.
        """
        context = task_context or {}
        data = result.get("data", {}) if isinstance(result, dict) else {}

        return {
            "verification_id": _new_id("verify"),
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "action": action,
            "success": bool(result.get("success")) if isinstance(result, dict) else False,
            "user_id": str(context.get("user_id", "")),
            "workspace_id": str(context.get("workspace_id", "")),
            "request_id": str(context.get("request_id", "")),
            "observational_or_planning_only": True,
            "direct_execution_performed": False,
            "requires_human_review": self._verification_requires_review(result),
            "evidence_summary": {
                "session_id": data.get("session_id") if isinstance(data, dict) else None,
                "macro_id": data.get("macro_id") if isinstance(data, dict) else None,
                "step_count": data.get("step_count") if isinstance(data, dict) else None,
                "risk": data.get("risk") if isinstance(data, dict) else None,
                "blocked": data.get("blocked") if isinstance(data, dict) else None,
            },
            "timestamp": _utc_now_iso(),
            "metadata": {
                "module": "agents/system_agent/task_recorder.py",
                "version": self.version,
            },
        }

    def _prepare_memory_payload(
        self,
        action: str,
        result: Dict[str, Any],
        task_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare safe Memory Agent payload.

        Memory Agent should store only sanitized summaries, not raw screenshots,
        credentials, or sensitive typed text.
        """
        context = task_context or {}
        data = result.get("data", {}) if isinstance(result, dict) else {}

        summary: Dict[str, Any] = {
            "action": action,
            "success": bool(result.get("success")) if isinstance(result, dict) else False,
        }

        if isinstance(data, dict):
            summary.update(
                {
                    "session_id": data.get("session_id"),
                    "macro_id": data.get("macro_id"),
                    "title": _redact_sensitive_text(str(data.get("title", "")))[:300],
                    "description": _redact_sensitive_text(str(data.get("description", "")))[:1000],
                    "step_count": data.get("step_count"),
                    "risk": data.get("risk"),
                }
            )

        return {
            "memory_id": _new_id("mem"),
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "action": action,
            "user_id": str(context.get("user_id", "")),
            "workspace_id": str(context.get("workspace_id", "")),
            "request_id": str(context.get("request_id", "")),
            "summary": summary,
            "store_policy": {
                "workspace_isolated": True,
                "save_redacted_summary_only": self.config.redact_sensitive_values,
                "save_raw_step_inputs": False,
            },
            "timestamp": _utc_now_iso(),
        }

    def _emit_agent_event(
        self,
        event_type: str,
        task_context: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Emit dashboard/task-history event."""
        context = task_context or {}
        event = {
            "event_id": _new_id("evt"),
            "event_type": event_type,
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "user_id": str(context.get("user_id", "")),
            "workspace_id": str(context.get("workspace_id", "")),
            "request_id": str(context.get("request_id", "")),
            "data": data or {},
            "timestamp": _utc_now_iso(),
        }

        try:
            if self.event_emitter:
                self.event_emitter(event)
            else:
                self.logger.debug("Agent event: %s", json.dumps(event, default=str))
        except Exception as exc:
            self.logger.warning("Failed to emit TaskRecorder event: %s", exc)

    def _log_audit_event(
        self,
        action: str,
        task_context: Optional[Dict[str, Any]] = None,
        status: str = "info",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Write audit event for SaaS compliance and dashboard records."""
        context = task_context or {}
        audit = {
            "audit_id": _new_id("audit"),
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "action": action,
            "status": status,
            "user_id": str(context.get("user_id", "")),
            "workspace_id": str(context.get("workspace_id", "")),
            "request_id": str(context.get("request_id", "")),
            "details": _redact_sensitive_data(details or {}),
            "timestamp": _utc_now_iso(),
        }

        try:
            if self.audit_logger:
                self.audit_logger(audit)
            else:
                self.logger.info("Audit event: %s", json.dumps(audit, default=str))
        except Exception as exc:
            self.logger.warning("Failed to write TaskRecorder audit event: %s", exc)

    def _safe_result(
        self,
        message: str = "OK",
        data: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return William/Jarvis standard success result."""
        return {
            "success": True,
            "message": message,
            "data": data if data is not None else {},
            "error": None,
            "metadata": {
                "agent": self.agent_name,
                "agent_type": self.agent_type,
                "version": self.version,
                "timestamp": _utc_now_iso(),
                **(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str = "Error",
        error_code: str = "TASK_RECORDER_ERROR",
        error: Optional[str] = None,
        data: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return William/Jarvis standard error result."""
        return {
            "success": False,
            "message": message,
            "data": data if data is not None else {},
            "error": {
                "code": error_code,
                "detail": error or message,
            },
            "metadata": {
                "agent": self.agent_name,
                "agent_type": self.agent_type,
                "version": self.version,
                "timestamp": _utc_now_iso(),
                **(metadata or {}),
            },
        }

    # -----------------------------------------------------------------------
    # Storage helpers
    # -----------------------------------------------------------------------

    def _workspace_dir(self, user_id: str, workspace_id: str) -> Path:
        """Return workspace-isolated storage directory."""
        safe_user = _sanitize_id_part(user_id)
        safe_workspace = _sanitize_id_part(workspace_id)
        path = Path(self.config.storage_dir) / f"user_{safe_user}" / f"workspace_{safe_workspace}"
        path.mkdir(parents=True, exist_ok=True)
        (path / "sessions").mkdir(parents=True, exist_ok=True)
        (path / "macros").mkdir(parents=True, exist_ok=True)
        (path / "exports").mkdir(parents=True, exist_ok=True)
        return path

    def _sessions_dir(self, user_id: str, workspace_id: str) -> Path:
        return self._workspace_dir(user_id, workspace_id) / "sessions"

    def _macros_dir(self, user_id: str, workspace_id: str) -> Path:
        return self._workspace_dir(user_id, workspace_id) / "macros"

    def _exports_dir(self, user_id: str, workspace_id: str) -> Path:
        return self._workspace_dir(user_id, workspace_id) / "exports"

    def _session_path(self, user_id: str, workspace_id: str, session_id: str) -> Path:
        return self._sessions_dir(user_id, workspace_id) / f"{_sanitize_id_part(session_id)}.json"

    def _macro_path(self, user_id: str, workspace_id: str, macro_id: str) -> Path:
        return self._macros_dir(user_id, workspace_id) / f"{_sanitize_id_part(macro_id)}.json"

    def _write_json_atomic(self, path: Path, data: Dict[str, Any]) -> None:
        """Write JSON atomically."""
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        tmp.replace(path)

    def _read_json(self, path: Path) -> Dict[str, Any]:
        """Read JSON safely."""
        if not path.exists():
            raise FileNotFoundError(str(path))

        if path.stat().st_size > self.config.max_macro_file_bytes:
            raise ValueError(f"File too large: {path}")

        return json.loads(path.read_text(encoding="utf-8"))

    # -----------------------------------------------------------------------
    # Serialization helpers
    # -----------------------------------------------------------------------

    def _session_from_dict(self, data: Dict[str, Any]) -> RecordingSession:
        """Create RecordingSession from dict."""
        steps = [
            self._step_from_dict(item)
            for item in data.get("steps", []) or []
            if isinstance(item, dict)
        ]

        return RecordingSession(
            session_id=str(data.get("session_id") or _new_id("session")),
            user_id=str(data.get("user_id") or ""),
            workspace_id=str(data.get("workspace_id") or ""),
            title=str(data.get("title") or "Untitled Recording"),
            status=str(data.get("status") or SessionStatus.STOPPED.value),
            steps=steps,
            tags=list(data.get("tags") or []),
            source=str(data.get("source") or "manual"),
            created_at=str(data.get("created_at") or _utc_now_iso()),
            updated_at=str(data.get("updated_at") or _utc_now_iso()),
            metadata=dict(data.get("metadata") or {}),
        )

    def _step_from_dict(self, data: Dict[str, Any]) -> RecordedStep:
        """Create RecordedStep from dict."""
        return RecordedStep(
            step_id=str(data.get("step_id") or _new_id("step")),
            step_index=int(data.get("step_index") or 0),
            step_type=str(data.get("step_type") or StepType.CUSTOM.value),
            action=str(data.get("action") or "unknown_action"),
            description=str(data.get("description") or ""),
            target=dict(data.get("target") or {}),
            input_data=dict(data.get("input_data") or {}),
            expected_result=dict(data.get("expected_result") or {}),
            safety=dict(data.get("safety") or {}),
            timing=dict(data.get("timing") or {}),
            screenshot_ref=data.get("screenshot_ref"),
            ocr_text=data.get("ocr_text"),
            metadata=dict(data.get("metadata") or {}),
            created_at=str(data.get("created_at") or _utc_now_iso()),
        )

    def _macro_from_dict(self, data: Dict[str, Any]) -> MacroDefinition:
        """Create MacroDefinition from dict."""
        steps = [
            self._step_from_dict(item)
            for item in data.get("steps", []) or []
            if isinstance(item, dict)
        ]

        return MacroDefinition(
            macro_id=str(data.get("macro_id") or _new_id("macro")),
            user_id=str(data.get("user_id") or ""),
            workspace_id=str(data.get("workspace_id") or ""),
            title=str(data.get("title") or "Untitled Macro"),
            description=str(data.get("description") or ""),
            version=str(data.get("version") or "1.0.0"),
            source_session_id=data.get("source_session_id"),
            steps=steps,
            variables=dict(data.get("variables") or {}),
            constraints=dict(data.get("constraints") or {}),
            safety=dict(data.get("safety") or {}),
            replay_policy=dict(data.get("replay_policy") or {}),
            tags=list(data.get("tags") or []),
            checksum=str(data.get("checksum") or ""),
            created_at=str(data.get("created_at") or _utc_now_iso()),
            updated_at=str(data.get("updated_at") or _utc_now_iso()),
            metadata=dict(data.get("metadata") or {}),
        )

    # -----------------------------------------------------------------------
    # Public actions
    # -----------------------------------------------------------------------

    def health(self, task_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Return TaskRecorder health."""
        return self._safe_result(
            message="TaskRecorder health check complete.",
            data={
                "agent": self.agent_name,
                "status": "ready",
                "storage_dir": self.config.storage_dir,
                "active_sessions": len(self._active_sessions),
                "config": {
                    "require_security_for_recording": self.config.require_security_for_recording,
                    "require_security_for_macro_compile": self.config.require_security_for_macro_compile,
                    "require_security_for_replay_plan": self.config.require_security_for_replay_plan,
                    "redact_sensitive_values": self.config.redact_sensitive_values,
                    "max_steps_per_session": self.config.max_steps_per_session,
                    "blocked_step_types": list(self.config.blocked_step_types),
                    "direct_execution_enabled": False,
                },
            },
            metadata={"action": RecorderAction.HEALTH.value},
        )

    def start_recording(
        self,
        title: str,
        task_context: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Start a new manual workflow recording session."""
        action = RecorderAction.START_RECORDING.value

        context_result = self._validate_task_context(task_context)
        if not context_result.get("success"):
            return context_result
        context = context_result["data"]

        if self._requires_security_check(action, task_context):
            approval = self._request_security_approval(
                action=action,
                task_context=task_context,
                reason="Start recording a manual workflow for macro creation.",
                metadata={"title": _redact_sensitive_text(title)},
            )
            if not approval.get("success"):
                return approval

        try:
            self._enforce_session_limit(context["user_id"], context["workspace_id"])

            session = RecordingSession(
                session_id=_new_id("session"),
                user_id=context["user_id"],
                workspace_id=context["workspace_id"],
                title=_redact_sensitive_text(_safe_string(title, 300))
                if self.config.redact_sensitive_values
                else _safe_string(title, 300),
                status=SessionStatus.RECORDING.value,
                tags=[_safe_string(tag, 80) for tag in (tags or [])],
                metadata=_redact_sensitive_data(metadata or {})
                if self.config.redact_sensitive_values
                else dict(metadata or {}),
            )

            self._active_sessions[session.session_id] = session
            self._save_session(session)

            result = self._safe_result(
                message="Recording session started.",
                data={
                    "session_id": session.session_id,
                    "title": session.title,
                    "status": session.status,
                    "step_count": 0,
                    "tags": session.tags,
                },
                metadata={"action": action},
            )

            result["metadata"]["verification_payload"] = self._prepare_verification_payload(
                action=action,
                result=result,
                task_context=task_context,
            )
            result["metadata"]["memory_payload"] = self._prepare_memory_payload(
                action=action,
                result=result,
                task_context=task_context,
            )

            self._emit_agent_event(
                event_type="task_recorder.session.started",
                task_context=task_context,
                data={"session_id": session.session_id, "title": session.title},
            )

            self._log_audit_event(
                action=action,
                task_context=task_context,
                status="success",
                details={"session_id": session.session_id, "title": session.title},
            )

            return result

        except Exception as exc:
            self.logger.exception("start_recording failed")
            return self._error_result(
                message="Failed to start recording session.",
                error_code="START_RECORDING_FAILED",
                error=str(exc),
                metadata={"action": action},
            )

    def record_step(
        self,
        session_id: str,
        step_type: str,
        action_name: str,
        task_context: Optional[Dict[str, Any]] = None,
        description: str = "",
        target: Optional[Dict[str, Any]] = None,
        input_data: Optional[Dict[str, Any]] = None,
        expected_result: Optional[Dict[str, Any]] = None,
        timing: Optional[Dict[str, Any]] = None,
        screenshot_ref: Optional[str] = None,
        ocr_text: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Record one manual workflow step into an active session."""
        action = RecorderAction.RECORD_STEP.value

        context_result = self._validate_task_context(task_context)
        if not context_result.get("success"):
            return context_result
        context = context_result["data"]

        if self._requires_security_check(action, task_context):
            approval = self._request_security_approval(
                action=action,
                task_context=task_context,
                reason="Record a manual workflow step.",
                metadata={
                    "session_id": session_id,
                    "step_type": step_type,
                    "action_name": action_name,
                },
            )
            if not approval.get("success"):
                return approval

        try:
            session = self._load_session_for_context(
                user_id=context["user_id"],
                workspace_id=context["workspace_id"],
                session_id=session_id,
            )

            if session.status != SessionStatus.RECORDING.value:
                return self._error_result(
                    message=f"Session is not recording. Current status: {session.status}",
                    error_code="SESSION_NOT_RECORDING",
                    data={"session_id": session_id, "status": session.status},
                    metadata={"action": action},
                )

            if len(session.steps) >= self.config.max_steps_per_session:
                return self._error_result(
                    message="Maximum steps per session reached.",
                    error_code="MAX_STEPS_REACHED",
                    data={
                        "session_id": session_id,
                        "max_steps": self.config.max_steps_per_session,
                    },
                    metadata={"action": action},
                )

            clean_step_type = self._validate_step_type(step_type)
            clean_action_name = _normalize_action_name(action_name)

            raw_payload = {
                "description": description,
                "target": target or {},
                "input_data": input_data or {},
                "expected_result": expected_result or {},
                "ocr_text": ocr_text or "",
                "metadata": metadata or {},
            }

            payload_size = len(json.dumps(raw_payload, default=str))
            if payload_size > self.config.max_step_payload_chars:
                return self._error_result(
                    message="Step payload is too large.",
                    error_code="STEP_PAYLOAD_TOO_LARGE",
                    data={
                        "payload_size": payload_size,
                        "max_allowed": self.config.max_step_payload_chars,
                    },
                    metadata={"action": action},
                )

            sanitized = self._sanitize_step_payload(
                description=description,
                target=target or {},
                input_data=input_data or {},
                expected_result=expected_result or {},
                ocr_text=ocr_text,
                metadata=metadata or {},
            )

            step_index = len(session.steps) + 1

            step = RecordedStep(
                step_id=_new_id("step"),
                step_index=step_index,
                step_type=clean_step_type,
                action=clean_action_name,
                description=sanitized["description"],
                target=sanitized["target"],
                input_data=sanitized["input_data"],
                expected_result=sanitized["expected_result"],
                safety=self._classify_step_safety(
                    step_type=clean_step_type,
                    action_name=clean_action_name,
                    description=sanitized["description"],
                    target=sanitized["target"],
                    input_data=sanitized["input_data"],
                ),
                timing=self._sanitize_timing(timing or {}),
                screenshot_ref=_safe_string(screenshot_ref, 500) if screenshot_ref else None,
                ocr_text=sanitized["ocr_text"],
                metadata=sanitized["metadata"],
            )

            session.steps.append(step)
            session.updated_at = _utc_now_iso()

            self._active_sessions[session.session_id] = session
            self._save_session(session)

            result = self._safe_result(
                message="Workflow step recorded.",
                data={
                    "session_id": session.session_id,
                    "step_id": step.step_id,
                    "step_index": step.step_index,
                    "step_type": step.step_type,
                    "action": step.action,
                    "safety": step.safety,
                    "step_count": len(session.steps),
                },
                metadata={"action": action},
            )

            self._emit_agent_event(
                event_type="task_recorder.step.recorded",
                task_context=task_context,
                data={
                    "session_id": session.session_id,
                    "step_id": step.step_id,
                    "step_index": step.step_index,
                    "step_type": step.step_type,
                },
            )

            self._log_audit_event(
                action=action,
                task_context=task_context,
                status="success",
                details={
                    "session_id": session.session_id,
                    "step_id": step.step_id,
                    "step_type": step.step_type,
                    "risk": step.safety.get("risk"),
                },
            )

            return result

        except Exception as exc:
            self.logger.exception("record_step failed")
            return self._error_result(
                message="Failed to record workflow step.",
                error_code="RECORD_STEP_FAILED",
                error=str(exc),
                metadata={"action": action},
            )

    def stop_recording(
        self,
        session_id: str,
        task_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Stop an active recording session."""
        action = RecorderAction.STOP_RECORDING.value

        context_result = self._validate_task_context(task_context)
        if not context_result.get("success"):
            return context_result
        context = context_result["data"]

        if self._requires_security_check(action, task_context):
            approval = self._request_security_approval(
                action=action,
                task_context=task_context,
                reason="Stop recording manual workflow session.",
                metadata={"session_id": session_id},
            )
            if not approval.get("success"):
                return approval

        try:
            session = self._load_session_for_context(
                user_id=context["user_id"],
                workspace_id=context["workspace_id"],
                session_id=session_id,
            )

            session.status = SessionStatus.STOPPED.value
            session.updated_at = _utc_now_iso()

            self._active_sessions.pop(session.session_id, None)
            self._save_session(session)

            safety = self._classify_session_safety(session)

            result = self._safe_result(
                message="Recording session stopped.",
                data={
                    "session_id": session.session_id,
                    "title": session.title,
                    "status": session.status,
                    "step_count": len(session.steps),
                    "risk": safety["risk"],
                    "safety": safety,
                },
                metadata={"action": action},
            )

            result["metadata"]["verification_payload"] = self._prepare_verification_payload(
                action=action,
                result=result,
                task_context=task_context,
            )
            result["metadata"]["memory_payload"] = self._prepare_memory_payload(
                action=action,
                result=result,
                task_context=task_context,
            )

            self._emit_agent_event(
                event_type="task_recorder.session.stopped",
                task_context=task_context,
                data={"session_id": session.session_id, "step_count": len(session.steps)},
            )

            self._log_audit_event(
                action=action,
                task_context=task_context,
                status="success",
                details={"session_id": session.session_id, "step_count": len(session.steps)},
            )

            return result

        except Exception as exc:
            self.logger.exception("stop_recording failed")
            return self._error_result(
                message="Failed to stop recording session.",
                error_code="STOP_RECORDING_FAILED",
                error=str(exc),
                metadata={"action": action},
            )

    def discard_recording(
        self,
        session_id: str,
        task_context: Optional[Dict[str, Any]] = None,
        delete_file: bool = False,
    ) -> Dict[str, Any]:
        """Discard a recording session. File deletion is optional."""
        action = RecorderAction.DISCARD_RECORDING.value

        context_result = self._validate_task_context(task_context)
        if not context_result.get("success"):
            return context_result
        context = context_result["data"]

        if self._requires_security_check(action, task_context):
            approval = self._request_security_approval(
                action=action,
                task_context=task_context,
                reason="Discard a recorded workflow session.",
                metadata={"session_id": session_id, "delete_file": delete_file},
            )
            if not approval.get("success"):
                return approval

        try:
            session = self._load_session_for_context(
                user_id=context["user_id"],
                workspace_id=context["workspace_id"],
                session_id=session_id,
            )

            session.status = SessionStatus.DISCARDED.value
            session.updated_at = _utc_now_iso()

            self._active_sessions.pop(session.session_id, None)

            path = self._session_path(context["user_id"], context["workspace_id"], session.session_id)
            if delete_file and path.exists():
                path.unlink()
                file_status = "deleted"
            else:
                self._save_session(session)
                file_status = "marked_discarded"

            result = self._safe_result(
                message="Recording session discarded.",
                data={
                    "session_id": session.session_id,
                    "status": session.status,
                    "file_status": file_status,
                },
                metadata={"action": action},
            )

            self._log_audit_event(
                action=action,
                task_context=task_context,
                status="success",
                details={
                    "session_id": session.session_id,
                    "delete_file": delete_file,
                    "file_status": file_status,
                },
            )

            return result

        except Exception as exc:
            return self._error_result(
                message="Failed to discard recording session.",
                error_code="DISCARD_RECORDING_FAILED",
                error=str(exc),
                metadata={"action": action},
            )

    def get_session(
        self,
        session_id: str,
        task_context: Optional[Dict[str, Any]] = None,
        include_steps: bool = True,
    ) -> Dict[str, Any]:
        """Get one recording session."""
        action = RecorderAction.GET_SESSION.value

        context_result = self._validate_task_context(task_context)
        if not context_result.get("success"):
            return context_result
        context = context_result["data"]

        try:
            session = self._load_session_for_context(
                user_id=context["user_id"],
                workspace_id=context["workspace_id"],
                session_id=session_id,
            )

            data = session.to_dict()
            if not include_steps:
                data["steps"] = []
            data["step_count"] = len(session.steps)

            return self._safe_result(
                message="Recording session loaded.",
                data=data,
                metadata={"action": action},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to load recording session.",
                error_code="GET_SESSION_FAILED",
                error=str(exc),
                metadata={"action": action},
            )

    def list_sessions(
        self,
        task_context: Optional[Dict[str, Any]] = None,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """List workspace-isolated recording sessions."""
        action = RecorderAction.LIST_SESSIONS.value

        context_result = self._validate_task_context(task_context)
        if not context_result.get("success"):
            return context_result
        context = context_result["data"]

        try:
            sessions: List[Dict[str, Any]] = []
            directory = self._sessions_dir(context["user_id"], context["workspace_id"])

            for path in sorted(directory.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
                try:
                    session = self._session_from_dict(self._read_json(path))
                    if status and session.status != status:
                        continue

                    sessions.append(
                        {
                            "session_id": session.session_id,
                            "title": session.title,
                            "status": session.status,
                            "step_count": len(session.steps),
                            "tags": session.tags,
                            "source": session.source,
                            "created_at": session.created_at,
                            "updated_at": session.updated_at,
                        }
                    )

                    if len(sessions) >= limit:
                        break
                except Exception as exc:
                    self.logger.warning("Skipping unreadable session file %s: %s", path, exc)

            return self._safe_result(
                message="Recording sessions listed.",
                data={
                    "sessions": sessions,
                    "count": len(sessions),
                    "limit": limit,
                    "status_filter": status,
                },
                metadata={"action": action},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to list recording sessions.",
                error_code="LIST_SESSIONS_FAILED",
                error=str(exc),
                metadata={"action": action},
            )

    def compile_macro(
        self,
        session_id: str,
        task_context: Optional[Dict[str, Any]] = None,
        title: Optional[str] = None,
        description: str = "",
        variables: Optional[Dict[str, Any]] = None,
        constraints: Optional[Dict[str, Any]] = None,
        replay_policy: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Compile a stopped recording session into a replayable macro definition."""
        action = RecorderAction.COMPILE_MACRO.value

        context_result = self._validate_task_context(task_context)
        if not context_result.get("success"):
            return context_result
        context = context_result["data"]

        if self._requires_security_check(action, task_context):
            approval = self._request_security_approval(
                action=action,
                task_context=task_context,
                reason="Compile recorded workflow into a replayable macro definition.",
                metadata={"session_id": session_id},
            )
            if not approval.get("success"):
                return approval

        try:
            session = self._load_session_for_context(
                user_id=context["user_id"],
                workspace_id=context["workspace_id"],
                session_id=session_id,
            )

            if not session.steps:
                return self._error_result(
                    message="Cannot compile an empty recording session.",
                    error_code="EMPTY_SESSION",
                    data={"session_id": session_id},
                    metadata={"action": action},
                )

            clean_steps = self._normalize_steps_for_macro(session.steps)
            safety = self._classify_steps_safety(clean_steps)

            macro = MacroDefinition(
                macro_id=_new_id("macro"),
                user_id=context["user_id"],
                workspace_id=context["workspace_id"],
                title=_redact_sensitive_text(title or session.title)
                if self.config.redact_sensitive_values
                else str(title or session.title),
                description=_redact_sensitive_text(description or f"Macro compiled from session {session.session_id}.")
                if self.config.redact_sensitive_values
                else str(description or f"Macro compiled from session {session.session_id}."),
                version="1.0.0",
                source_session_id=session.session_id,
                steps=clean_steps,
                variables=_redact_sensitive_data(variables or {})
                if self.config.redact_sensitive_values
                else dict(variables or {}),
                constraints=_redact_sensitive_data(constraints or {})
                if self.config.redact_sensitive_values
                else dict(constraints or {}),
                safety=safety,
                replay_policy=self._build_replay_policy(replay_policy or {}, safety),
                tags=[_safe_string(tag, 80) for tag in (tags or session.tags)],
                metadata={
                    "compiled_by": self.agent_name,
                    "compiled_at": _utc_now_iso(),
                    "source_step_count": len(session.steps),
                },
            )

            macro.checksum = self._calculate_macro_checksum(macro)

            validation = self._validate_macro_object(macro)

            data = {
                "macro_id": macro.macro_id,
                "session_id": session.session_id,
                "title": macro.title,
                "description": macro.description,
                "step_count": len(macro.steps),
                "risk": safety["risk"],
                "safety": safety,
                "replay_policy": macro.replay_policy,
                "checksum": macro.checksum,
                "macro": macro.to_dict(),
                "validation": validation,
            }

            result = self._safe_result(
                message="Recording session compiled into macro definition.",
                data=data,
                metadata={"action": action},
            )

            result["metadata"]["verification_payload"] = self._prepare_verification_payload(
                action=action,
                result=result,
                task_context=task_context,
            )
            result["metadata"]["memory_payload"] = self._prepare_memory_payload(
                action=action,
                result=result,
                task_context=task_context,
            )

            self._log_audit_event(
                action=action,
                task_context=task_context,
                status="success",
                details={
                    "session_id": session.session_id,
                    "macro_id": macro.macro_id,
                    "risk": safety["risk"],
                    "step_count": len(macro.steps),
                },
            )

            return result

        except Exception as exc:
            self.logger.exception("compile_macro failed")
            return self._error_result(
                message="Failed to compile macro.",
                error_code="COMPILE_MACRO_FAILED",
                error=str(exc),
                metadata={"action": action},
            )

    def validate_macro(
        self,
        task_context: Optional[Dict[str, Any]] = None,
        macro_id: Optional[str] = None,
        macro: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Validate a macro by ID or raw macro dict."""
        action = RecorderAction.VALIDATE_MACRO.value

        context_result = self._validate_task_context(task_context)
        if not context_result.get("success"):
            return context_result
        context = context_result["data"]

        if self._requires_security_check(action, task_context):
            approval = self._request_security_approval(
                action=action,
                task_context=task_context,
                reason="Validate macro safety and replay policy.",
                metadata={"macro_id": macro_id},
            )
            if not approval.get("success"):
                return approval

        try:
            macro_obj: MacroDefinition

            if macro is not None:
                macro_obj = self._macro_from_dict(macro)
                macro_obj.user_id = context["user_id"]
                macro_obj.workspace_id = context["workspace_id"]
            elif macro_id:
                macro_obj = self._load_macro_for_context(
                    user_id=context["user_id"],
                    workspace_id=context["workspace_id"],
                    macro_id=macro_id,
                )
            else:
                return self._error_result(
                    message="validate_macro requires macro_id or macro.",
                    error_code="MISSING_MACRO_INPUT",
                    metadata={"action": action},
                )

            validation = self._validate_macro_object(macro_obj)

            result = self._safe_result(
                message="Macro validation completed.",
                data=validation,
                metadata={"action": action},
            )

            result["metadata"]["verification_payload"] = self._prepare_verification_payload(
                action=action,
                result=result,
                task_context=task_context,
            )

            return result

        except Exception as exc:
            return self._error_result(
                message="Failed to validate macro.",
                error_code="VALIDATE_MACRO_FAILED",
                error=str(exc),
                metadata={"action": action},
            )

    def save_macro(
        self,
        macro: Dict[str, Any],
        task_context: Optional[Dict[str, Any]] = None,
        overwrite: bool = False,
    ) -> Dict[str, Any]:
        """Save a macro definition in workspace-isolated storage."""
        action = RecorderAction.SAVE_MACRO.value

        context_result = self._validate_task_context(task_context)
        if not context_result.get("success"):
            return context_result
        context = context_result["data"]

        if self._requires_security_check(action, task_context):
            approval = self._request_security_approval(
                action=action,
                task_context=task_context,
                reason="Save replayable macro definition.",
                metadata={"overwrite": overwrite},
            )
            if not approval.get("success"):
                return approval

        try:
            self._enforce_macro_limit(context["user_id"], context["workspace_id"])

            macro_obj = self._macro_from_dict(macro)
            macro_obj.user_id = context["user_id"]
            macro_obj.workspace_id = context["workspace_id"]
            macro_obj.updated_at = _utc_now_iso()

            if self.config.redact_sensitive_values:
                macro_obj = self._sanitize_macro_object(macro_obj)

            macro_obj.safety = self._classify_steps_safety(macro_obj.steps)
            macro_obj.replay_policy = self._build_replay_policy(macro_obj.replay_policy, macro_obj.safety)
            macro_obj.checksum = self._calculate_macro_checksum(macro_obj)

            validation = self._validate_macro_object(macro_obj)

            if not validation["valid"]:
                return self._error_result(
                    message="Macro failed validation and was not saved.",
                    error_code="MACRO_VALIDATION_FAILED",
                    data=validation,
                    metadata={"action": action},
                )

            risk = validation["risk"]
            if risk == MacroRisk.BLOCKED.value and not self.config.allow_blocked_macro_save:
                return self._error_result(
                    message="Blocked-risk macro cannot be saved by current configuration.",
                    error_code="BLOCKED_MACRO_SAVE_DENIED",
                    data=validation,
                    metadata={"action": action},
                )

            if risk == MacroRisk.HIGH.value and not self.config.allow_high_risk_macro_save:
                return self._error_result(
                    message="High-risk macro cannot be saved by current configuration.",
                    error_code="HIGH_RISK_MACRO_SAVE_DENIED",
                    data=validation,
                    metadata={"action": action},
                )

            path = self._macro_path(context["user_id"], context["workspace_id"], macro_obj.macro_id)

            if path.exists() and not overwrite:
                return self._error_result(
                    message="Macro already exists. Use overwrite=True to replace it.",
                    error_code="MACRO_ALREADY_EXISTS",
                    data={"macro_id": macro_obj.macro_id},
                    metadata={"action": action},
                )

            self._write_json_atomic(path, macro_obj.to_dict())

            result = self._safe_result(
                message="Macro saved successfully.",
                data={
                    "macro_id": macro_obj.macro_id,
                    "title": macro_obj.title,
                    "description": macro_obj.description,
                    "step_count": len(macro_obj.steps),
                    "risk": macro_obj.safety.get("risk"),
                    "checksum": macro_obj.checksum,
                    "path": str(path),
                    "validation": validation,
                },
                metadata={"action": action},
            )

            result["metadata"]["verification_payload"] = self._prepare_verification_payload(
                action=action,
                result=result,
                task_context=task_context,
            )
            result["metadata"]["memory_payload"] = self._prepare_memory_payload(
                action=action,
                result=result,
                task_context=task_context,
            )

            self._emit_agent_event(
                event_type="task_recorder.macro.saved",
                task_context=task_context,
                data={
                    "macro_id": macro_obj.macro_id,
                    "title": macro_obj.title,
                    "risk": macro_obj.safety.get("risk"),
                },
            )

            self._log_audit_event(
                action=action,
                task_context=task_context,
                status="success",
                details={
                    "macro_id": macro_obj.macro_id,
                    "risk": macro_obj.safety.get("risk"),
                    "overwrite": overwrite,
                },
            )

            return result

        except Exception as exc:
            self.logger.exception("save_macro failed")
            return self._error_result(
                message="Failed to save macro.",
                error_code="SAVE_MACRO_FAILED",
                error=str(exc),
                metadata={"action": action},
            )

    def get_macro(
        self,
        macro_id: str,
        task_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Get one macro by ID."""
        action = RecorderAction.GET_MACRO.value

        context_result = self._validate_task_context(task_context)
        if not context_result.get("success"):
            return context_result
        context = context_result["data"]

        try:
            macro = self._load_macro_for_context(
                user_id=context["user_id"],
                workspace_id=context["workspace_id"],
                macro_id=macro_id,
            )

            data = macro.to_dict()
            data["step_count"] = len(macro.steps)

            return self._safe_result(
                message="Macro loaded.",
                data=data,
                metadata={"action": action},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to load macro.",
                error_code="GET_MACRO_FAILED",
                error=str(exc),
                metadata={"action": action},
            )

    def list_macros(
        self,
        task_context: Optional[Dict[str, Any]] = None,
        risk: Optional[str] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """List workspace-isolated macros."""
        action = RecorderAction.LIST_MACROS.value

        context_result = self._validate_task_context(task_context)
        if not context_result.get("success"):
            return context_result
        context = context_result["data"]

        try:
            macros: List[Dict[str, Any]] = []
            directory = self._macros_dir(context["user_id"], context["workspace_id"])

            for path in sorted(directory.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
                try:
                    macro = self._macro_from_dict(self._read_json(path))
                    macro_risk = macro.safety.get("risk", MacroRisk.LOW.value)

                    if risk and macro_risk != risk:
                        continue

                    macros.append(
                        {
                            "macro_id": macro.macro_id,
                            "title": macro.title,
                            "description": macro.description,
                            "version": macro.version,
                            "source_session_id": macro.source_session_id,
                            "step_count": len(macro.steps),
                            "risk": macro_risk,
                            "tags": macro.tags,
                            "checksum": macro.checksum,
                            "created_at": macro.created_at,
                            "updated_at": macro.updated_at,
                        }
                    )

                    if len(macros) >= limit:
                        break
                except Exception as exc:
                    self.logger.warning("Skipping unreadable macro file %s: %s", path, exc)

            return self._safe_result(
                message="Macros listed.",
                data={
                    "macros": macros,
                    "count": len(macros),
                    "limit": limit,
                    "risk_filter": risk,
                },
                metadata={"action": action},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to list macros.",
                error_code="LIST_MACROS_FAILED",
                error=str(exc),
                metadata={"action": action},
            )

    def delete_macro(
        self,
        macro_id: str,
        task_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Delete a macro definition from workspace-isolated storage."""
        action = RecorderAction.DELETE_MACRO.value

        context_result = self._validate_task_context(task_context)
        if not context_result.get("success"):
            return context_result
        context = context_result["data"]

        try:
            path = self._macro_path(context["user_id"], context["workspace_id"], macro_id)

            if not path.exists():
                return self._error_result(
                    message="Macro not found.",
                    error_code="MACRO_NOT_FOUND",
                    data={"macro_id": macro_id},
                    metadata={"action": action},
                )

            path.unlink()

            result = self._safe_result(
                message="Macro deleted.",
                data={"macro_id": macro_id, "deleted": True},
                metadata={"action": action},
            )

            self._log_audit_event(
                action=action,
                task_context=task_context,
                status="success",
                details={"macro_id": macro_id},
            )

            return result

        except Exception as exc:
            return self._error_result(
                message="Failed to delete macro.",
                error_code="DELETE_MACRO_FAILED",
                error=str(exc),
                metadata={"action": action},
            )

    def export_macro(
        self,
        macro_id: str,
        task_context: Optional[Dict[str, Any]] = None,
        include_file_path: bool = True,
    ) -> Dict[str, Any]:
        """Export a macro as JSON in workspace-isolated exports folder."""
        action = RecorderAction.EXPORT_MACRO.value

        context_result = self._validate_task_context(task_context)
        if not context_result.get("success"):
            return context_result
        context = context_result["data"]

        if self._requires_security_check(action, task_context):
            approval = self._request_security_approval(
                action=action,
                task_context=task_context,
                reason="Export macro definition.",
                metadata={"macro_id": macro_id},
            )
            if not approval.get("success"):
                return approval

        try:
            macro = self._load_macro_for_context(
                user_id=context["user_id"],
                workspace_id=context["workspace_id"],
                macro_id=macro_id,
            )

            export_data = macro.to_dict()
            export_data["exported_at"] = _utc_now_iso()
            export_data["exported_by_agent"] = self.agent_name
            export_data["export_format"] = "william_task_macro_v1"

            path = self._exports_dir(context["user_id"], context["workspace_id"]) / f"{_sanitize_id_part(macro_id)}_export.json"
            self._write_json_atomic(path, export_data)

            result_data = {
                "macro_id": macro_id,
                "export_format": "william_task_macro_v1",
                "checksum": macro.checksum,
                "export": export_data,
            }

            if include_file_path:
                result_data["path"] = str(path)

            return self._safe_result(
                message="Macro exported successfully.",
                data=result_data,
                metadata={"action": action},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to export macro.",
                error_code="EXPORT_MACRO_FAILED",
                error=str(exc),
                metadata={"action": action},
            )

    def import_macro(
        self,
        macro_data: Dict[str, Any],
        task_context: Optional[Dict[str, Any]] = None,
        overwrite: bool = False,
        assign_new_id: bool = True,
    ) -> Dict[str, Any]:
        """Import a macro JSON payload into current user/workspace."""
        action = RecorderAction.IMPORT_MACRO.value

        context_result = self._validate_task_context(task_context)
        if not context_result.get("success"):
            return context_result
        context = context_result["data"]

        if self._requires_security_check(action, task_context):
            approval = self._request_security_approval(
                action=action,
                task_context=task_context,
                reason="Import macro definition into workspace.",
                metadata={"assign_new_id": assign_new_id, "overwrite": overwrite},
            )
            if not approval.get("success"):
                return approval

        try:
            if not isinstance(macro_data, dict):
                return self._error_result(
                    message="macro_data must be a dict.",
                    error_code="INVALID_MACRO_DATA",
                    metadata={"action": action},
                )

            macro = self._macro_from_dict(macro_data)

            if assign_new_id:
                macro.macro_id = _new_id("macro")

            macro.user_id = context["user_id"]
            macro.workspace_id = context["workspace_id"]
            macro.updated_at = _utc_now_iso()
            macro.metadata["imported_at"] = _utc_now_iso()
            macro.metadata["imported_by_agent"] = self.agent_name

            save_result = self.save_macro(
                macro=macro.to_dict(),
                task_context=task_context,
                overwrite=overwrite,
            )

            if not save_result.get("success"):
                return save_result

            save_result["message"] = "Macro imported successfully."
            save_result["metadata"]["action"] = action
            return save_result

        except Exception as exc:
            return self._error_result(
                message="Failed to import macro.",
                error_code="IMPORT_MACRO_FAILED",
                error=str(exc),
                metadata={"action": action},
            )

    def prepare_replay(
        self,
        macro_id: str,
        task_context: Optional[Dict[str, Any]] = None,
        variables: Optional[Dict[str, Any]] = None,
        dry_run: bool = True,
    ) -> Dict[str, Any]:
        """
        Prepare a safe replay plan for an existing macro.

        This method does NOT execute anything. It returns a replay plan for an
        approved executor agent.
        """
        action = RecorderAction.PREPARE_REPLAY.value

        context_result = self._validate_task_context(task_context)
        if not context_result.get("success"):
            return context_result
        context = context_result["data"]

        if self._requires_security_check(action, task_context):
            approval = self._request_security_approval(
                action=action,
                task_context=task_context,
                reason="Prepare macro replay plan without executing it.",
                metadata={"macro_id": macro_id, "dry_run": dry_run},
            )
            if not approval.get("success"):
                return approval

        try:
            macro = self._load_macro_for_context(
                user_id=context["user_id"],
                workspace_id=context["workspace_id"],
                macro_id=macro_id,
            )

            validation = self._validate_macro_object(macro)

            if not validation["valid"]:
                return self._error_result(
                    message="Macro is not valid for replay planning.",
                    error_code="INVALID_MACRO_FOR_REPLAY",
                    data=validation,
                    metadata={"action": action},
                )

            resolved_variables = self._resolve_macro_variables(
                macro.variables,
                variables or {},
            )

            replay_steps = []
            for step in macro.steps:
                replay_steps.append(
                    self._build_replay_step(
                        step=step,
                        variables=resolved_variables,
                        dry_run=dry_run,
                    )
                )

            replay_plan = {
                "replay_plan_id": _new_id("replay"),
                "macro_id": macro.macro_id,
                "macro_title": macro.title,
                "user_id": context["user_id"],
                "workspace_id": context["workspace_id"],
                "dry_run": bool(dry_run),
                "direct_execution_performed": False,
                "executor_required": True,
                "requires_security_approval_before_execution": True,
                "requires_human_confirmation": macro.replay_policy.get(
                    "requires_human_confirmation",
                    self.config.default_replay_requires_human_confirmation,
                ),
                "risk": macro.safety.get("risk"),
                "safety": macro.safety,
                "variables": resolved_variables,
                "steps": replay_steps,
                "step_count": len(replay_steps),
                "created_at": _utc_now_iso(),
            }

            result = self._safe_result(
                message="Replay plan prepared. No actions were executed.",
                data={
                    "macro_id": macro.macro_id,
                    "replay_plan": replay_plan,
                    "risk": macro.safety.get("risk"),
                    "step_count": len(replay_steps),
                    "dry_run": bool(dry_run),
                    "executed": False,
                },
                metadata={"action": action},
            )

            result["metadata"]["verification_payload"] = self._prepare_verification_payload(
                action=action,
                result=result,
                task_context=task_context,
            )
            result["metadata"]["memory_payload"] = self._prepare_memory_payload(
                action=action,
                result=result,
                task_context=task_context,
            )

            self._log_audit_event(
                action=action,
                task_context=task_context,
                status="success",
                details={
                    "macro_id": macro.macro_id,
                    "risk": macro.safety.get("risk"),
                    "dry_run": dry_run,
                    "executed": False,
                },
            )

            return result

        except Exception as exc:
            return self._error_result(
                message="Failed to prepare replay plan.",
                error_code="PREPARE_REPLAY_FAILED",
                error=str(exc),
                metadata={"action": action},
            )

    def describe_macro(
        self,
        macro_id: str,
        task_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return a human-readable macro description summary."""
        action = RecorderAction.DESCRIBE_MACRO.value

        context_result = self._validate_task_context(task_context)
        if not context_result.get("success"):
            return context_result
        context = context_result["data"]

        try:
            macro = self._load_macro_for_context(
                user_id=context["user_id"],
                workspace_id=context["workspace_id"],
                macro_id=macro_id,
            )

            lines = [
                f"Macro: {macro.title}",
                f"Description: {macro.description}",
                f"Version: {macro.version}",
                f"Risk: {macro.safety.get('risk', 'unknown')}",
                f"Steps: {len(macro.steps)}",
                "Workflow:",
            ]

            for step in macro.steps[:100]:
                lines.append(
                    f"{step.step_index}. [{step.step_type}] {step.action}"
                    + (f" — {step.description}" if step.description else "")
                )

            if len(macro.steps) > 100:
                lines.append(f"... {len(macro.steps) - 100} more steps")

            return self._safe_result(
                message="Macro description generated.",
                data={
                    "macro_id": macro.macro_id,
                    "title": macro.title,
                    "description_text": "\n".join(lines),
                    "step_count": len(macro.steps),
                    "risk": macro.safety.get("risk"),
                },
                metadata={"action": action},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to describe macro.",
                error_code="DESCRIBE_MACRO_FAILED",
                error=str(exc),
                metadata={"action": action},
            )

    # -----------------------------------------------------------------------
    # Internal session/macro loading
    # -----------------------------------------------------------------------

    def _save_session(self, session: RecordingSession) -> None:
        """Save recording session."""
        path = self._session_path(session.user_id, session.workspace_id, session.session_id)
        self._write_json_atomic(path, session.to_dict())

    def _load_session_for_context(
        self,
        user_id: str,
        workspace_id: str,
        session_id: str,
    ) -> RecordingSession:
        """Load session while enforcing user/workspace isolation."""
        if session_id in self._active_sessions:
            session = self._active_sessions[session_id]
            if session.user_id == user_id and session.workspace_id == workspace_id:
                return session

        path = self._session_path(user_id, workspace_id, session_id)
        session = self._session_from_dict(self._read_json(path))

        if session.user_id != user_id or session.workspace_id != workspace_id:
            raise PermissionError("Session does not belong to this user/workspace.")

        if session.status == SessionStatus.RECORDING.value:
            self._active_sessions[session.session_id] = session

        return session

    def _load_macro_for_context(
        self,
        user_id: str,
        workspace_id: str,
        macro_id: str,
    ) -> MacroDefinition:
        """Load macro while enforcing user/workspace isolation."""
        path = self._macro_path(user_id, workspace_id, macro_id)
        macro = self._macro_from_dict(self._read_json(path))

        if macro.user_id != user_id or macro.workspace_id != workspace_id:
            raise PermissionError("Macro does not belong to this user/workspace.")

        return macro

    def _enforce_session_limit(self, user_id: str, workspace_id: str) -> None:
        """Enforce max sessions per workspace."""
        sessions = list(self._sessions_dir(user_id, workspace_id).glob("*.json"))
        if len(sessions) >= self.config.max_sessions_per_workspace:
            raise RuntimeError(
                f"Session limit reached: {len(sessions)}/{self.config.max_sessions_per_workspace}"
            )

    def _enforce_macro_limit(self, user_id: str, workspace_id: str) -> None:
        """Enforce max macros per workspace."""
        macros = list(self._macros_dir(user_id, workspace_id).glob("*.json"))
        if len(macros) >= self.config.max_macros_per_workspace:
            raise RuntimeError(
                f"Macro limit reached: {len(macros)}/{self.config.max_macros_per_workspace}"
            )

    # -----------------------------------------------------------------------
    # Step sanitization / safety
    # -----------------------------------------------------------------------

    def _validate_step_type(self, step_type: str) -> str:
        """Validate step type."""
        clean = _normalize_action_name(step_type)

        allowed = set(self.config.allowed_step_types)
        if clean not in allowed:
            clean = StepType.CUSTOM.value

        return clean

    def _sanitize_step_payload(
        self,
        description: str,
        target: Dict[str, Any],
        input_data: Dict[str, Any],
        expected_result: Dict[str, Any],
        ocr_text: Optional[str],
        metadata: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Sanitize recorded step payload."""
        payload = {
            "description": _safe_string(description, 2000),
            "target": target,
            "input_data": input_data,
            "expected_result": expected_result,
            "ocr_text": _safe_string(ocr_text, 5000) if ocr_text else None,
            "metadata": metadata,
        }

        if self.config.redact_sensitive_values:
            payload = _redact_sensitive_data(payload)

        return payload

    def _sanitize_timing(self, timing: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize timing payload."""
        clean: Dict[str, Any] = {}

        allowed = {
            "delay_before_ms",
            "delay_after_ms",
            "duration_ms",
            "timeout_ms",
            "recorded_at_ms",
        }

        for key, value in timing.items():
            if key not in allowed:
                continue

            try:
                number = int(float(value))
            except Exception:
                number = 0

            clean[key] = max(0, min(number, 600000))

        if "recorded_at_ms" not in clean:
            clean["recorded_at_ms"] = int(time.time() * 1000)

        return clean

    def _classify_step_safety(
        self,
        step_type: str,
        action_name: str,
        description: str,
        target: Dict[str, Any],
        input_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Classify one step risk."""
        combined = " ".join(
            [
                step_type,
                action_name,
                description,
                json.dumps(target, default=str),
                json.dumps(input_data, default=str),
            ]
        ).lower()

        reasons: List[str] = []
        risk = MacroRisk.LOW.value
        blocked = False

        if step_type in set(self.config.blocked_step_types):
            risk = MacroRisk.BLOCKED.value
            blocked = True
            reasons.append(f"Step type '{step_type}' is blocked by default.")

        high_hits = [kw for kw in self.config.high_risk_keywords if kw.lower() in combined]
        medium_hits = [kw for kw in self.config.medium_risk_keywords if kw.lower() in combined]

        if high_hits and risk != MacroRisk.BLOCKED.value:
            risk = MacroRisk.HIGH.value
            reasons.append(f"High-risk keywords detected: {high_hits[:10]}")

        elif medium_hits and risk == MacroRisk.LOW.value:
            risk = MacroRisk.MEDIUM.value
            reasons.append(f"Medium-risk keywords detected: {medium_hits[:10]}")

        if step_type in {
            StepType.TYPE_TEXT.value,
            StepType.PASTE.value,
            StepType.API_CALL.value,
        }:
            if self._payload_looks_sensitive(input_data):
                if risk != MacroRisk.BLOCKED.value:
                    risk = MacroRisk.HIGH.value
                reasons.append("Input payload may contain sensitive values.")

        return {
            "risk": risk,
            "blocked": blocked,
            "reasons": reasons,
            "requires_security_before_replay": risk in {
                MacroRisk.MEDIUM.value,
                MacroRisk.HIGH.value,
                MacroRisk.BLOCKED.value,
            },
            "requires_human_confirmation": risk in {
                MacroRisk.MEDIUM.value,
                MacroRisk.HIGH.value,
                MacroRisk.BLOCKED.value,
            },
        }

    def _payload_looks_sensitive(self, payload: Any) -> bool:
        """Detect sensitive-looking payload."""
        text = json.dumps(payload, default=str).lower()

        patterns = (
            "password",
            "passwd",
            "pwd",
            "secret",
            "token",
            "api_key",
            "apikey",
            "authorization",
            "cookie",
            "private key",
            "credit card",
            "card number",
            "cvv",
        )

        return any(pattern in text for pattern in patterns)

    def _normalize_steps_for_macro(self, steps: List[RecordedStep]) -> List[RecordedStep]:
        """Normalize step indexes and sanitize before macro compilation."""
        clean_steps: List[RecordedStep] = []

        for index, step in enumerate(steps, start=1):
            step_dict = step.to_dict()
            step_dict["step_index"] = index
            step_dict["step_id"] = step.step_id or _new_id("step")

            clean = self._step_from_dict(step_dict)
            clean.step_type = self._validate_step_type(clean.step_type)
            clean.action = _normalize_action_name(clean.action)

            if self.config.redact_sensitive_values:
                sanitized = self._sanitize_step_payload(
                    description=clean.description,
                    target=clean.target,
                    input_data=clean.input_data,
                    expected_result=clean.expected_result,
                    ocr_text=clean.ocr_text,
                    metadata=clean.metadata,
                )
                clean.description = sanitized["description"]
                clean.target = sanitized["target"]
                clean.input_data = sanitized["input_data"]
                clean.expected_result = sanitized["expected_result"]
                clean.ocr_text = sanitized["ocr_text"]
                clean.metadata = sanitized["metadata"]

            clean.safety = self._classify_step_safety(
                step_type=clean.step_type,
                action_name=clean.action,
                description=clean.description,
                target=clean.target,
                input_data=clean.input_data,
            )

            clean_steps.append(clean)

        return clean_steps

    def _classify_session_safety(self, session: RecordingSession) -> Dict[str, Any]:
        """Classify full recording session safety."""
        return self._classify_steps_safety(session.steps)

    def _classify_steps_safety(self, steps: List[RecordedStep]) -> Dict[str, Any]:
        """Classify macro/session safety from all steps."""
        risks = [step.safety.get("risk", MacroRisk.LOW.value) for step in steps]
        blocked_count = sum(1 for step in steps if step.safety.get("blocked"))
        high_count = sum(1 for risk in risks if risk == MacroRisk.HIGH.value)
        medium_count = sum(1 for risk in risks if risk == MacroRisk.MEDIUM.value)

        if blocked_count > 0:
            overall = MacroRisk.BLOCKED.value
        elif high_count > 0:
            overall = MacroRisk.HIGH.value
        elif medium_count > 0:
            overall = MacroRisk.MEDIUM.value
        else:
            overall = MacroRisk.LOW.value

        reasons: List[str] = []
        for step in steps:
            for reason in step.safety.get("reasons", []) or []:
                if reason not in reasons:
                    reasons.append(reason)

        return {
            "risk": overall,
            "blocked": overall == MacroRisk.BLOCKED.value,
            "step_count": len(steps),
            "blocked_step_count": blocked_count,
            "high_risk_step_count": high_count,
            "medium_risk_step_count": medium_count,
            "low_risk_step_count": sum(1 for risk in risks if risk == MacroRisk.LOW.value),
            "requires_security_before_replay": overall in {
                MacroRisk.MEDIUM.value,
                MacroRisk.HIGH.value,
                MacroRisk.BLOCKED.value,
            },
            "requires_human_confirmation": overall in {
                MacroRisk.MEDIUM.value,
                MacroRisk.HIGH.value,
                MacroRisk.BLOCKED.value,
            },
            "direct_execution_allowed_by_task_recorder": False,
            "reasons": reasons[:100],
        }

    # -----------------------------------------------------------------------
    # Macro validation/replay planning
    # -----------------------------------------------------------------------

    def _build_replay_policy(
        self,
        replay_policy: Dict[str, Any],
        safety: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Build safe replay policy."""
        policy = dict(replay_policy or {})

        policy.setdefault("dry_run_first", True)
        policy.setdefault(
            "requires_human_confirmation",
            self.config.default_replay_requires_human_confirmation
            or safety.get("requires_human_confirmation", True),
        )
        policy.setdefault("requires_security_approval", True)
        policy.setdefault("allow_direct_execution_by_task_recorder", False)
        policy.setdefault("max_replay_steps", self.config.max_steps_per_session)
        policy.setdefault("stop_on_error", True)
        policy.setdefault("record_replay_audit", True)
        policy.setdefault("workspace_isolated", True)

        if safety.get("risk") in {MacroRisk.HIGH.value, MacroRisk.BLOCKED.value}:
            policy["requires_human_confirmation"] = True
            policy["requires_security_approval"] = True

        return policy

    def _calculate_macro_checksum(self, macro: MacroDefinition) -> str:
        """Calculate macro checksum excluding checksum field."""
        data = macro.to_dict()
        data.pop("checksum", None)
        return _json_hash(data)

    def _validate_macro_object(self, macro: MacroDefinition) -> Dict[str, Any]:
        """Validate macro definition for safe storage/replay planning."""
        errors: List[str] = []
        warnings: List[str] = []

        if not macro.macro_id:
            errors.append("Missing macro_id.")

        if not macro.user_id:
            errors.append("Missing user_id.")

        if not macro.workspace_id:
            errors.append("Missing workspace_id.")

        if not macro.title:
            warnings.append("Macro title is empty.")

        if not macro.steps:
            errors.append("Macro has no steps.")

        if len(macro.steps) > self.config.max_steps_per_session:
            errors.append(
                f"Macro exceeds max steps: {len(macro.steps)} > {self.config.max_steps_per_session}"
            )

        for index, step in enumerate(macro.steps, start=1):
            if step.step_index != index:
                warnings.append(f"Step index mismatch at position {index}.")

            if step.step_type not in set(self.config.allowed_step_types):
                warnings.append(f"Unknown step type at step {index}: {step.step_type}")

            if step.step_type in set(self.config.blocked_step_types):
                warnings.append(f"Blocked step type at step {index}: {step.step_type}")

        safety = self._classify_steps_safety(macro.steps)
        risk = safety["risk"]

        if risk == MacroRisk.BLOCKED.value:
            warnings.append("Macro contains blocked steps and cannot be replayed without special review.")

        checksum_expected = self._calculate_macro_checksum(macro)
        checksum_valid = not macro.checksum or macro.checksum == checksum_expected

        if macro.checksum and not checksum_valid:
            warnings.append("Macro checksum does not match current macro contents.")

        valid = len(errors) == 0

        return {
            "valid": valid,
            "errors": errors,
            "warnings": warnings,
            "risk": risk,
            "blocked": risk == MacroRisk.BLOCKED.value,
            "safety": safety,
            "checksum": {
                "provided": macro.checksum,
                "expected": checksum_expected,
                "valid": checksum_valid,
            },
            "step_count": len(macro.steps),
            "macro_id": macro.macro_id,
            "title": macro.title,
        }

    def _sanitize_macro_object(self, macro: MacroDefinition) -> MacroDefinition:
        """Redact sensitive values inside macro."""
        data = _redact_sensitive_data(macro.to_dict())
        return self._macro_from_dict(data)

    def _resolve_macro_variables(
        self,
        defaults: Dict[str, Any],
        overrides: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Resolve macro variables safely."""
        resolved = dict(defaults or {})
        resolved.update(overrides or {})

        if self.config.redact_sensitive_values:
            resolved = _redact_sensitive_data(resolved)

        return resolved

    def _replace_variables_in_value(self, value: Any, variables: Dict[str, Any]) -> Any:
        """
        Replace {{variable}} tokens in strings.

        This keeps replay planning flexible while avoiding execution.
        """
        if isinstance(value, str):
            result = value
            for key, item in variables.items():
                token = "{{" + str(key) + "}}"
                result = result.replace(token, str(item))
            return result

        if isinstance(value, list):
            return [self._replace_variables_in_value(item, variables) for item in value]

        if isinstance(value, dict):
            return {
                key: self._replace_variables_in_value(item, variables)
                for key, item in value.items()
            }

        return value

    def _build_replay_step(
        self,
        step: RecordedStep,
        variables: Dict[str, Any],
        dry_run: bool,
    ) -> Dict[str, Any]:
        """Build one replay-plan step without execution."""
        return {
            "replay_step_id": _new_id("replay_step"),
            "source_step_id": step.step_id,
            "step_index": step.step_index,
            "step_type": step.step_type,
            "action": step.action,
            "description": self._replace_variables_in_value(step.description, variables),
            "target": self._replace_variables_in_value(step.target, variables),
            "input_data": self._replace_variables_in_value(step.input_data, variables),
            "expected_result": self._replace_variables_in_value(step.expected_result, variables),
            "timing": step.timing,
            "safety": step.safety,
            "dry_run": bool(dry_run),
            "execute_by_task_recorder": False,
            "executor_agent_required": True,
            "requires_security_before_execution": step.safety.get(
                "requires_security_before_replay",
                True,
            ),
            "requires_human_confirmation": step.safety.get(
                "requires_human_confirmation",
                True,
            ),
        }

    def _verification_requires_review(self, result: Dict[str, Any]) -> bool:
        """Return whether Verification Agent should review result."""
        if not result.get("success"):
            return True

        data = result.get("data", {}) or {}
        risk = ""

        if isinstance(data, dict):
            risk = str(data.get("risk") or "")
            safety = data.get("safety") or {}
            if isinstance(safety, dict):
                risk = risk or str(safety.get("risk") or "")

            validation = data.get("validation") or {}
            if isinstance(validation, dict):
                risk = risk or str(validation.get("risk") or "")
                if validation.get("blocked"):
                    return True

        return risk in {MacroRisk.MEDIUM.value, MacroRisk.HIGH.value, MacroRisk.BLOCKED.value}

    # -----------------------------------------------------------------------
    # Router entrypoint
    # -----------------------------------------------------------------------

    async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Async entrypoint for Master Agent / Agent Router.

        Example:
            await TaskRecorder().run({
                "action": "start_recording",
                "user_id": "1",
                "workspace_id": "main",
                "permissions": ["task_recorder"],
                "params": {
                    "title": "Login Workflow"
                }
            })
        """
        if not isinstance(task, dict):
            return self._error_result(
                message="TaskRecorder task must be a dict.",
                error_code="INVALID_TASK",
            )

        action = str(task.get("action") or RecorderAction.HEALTH.value)
        params = task.get("params") or {}

        if not isinstance(params, dict):
            return self._error_result(
                message="TaskRecorder params must be a dict.",
                error_code="INVALID_TASK_PARAMS",
                metadata={"action": action},
            )

        task_context = self._extract_task_context(task)

        self._emit_agent_event(
            event_type="task_recorder.task.received",
            task_context=task_context,
            data={"action": action},
        )

        try:
            if action == RecorderAction.HEALTH.value:
                return self.health(task_context=task_context)

            if action == RecorderAction.START_RECORDING.value:
                return self.start_recording(
                    title=str(params.get("title") or "Untitled Recording"),
                    task_context=task_context,
                    tags=params.get("tags") or [],
                    metadata=params.get("metadata") or {},
                )

            if action == RecorderAction.RECORD_STEP.value:
                return self.record_step(
                    session_id=str(params.get("session_id") or ""),
                    step_type=str(params.get("step_type") or StepType.CUSTOM.value),
                    action_name=str(params.get("action_name") or params.get("recorded_action") or "unknown_action"),
                    task_context=task_context,
                    description=str(params.get("description") or ""),
                    target=params.get("target") or {},
                    input_data=params.get("input_data") or {},
                    expected_result=params.get("expected_result") or {},
                    timing=params.get("timing") or {},
                    screenshot_ref=params.get("screenshot_ref"),
                    ocr_text=params.get("ocr_text"),
                    metadata=params.get("metadata") or {},
                )

            if action == RecorderAction.STOP_RECORDING.value:
                return self.stop_recording(
                    session_id=str(params.get("session_id") or ""),
                    task_context=task_context,
                )

            if action == RecorderAction.DISCARD_RECORDING.value:
                return self.discard_recording(
                    session_id=str(params.get("session_id") or ""),
                    task_context=task_context,
                    delete_file=bool(params.get("delete_file", False)),
                )

            if action == RecorderAction.GET_SESSION.value:
                return self.get_session(
                    session_id=str(params.get("session_id") or ""),
                    task_context=task_context,
                    include_steps=bool(params.get("include_steps", True)),
                )

            if action == RecorderAction.LIST_SESSIONS.value:
                return self.list_sessions(
                    task_context=task_context,
                    status=params.get("status"),
                    limit=int(params.get("limit", 100)),
                )

            if action == RecorderAction.COMPILE_MACRO.value:
                return self.compile_macro(
                    session_id=str(params.get("session_id") or ""),
                    task_context=task_context,
                    title=params.get("title"),
                    description=str(params.get("description") or ""),
                    variables=params.get("variables") or {},
                    constraints=params.get("constraints") or {},
                    replay_policy=params.get("replay_policy") or {},
                    tags=params.get("tags") or [],
                )

            if action == RecorderAction.VALIDATE_MACRO.value:
                return self.validate_macro(
                    task_context=task_context,
                    macro_id=params.get("macro_id"),
                    macro=params.get("macro"),
                )

            if action == RecorderAction.SAVE_MACRO.value:
                return self.save_macro(
                    macro=params.get("macro") or {},
                    task_context=task_context,
                    overwrite=bool(params.get("overwrite", False)),
                )

            if action == RecorderAction.GET_MACRO.value:
                return self.get_macro(
                    macro_id=str(params.get("macro_id") or ""),
                    task_context=task_context,
                )

            if action == RecorderAction.LIST_MACROS.value:
                return self.list_macros(
                    task_context=task_context,
                    risk=params.get("risk"),
                    limit=int(params.get("limit", 100)),
                )

            if action == RecorderAction.DELETE_MACRO.value:
                return self.delete_macro(
                    macro_id=str(params.get("macro_id") or ""),
                    task_context=task_context,
                )

            if action == RecorderAction.EXPORT_MACRO.value:
                return self.export_macro(
                    macro_id=str(params.get("macro_id") or ""),
                    task_context=task_context,
                    include_file_path=bool(params.get("include_file_path", True)),
                )

            if action == RecorderAction.IMPORT_MACRO.value:
                return self.import_macro(
                    macro_data=params.get("macro_data") or {},
                    task_context=task_context,
                    overwrite=bool(params.get("overwrite", False)),
                    assign_new_id=bool(params.get("assign_new_id", True)),
                )

            if action == RecorderAction.PREPARE_REPLAY.value:
                return self.prepare_replay(
                    macro_id=str(params.get("macro_id") or ""),
                    task_context=task_context,
                    variables=params.get("variables") or {},
                    dry_run=bool(params.get("dry_run", True)),
                )

            if action == RecorderAction.DESCRIBE_MACRO.value:
                return self.describe_macro(
                    macro_id=str(params.get("macro_id") or ""),
                    task_context=task_context,
                )

            return self._error_result(
                message=f"Unsupported TaskRecorder action: {action}",
                error_code="UNSUPPORTED_ACTION",
                data={"supported_actions": [item.value for item in RecorderAction]},
                metadata={"action": action},
            )

        except Exception as exc:
            self.logger.exception("TaskRecorder run failed")
            return self._error_result(
                message="TaskRecorder task failed.",
                error_code="RUN_FAILED",
                error=str(exc),
                metadata={"action": action},
            )

    def _extract_task_context(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Extract context from router task."""
        context = dict(task.get("context") or {})

        for key in (
            "user_id",
            "workspace_id",
            "request_id",
            "session_id",
            "role",
            "permissions",
        ):
            if key in task and key not in context:
                context[key] = task.get(key)

        if "request_id" not in context or not context.get("request_id"):
            context["request_id"] = _new_id("req")

        return context


# ---------------------------------------------------------------------------
# Standalone safe smoke test
# ---------------------------------------------------------------------------

def _standalone_smoke_test() -> Dict[str, Any]:
    """
    Safe local smoke test.

    Run:
        python agents/system_agent/task_recorder.py
    """
    recorder = TaskRecorder(
        config={
            "require_security_for_recording": False,
            "require_security_for_macro_compile": False,
            "require_security_for_replay_plan": False,
        }
    )

    context = {
        "user_id": "local_test_user",
        "workspace_id": "local_test_workspace",
        "permissions": ["task_recorder"],
    }

    start = recorder.start_recording(
        title="Local Smoke Test Workflow",
        task_context=context,
        tags=["smoke-test"],
    )

    if not start.get("success"):
        return start

    session_id = start["data"]["session_id"]

    step = recorder.record_step(
        session_id=session_id,
        step_type=StepType.NOTE.value,
        action_name="note_manual_step",
        task_context=context,
        description="This is a safe test note step.",
        target={"screen": "test"},
        input_data={},
        expected_result={"status": "noted"},
    )

    if not step.get("success"):
        return step

    stop = recorder.stop_recording(
        session_id=session_id,
        task_context=context,
    )

    if not stop.get("success"):
        return stop

    compiled = recorder.compile_macro(
        session_id=session_id,
        task_context=context,
        title="Local Smoke Test Macro",
        description="Safe local smoke test macro.",
    )

    return {
        "health": recorder.health(task_context=context),
        "start": start,
        "step": step,
        "stop": stop,
        "compiled": compiled,
    }


if __name__ == "__main__":
    print(json.dumps(_standalone_smoke_test(), indent=2, default=str))


"""
Agent/Module: System Agent
File Completed: task_recorder.py
Completion: 88.2%
Completed Files: ['system_agent.py', 'app_controller.py', 'file_manager.py', 'os_commands.py', 'device_controls.py', 'automation.py', 'notification_reader.py', 'message_controller.py', 'call_controller.py', 'permission_guard.py', 'app_profiles.py', 'device_sync.py', 'gesture_control.py', 'desktop_vision.py', 'task_recorder.py']
Remaining Files: ['system_memory.py', 'config.py']
Next Recommended File: agents/system_agent/system_memory.py
FILE COMPLETE
"""