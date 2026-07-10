"""
agents/memory_agent/preference_manager.py

William / Jarvis Multi-Agent AI SaaS System - Digital Promotix

Purpose:
    Stores and manages answer style, code format, design, brand, tone,
    output, and language preferences for SaaS users and workspaces.

Responsibilities:
    - Store user/workspace-specific preferences safely.
    - Prevent preference leakage across users/workspaces.
    - Provide structured JSON/dict-style results.
    - Support dashboard/API integration.
    - Prepare payloads for Memory Agent and Verification Agent.
    - Include compatibility hooks for BaseAgent, Master Agent, Agent Registry,
      Security Agent, Verification Agent, and audit/event pipelines.
    - Remain import-safe even when the full William/Jarvis system is not yet built.

Design Notes:
    This file intentionally uses a safe JSON-backed local storage implementation
    as the default persistence layer. Later, it can be replaced or extended with
    Postgres, Redis, vector memory, encrypted storage, or workspace-level memory
    services without changing the public interface.
"""

from __future__ import annotations

import copy
import json
import logging
import os
import re
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Literal, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Optional William/Jarvis imports with safe fallbacks
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for unfinished project state
    class BaseAgent:  # type: ignore
        """
        Safe fallback BaseAgent.

        This keeps the file import-safe before the real BaseAgent exists.
        The real William/Jarvis BaseAgent can override lifecycle, event,
        registry, and routing behavior later.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())


try:
    from agents.security_agent.security_agent import SecurityAgent  # type: ignore
except Exception:  # pragma: no cover
    SecurityAgent = None  # type: ignore


try:
    from agents.verification_agent.verification_agent import VerificationAgent  # type: ignore
except Exception:  # pragma: no cover
    VerificationAgent = None  # type: ignore


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOGGER = logging.getLogger("william.memory_agent.preference_manager")
if not LOGGER.handlers:
    logging.basicConfig(level=logging.INFO)


# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

PreferenceScope = Literal["user", "workspace", "team", "project", "client", "global"]
PreferenceCategory = Literal[
    "answer_style",
    "code_format",
    "design",
    "brand",
    "language",
    "tone",
    "output",
    "workflow",
    "accessibility",
    "content_rules",
    "agent_behavior",
    "custom",
]

PreferenceVisibility = Literal["private", "workspace", "team", "public"]
PreferenceSensitivity = Literal["low", "medium", "high"]


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_STORAGE_DIR = Path(
    os.getenv(
        "WILLIAM_MEMORY_STORAGE_DIR",
        str(Path.cwd() / ".william_memory" / "preferences"),
    )
)

DEFAULT_STORAGE_FILE = DEFAULT_STORAGE_DIR / "preference_manager.json"

SAFE_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-:.@]+$")

SUPPORTED_CATEGORIES: Tuple[str, ...] = (
    "answer_style",
    "code_format",
    "design",
    "brand",
    "language",
    "tone",
    "output",
    "workflow",
    "accessibility",
    "content_rules",
    "agent_behavior",
    "custom",
)

SENSITIVE_KEYWORDS: Tuple[str, ...] = (
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "credential",
    "auth",
    "session",
    "cookie",
    "bank",
    "card",
    "ssn",
    "cnic",
    "passport",
)

DEFAULT_PREFERENCE_PROFILE: Dict[str, Dict[str, Any]] = {
    "answer_style": {
        "verbosity": "balanced",
        "structure": "clear_sections",
        "explanation_depth": "production_ready",
        "include_examples": True,
        "avoid_filler": True,
        "preferred_response_style": "direct_professional",
    },
    "code_format": {
        "include_full_file": True,
        "include_type_hints": True,
        "include_docstrings": True,
        "include_error_handling": True,
        "include_logging": True,
        "avoid_placeholders": True,
        "safe_imports": True,
        "production_level": True,
        "format": "single_code_block",
    },
    "design": {
        "style": "modern_saas",
        "layout_preference": "dashboard_ready",
        "responsive": True,
        "accessibility": True,
        "brand_consistency": True,
    },
    "brand": {
        "brand_name": "Digital Promotix",
        "voice": "confident_expert_friendly",
        "positioning": "conversion_first_ai_and_digital_growth",
        "avoid_generic_copy": True,
    },
    "language": {
        "primary": "en",
        "secondary": "roman_urdu",
        "auto_match_user_language": True,
        "keep_code_comments_english": True,
    },
    "tone": {
        "default": "professional_warm_confident",
        "sales_copy": "conversion_focused",
        "technical": "clear_precise_production_ready",
    },
    "output": {
        "structured_results": True,
        "include_completion_tracking": True,
        "include_next_step": True,
        "json_compatible": True,
    },
    "workflow": {
        "prefer_best_effort_without_repeated_questions": True,
        "continue_large_files_in_parts_if_needed": True,
        "preserve_user_requested_format": True,
    },
    "accessibility": {
        "plain_language": True,
        "readable_sections": True,
        "avoid_overly_dense_blocks": True,
    },
    "content_rules": {
        "safety_first": True,
        "saas_isolation_first": True,
        "no_hardcoded_secrets": True,
        "no_cross_workspace_leakage": True,
    },
    "agent_behavior": {
        "compatible_with_master_agent": True,
        "compatible_with_registry": True,
        "compatible_with_router": True,
        "prepare_memory_payload": True,
        "prepare_verification_payload": True,
    },
    "custom": {},
}


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class PreferenceContext:
    """
    SaaS task context used to guarantee isolation.

    user_id:
        Required for user-specific preferences.

    workspace_id:
        Required for workspace-specific execution.

    role:
        Optional role for future RBAC integration.

    subscription_tier:
        Optional SaaS plan tier for future feature gating.

    request_id:
        Trace ID for dashboard, audit logs, verification, and event streams.
    """

    user_id: str
    workspace_id: str
    role: Optional[str] = None
    subscription_tier: Optional[str] = None
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source: str = "preference_manager"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PreferenceRecord:
    """
    A single stored preference record.
    """

    preference_id: str
    user_id: str
    workspace_id: str
    category: str
    key: str
    value: Any
    scope: PreferenceScope = "user"
    visibility: PreferenceVisibility = "private"
    sensitivity: PreferenceSensitivity = "low"
    description: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    version: int = 1
    created_at: str = field(default_factory=lambda: utc_now_iso())
    updated_at: str = field(default_factory=lambda: utc_now_iso())
    created_by: Optional[str] = None
    updated_by: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PreferenceProfile:
    """
    Resolved preference profile for an agent, dashboard, API route,
    or Master Agent response-generation step.
    """

    user_id: str
    workspace_id: str
    preferences: Dict[str, Dict[str, Any]]
    source: str = "preference_manager"
    generated_at: str = field(default_factory=lambda: utc_now_iso())
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO format."""
    return datetime.now(timezone.utc).isoformat()


def safe_json_dumps(data: Any) -> str:
    """Serialize data safely for logs/debugging."""
    try:
        return json.dumps(data, ensure_ascii=False, default=str)
    except Exception:
        return str(data)


def deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively merge override into base without mutating either input.
    """
    result = copy.deepcopy(base)
    for key, value in override.items():
        if (
            isinstance(value, dict)
            and isinstance(result.get(key), dict)
        ):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def normalize_category(category: str) -> str:
    """Normalize a preference category."""
    category = (category or "").strip().lower()
    category = category.replace("-", "_").replace(" ", "_")
    return category or "custom"


def is_safe_identifier(value: str) -> bool:
    """Validate user_id/workspace_id/key-style identifiers."""
    if not isinstance(value, str) or not value.strip():
        return False
    return bool(SAFE_ID_PATTERN.match(value.strip()))


def redact_sensitive_value(key: str, value: Any) -> Any:
    """
    Redact sensitive values from logs/events/results where needed.
    Preference values should not store secrets, but this protects logs.
    """
    key_lower = key.lower()
    if any(token in key_lower for token in SENSITIVE_KEYWORDS):
        return "***REDACTED***"
    return value


def infer_sensitivity(key: str, value: Any) -> PreferenceSensitivity:
    """
    Infer sensitivity level from key/value.
    """
    key_lower = str(key).lower()

    if any(token in key_lower for token in SENSITIVE_KEYWORDS):
        return "high"

    value_text = str(value).lower() if isinstance(value, (str, int, float, bool)) else ""
    if any(token in value_text for token in SENSITIVE_KEYWORDS):
        return "medium"

    if key_lower in {"brand", "tone", "language", "style", "format"}:
        return "low"

    return "low"


def make_preference_id(
    user_id: str,
    workspace_id: str,
    category: str,
    key: str,
    scope: PreferenceScope = "user",
) -> str:
    """
    Deterministic ID for idempotent preference upserts.
    """
    raw = f"{scope}:{user_id}:{workspace_id}:{category}:{key}".lower()
    safe = re.sub(r"[^a-zA-Z0-9_\-:.@]+", "_", raw)
    return safe[:240]


# ---------------------------------------------------------------------------
# JSON storage backend
# ---------------------------------------------------------------------------

class PreferenceStorage:
    """
    Simple thread-safe JSON storage backend.

    This is intentionally small and replaceable. A future Postgres/Redis
    implementation can provide the same methods:
        - load_all()
        - save_all(data)
        - upsert(record)
        - delete(preference_id)
    """

    def __init__(self, storage_file: Union[str, Path] = DEFAULT_STORAGE_FILE) -> None:
        self.storage_file = Path(storage_file)
        self.storage_file.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._ensure_file()

    def _ensure_file(self) -> None:
        with self._lock:
            if not self.storage_file.exists():
                self.storage_file.write_text(
                    json.dumps(
                        {
                            "version": 1,
                            "created_at": utc_now_iso(),
                            "updated_at": utc_now_iso(),
                            "records": {},
                        },
                        indent=2,
                    ),
                    encoding="utf-8",
                )

    def load_all(self) -> Dict[str, Any]:
        with self._lock:
            self._ensure_file()
            try:
                raw = self.storage_file.read_text(encoding="utf-8")
                data = json.loads(raw or "{}")
                if not isinstance(data, dict):
                    raise ValueError("Preference storage root must be a dict.")
                data.setdefault("version", 1)
                data.setdefault("created_at", utc_now_iso())
                data.setdefault("updated_at", utc_now_iso())
                data.setdefault("records", {})
                if not isinstance(data["records"], dict):
                    data["records"] = {}
                return data
            except Exception as exc:
                backup_file = self.storage_file.with_suffix(
                    f".corrupt.{int(datetime.now().timestamp())}.json"
                )
                try:
                    self.storage_file.rename(backup_file)
                except Exception:
                    pass

                LOGGER.exception("Preference storage corrupted. Recreated clean file: %s", exc)
                clean = {
                    "version": 1,
                    "created_at": utc_now_iso(),
                    "updated_at": utc_now_iso(),
                    "records": {},
                    "recovered_from_corruption": True,
                }
                self.save_all(clean)
                return clean

    def save_all(self, data: Dict[str, Any]) -> None:
        with self._lock:
            data["updated_at"] = utc_now_iso()
            tmp_file = self.storage_file.with_suffix(".tmp")
            tmp_file.write_text(
                json.dumps(data, ensure_ascii=False, indent=2, default=str),
                encoding="utf-8",
            )
            tmp_file.replace(self.storage_file)

    def upsert(self, record: PreferenceRecord) -> PreferenceRecord:
        with self._lock:
            data = self.load_all()
            records = data.setdefault("records", {})
            records[record.preference_id] = asdict(record)
            self.save_all(data)
            return record

    def delete(self, preference_id: str) -> bool:
        with self._lock:
            data = self.load_all()
            records = data.setdefault("records", {})
            existed = preference_id in records
            if existed:
                del records[preference_id]
                self.save_all(data)
            return existed

    def clear_context(self, user_id: str, workspace_id: str) -> int:
        with self._lock:
            data = self.load_all()
            records = data.setdefault("records", {})
            to_delete = [
                pref_id
                for pref_id, record in records.items()
                if record.get("user_id") == user_id
                and record.get("workspace_id") == workspace_id
            ]
            for pref_id in to_delete:
                del records[pref_id]
            self.save_all(data)
            return len(to_delete)


# ---------------------------------------------------------------------------
# Preference Manager
# ---------------------------------------------------------------------------

class PreferenceManager(BaseAgent):
    """
    Stores answer style, code format, design, brand, and language preferences.

    Master Agent:
        Can call resolve_preference_profile() before generating a response.

    Memory Agent:
        Can use _prepare_memory_payload() to store useful preference updates
        in a long-term memory layer.

    Security Agent:
        Sensitive preference operations can be routed through
        _request_security_approval().

    Verification Agent:
        Any completed preference change can produce a verification payload.

    Dashboard/API:
        Public methods return structured dictionaries with:
        success, message, data, error, metadata.
    """

    agent_name = "PreferenceManager"
    agent_type = "memory_agent_helper"
    version = "1.0.0"

    def __init__(
        self,
        storage_file: Union[str, Path] = DEFAULT_STORAGE_FILE,
        security_agent: Any = None,
        verification_agent: Any = None,
        enable_audit_log: bool = True,
        enable_agent_events: bool = True,
        strict_identifier_validation: bool = True,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            agent_name=self.agent_name,
            agent_id="memory_agent.preference_manager",
            *args,
            **kwargs,
        )

        self.storage = PreferenceStorage(storage_file)
        self.security_agent = security_agent or self._build_optional_security_agent()
        self.verification_agent = verification_agent or self._build_optional_verification_agent()
        self.enable_audit_log = enable_audit_log
        self.enable_agent_events = enable_agent_events
        self.strict_identifier_validation = strict_identifier_validation
        self.logger = LOGGER

    # ------------------------------------------------------------------
    # Optional agent builders
    # ------------------------------------------------------------------

    def _build_optional_security_agent(self) -> Any:
        """Instantiate SecurityAgent if available and safe."""
        if SecurityAgent is None:
            return None
        try:
            return SecurityAgent()
        except Exception:
            return None

    def _build_optional_verification_agent(self) -> Any:
        """Instantiate VerificationAgent if available and safe."""
        if VerificationAgent is None:
            return None
        try:
            return VerificationAgent()
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Required compatibility hooks
    # ------------------------------------------------------------------

    def _safe_result(
        self,
        success: bool = True,
        message: str = "",
        data: Optional[Dict[str, Any]] = None,
        error: Optional[Union[str, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return William/Jarvis standard structured result."""
        return {
            "success": bool(success),
            "message": message or ("Success" if success else "Failed"),
            "data": data or {},
            "error": error,
            "metadata": {
                "agent": self.agent_name,
                "agent_type": self.agent_type,
                "version": self.version,
                "timestamp": utc_now_iso(),
                **(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Union[str, Dict[str, Any], Exception]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standardized error result."""
        if isinstance(error, Exception):
            error_payload: Union[str, Dict[str, Any]] = {
                "type": error.__class__.__name__,
                "detail": str(error),
            }
        elif error is None:
            error_payload = message
        else:
            error_payload = error

        return self._safe_result(
            success=False,
            message=message,
            data={},
            error=error_payload,
            metadata=metadata,
        )

    def _validate_task_context(
        self,
        user_id: Optional[str],
        workspace_id: Optional[str],
        context: Optional[Union[PreferenceContext, Dict[str, Any]]] = None,
    ) -> Tuple[bool, Optional[PreferenceContext], Optional[str]]:
        """
        Validate SaaS context.

        Every preference operation must be isolated by user_id and workspace_id.
        """
        try:
            if isinstance(context, PreferenceContext):
                ctx = context
            elif isinstance(context, dict):
                ctx = PreferenceContext(
                    user_id=str(context.get("user_id") or user_id or "").strip(),
                    workspace_id=str(context.get("workspace_id") or workspace_id or "").strip(),
                    role=context.get("role"),
                    subscription_tier=context.get("subscription_tier"),
                    request_id=context.get("request_id") or str(uuid.uuid4()),
                    source=context.get("source") or "preference_manager",
                    metadata=context.get("metadata") or {},
                )
            else:
                ctx = PreferenceContext(
                    user_id=str(user_id or "").strip(),
                    workspace_id=str(workspace_id or "").strip(),
                )

            if not ctx.user_id:
                return False, None, "Missing required user_id."
            if not ctx.workspace_id:
                return False, None, "Missing required workspace_id."

            if self.strict_identifier_validation:
                if not is_safe_identifier(ctx.user_id):
                    return False, None, "Invalid user_id format."
                if not is_safe_identifier(ctx.workspace_id):
                    return False, None, "Invalid workspace_id format."

            return True, ctx, None
        except Exception as exc:
            return False, None, f"Invalid task context: {exc}"

    def _requires_security_check(
        self,
        action: str,
        category: Optional[str] = None,
        key: Optional[str] = None,
        value: Any = None,
        sensitivity: Optional[PreferenceSensitivity] = None,
        scope: Optional[str] = None,
    ) -> bool:
        """
        Decide whether preference operation requires Security Agent approval.
        """
        action = (action or "").lower()
        category = normalize_category(category or "custom")
        key = (key or "").lower()
        sensitivity = sensitivity or infer_sensitivity(key, value)

        if action in {"clear_all_preferences", "import_preferences", "delete_preference"}:
            return True

        if sensitivity in {"high"}:
            return True

        if scope in {"team", "workspace", "global"} and action in {
            "set_preference",
            "bulk_set_preferences",
        }:
            return True

        if any(token in key for token in SENSITIVE_KEYWORDS):
            return True

        if category in {"content_rules", "agent_behavior"} and action in {
            "set_preference",
            "bulk_set_preferences",
        }:
            return True

        return False

    def _request_security_approval(
        self,
        action: str,
        context: PreferenceContext,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        If no Security Agent exists yet, safe local policy is applied:
        - Deny secret-like preference storage.
        - Allow normal non-destructive operations.
        - Require context for destructive operations.
        """
        payload = payload or {}

        redacted_payload = copy.deepcopy(payload)
        if "key" in redacted_payload and "value" in redacted_payload:
            redacted_payload["value"] = redact_sensitive_value(
                str(redacted_payload["key"]),
                redacted_payload["value"],
            )

        if self.security_agent and hasattr(self.security_agent, "approve_action"):
            try:
                approval = self.security_agent.approve_action(
                    action=action,
                    user_id=context.user_id,
                    workspace_id=context.workspace_id,
                    payload=redacted_payload,
                )
                if isinstance(approval, dict):
                    return approval
                return {
                    "approved": bool(approval),
                    "message": "Security approval completed.",
                    "metadata": {"source": "security_agent"},
                }
            except Exception as exc:
                self.logger.exception("Security approval failed: %s", exc)
                return {
                    "approved": False,
                    "message": "Security Agent approval failed.",
                    "error": str(exc),
                    "metadata": {"source": "security_agent"},
                }

        key = str(payload.get("key", "")).lower()
        sensitivity = payload.get("sensitivity") or infer_sensitivity(
            key,
            payload.get("value"),
        )

        if sensitivity == "high" or any(token in key for token in SENSITIVE_KEYWORDS):
            return {
                "approved": False,
                "message": "Preference appears sensitive and should not be stored here.",
                "metadata": {"source": "local_policy"},
            }

        return {
            "approved": True,
            "message": "Approved by local safe preference policy.",
            "metadata": {"source": "local_policy"},
        }

    def _prepare_verification_payload(
        self,
        action: str,
        context: PreferenceContext,
        result_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent-compatible payload.
        """
        return {
            "verification_type": "preference_operation",
            "agent": self.agent_name,
            "action": action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "result_data": result_data or {},
            "checks": {
                "saas_isolation": True,
                "structured_result": True,
                "no_secret_storage": True,
                "timestamp_present": True,
            },
            "created_at": utc_now_iso(),
        }

    def _prepare_memory_payload(
        self,
        action: str,
        context: PreferenceContext,
        preference_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent-compatible payload.
        """
        return {
            "memory_type": "preference",
            "memory_layer": "long_term",
            "agent": self.agent_name,
            "action": action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "content": preference_data or {},
            "importance": "medium",
            "privacy": "user_workspace_isolated",
            "created_at": utc_now_iso(),
            "metadata": {
                "request_id": context.request_id,
                "source": context.source,
            },
        }

    def _emit_agent_event(
        self,
        event_name: str,
        context: PreferenceContext,
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Emit internal event for future dashboard, analytics, or agent bus.

        This safe implementation logs only. A future event bus can override it.
        """
        if not self.enable_agent_events:
            return

        try:
            safe_payload = copy.deepcopy(payload or {})
            if "key" in safe_payload and "value" in safe_payload:
                safe_payload["value"] = redact_sensitive_value(
                    str(safe_payload["key"]),
                    safe_payload["value"],
                )

            self.logger.info(
                "Agent event: %s | user=%s workspace=%s payload=%s",
                event_name,
                context.user_id,
                context.workspace_id,
                safe_json_dumps(safe_payload),
            )
        except Exception:
            self.logger.exception("Failed to emit agent event.")

    def _log_audit_event(
        self,
        action: str,
        context: PreferenceContext,
        payload: Optional[Dict[str, Any]] = None,
        success: bool = True,
        error: Optional[str] = None,
    ) -> None:
        """
        Log audit event.

        Later this can be redirected to dashboard analytics or a database.
        """
        if not self.enable_audit_log:
            return

        try:
            safe_payload = copy.deepcopy(payload or {})
            if "key" in safe_payload and "value" in safe_payload:
                safe_payload["value"] = redact_sensitive_value(
                    str(safe_payload["key"]),
                    safe_payload["value"],
                )

            log_data = {
                "action": action,
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
                "request_id": context.request_id,
                "success": success,
                "error": error,
                "payload": safe_payload,
                "timestamp": utc_now_iso(),
            }
            self.logger.info("Preference audit: %s", safe_json_dumps(log_data))
        except Exception:
            self.logger.exception("Failed to log audit event.")

    # ------------------------------------------------------------------
    # Validation helpers
    # ------------------------------------------------------------------

    def _validate_category(self, category: str) -> Tuple[bool, str, Optional[str]]:
        normalized = normalize_category(category)
        if normalized not in SUPPORTED_CATEGORIES:
            return (
                False,
                normalized,
                f"Unsupported category '{category}'. Supported categories: {list(SUPPORTED_CATEGORIES)}",
            )
        return True, normalized, None

    def _validate_key(self, key: str) -> Tuple[bool, str, Optional[str]]:
        normalized = str(key or "").strip()
        if not normalized:
            return False, "", "Preference key is required."
        if len(normalized) > 120:
            return False, normalized, "Preference key is too long."
        if self.strict_identifier_validation and not re.match(r"^[a-zA-Z0-9_\-:. ]+$", normalized):
            return False, normalized, "Preference key contains unsupported characters."
        return True, normalized, None

    def _validate_value(self, key: str, value: Any) -> Tuple[bool, Optional[str]]:
        if value is None:
            return False, "Preference value cannot be None."

        try:
            json.dumps(value, default=str)
        except Exception:
            return False, "Preference value must be JSON-serializable."

        value_size = len(safe_json_dumps(value))
        if value_size > 25000:
            return False, "Preference value is too large."

        sensitivity = infer_sensitivity(key, value)
        if sensitivity == "high":
            return False, "Sensitive secrets or credentials cannot be stored as preferences."

        return True, None

    def _record_from_dict(self, data: Dict[str, Any]) -> PreferenceRecord:
        return PreferenceRecord(
            preference_id=data["preference_id"],
            user_id=data["user_id"],
            workspace_id=data["workspace_id"],
            category=data["category"],
            key=data["key"],
            value=data.get("value"),
            scope=data.get("scope", "user"),
            visibility=data.get("visibility", "private"),
            sensitivity=data.get("sensitivity", "low"),
            description=data.get("description"),
            tags=list(data.get("tags") or []),
            version=int(data.get("version") or 1),
            created_at=data.get("created_at") or utc_now_iso(),
            updated_at=data.get("updated_at") or utc_now_iso(),
            created_by=data.get("created_by"),
            updated_by=data.get("updated_by"),
            metadata=data.get("metadata") or {},
        )

    # ------------------------------------------------------------------
    # Public API methods
    # ------------------------------------------------------------------

    def set_preference(
        self,
        user_id: str,
        workspace_id: str,
        category: str,
        key: str,
        value: Any,
        scope: PreferenceScope = "user",
        visibility: PreferenceVisibility = "private",
        description: Optional[str] = None,
        tags: Optional[List[str]] = None,
        context: Optional[Union[PreferenceContext, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create or update one preference.

        Example:
            manager.set_preference(
                user_id="u_1",
                workspace_id="w_1",
                category="answer_style",
                key="verbosity",
                value="concise"
            )
        """
        valid_ctx, ctx, ctx_error = self._validate_task_context(user_id, workspace_id, context)
        if not valid_ctx or ctx is None:
            return self._error_result("Invalid task context.", ctx_error)

        try:
            valid_category, normalized_category, category_error = self._validate_category(category)
            if not valid_category:
                return self._error_result("Invalid preference category.", category_error)

            valid_key, normalized_key, key_error = self._validate_key(key)
            if not valid_key:
                return self._error_result("Invalid preference key.", key_error)

            valid_value, value_error = self._validate_value(normalized_key, value)
            if not valid_value:
                return self._error_result("Invalid preference value.", value_error)

            sensitivity = infer_sensitivity(normalized_key, value)

            payload = {
                "category": normalized_category,
                "key": normalized_key,
                "value": value,
                "scope": scope,
                "visibility": visibility,
                "sensitivity": sensitivity,
            }

            if self._requires_security_check(
                action="set_preference",
                category=normalized_category,
                key=normalized_key,
                value=value,
                sensitivity=sensitivity,
                scope=scope,
            ):
                approval = self._request_security_approval("set_preference", ctx, payload)
                if not approval.get("approved"):
                    self._log_audit_event(
                        "set_preference",
                        ctx,
                        payload,
                        success=False,
                        error=approval.get("message"),
                    )
                    return self._error_result(
                        "Security approval denied for preference update.",
                        approval,
                    )

            preference_id = make_preference_id(
                ctx.user_id,
                ctx.workspace_id,
                normalized_category,
                normalized_key,
                scope,
            )

            existing = self._get_record_by_id(preference_id)
            if existing:
                record = existing
                record.value = value
                record.visibility = visibility
                record.sensitivity = sensitivity
                record.description = description if description is not None else record.description
                record.tags = tags if tags is not None else record.tags
                record.version += 1
                record.updated_at = utc_now_iso()
                record.updated_by = ctx.user_id
                record.metadata = deep_merge(record.metadata, metadata or {})
            else:
                record = PreferenceRecord(
                    preference_id=preference_id,
                    user_id=ctx.user_id,
                    workspace_id=ctx.workspace_id,
                    category=normalized_category,
                    key=normalized_key,
                    value=value,
                    scope=scope,
                    visibility=visibility,
                    sensitivity=sensitivity,
                    description=description,
                    tags=tags or [],
                    created_by=ctx.user_id,
                    updated_by=ctx.user_id,
                    metadata=metadata or {},
                )

            self.storage.upsert(record)

            record_data = asdict(record)
            record_data["value"] = redact_sensitive_value(record.key, record.value)

            memory_payload = self._prepare_memory_payload(
                "set_preference",
                ctx,
                record_data,
            )
            verification_payload = self._prepare_verification_payload(
                "set_preference",
                ctx,
                {"preference_id": preference_id, "category": normalized_category, "key": normalized_key},
            )

            self._emit_agent_event("preference.updated", ctx, record_data)
            self._log_audit_event("set_preference", ctx, record_data, success=True)

            return self._safe_result(
                success=True,
                message="Preference saved successfully.",
                data={
                    "preference": record_data,
                    "memory_payload": memory_payload,
                    "verification_payload": verification_payload,
                },
                metadata={
                    "request_id": ctx.request_id,
                    "category": normalized_category,
                    "key": normalized_key,
                    "scope": scope,
                },
            )

        except Exception as exc:
            self.logger.exception("Failed to set preference.")
            self._log_audit_event(
                "set_preference",
                ctx,
                {"category": category, "key": key},
                success=False,
                error=str(exc),
            )
            return self._error_result("Failed to set preference.", exc)

    def bulk_set_preferences(
        self,
        user_id: str,
        workspace_id: str,
        preferences: Dict[str, Dict[str, Any]],
        scope: PreferenceScope = "user",
        visibility: PreferenceVisibility = "private",
        context: Optional[Union[PreferenceContext, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Set multiple preferences.

        preferences format:
            {
                "answer_style": {
                    "verbosity": "concise",
                    "include_examples": true
                },
                "brand": {
                    "brand_name": "Digital Promotix"
                }
            }
        """
        valid_ctx, ctx, ctx_error = self._validate_task_context(user_id, workspace_id, context)
        if not valid_ctx or ctx is None:
            return self._error_result("Invalid task context.", ctx_error)

        if not isinstance(preferences, dict) or not preferences:
            return self._error_result("Preferences must be a non-empty dictionary.")

        saved: List[Dict[str, Any]] = []
        failed: List[Dict[str, Any]] = []

        for category, category_values in preferences.items():
            if not isinstance(category_values, dict):
                failed.append(
                    {
                        "category": category,
                        "error": "Category value must be a dictionary.",
                    }
                )
                continue

            for key, value in category_values.items():
                result = self.set_preference(
                    user_id=ctx.user_id,
                    workspace_id=ctx.workspace_id,
                    category=category,
                    key=key,
                    value=value,
                    scope=scope,
                    visibility=visibility,
                    context=ctx,
                    metadata=metadata,
                )
                if result.get("success"):
                    saved.append(result["data"]["preference"])
                else:
                    failed.append(
                        {
                            "category": category,
                            "key": key,
                            "error": result.get("error"),
                        }
                    )

        success = len(failed) == 0
        self._emit_agent_event(
            "preferences.bulk_updated",
            ctx,
            {"saved_count": len(saved), "failed_count": len(failed)},
        )

        return self._safe_result(
            success=success,
            message=(
                "All preferences saved successfully."
                if success
                else "Some preferences could not be saved."
            ),
            data={
                "saved": saved,
                "failed": failed,
                "saved_count": len(saved),
                "failed_count": len(failed),
                "verification_payload": self._prepare_verification_payload(
                    "bulk_set_preferences",
                    ctx,
                    {"saved_count": len(saved), "failed_count": len(failed)},
                ),
            },
            metadata={"request_id": ctx.request_id},
        )

    def get_preference(
        self,
        user_id: str,
        workspace_id: str,
        category: str,
        key: str,
        scope: PreferenceScope = "user",
        include_metadata: bool = True,
        context: Optional[Union[PreferenceContext, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Get one preference by category/key.
        """
        valid_ctx, ctx, ctx_error = self._validate_task_context(user_id, workspace_id, context)
        if not valid_ctx or ctx is None:
            return self._error_result("Invalid task context.", ctx_error)

        try:
            valid_category, normalized_category, category_error = self._validate_category(category)
            if not valid_category:
                return self._error_result("Invalid preference category.", category_error)

            valid_key, normalized_key, key_error = self._validate_key(key)
            if not valid_key:
                return self._error_result("Invalid preference key.", key_error)

            preference_id = make_preference_id(
                ctx.user_id,
                ctx.workspace_id,
                normalized_category,
                normalized_key,
                scope,
            )
            record = self._get_record_by_id(preference_id)

            if not record:
                default_value = DEFAULT_PREFERENCE_PROFILE.get(normalized_category, {}).get(normalized_key)
                return self._safe_result(
                    success=True,
                    message="Preference not found. Returned default value if available.",
                    data={
                        "preference": None,
                        "value": default_value,
                        "is_default": True,
                    },
                    metadata={
                        "request_id": ctx.request_id,
                        "category": normalized_category,
                        "key": normalized_key,
                    },
                )

            record_data = asdict(record)
            if record.sensitivity != "low":
                record_data["value"] = redact_sensitive_value(record.key, record.value)

            if not include_metadata:
                record_data.pop("metadata", None)

            return self._safe_result(
                success=True,
                message="Preference retrieved successfully.",
                data={
                    "preference": record_data,
                    "value": record.value if record.sensitivity == "low" else record_data["value"],
                    "is_default": False,
                },
                metadata={
                    "request_id": ctx.request_id,
                    "category": normalized_category,
                    "key": normalized_key,
                },
            )

        except Exception as exc:
            self.logger.exception("Failed to get preference.")
            return self._error_result("Failed to get preference.", exc)

    def get_preferences(
        self,
        user_id: str,
        workspace_id: str,
        category: Optional[str] = None,
        scope: Optional[PreferenceScope] = None,
        include_defaults: bool = True,
        include_records: bool = False,
        context: Optional[Union[PreferenceContext, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Get resolved preferences for a user/workspace.

        Returns category-grouped preferences:
            {
                "answer_style": {"verbosity": "balanced"},
                "brand": {"brand_name": "Digital Promotix"}
            }
        """
        valid_ctx, ctx, ctx_error = self._validate_task_context(user_id, workspace_id, context)
        if not valid_ctx or ctx is None:
            return self._error_result("Invalid task context.", ctx_error)

        try:
            normalized_category = normalize_category(category) if category else None
            if normalized_category:
                valid_category, normalized_category, category_error = self._validate_category(normalized_category)
                if not valid_category:
                    return self._error_result("Invalid preference category.", category_error)

            records = self._list_records(
                user_id=ctx.user_id,
                workspace_id=ctx.workspace_id,
                category=normalized_category,
                scope=scope,
            )

            resolved: Dict[str, Dict[str, Any]] = (
                copy.deepcopy(DEFAULT_PREFERENCE_PROFILE) if include_defaults else {}
            )

            for record in records:
                resolved.setdefault(record.category, {})
                resolved[record.category][record.key] = record.value

            if normalized_category:
                resolved = {
                    normalized_category: resolved.get(normalized_category, {})
                }

            record_payload = []
            if include_records:
                for record in records:
                    item = asdict(record)
                    if record.sensitivity != "low":
                        item["value"] = redact_sensitive_value(record.key, record.value)
                    record_payload.append(item)

            profile = PreferenceProfile(
                user_id=ctx.user_id,
                workspace_id=ctx.workspace_id,
                preferences=resolved,
                metadata={
                    "include_defaults": include_defaults,
                    "category": normalized_category,
                    "scope": scope,
                    "record_count": len(records),
                },
            )

            return self._safe_result(
                success=True,
                message="Preferences retrieved successfully.",
                data={
                    "profile": asdict(profile),
                    "preferences": resolved,
                    "records": record_payload,
                    "record_count": len(records),
                },
                metadata={"request_id": ctx.request_id},
            )

        except Exception as exc:
            self.logger.exception("Failed to get preferences.")
            return self._error_result("Failed to get preferences.", exc)

    def resolve_preference_profile(
        self,
        user_id: str,
        workspace_id: str,
        agent_name: Optional[str] = None,
        task_type: Optional[str] = None,
        context: Optional[Union[PreferenceContext, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Resolve final preference profile for Master Agent routing or response generation.

        This method merges:
            - system defaults
            - stored user/workspace preferences
            - small task-aware metadata
        """
        result = self.get_preferences(
            user_id=user_id,
            workspace_id=workspace_id,
            include_defaults=True,
            include_records=False,
            context=context,
        )

        if not result.get("success"):
            return result

        preferences = result["data"]["preferences"]

        response_profile = {
            "answer_style": preferences.get("answer_style", {}),
            "code_format": preferences.get("code_format", {}),
            "design": preferences.get("design", {}),
            "brand": preferences.get("brand", {}),
            "language": preferences.get("language", {}),
            "tone": preferences.get("tone", {}),
            "output": preferences.get("output", {}),
            "workflow": preferences.get("workflow", {}),
            "content_rules": preferences.get("content_rules", {}),
            "agent_behavior": preferences.get("agent_behavior", {}),
            "resolved_for": {
                "agent_name": agent_name,
                "task_type": task_type,
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        }

        return self._safe_result(
            success=True,
            message="Preference profile resolved successfully.",
            data={
                "response_profile": response_profile,
                "preferences": preferences,
            },
            metadata={
                "agent_name": agent_name,
                "task_type": task_type,
            },
        )

    def delete_preference(
        self,
        user_id: str,
        workspace_id: str,
        category: str,
        key: str,
        scope: PreferenceScope = "user",
        context: Optional[Union[PreferenceContext, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Delete one preference.
        """
        valid_ctx, ctx, ctx_error = self._validate_task_context(user_id, workspace_id, context)
        if not valid_ctx or ctx is None:
            return self._error_result("Invalid task context.", ctx_error)

        try:
            valid_category, normalized_category, category_error = self._validate_category(category)
            if not valid_category:
                return self._error_result("Invalid preference category.", category_error)

            valid_key, normalized_key, key_error = self._validate_key(key)
            if not valid_key:
                return self._error_result("Invalid preference key.", key_error)

            payload = {
                "category": normalized_category,
                "key": normalized_key,
                "scope": scope,
            }

            if self._requires_security_check(
                action="delete_preference",
                category=normalized_category,
                key=normalized_key,
                scope=scope,
            ):
                approval = self._request_security_approval("delete_preference", ctx, payload)
                if not approval.get("approved"):
                    return self._error_result(
                        "Security approval denied for preference deletion.",
                        approval,
                    )

            preference_id = make_preference_id(
                ctx.user_id,
                ctx.workspace_id,
                normalized_category,
                normalized_key,
                scope,
            )
            deleted = self.storage.delete(preference_id)

            self._emit_agent_event(
                "preference.deleted",
                ctx,
                {"preference_id": preference_id, "deleted": deleted},
            )
            self._log_audit_event(
                "delete_preference",
                ctx,
                {"preference_id": preference_id, "deleted": deleted},
                success=True,
            )

            return self._safe_result(
                success=True,
                message="Preference deleted successfully." if deleted else "Preference did not exist.",
                data={
                    "deleted": deleted,
                    "preference_id": preference_id,
                    "verification_payload": self._prepare_verification_payload(
                        "delete_preference",
                        ctx,
                        {"preference_id": preference_id, "deleted": deleted},
                    ),
                },
                metadata={"request_id": ctx.request_id},
            )

        except Exception as exc:
            self.logger.exception("Failed to delete preference.")
            return self._error_result("Failed to delete preference.", exc)

    def clear_preferences(
        self,
        user_id: str,
        workspace_id: str,
        context: Optional[Union[PreferenceContext, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Clear all preferences for one user/workspace only.
        """
        valid_ctx, ctx, ctx_error = self._validate_task_context(user_id, workspace_id, context)
        if not valid_ctx or ctx is None:
            return self._error_result("Invalid task context.", ctx_error)

        try:
            approval = self._request_security_approval(
                "clear_all_preferences",
                ctx,
                {"user_id": ctx.user_id, "workspace_id": ctx.workspace_id},
            )
            if not approval.get("approved"):
                return self._error_result(
                    "Security approval denied for clearing preferences.",
                    approval,
                )

            deleted_count = self.storage.clear_context(ctx.user_id, ctx.workspace_id)

            self._emit_agent_event(
                "preferences.cleared",
                ctx,
                {"deleted_count": deleted_count},
            )
            self._log_audit_event(
                "clear_preferences",
                ctx,
                {"deleted_count": deleted_count},
                success=True,
            )

            return self._safe_result(
                success=True,
                message="Preferences cleared for this user/workspace.",
                data={
                    "deleted_count": deleted_count,
                    "verification_payload": self._prepare_verification_payload(
                        "clear_preferences",
                        ctx,
                        {"deleted_count": deleted_count},
                    ),
                },
                metadata={"request_id": ctx.request_id},
            )

        except Exception as exc:
            self.logger.exception("Failed to clear preferences.")
            return self._error_result("Failed to clear preferences.", exc)

    def export_preferences(
        self,
        user_id: str,
        workspace_id: str,
        include_defaults: bool = True,
        context: Optional[Union[PreferenceContext, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Export preferences for dashboard/API backup or user data portability.
        """
        result = self.get_preferences(
            user_id=user_id,
            workspace_id=workspace_id,
            include_defaults=include_defaults,
            include_records=True,
            context=context,
        )
        if not result.get("success"):
            return result

        export_payload = {
            "export_id": str(uuid.uuid4()),
            "user_id": user_id,
            "workspace_id": workspace_id,
            "exported_at": utc_now_iso(),
            "include_defaults": include_defaults,
            "preferences": result["data"]["preferences"],
            "records": result["data"]["records"],
            "schema_version": 1,
        }

        return self._safe_result(
            success=True,
            message="Preferences exported successfully.",
            data={"export": export_payload},
        )

    def import_preferences(
        self,
        user_id: str,
        workspace_id: str,
        preferences: Dict[str, Dict[str, Any]],
        overwrite: bool = True,
        scope: PreferenceScope = "user",
        visibility: PreferenceVisibility = "private",
        context: Optional[Union[PreferenceContext, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Import preferences from a category/key dictionary.

        This does not accept secrets and remains user/workspace-isolated.
        """
        valid_ctx, ctx, ctx_error = self._validate_task_context(user_id, workspace_id, context)
        if not valid_ctx or ctx is None:
            return self._error_result("Invalid task context.", ctx_error)

        approval = self._request_security_approval(
            "import_preferences",
            ctx,
            {
                "category_count": len(preferences) if isinstance(preferences, dict) else 0,
                "overwrite": overwrite,
                "scope": scope,
            },
        )
        if not approval.get("approved"):
            return self._error_result("Security approval denied for preference import.", approval)

        if overwrite:
            clear_result = self.clear_preferences(ctx.user_id, ctx.workspace_id, context=ctx)
            if not clear_result.get("success"):
                return clear_result

        return self.bulk_set_preferences(
            user_id=ctx.user_id,
            workspace_id=ctx.workspace_id,
            preferences=preferences,
            scope=scope,
            visibility=visibility,
            context=ctx,
            metadata={"imported": True, "overwrite": overwrite},
        )

    def list_categories(self) -> Dict[str, Any]:
        """
        List supported preference categories.
        """
        return self._safe_result(
            success=True,
            message="Supported preference categories retrieved.",
            data={
                "categories": list(SUPPORTED_CATEGORIES),
                "default_profile": copy.deepcopy(DEFAULT_PREFERENCE_PROFILE),
            },
        )

    def get_default_profile(self) -> Dict[str, Any]:
        """
        Return default William/Jarvis preference profile.
        """
        return self._safe_result(
            success=True,
            message="Default preference profile retrieved.",
            data={"default_profile": copy.deepcopy(DEFAULT_PREFERENCE_PROFILE)},
        )

    def apply_default_digital_promotix_profile(
        self,
        user_id: str,
        workspace_id: str,
        context: Optional[Union[PreferenceContext, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Apply Digital Promotix production defaults.

        Useful when onboarding a workspace or creating a new SaaS user.
        """
        profile = copy.deepcopy(DEFAULT_PREFERENCE_PROFILE)
        return self.bulk_set_preferences(
            user_id=user_id,
            workspace_id=workspace_id,
            preferences=profile,
            scope="user",
            visibility="private",
            context=context,
            metadata={"preset": "digital_promotix_default"},
        )

    # ------------------------------------------------------------------
    # Internal query helpers
    # ------------------------------------------------------------------

    def _get_record_by_id(self, preference_id: str) -> Optional[PreferenceRecord]:
        data = self.storage.load_all()
        record_data = data.get("records", {}).get(preference_id)
        if not record_data:
            return None
        try:
            return self._record_from_dict(record_data)
        except Exception:
            self.logger.exception("Invalid preference record found: %s", preference_id)
            return None

    def _list_records(
        self,
        user_id: str,
        workspace_id: str,
        category: Optional[str] = None,
        scope: Optional[PreferenceScope] = None,
    ) -> List[PreferenceRecord]:
        data = self.storage.load_all()
        records: List[PreferenceRecord] = []

        for record_data in data.get("records", {}).values():
            try:
                record = self._record_from_dict(record_data)
            except Exception:
                continue

            if record.user_id != user_id:
                continue
            if record.workspace_id != workspace_id:
                continue
            if category and record.category != category:
                continue
            if scope and record.scope != scope:
                continue

            records.append(record)

        records.sort(key=lambda item: (item.category, item.key, item.updated_at))
        return records

    # ------------------------------------------------------------------
    # Convenience methods for common preference groups
    # ------------------------------------------------------------------

    def set_answer_style(
        self,
        user_id: str,
        workspace_id: str,
        verbosity: Optional[str] = None,
        structure: Optional[str] = None,
        explanation_depth: Optional[str] = None,
        include_examples: Optional[bool] = None,
        context: Optional[Union[PreferenceContext, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Convenience method for answer style preferences.
        """
        prefs: Dict[str, Any] = {}
        if verbosity is not None:
            prefs["verbosity"] = verbosity
        if structure is not None:
            prefs["structure"] = structure
        if explanation_depth is not None:
            prefs["explanation_depth"] = explanation_depth
        if include_examples is not None:
            prefs["include_examples"] = include_examples

        if not prefs:
            return self._error_result("No answer style preferences provided.")

        return self.bulk_set_preferences(
            user_id=user_id,
            workspace_id=workspace_id,
            preferences={"answer_style": prefs},
            context=context,
        )

    def set_code_format(
        self,
        user_id: str,
        workspace_id: str,
        include_full_file: Optional[bool] = None,
        include_type_hints: Optional[bool] = None,
        include_docstrings: Optional[bool] = None,
        include_error_handling: Optional[bool] = None,
        format: Optional[str] = None,
        context: Optional[Union[PreferenceContext, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Convenience method for code output preferences.
        """
        prefs: Dict[str, Any] = {}
        if include_full_file is not None:
            prefs["include_full_file"] = include_full_file
        if include_type_hints is not None:
            prefs["include_type_hints"] = include_type_hints
        if include_docstrings is not None:
            prefs["include_docstrings"] = include_docstrings
        if include_error_handling is not None:
            prefs["include_error_handling"] = include_error_handling
        if format is not None:
            prefs["format"] = format

        if not prefs:
            return self._error_result("No code format preferences provided.")

        return self.bulk_set_preferences(
            user_id=user_id,
            workspace_id=workspace_id,
            preferences={"code_format": prefs},
            context=context,
        )

    def set_brand_preferences(
        self,
        user_id: str,
        workspace_id: str,
        brand_name: Optional[str] = None,
        voice: Optional[str] = None,
        positioning: Optional[str] = None,
        avoid_generic_copy: Optional[bool] = None,
        context: Optional[Union[PreferenceContext, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Convenience method for brand preferences.
        """
        prefs: Dict[str, Any] = {}
        if brand_name is not None:
            prefs["brand_name"] = brand_name
        if voice is not None:
            prefs["voice"] = voice
        if positioning is not None:
            prefs["positioning"] = positioning
        if avoid_generic_copy is not None:
            prefs["avoid_generic_copy"] = avoid_generic_copy

        if not prefs:
            return self._error_result("No brand preferences provided.")

        return self.bulk_set_preferences(
            user_id=user_id,
            workspace_id=workspace_id,
            preferences={"brand": prefs},
            context=context,
        )

    def set_language_preferences(
        self,
        user_id: str,
        workspace_id: str,
        primary: Optional[str] = None,
        secondary: Optional[str] = None,
        auto_match_user_language: Optional[bool] = None,
        keep_code_comments_english: Optional[bool] = None,
        context: Optional[Union[PreferenceContext, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Convenience method for language preferences.
        """
        prefs: Dict[str, Any] = {}
        if primary is not None:
            prefs["primary"] = primary
        if secondary is not None:
            prefs["secondary"] = secondary
        if auto_match_user_language is not None:
            prefs["auto_match_user_language"] = auto_match_user_language
        if keep_code_comments_english is not None:
            prefs["keep_code_comments_english"] = keep_code_comments_english

        if not prefs:
            return self._error_result("No language preferences provided.")

        return self.bulk_set_preferences(
            user_id=user_id,
            workspace_id=workspace_id,
            preferences={"language": prefs},
            context=context,
        )

    # ------------------------------------------------------------------
    # Registry / loader compatibility
    # ------------------------------------------------------------------

    def get_agent_manifest(self) -> Dict[str, Any]:
        """
        Return Agent Registry-compatible manifest.
        """
        return {
            "agent_name": self.agent_name,
            "agent_type": self.agent_type,
            "version": self.version,
            "module": "agents.memory_agent.preference_manager",
            "class": "PreferenceManager",
            "description": "Stores answer style, code format, design, brand, language, and output preferences.",
            "public_methods": [
                "set_preference",
                "bulk_set_preferences",
                "get_preference",
                "get_preferences",
                "resolve_preference_profile",
                "delete_preference",
                "clear_preferences",
                "export_preferences",
                "import_preferences",
                "list_categories",
                "get_default_profile",
                "apply_default_digital_promotix_profile",
                "set_answer_style",
                "set_code_format",
                "set_brand_preferences",
                "set_language_preferences",
            ],
            "requires": {
                "user_id": True,
                "workspace_id": True,
                "security_agent": "optional",
                "verification_agent": "optional",
                "memory_agent": "compatible_payloads",
            },
            "safety": {
                "saas_isolation": True,
                "no_secret_storage": True,
                "security_check_for_sensitive_or_destructive_actions": True,
                "structured_results": True,
            },
            "storage": {
                "default_backend": "json_file",
                "storage_file": str(self.storage.storage_file),
                "replaceable": True,
            },
        }

    def health_check(self) -> Dict[str, Any]:
        """
        Basic health check for dashboard/API readiness.
        """
        try:
            data = self.storage.load_all()
            record_count = len(data.get("records", {}))
            return self._safe_result(
                success=True,
                message="PreferenceManager is healthy.",
                data={
                    "storage_file": str(self.storage.storage_file),
                    "record_count": record_count,
                    "supported_categories": list(SUPPORTED_CATEGORIES),
                    "security_agent_available": self.security_agent is not None,
                    "verification_agent_available": self.verification_agent is not None,
                },
            )
        except Exception as exc:
            return self._error_result("PreferenceManager health check failed.", exc)


# ---------------------------------------------------------------------------
# Standalone smoke test
# ---------------------------------------------------------------------------

def _smoke_test() -> Dict[str, Any]:
    """
    Lightweight local test.

    Run:
        python agents/memory_agent/preference_manager.py
    """
    manager = PreferenceManager(
        storage_file=DEFAULT_STORAGE_DIR / "preference_manager_smoke_test.json"
    )

    user_id = "test_user"
    workspace_id = "test_workspace"

    set_result = manager.set_preference(
        user_id=user_id,
        workspace_id=workspace_id,
        category="answer_style",
        key="verbosity",
        value="concise",
    )

    get_result = manager.get_preference(
        user_id=user_id,
        workspace_id=workspace_id,
        category="answer_style",
        key="verbosity",
    )

    profile_result = manager.resolve_preference_profile(
        user_id=user_id,
        workspace_id=workspace_id,
        agent_name="MasterAgent",
        task_type="code_generation",
    )

    health_result = manager.health_check()

    return {
        "set_result_success": set_result.get("success"),
        "get_result_success": get_result.get("success"),
        "profile_result_success": profile_result.get("success"),
        "health_result_success": health_result.get("success"),
        "value": get_result.get("data", {}).get("value"),
    }


if __name__ == "__main__":
    print(json.dumps(_smoke_test(), indent=2, ensure_ascii=False))