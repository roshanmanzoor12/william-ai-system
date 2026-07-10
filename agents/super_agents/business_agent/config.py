"""
agents/super_agents/business_agent/business_memory.py

BusinessMemory for William / Jarvis Multi-Agent AI SaaS System.

Purpose:
    Stores business preferences, CRM rules, and recurring reports for the Business Agent.

Architecture Compatibility:
    - BaseAgent compatible with safe fallback if BaseAgent is not available yet.
    - Master Agent / Agent Router compatible through `handle_task()` and `route_task()`.
    - Agent Registry / Agent Loader safe because imports are optional and this file does not
      require unfinished William modules to exist.
    - Security Agent compatible through approval hooks before sensitive writes/deletes.
    - Memory Agent compatible through normalized memory payloads.
    - Verification Agent compatible through normalized verification payloads.
    - Dashboard / FastAPI ready through structured dict responses.

SaaS Isolation:
    Every user-specific operation requires user_id and workspace_id.
    Stored data is scoped by user_id + workspace_id and never mixed globally.

Storage:
    Uses a safe local JSON document store by default.
    This is intentionally simple and import-safe. Later it can be replaced by a database adapter
    without changing the public method interface.
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
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Literal, Optional, Tuple, Union


try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:
    class BaseAgent:  # type: ignore
        """
        Safe fallback BaseAgent.

        This keeps the file import-safe while the wider William/Jarvis codebase is still
        being generated. The real BaseAgent can replace this automatically when available.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_type = kwargs.get("agent_type", "business")
            self.logger = logging.getLogger(self.agent_name)

        async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
            if hasattr(self, "handle_task"):
                return await self.handle_task(task)  # type: ignore
            return {
                "success": False,
                "message": "Fallback BaseAgent has no task handler.",
                "data": {},
                "error": "NO_HANDLER",
                "metadata": {},
            }


try:
    from agents.super_agents.business_agent.config import BUSINESS_MEMORY_DEFAULTS  # type: ignore
except Exception:
    BUSINESS_MEMORY_DEFAULTS: Dict[str, Any] = {
        "storage_dir": os.getenv(
            "WILLIAM_BUSINESS_MEMORY_DIR",
            str(Path.cwd() / ".william_data" / "business_memory"),
        ),
        "max_key_length": 120,
        "max_value_size_chars": 25_000,
        "max_rule_conditions": 20,
        "max_report_recipients": 50,
        "audit_enabled": True,
        "events_enabled": True,
    }


JsonDict = Dict[str, Any]
ResultDict = Dict[str, Any]

PreferenceValue = Union[str, int, float, bool, None, JsonDict, List[Any]]
CrmRuleStatus = Literal["active", "inactive", "draft", "archived"]
ReportStatus = Literal["active", "paused", "archived"]
ReportFrequency = Literal["daily", "weekly", "monthly", "quarterly"]


def _utcnow() -> datetime:
    """Return timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def _iso_now() -> str:
    """Return current UTC time as ISO string."""
    return _utcnow().isoformat()


def _safe_slug(value: str, default: str = "unknown") -> str:
    """
    Convert user/workspace IDs into filesystem-safe names without changing logical IDs.

    The original IDs are still stored inside records. This slug is only used for file paths.
    """
    if value is None:
        return default
    value = str(value).strip()
    if not value:
        return default
    return re.sub(r"[^a-zA-Z0-9_.=-]+", "_", value)[:160] or default


def _json_size(value: Any) -> int:
    """Return approximate JSON serialized size in characters."""
    try:
        return len(json.dumps(value, ensure_ascii=False, default=str))
    except Exception:
        return len(str(value))


def _deepcopy(value: Any) -> Any:
    """Safe deep copy helper."""
    try:
        return copy.deepcopy(value)
    except Exception:
        return value


@dataclass
class BusinessPreference:
    """
    Stores a user/workspace scoped business preference.

    Examples:
        - preferred_report_tone = "executive"
        - default_lead_currency = "USD"
        - crm_default_pipeline = "sales"
        - mature_client_filter = {"minimum_budget": 1000}
    """

    preference_id: str
    user_id: str
    workspace_id: str
    key: str
    value: PreferenceValue
    category: str = "general"
    description: str = ""
    source: str = "business_agent"
    tags: List[str] = field(default_factory=list)
    is_active: bool = True
    created_at: str = field(default_factory=_iso_now)
    updated_at: str = field(default_factory=_iso_now)
    metadata: JsonDict = field(default_factory=dict)


@dataclass
class CrmRule:
    """
    Stores CRM automation and governance rules.

    Rules are stored only. They do not directly perform external actions.
    Execution should be routed through the Business Agent, Security Agent, Workflow Agent,
    and Verification Agent as needed.

    Example:
        condition:
            {"field": "lead_score", "operator": ">=", "value": 80}
        action:
            {"type": "assign_stage", "stage": "Hot Lead"}
    """

    rule_id: str
    user_id: str
    workspace_id: str
    name: str
    conditions: List[JsonDict]
    actions: List[JsonDict]
    priority: int = 100
    status: CrmRuleStatus = "active"
    description: str = ""
    applies_to: str = "lead"
    tags: List[str] = field(default_factory=list)
    created_by: Optional[str] = None
    created_at: str = field(default_factory=_iso_now)
    updated_at: str = field(default_factory=_iso_now)
    metadata: JsonDict = field(default_factory=dict)


@dataclass
class RecurringReport:
    """
    Stores recurring business report definitions.

    This file stores report schedules and settings only.
    A scheduler/Workflow Agent can later call Business Agent or Report Builder to generate
    and send reports after security and permission checks.

    Example:
        report_type = "weekly_business_summary"
        frequency = "weekly"
        schedule = {"day_of_week": "monday", "time": "09:00", "timezone": "America/New_York"}
    """

    report_id: str
    user_id: str
    workspace_id: str
    name: str
    report_type: str
    frequency: ReportFrequency
    schedule: JsonDict
    recipients: List[str] = field(default_factory=list)
    filters: JsonDict = field(default_factory=dict)
    delivery_channels: List[str] = field(default_factory=lambda: ["dashboard"])
    status: ReportStatus = "active"
    description: str = ""
    last_run_at: Optional[str] = None
    next_run_at: Optional[str] = None
    created_by: Optional[str] = None
    created_at: str = field(default_factory=_iso_now)
    updated_at: str = field(default_factory=_iso_now)
    metadata: JsonDict = field(default_factory=dict)


class BusinessMemory(BaseAgent):
    """
    Business Agent memory helper.

    Responsibilities:
        1. Store and retrieve business preferences.
        2. Store and retrieve CRM rules.
        3. Store and retrieve recurring report definitions.
        4. Keep all stored data isolated by user_id and workspace_id.
        5. Prepare payloads for Security Agent, Memory Agent, Verification Agent, audit logs,
           dashboard/API consumers, and Master Agent routing.

    Public methods are intentionally structured around JSON/dict inputs and outputs so this class
    can be used from FastAPI endpoints, dashboards, CLI tests, Agent Router, or Master Agent.
    """

    AGENT_NAME = "BusinessMemory"
    AGENT_TYPE = "business"
    MODULE = "business_agent"
    FILE_NAME = "business_memory.py"

    SUPPORTED_TASKS = {
        "set_business_preference",
        "get_business_preference",
        "list_business_preferences",
        "delete_business_preference",
        "upsert_crm_rule",
        "get_crm_rule",
        "list_crm_rules",
        "delete_crm_rule",
        "evaluate_crm_rules",
        "create_recurring_report",
        "update_recurring_report",
        "get_recurring_report",
        "list_recurring_reports",
        "delete_recurring_report",
        "list_due_recurring_reports",
        "mark_recurring_report_run",
        "export_business_memory_summary",
    }

    SENSITIVE_ACTIONS = {
        "set_business_preference",
        "delete_business_preference",
        "upsert_crm_rule",
        "delete_crm_rule",
        "create_recurring_report",
        "update_recurring_report",
        "delete_recurring_report",
        "mark_recurring_report_run",
    }

    DESTRUCTIVE_ACTIONS = {
        "delete_business_preference",
        "delete_crm_rule",
        "delete_recurring_report",
    }

    def __init__(
        self,
        storage_dir: Optional[Union[str, Path]] = None,
        security_approval_callback: Optional[Callable[[JsonDict], Union[bool, JsonDict]]] = None,
        event_callback: Optional[Callable[[JsonDict], None]] = None,
        audit_callback: Optional[Callable[[JsonDict], None]] = None,
        memory_callback: Optional[Callable[[JsonDict], None]] = None,
        verification_callback: Optional[Callable[[JsonDict], None]] = None,
        logger: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            agent_name=self.AGENT_NAME,
            agent_type=self.AGENT_TYPE,
            **kwargs,
        )

        self.logger = logger or logging.getLogger(self.AGENT_NAME)
        self.storage_dir = Path(storage_dir or BUSINESS_MEMORY_DEFAULTS["storage_dir"])
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        self.security_approval_callback = security_approval_callback
        self.event_callback = event_callback
        self.audit_callback = audit_callback
        self.memory_callback = memory_callback
        self.verification_callback = verification_callback

        self.max_key_length = int(BUSINESS_MEMORY_DEFAULTS.get("max_key_length", 120))
        self.max_value_size_chars = int(BUSINESS_MEMORY_DEFAULTS.get("max_value_size_chars", 25_000))
        self.max_rule_conditions = int(BUSINESS_MEMORY_DEFAULTS.get("max_rule_conditions", 20))
        self.max_report_recipients = int(BUSINESS_MEMORY_DEFAULTS.get("max_report_recipients", 50))
        self.audit_enabled = bool(BUSINESS_MEMORY_DEFAULTS.get("audit_enabled", True))
        self.events_enabled = bool(BUSINESS_MEMORY_DEFAULTS.get("events_enabled", True))

        self._lock = threading.RLock()

    # -------------------------------------------------------------------------
    # Standard result helpers
    # -------------------------------------------------------------------------

    def _safe_result(
        self,
        message: str,
        data: Optional[JsonDict] = None,
        metadata: Optional[JsonDict] = None,
    ) -> ResultDict:
        """Return a standard successful structured result."""
        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": {
                "agent": self.AGENT_NAME,
                "module": self.MODULE,
                "file": self.FILE_NAME,
                "timestamp": _iso_now(),
                **(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Union[str, Exception, JsonDict]] = None,
        data: Optional[JsonDict] = None,
        metadata: Optional[JsonDict] = None,
    ) -> ResultDict:
        """Return a standard error structured result."""
        error_payload: Any
        if isinstance(error, Exception):
            error_payload = {
                "type": error.__class__.__name__,
                "detail": str(error),
            }
        elif error is None:
            error_payload = message
        else:
            error_payload = error

        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": error_payload,
            "metadata": {
                "agent": self.AGENT_NAME,
                "module": self.MODULE,
                "file": self.FILE_NAME,
                "timestamp": _iso_now(),
                **(metadata or {}),
            },
        }

    # -------------------------------------------------------------------------
    # Context, security, memory, verification, audit, and event hooks
    # -------------------------------------------------------------------------

    def _validate_task_context(self, context: JsonDict) -> Tuple[bool, Optional[str]]:
        """
        Validate SaaS task context.

        Every user/workspace scoped business memory operation requires:
            - user_id
            - workspace_id

        This prevents cross-user and cross-workspace data mixing.
        """
        if not isinstance(context, dict):
            return False, "Task context must be a dictionary."

        user_id = str(context.get("user_id", "")).strip()
        workspace_id = str(context.get("workspace_id", "")).strip()

        if not user_id:
            return False, "Missing required user_id."
        if not workspace_id:
            return False, "Missing required workspace_id."

        return True, None

    def _requires_security_check(self, action: str, payload: Optional[JsonDict] = None) -> bool:
        """
        Decide whether a BusinessMemory action needs Security Agent approval.

        Writes and deletes are sensitive because they modify persistent business memory.
        Read-only methods are not considered sensitive here.
        """
        if action in self.SENSITIVE_ACTIONS:
            return True

        payload = payload or {}
        if bool(payload.get("force_security_check")):
            return True

        return False

    def _request_security_approval(
        self,
        action: str,
        context: JsonDict,
        payload: Optional[JsonDict] = None,
    ) -> ResultDict:
        """
        Request approval from Security Agent or callback.

        Import-safe behavior:
            - If a callback exists, use it.
            - If no callback exists, allow non-destructive writes by default.
            - Destructive operations require explicit `security_approved=True` in context/payload
              when no callback is wired.

        This protects deletes while keeping development/test environments usable.
        """
        payload = payload or {}
        approval_payload = {
            "agent": self.AGENT_NAME,
            "action": action,
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "risk_level": "high" if action in self.DESTRUCTIVE_ACTIONS else "medium",
            "payload_summary": self._summarize_payload_for_security(payload),
            "timestamp": _iso_now(),
        }

        explicit_approval = bool(context.get("security_approved") or payload.get("security_approved"))

        if self.security_approval_callback:
            try:
                response = self.security_approval_callback(approval_payload)
                if isinstance(response, dict):
                    approved = bool(response.get("approved") or response.get("success"))
                    if approved:
                        return self._safe_result(
                            "Security approval granted.",
                            data={"approval": response},
                            metadata={"action": action},
                        )
                    return self._error_result(
                        "Security approval denied.",
                        error=response.get("error") or "SECURITY_DENIED",
                        data={"approval": response},
                        metadata={"action": action},
                    )

                if bool(response):
                    return self._safe_result(
                        "Security approval granted.",
                        data={"approval": {"approved": True}},
                        metadata={"action": action},
                    )

                return self._error_result(
                    "Security approval denied.",
                    error="SECURITY_DENIED",
                    data={"approval": {"approved": False}},
                    metadata={"action": action},
                )
            except Exception as exc:
                self.logger.exception("Security approval callback failed.")
                return self._error_result(
                    "Security approval check failed.",
                    error=exc,
                    metadata={"action": action},
                )

        if action in self.DESTRUCTIVE_ACTIONS and not explicit_approval:
            return self._error_result(
                "Security approval required for destructive business memory action.",
                error="SECURITY_APPROVAL_REQUIRED",
                data={
                    "required_context_flag": "security_approved=True",
                    "approval_payload": approval_payload,
                },
                metadata={"action": action},
            )

        return self._safe_result(
            "Security approval granted by safe local policy.",
            data={
                "approval": {
                    "approved": True,
                    "mode": "local_policy",
                    "destructive": action in self.DESTRUCTIVE_ACTIONS,
                }
            },
            metadata={"action": action},
        )

    def _prepare_verification_payload(
        self,
        action: str,
        context: JsonDict,
        before: Optional[JsonDict] = None,
        after: Optional[JsonDict] = None,
        result: Optional[ResultDict] = None,
    ) -> JsonDict:
        """
        Prepare a Verification Agent payload.

        The Verification Agent can later use this payload to confirm that:
            - the correct user/workspace scope was used,
            - the requested mutation happened,
            - the resulting data is structured and safe.
        """
        return {
            "verification_type": "business_memory_operation",
            "agent": self.AGENT_NAME,
            "action": action,
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "before": before,
            "after": after,
            "result_success": bool(result.get("success")) if isinstance(result, dict) else None,
            "result_message": result.get("message") if isinstance(result, dict) else None,
            "timestamp": _iso_now(),
        }

    def _prepare_memory_payload(
        self,
        action: str,
        context: JsonDict,
        record_type: str,
        record: JsonDict,
    ) -> JsonDict:
        """
        Prepare a Memory Agent compatible payload.

        This does not directly store anything in the global Memory Agent unless a callback is wired.
        It returns normalized context that Memory Agent can consume later.
        """
        return {
            "memory_type": "business_memory",
            "source_agent": self.AGENT_NAME,
            "source_module": self.MODULE,
            "action": action,
            "record_type": record_type,
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "content": record,
            "tags": [
                "business",
                "business_agent",
                "business_memory",
                record_type,
            ],
            "timestamp": _iso_now(),
        }

    def _emit_agent_event(
        self,
        event_name: str,
        context: JsonDict,
        payload: Optional[JsonDict] = None,
    ) -> None:
        """
        Emit an event for dashboards, task history, or observability.

        Safe behavior:
            - If callback exists, call it.
            - Otherwise, log at debug level.
        """
        if not self.events_enabled:
            return

        event = {
            "event_name": event_name,
            "agent": self.AGENT_NAME,
            "module": self.MODULE,
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "payload": payload or {},
            "timestamp": _iso_now(),
        }

        try:
            if self.event_callback:
                self.event_callback(event)
            else:
                self.logger.debug("BusinessMemory event: %s", event)
        except Exception:
            self.logger.exception("Failed to emit BusinessMemory event.")

    def _log_audit_event(
        self,
        action: str,
        context: JsonDict,
        success: bool,
        details: Optional[JsonDict] = None,
    ) -> None:
        """
        Log an audit event.

        Audit events are scoped by user_id/workspace_id and can be forwarded to a future Audit
        Log service. A local audit log file is also maintained for development/test safety.
        """
        if not self.audit_enabled:
            return

        audit_event = {
            "audit_id": str(uuid.uuid4()),
            "agent": self.AGENT_NAME,
            "module": self.MODULE,
            "action": action,
            "success": success,
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "actor_id": context.get("actor_id") or context.get("user_id"),
            "details": details or {},
            "timestamp": _iso_now(),
        }

        try:
            if self.audit_callback:
                self.audit_callback(audit_event)

            audit_path = self._scope_dir(context["user_id"], context["workspace_id"]) / "audit.log"
            audit_path.parent.mkdir(parents=True, exist_ok=True)
            with audit_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(audit_event, ensure_ascii=False, default=str) + "\n")
        except Exception:
            self.logger.exception("Failed to write BusinessMemory audit event.")

    # -------------------------------------------------------------------------
    # Storage helpers
    # -------------------------------------------------------------------------

    def _scope_dir(self, user_id: str, workspace_id: str) -> Path:
        """Return isolated storage directory for user_id + workspace_id."""
        return self.storage_dir / _safe_slug(user_id, "user") / _safe_slug(workspace_id, "workspace")

    def _scope_file(self, user_id: str, workspace_id: str) -> Path:
        """Return isolated JSON storage file path."""
        return self._scope_dir(user_id, workspace_id) / "business_memory.json"

    def _empty_store(self, user_id: str, workspace_id: str) -> JsonDict:
        """Return an empty scoped store."""
        return {
            "schema_version": "1.0",
            "user_id": user_id,
            "workspace_id": workspace_id,
            "preferences": {},
            "crm_rules": {},
            "recurring_reports": {},
            "created_at": _iso_now(),
            "updated_at": _iso_now(),
        }

    def _load_store(self, user_id: str, workspace_id: str) -> JsonDict:
        """Load isolated business memory store."""
        path = self._scope_file(user_id, workspace_id)
        path.parent.mkdir(parents=True, exist_ok=True)

        if not path.exists():
            return self._empty_store(user_id, workspace_id)

        try:
            with path.open("r", encoding="utf-8") as handle:
                store = json.load(handle)

            if store.get("user_id") != user_id or store.get("workspace_id") != workspace_id:
                raise ValueError("Stored business memory scope does not match requested scope.")

            store.setdefault("preferences", {})
            store.setdefault("crm_rules", {})
            store.setdefault("recurring_reports", {})
            store.setdefault("schema_version", "1.0")
            return store
        except json.JSONDecodeError as exc:
            raise ValueError(f"Business memory store is corrupted: {path}") from exc

    def _save_store(self, user_id: str, workspace_id: str, store: JsonDict) -> None:
        """Persist isolated business memory store atomically."""
        if store.get("user_id") != user_id or store.get("workspace_id") != workspace_id:
            raise ValueError("Refusing to save store with mismatched user/workspace scope.")

        store["updated_at"] = _iso_now()

        path = self._scope_file(user_id, workspace_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = path.with_suffix(".tmp")

        with temp_path.open("w", encoding="utf-8") as handle:
            json.dump(store, handle, indent=2, ensure_ascii=False, default=str)

        temp_path.replace(path)

    # -------------------------------------------------------------------------
    # Validation helpers
    # -------------------------------------------------------------------------

    def _validate_key(self, key: str, field_name: str = "key") -> Tuple[bool, Optional[str]]:
        """Validate preference/rule/report keys."""
        if not isinstance(key, str) or not key.strip():
            return False, f"{field_name} must be a non-empty string."

        if len(key.strip()) > self.max_key_length:
            return False, f"{field_name} cannot exceed {self.max_key_length} characters."

        if not re.match(r"^[a-zA-Z0-9_.:\-/ ]+$", key.strip()):
            return False, f"{field_name} contains unsupported characters."

        return True, None

    def _validate_preference_value(self, value: PreferenceValue) -> Tuple[bool, Optional[str]]:
        """Validate preference value size and JSON compatibility."""
        if _json_size(value) > self.max_value_size_chars:
            return False, f"Preference value exceeds {self.max_value_size_chars} serialized characters."

        try:
            json.dumps(value, ensure_ascii=False, default=str)
        except Exception as exc:
            return False, f"Preference value must be JSON serializable: {exc}"

        return True, None

    def _validate_tags(self, tags: Optional[Iterable[Any]]) -> List[str]:
        """Normalize tags."""
        if not tags:
            return []

        normalized: List[str] = []
        for tag in tags:
            value = str(tag).strip().lower()
            if value and value not in normalized:
                normalized.append(value[:80])

        return normalized[:50]

    def _validate_crm_rule_payload(self, payload: JsonDict) -> Tuple[bool, Optional[str]]:
        """Validate CRM rule payload."""
        name = str(payload.get("name", "")).strip()
        if not name:
            return False, "CRM rule name is required."

        conditions = payload.get("conditions")
        actions = payload.get("actions")

        if not isinstance(conditions, list) or not conditions:
            return False, "CRM rule conditions must be a non-empty list."

        if len(conditions) > self.max_rule_conditions:
            return False, f"CRM rule cannot exceed {self.max_rule_conditions} conditions."

        if not all(isinstance(item, dict) for item in conditions):
            return False, "Every CRM rule condition must be a dictionary."

        if not isinstance(actions, list) or not actions:
            return False, "CRM rule actions must be a non-empty list."

        if not all(isinstance(item, dict) for item in actions):
            return False, "Every CRM rule action must be a dictionary."

        status = payload.get("status", "active")
        if status not in {"active", "inactive", "draft", "archived"}:
            return False, "CRM rule status must be one of: active, inactive, draft, archived."

        try:
            int(payload.get("priority", 100))
        except Exception:
            return False, "CRM rule priority must be an integer."

        return True, None

    def _validate_report_payload(self, payload: JsonDict, partial: bool = False) -> Tuple[bool, Optional[str]]:
        """Validate recurring report payload."""
        if not partial or "name" in payload:
            if not str(payload.get("name", "")).strip():
                return False, "Recurring report name is required."

        if not partial or "report_type" in payload:
            if not str(payload.get("report_type", "")).strip():
                return False, "Recurring report report_type is required."

        if not partial or "frequency" in payload:
            if payload.get("frequency") not in {"daily", "weekly", "monthly", "quarterly"}:
                return False, "Recurring report frequency must be one of: daily, weekly, monthly, quarterly."

        if not partial or "schedule" in payload:
            if not isinstance(payload.get("schedule"), dict):
                return False, "Recurring report schedule must be a dictionary."

        if "recipients" in payload:
            recipients = payload.get("recipients")
            if recipients is None:
                recipients = []
            if not isinstance(recipients, list):
                return False, "Recurring report recipients must be a list."
            if len(recipients) > self.max_report_recipients:
                return False, f"Recurring report cannot exceed {self.max_report_recipients} recipients."

        if "delivery_channels" in payload:
            channels = payload.get("delivery_channels")
            if not isinstance(channels, list) or not channels:
                return False, "Recurring report delivery_channels must be a non-empty list."

        if "status" in payload and payload.get("status") not in {"active", "paused", "archived"}:
            return False, "Recurring report status must be one of: active, paused, archived."

        return True, None

    # -------------------------------------------------------------------------
    # Business preferences
    # -------------------------------------------------------------------------

    def set_business_preference(
        self,
        context: JsonDict,
        key: str,
        value: PreferenceValue,
        category: str = "general",
        description: str = "",
        tags: Optional[List[str]] = None,
        source: str = "business_agent",
        metadata: Optional[JsonDict] = None,
    ) -> ResultDict:
        """
        Create or update a business preference.

        Requires user_id and workspace_id.
        """
        action = "set_business_preference"

        valid, error = self._validate_task_context(context)
        if not valid:
            return self._error_result("Invalid task context.", error=error, metadata={"action": action})

        valid, error = self._validate_key(key, "preference key")
        if not valid:
            return self._error_result("Invalid business preference key.", error=error, metadata={"action": action})

        valid, error = self._validate_preference_value(value)
        if not valid:
            return self._error_result("Invalid business preference value.", error=error, metadata={"action": action})

        payload = {
            "key": key,
            "category": category,
            "description": description,
            "tags": tags or [],
            "source": source,
            "metadata": metadata or {},
        }

        if self._requires_security_check(action, payload):
            approval = self._request_security_approval(action, context, payload)
            if not approval["success"]:
                self._log_audit_event(action, context, False, {"reason": "security_denied", "key": key})
                return approval

        user_id = str(context["user_id"])
        workspace_id = str(context["workspace_id"])
        normalized_key = key.strip()

        try:
            with self._lock:
                store = self._load_store(user_id, workspace_id)
                before = _deepcopy(store["preferences"].get(normalized_key))

                if before:
                    record = before
                    record["value"] = value
                    record["category"] = str(category or record.get("category") or "general").strip()
                    record["description"] = str(description or record.get("description") or "")
                    record["tags"] = self._validate_tags(tags if tags is not None else record.get("tags", []))
                    record["source"] = str(source or record.get("source") or "business_agent")
                    record["metadata"] = {
                        **(record.get("metadata") or {}),
                        **(metadata or {}),
                    }
                    record["is_active"] = True
                    record["updated_at"] = _iso_now()
                else:
                    preference = BusinessPreference(
                        preference_id=str(uuid.uuid4()),
                        user_id=user_id,
                        workspace_id=workspace_id,
                        key=normalized_key,
                        value=value,
                        category=str(category or "general").strip(),
                        description=str(description or ""),
                        source=str(source or "business_agent"),
                        tags=self._validate_tags(tags),
                        metadata=metadata or {},
                    )
                    record = asdict(preference)

                store["preferences"][normalized_key] = record
                self._save_store(user_id, workspace_id, store)

            result = self._safe_result(
                "Business preference stored successfully.",
                data={
                    "preference": record,
                    "memory_payload": self._prepare_memory_payload(action, context, "business_preference", record),
                },
                metadata={"action": action, "key": normalized_key},
            )

            verification_payload = self._prepare_verification_payload(
                action=action,
                context=context,
                before=before,
                after=record,
                result=result,
            )
            result["data"]["verification_payload"] = verification_payload

            self._forward_memory_payload(result["data"]["memory_payload"])
            self._forward_verification_payload(verification_payload)
            self._emit_agent_event("business_memory.preference_stored", context, {"key": normalized_key})
            self._log_audit_event(action, context, True, {"key": normalized_key})

            return result
        except Exception as exc:
            self.logger.exception("Failed to store business preference.")
            self._log_audit_event(action, context, False, {"key": key, "error": str(exc)})
            return self._error_result(
                "Failed to store business preference.",
                error=exc,
                metadata={"action": action, "key": key},
            )

    def get_business_preference(
        self,
        context: JsonDict,
        key: str,
        default: Optional[PreferenceValue] = None,
        include_inactive: bool = False,
    ) -> ResultDict:
        """Get a business preference by key."""
        action = "get_business_preference"

        valid, error = self._validate_task_context(context)
        if not valid:
            return self._error_result("Invalid task context.", error=error, metadata={"action": action})

        valid, error = self._validate_key(key, "preference key")
        if not valid:
            return self._error_result("Invalid business preference key.", error=error, metadata={"action": action})

        user_id = str(context["user_id"])
        workspace_id = str(context["workspace_id"])
        normalized_key = key.strip()

        try:
            with self._lock:
                store = self._load_store(user_id, workspace_id)
                record = store["preferences"].get(normalized_key)

            if not record:
                return self._safe_result(
                    "Business preference not found.",
                    data={
                        "preference": None,
                        "value": default,
                        "found": False,
                    },
                    metadata={"action": action, "key": normalized_key},
                )

            if not include_inactive and not bool(record.get("is_active", True)):
                return self._safe_result(
                    "Business preference is inactive.",
                    data={
                        "preference": None,
                        "value": default,
                        "found": False,
                        "inactive": True,
                    },
                    metadata={"action": action, "key": normalized_key},
                )

            return self._safe_result(
                "Business preference retrieved successfully.",
                data={
                    "preference": record,
                    "value": record.get("value"),
                    "found": True,
                },
                metadata={"action": action, "key": normalized_key},
            )
        except Exception as exc:
            self.logger.exception("Failed to retrieve business preference.")
            return self._error_result(
                "Failed to retrieve business preference.",
                error=exc,
                metadata={"action": action, "key": key},
            )

    def list_business_preferences(
        self,
        context: JsonDict,
        category: Optional[str] = None,
        tags: Optional[List[str]] = None,
        include_inactive: bool = False,
    ) -> ResultDict:
        """List business preferences for a user/workspace scope."""
        action = "list_business_preferences"

        valid, error = self._validate_task_context(context)
        if not valid:
            return self._error_result("Invalid task context.", error=error, metadata={"action": action})

        user_id = str(context["user_id"])
        workspace_id = str(context["workspace_id"])
        required_tags = set(self._validate_tags(tags))

        try:
            with self._lock:
                store = self._load_store(user_id, workspace_id)
                preferences = list(store["preferences"].values())

            filtered: List[JsonDict] = []
            for item in preferences:
                if not include_inactive and not bool(item.get("is_active", True)):
                    continue
                if category and item.get("category") != category:
                    continue
                if required_tags and not required_tags.issubset(set(item.get("tags", []))):
                    continue
                filtered.append(item)

            filtered.sort(key=lambda item: (item.get("category", ""), item.get("key", "")))

            return self._safe_result(
                "Business preferences listed successfully.",
                data={
                    "preferences": filtered,
                    "count": len(filtered),
                },
                metadata={"action": action, "category": category, "tags": list(required_tags)},
            )
        except Exception as exc:
            self.logger.exception("Failed to list business preferences.")
            return self._error_result(
                "Failed to list business preferences.",
                error=exc,
                metadata={"action": action},
            )

    def delete_business_preference(
        self,
        context: JsonDict,
        key: str,
        soft_delete: bool = True,
    ) -> ResultDict:
        """
        Delete or deactivate a business preference.

        Destructive operation:
            - Requires Security Agent approval or explicit security_approved=True.
        """
        action = "delete_business_preference"

        valid, error = self._validate_task_context(context)
        if not valid:
            return self._error_result("Invalid task context.", error=error, metadata={"action": action})

        valid, error = self._validate_key(key, "preference key")
        if not valid:
            return self._error_result("Invalid business preference key.", error=error, metadata={"action": action})

        payload = {"key": key, "soft_delete": soft_delete}
        approval = self._request_security_approval(action, context, payload)
        if not approval["success"]:
            self._log_audit_event(action, context, False, {"reason": "security_denied", "key": key})
            return approval

        user_id = str(context["user_id"])
        workspace_id = str(context["workspace_id"])
        normalized_key = key.strip()

        try:
            with self._lock:
                store = self._load_store(user_id, workspace_id)
                before = _deepcopy(store["preferences"].get(normalized_key))

                if not before:
                    return self._safe_result(
                        "Business preference not found.",
                        data={"deleted": False, "found": False},
                        metadata={"action": action, "key": normalized_key},
                    )

                if soft_delete:
                    store["preferences"][normalized_key]["is_active"] = False
                    store["preferences"][normalized_key]["updated_at"] = _iso_now()
                    after = store["preferences"][normalized_key]
                else:
                    after = None
                    del store["preferences"][normalized_key]

                self._save_store(user_id, workspace_id, store)

            result = self._safe_result(
                "Business preference deleted successfully." if not soft_delete else "Business preference deactivated successfully.",
                data={
                    "deleted": True,
                    "soft_delete": soft_delete,
                    "preference": after,
                },
                metadata={"action": action, "key": normalized_key},
            )

            verification_payload = self._prepare_verification_payload(
                action=action,
                context=context,
                before=before,
                after=after,
                result=result,
            )
            result["data"]["verification_payload"] = verification_payload

            self._forward_verification_payload(verification_payload)
            self._emit_agent_event("business_memory.preference_deleted", context, {"key": normalized_key, "soft_delete": soft_delete})
            self._log_audit_event(action, context, True, {"key": normalized_key, "soft_delete": soft_delete})

            return result
        except Exception as exc:
            self.logger.exception("Failed to delete business preference.")
            self._log_audit_event(action, context, False, {"key": key, "error": str(exc)})
            return self._error_result(
                "Failed to delete business preference.",
                error=exc,
                metadata={"action": action, "key": key},
            )

    # -------------------------------------------------------------------------
    # CRM rules
    # -------------------------------------------------------------------------

    def upsert_crm_rule(
        self,
        context: JsonDict,
        name: str,
        conditions: List[JsonDict],
        actions: List[JsonDict],
        rule_id: Optional[str] = None,
        priority: int = 100,
        status: CrmRuleStatus = "active",
        description: str = "",
        applies_to: str = "lead",
        tags: Optional[List[str]] = None,
        metadata: Optional[JsonDict] = None,
    ) -> ResultDict:
        """Create or update a CRM rule."""
        action = "upsert_crm_rule"

        valid, error = self._validate_task_context(context)
        if not valid:
            return self._error_result("Invalid task context.", error=error, metadata={"action": action})

        payload = {
            "rule_id": rule_id,
            "name": name,
            "conditions": conditions,
            "actions": actions,
            "priority": priority,
            "status": status,
            "description": description,
            "applies_to": applies_to,
            "tags": tags or [],
            "metadata": metadata or {},
        }

        valid, error = self._validate_crm_rule_payload(payload)
        if not valid:
            return self._error_result("Invalid CRM rule payload.", error=error, metadata={"action": action})

        approval = self._request_security_approval(action, context, payload)
        if not approval["success"]:
            self._log_audit_event(action, context, False, {"reason": "security_denied", "name": name})
            return approval

        user_id = str(context["user_id"])
        workspace_id = str(context["workspace_id"])
        normalized_rule_id = str(rule_id or uuid.uuid4())

        try:
            with self._lock:
                store = self._load_store(user_id, workspace_id)
                before = _deepcopy(store["crm_rules"].get(normalized_rule_id))

                if before:
                    record = before
                    record.update(
                        {
                            "name": str(name).strip(),
                            "conditions": _deepcopy(conditions),
                            "actions": _deepcopy(actions),
                            "priority": int(priority),
                            "status": status,
                            "description": str(description or ""),
                            "applies_to": str(applies_to or "lead").strip(),
                            "tags": self._validate_tags(tags),
                            "metadata": {
                                **(record.get("metadata") or {}),
                                **(metadata or {}),
                            },
                            "updated_at": _iso_now(),
                        }
                    )
                else:
                    crm_rule = CrmRule(
                        rule_id=normalized_rule_id,
                        user_id=user_id,
                        workspace_id=workspace_id,
                        name=str(name).strip(),
                        conditions=_deepcopy(conditions),
                        actions=_deepcopy(actions),
                        priority=int(priority),
                        status=status,
                        description=str(description or ""),
                        applies_to=str(applies_to or "lead").strip(),
                        tags=self._validate_tags(tags),
                        created_by=context.get("actor_id") or context.get("user_id"),
                        metadata=metadata or {},
                    )
                    record = asdict(crm_rule)

                store["crm_rules"][normalized_rule_id] = record
                self._save_store(user_id, workspace_id, store)

            result = self._safe_result(
                "CRM rule stored successfully.",
                data={
                    "crm_rule": record,
                    "memory_payload": self._prepare_memory_payload(action, context, "crm_rule", record),
                },
                metadata={"action": action, "rule_id": normalized_rule_id},
            )

            verification_payload = self._prepare_verification_payload(
                action=action,
                context=context,
                before=before,
                after=record,
                result=result,
            )
            result["data"]["verification_payload"] = verification_payload

            self._forward_memory_payload(result["data"]["memory_payload"])
            self._forward_verification_payload(verification_payload)
            self._emit_agent_event("business_memory.crm_rule_stored", context, {"rule_id": normalized_rule_id})
            self._log_audit_event(action, context, True, {"rule_id": normalized_rule_id})

            return result
        except Exception as exc:
            self.logger.exception("Failed to store CRM rule.")
            self._log_audit_event(action, context, False, {"name": name, "error": str(exc)})
            return self._error_result(
                "Failed to store CRM rule.",
                error=exc,
                metadata={"action": action, "rule_id": rule_id},
            )

    def get_crm_rule(self, context: JsonDict, rule_id: str) -> ResultDict:
        """Get CRM rule by ID."""
        action = "get_crm_rule"

        valid, error = self._validate_task_context(context)
        if not valid:
            return self._error_result("Invalid task context.", error=error, metadata={"action": action})

        if not rule_id:
            return self._error_result("CRM rule ID is required.", error="MISSING_RULE_ID", metadata={"action": action})

        user_id = str(context["user_id"])
        workspace_id = str(context["workspace_id"])

        try:
            with self._lock:
                store = self._load_store(user_id, workspace_id)
                record = store["crm_rules"].get(str(rule_id))

            if not record:
                return self._safe_result(
                    "CRM rule not found.",
                    data={"crm_rule": None, "found": False},
                    metadata={"action": action, "rule_id": rule_id},
                )

            return self._safe_result(
                "CRM rule retrieved successfully.",
                data={"crm_rule": record, "found": True},
                metadata={"action": action, "rule_id": rule_id},
            )
        except Exception as exc:
            self.logger.exception("Failed to retrieve CRM rule.")
            return self._error_result(
                "Failed to retrieve CRM rule.",
                error=exc,
                metadata={"action": action, "rule_id": rule_id},
            )

    def list_crm_rules(
        self,
        context: JsonDict,
        status: Optional[CrmRuleStatus] = None,
        applies_to: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> ResultDict:
        """List CRM rules for the scoped user/workspace."""
        action = "list_crm_rules"

        valid, error = self._validate_task_context(context)
        if not valid:
            return self._error_result("Invalid task context.", error=error, metadata={"action": action})

        user_id = str(context["user_id"])
        workspace_id = str(context["workspace_id"])
        required_tags = set(self._validate_tags(tags))

        try:
            with self._lock:
                store = self._load_store(user_id, workspace_id)
                rules = list(store["crm_rules"].values())

            filtered: List[JsonDict] = []
            for rule in rules:
                if status and rule.get("status") != status:
                    continue
                if applies_to and rule.get("applies_to") != applies_to:
                    continue
                if required_tags and not required_tags.issubset(set(rule.get("tags", []))):
                    continue
                filtered.append(rule)

            filtered.sort(key=lambda item: (int(item.get("priority", 100)), item.get("name", "")))

            return self._safe_result(
                "CRM rules listed successfully.",
                data={"crm_rules": filtered, "count": len(filtered)},
                metadata={"action": action, "status": status, "applies_to": applies_to},
            )
        except Exception as exc:
            self.logger.exception("Failed to list CRM rules.")
            return self._error_result("Failed to list CRM rules.", error=exc, metadata={"action": action})

    def delete_crm_rule(
        self,
        context: JsonDict,
        rule_id: str,
        soft_delete: bool = True,
    ) -> ResultDict:
        """Delete or archive a CRM rule."""
        action = "delete_crm_rule"

        valid, error = self._validate_task_context(context)
        if not valid:
            return self._error_result("Invalid task context.", error=error, metadata={"action": action})

        if not rule_id:
            return self._error_result("CRM rule ID is required.", error="MISSING_RULE_ID", metadata={"action": action})

        approval = self._request_security_approval(action, context, {"rule_id": rule_id, "soft_delete": soft_delete})
        if not approval["success"]:
            self._log_audit_event(action, context, False, {"reason": "security_denied", "rule_id": rule_id})
            return approval

        user_id = str(context["user_id"])
        workspace_id = str(context["workspace_id"])

        try:
            with self._lock:
                store = self._load_store(user_id, workspace_id)
                before = _deepcopy(store["crm_rules"].get(str(rule_id)))

                if not before:
                    return self._safe_result(
                        "CRM rule not found.",
                        data={"deleted": False, "found": False},
                        metadata={"action": action, "rule_id": rule_id},
                    )

                if soft_delete:
                    store["crm_rules"][str(rule_id)]["status"] = "archived"
                    store["crm_rules"][str(rule_id)]["updated_at"] = _iso_now()
                    after = store["crm_rules"][str(rule_id)]
                else:
                    after = None
                    del store["crm_rules"][str(rule_id)]

                self._save_store(user_id, workspace_id, store)

            result = self._safe_result(
                "CRM rule deleted successfully." if not soft_delete else "CRM rule archived successfully.",
                data={"deleted": True, "soft_delete": soft_delete, "crm_rule": after},
                metadata={"action": action, "rule_id": rule_id},
            )

            verification_payload = self._prepare_verification_payload(action, context, before, after, result)
            result["data"]["verification_payload"] = verification_payload

            self._forward_verification_payload(verification_payload)
            self._emit_agent_event("business_memory.crm_rule_deleted", context, {"rule_id": rule_id, "soft_delete": soft_delete})
            self._log_audit_event(action, context, True, {"rule_id": rule_id, "soft_delete": soft_delete})

            return result
        except Exception as exc:
            self.logger.exception("Failed to delete CRM rule.")
            self._log_audit_event(action, context, False, {"rule_id": rule_id, "error": str(exc)})
            return self._error_result(
                "Failed to delete CRM rule.",
                error=exc,
                metadata={"action": action, "rule_id": rule_id},
            )

    def evaluate_crm_rules(
        self,
        context: JsonDict,
        entity: JsonDict,
        applies_to: str = "lead",
    ) -> ResultDict:
        """
        Evaluate active CRM rules against an entity.

        This method only returns matched rules and suggested actions.
        It does not execute actions directly. Execution should go through Security Agent,
        Workflow Agent, Business Agent, and Verification Agent.
        """
        action = "evaluate_crm_rules"

        valid, error = self._validate_task_context(context)
        if not valid:
            return self._error_result("Invalid task context.", error=error, metadata={"action": action})

        if not isinstance(entity, dict):
            return self._error_result("Entity must be a dictionary.", error="INVALID_ENTITY", metadata={"action": action})

        rules_result = self.list_crm_rules(context, status="active", applies_to=applies_to)
        if not rules_result["success"]:
            return rules_result

        matched: List[JsonDict] = []
        suggested_actions: List[JsonDict] = []

        for rule in rules_result["data"].get("crm_rules", []):
            if self._rule_matches(entity, rule.get("conditions", [])):
                matched_rule = {
                    "rule_id": rule.get("rule_id"),
                    "name": rule.get("name"),
                    "priority": rule.get("priority"),
                    "actions": rule.get("actions", []),
                }
                matched.append(matched_rule)
                for item in rule.get("actions", []):
                    suggested_actions.append(
                        {
                            "source_rule_id": rule.get("rule_id"),
                            "source_rule_name": rule.get("name"),
                            "action": item,
                            "requires_security_check": True,
                        }
                    )

        return self._safe_result(
            "CRM rules evaluated successfully.",
            data={
                "matched_rules": matched,
                "suggested_actions": suggested_actions,
                "matched_count": len(matched),
                "actions_count": len(suggested_actions),
                "executed": False,
            },
            metadata={"action": action, "applies_to": applies_to},
        )

    # -------------------------------------------------------------------------
    # Recurring reports
    # -------------------------------------------------------------------------

    def create_recurring_report(
        self,
        context: JsonDict,
        name: str,
        report_type: str,
        frequency: ReportFrequency,
        schedule: JsonDict,
        recipients: Optional[List[str]] = None,
        filters: Optional[JsonDict] = None,
        delivery_channels: Optional[List[str]] = None,
        status: ReportStatus = "active",
        description: str = "",
        metadata: Optional[JsonDict] = None,
    ) -> ResultDict:
        """Create a recurring report definition."""
        action = "create_recurring_report"

        valid, error = self._validate_task_context(context)
        if not valid:
            return self._error_result("Invalid task context.", error=error, metadata={"action": action})

        payload = {
            "name": name,
            "report_type": report_type,
            "frequency": frequency,
            "schedule": schedule,
            "recipients": recipients or [],
            "filters": filters or {},
            "delivery_channels": delivery_channels or ["dashboard"],
            "status": status,
            "description": description,
            "metadata": metadata or {},
        }

        valid, error = self._validate_report_payload(payload)
        if not valid:
            return self._error_result("Invalid recurring report payload.", error=error, metadata={"action": action})

        approval = self._request_security_approval(action, context, payload)
        if not approval["success"]:
            self._log_audit_event(action, context, False, {"reason": "security_denied", "name": name})
            return approval

        user_id = str(context["user_id"])
        workspace_id = str(context["workspace_id"])
        report_id = str(uuid.uuid4())

        try:
            next_run_at = self._calculate_next_run_at(frequency, schedule)
            report = RecurringReport(
                report_id=report_id,
                user_id=user_id,
                workspace_id=workspace_id,
                name=str(name).strip(),
                report_type=str(report_type).strip(),
                frequency=frequency,
                schedule=_deepcopy(schedule),
                recipients=self._normalize_recipients(recipients or []),
                filters=filters or {},
                delivery_channels=[str(channel).strip() for channel in (delivery_channels or ["dashboard"]) if str(channel).strip()],
                status=status,
                description=str(description or ""),
                next_run_at=next_run_at,
                created_by=context.get("actor_id") or context.get("user_id"),
                metadata=metadata or {},
            )
            record = asdict(report)

            with self._lock:
                store = self._load_store(user_id, workspace_id)
                store["recurring_reports"][report_id] = record
                self._save_store(user_id, workspace_id, store)

            result = self._safe_result(
                "Recurring report created successfully.",
                data={
                    "recurring_report": record,
                    "memory_payload": self._prepare_memory_payload(action, context, "recurring_report", record),
                },
                metadata={"action": action, "report_id": report_id},
            )

            verification_payload = self._prepare_verification_payload(action, context, None, record, result)
            result["data"]["verification_payload"] = verification_payload

            self._forward_memory_payload(result["data"]["memory_payload"])
            self._forward_verification_payload(verification_payload)
            self._emit_agent_event("business_memory.recurring_report_created", context, {"report_id": report_id})
            self._log_audit_event(action, context, True, {"report_id": report_id})

            return result
        except Exception as exc:
            self.logger.exception("Failed to create recurring report.")
            self._log_audit_event(action, context, False, {"name": name, "error": str(exc)})
            return self._error_result(
                "Failed to create recurring report.",
                error=exc,
                metadata={"action": action},
            )

    def update_recurring_report(
        self,
        context: JsonDict,
        report_id: str,
        updates: JsonDict,
    ) -> ResultDict:
        """Update a recurring report definition."""
        action = "update_recurring_report"

        valid, error = self._validate_task_context(context)
        if not valid:
            return self._error_result("Invalid task context.", error=error, metadata={"action": action})

        if not report_id:
            return self._error_result("Recurring report ID is required.", error="MISSING_REPORT_ID", metadata={"action": action})

        if not isinstance(updates, dict) or not updates:
            return self._error_result("Recurring report updates must be a non-empty dictionary.", error="INVALID_UPDATES", metadata={"action": action})

        allowed = {
            "name",
            "report_type",
            "frequency",
            "schedule",
            "recipients",
            "filters",
            "delivery_channels",
            "status",
            "description",
            "metadata",
        }
        clean_updates = {key: value for key, value in updates.items() if key in allowed}

        if not clean_updates:
            return self._error_result(
                "No allowed recurring report update fields supplied.",
                error="NO_ALLOWED_FIELDS",
                metadata={"action": action},
            )

        valid, error = self._validate_report_payload(clean_updates, partial=True)
        if not valid:
            return self._error_result("Invalid recurring report update payload.", error=error, metadata={"action": action})

        approval = self._request_security_approval(action, context, {"report_id": report_id, "updates": clean_updates})
        if not approval["success"]:
            self._log_audit_event(action, context, False, {"reason": "security_denied", "report_id": report_id})
            return approval

        user_id = str(context["user_id"])
        workspace_id = str(context["workspace_id"])

        try:
            with self._lock:
                store = self._load_store(user_id, workspace_id)
                before = _deepcopy(store["recurring_reports"].get(str(report_id)))

                if not before:
                    return self._safe_result(
                        "Recurring report not found.",
                        data={"updated": False, "found": False},
                        metadata={"action": action, "report_id": report_id},
                    )

                record = store["recurring_reports"][str(report_id)]

                for key, value in clean_updates.items():
                    if key == "recipients":
                        record[key] = self._normalize_recipients(value or [])
                    elif key == "delivery_channels":
                        record[key] = [str(channel).strip() for channel in value if str(channel).strip()]
                    elif key == "metadata":
                        record[key] = {
                            **(record.get("metadata") or {}),
                            **(value or {}),
                        }
                    else:
                        record[key] = _deepcopy(value)

                if "frequency" in clean_updates or "schedule" in clean_updates:
                    record["next_run_at"] = self._calculate_next_run_at(record["frequency"], record["schedule"])

                record["updated_at"] = _iso_now()
                after = _deepcopy(record)

                self._save_store(user_id, workspace_id, store)

            result = self._safe_result(
                "Recurring report updated successfully.",
                data={"updated": True, "recurring_report": after},
                metadata={"action": action, "report_id": report_id},
            )

            verification_payload = self._prepare_verification_payload(action, context, before, after, result)
            result["data"]["verification_payload"] = verification_payload

            self._forward_verification_payload(verification_payload)
            self._emit_agent_event("business_memory.recurring_report_updated", context, {"report_id": report_id})
            self._log_audit_event(action, context, True, {"report_id": report_id})

            return result
        except Exception as exc:
            self.logger.exception("Failed to update recurring report.")
            self._log_audit_event(action, context, False, {"report_id": report_id, "error": str(exc)})
            return self._error_result(
                "Failed to update recurring report.",
                error=exc,
                metadata={"action": action, "report_id": report_id},
            )

    def get_recurring_report(self, context: JsonDict, report_id: str) -> ResultDict:
        """Get recurring report by ID."""
        action = "get_recurring_report"

        valid, error = self._validate_task_context(context)
        if not valid:
            return self._error_result("Invalid task context.", error=error, metadata={"action": action})

        if not report_id:
            return self._error_result("Recurring report ID is required.", error="MISSING_REPORT_ID", metadata={"action": action})

        user_id = str(context["user_id"])
        workspace_id = str(context["workspace_id"])

        try:
            with self._lock:
                store = self._load_store(user_id, workspace_id)
                record = store["recurring_reports"].get(str(report_id))

            if not record:
                return self._safe_result(
                    "Recurring report not found.",
                    data={"recurring_report": None, "found": False},
                    metadata={"action": action, "report_id": report_id},
                )

            return self._safe_result(
                "Recurring report retrieved successfully.",
                data={"recurring_report": record, "found": True},
                metadata={"action": action, "report_id": report_id},
            )
        except Exception as exc:
            self.logger.exception("Failed to retrieve recurring report.")
            return self._error_result(
                "Failed to retrieve recurring report.",
                error=exc,
                metadata={"action": action, "report_id": report_id},
            )

    def list_recurring_reports(
        self,
        context: JsonDict,
        status: Optional[ReportStatus] = None,
        frequency: Optional[ReportFrequency] = None,
        report_type: Optional[str] = None,
    ) -> ResultDict:
        """List recurring reports for the scoped user/workspace."""
        action = "list_recurring_reports"

        valid, error = self._validate_task_context(context)
        if not valid:
            return self._error_result("Invalid task context.", error=error, metadata={"action": action})

        user_id = str(context["user_id"])
        workspace_id = str(context["workspace_id"])

        try:
            with self._lock:
                store = self._load_store(user_id, workspace_id)
                reports = list(store["recurring_reports"].values())

            filtered: List[JsonDict] = []
            for report in reports:
                if status and report.get("status") != status:
                    continue
                if frequency and report.get("frequency") != frequency:
                    continue
                if report_type and report.get("report_type") != report_type:
                    continue
                filtered.append(report)

            filtered.sort(key=lambda item: (item.get("next_run_at") or "9999", item.get("name", "")))

            return self._safe_result(
                "Recurring reports listed successfully.",
                data={"recurring_reports": filtered, "count": len(filtered)},
                metadata={"action": action, "status": status, "frequency": frequency, "report_type": report_type},
            )
        except Exception as exc:
            self.logger.exception("Failed to list recurring reports.")
            return self._error_result(
                "Failed to list recurring reports.",
                error=exc,
                metadata={"action": action},
            )

    def delete_recurring_report(
        self,
        context: JsonDict,
        report_id: str,
        soft_delete: bool = True,
    ) -> ResultDict:
        """Delete or archive a recurring report definition."""
        action = "delete_recurring_report"

        valid, error = self._validate_task_context(context)
        if not valid:
            return self._error_result("Invalid task context.", error=error, metadata={"action": action})

        if not report_id:
            return self._error_result("Recurring report ID is required.", error="MISSING_REPORT_ID", metadata={"action": action})

        approval = self._request_security_approval(action, context, {"report_id": report_id, "soft_delete": soft_delete})
        if not approval["success"]:
            self._log_audit_event(action, context, False, {"reason": "security_denied", "report_id": report_id})
            return approval

        user_id = str(context["user_id"])
        workspace_id = str(context["workspace_id"])

        try:
            with self._lock:
                store = self._load_store(user_id, workspace_id)
                before = _deepcopy(store["recurring_reports"].get(str(report_id)))

                if not before:
                    return self._safe_result(
                        "Recurring report not found.",
                        data={"deleted": False, "found": False},
                        metadata={"action": action, "report_id": report_id},
                    )

                if soft_delete:
                    store["recurring_reports"][str(report_id)]["status"] = "archived"
                    store["recurring_reports"][str(report_id)]["updated_at"] = _iso_now()
                    after = store["recurring_reports"][str(report_id)]
                else:
                    after = None
                    del store["recurring_reports"][str(report_id)]

                self._save_store(user_id, workspace_id, store)

            result = self._safe_result(
                "Recurring report deleted successfully." if not soft_delete else "Recurring report archived successfully.",
                data={"deleted": True, "soft_delete": soft_delete, "recurring_report": after},
                metadata={"action": action, "report_id": report_id},
            )

            verification_payload = self._prepare_verification_payload(action, context, before, after, result)
            result["data"]["verification_payload"] = verification_payload

            self._forward_verification_payload(verification_payload)
            self._emit_agent_event("business_memory.recurring_report_deleted", context, {"report_id": report_id, "soft_delete": soft_delete})
            self._log_audit_event(action, context, True, {"report_id": report_id, "soft_delete": soft_delete})

            return result
        except Exception as exc:
            self.logger.exception("Failed to delete recurring report.")
            self._log_audit_event(action, context, False, {"report_id": report_id, "error": str(exc)})
            return self._error_result(
                "Failed to delete recurring report.",
                error=exc,
                metadata={"action": action, "report_id": report_id},
            )

    def list_due_recurring_reports(
        self,
        context: JsonDict,
        as_of: Optional[str] = None,
    ) -> ResultDict:
        """
        List active recurring reports due at or before `as_of`.

        This method does not generate or send reports. It only returns definitions that a
        scheduler/Workflow Agent can process later.
        """
        action = "list_due_recurring_reports"

        valid, error = self._validate_task_context(context)
        if not valid:
            return self._error_result("Invalid task context.", error=error, metadata={"action": action})

        try:
            as_of_dt = self._parse_iso_datetime(as_of) if as_of else _utcnow()
        except Exception as exc:
            return self._error_result("Invalid as_of datetime.", error=exc, metadata={"action": action})

        reports_result = self.list_recurring_reports(context, status="active")
        if not reports_result["success"]:
            return reports_result

        due_reports: List[JsonDict] = []
        for report in reports_result["data"].get("recurring_reports", []):
            next_run_at = report.get("next_run_at")
            if not next_run_at:
                continue
            try:
                next_run_dt = self._parse_iso_datetime(next_run_at)
            except Exception:
                continue

            if next_run_dt <= as_of_dt:
                due_reports.append(report)

        return self._safe_result(
            "Due recurring reports listed successfully.",
            data={"due_recurring_reports": due_reports, "count": len(due_reports), "as_of": as_of_dt.isoformat()},
            metadata={"action": action},
        )

    def mark_recurring_report_run(
        self,
        context: JsonDict,
        report_id: str,
        run_at: Optional[str] = None,
        run_metadata: Optional[JsonDict] = None,
    ) -> ResultDict:
        """
        Mark a recurring report as run and calculate its next run time.

        This supports Workflow Agent / Report Builder integration after report generation.
        """
        action = "mark_recurring_report_run"

        valid, error = self._validate_task_context(context)
        if not valid:
            return self._error_result("Invalid task context.", error=error, metadata={"action": action})

        if not report_id:
            return self._error_result("Recurring report ID is required.", error="MISSING_REPORT_ID", metadata={"action": action})

        approval = self._request_security_approval(action, context, {"report_id": report_id, "run_at": run_at})
        if not approval["success"]:
            self._log_audit_event(action, context, False, {"reason": "security_denied", "report_id": report_id})
            return approval

        user_id = str(context["user_id"])
        workspace_id = str(context["workspace_id"])

        try:
            run_dt = self._parse_iso_datetime(run_at) if run_at else _utcnow()

            with self._lock:
                store = self._load_store(user_id, workspace_id)
                before = _deepcopy(store["recurring_reports"].get(str(report_id)))

                if not before:
                    return self._safe_result(
                        "Recurring report not found.",
                        data={"updated": False, "found": False},
                        metadata={"action": action, "report_id": report_id},
                    )

                record = store["recurring_reports"][str(report_id)]
                record["last_run_at"] = run_dt.isoformat()
                record["next_run_at"] = self._calculate_next_run_at(
                    frequency=record["frequency"],
                    schedule=record.get("schedule") or {},
                    from_dt=run_dt,
                )
                record["updated_at"] = _iso_now()
                record["metadata"] = {
                    **(record.get("metadata") or {}),
                    "last_run_metadata": run_metadata or {},
                }

                after = _deepcopy(record)
                self._save_store(user_id, workspace_id, store)

            result = self._safe_result(
                "Recurring report run marked successfully.",
                data={"updated": True, "recurring_report": after},
                metadata={"action": action, "report_id": report_id},
            )

            verification_payload = self._prepare_verification_payload(action, context, before, after, result)
            result["data"]["verification_payload"] = verification_payload

            self._forward_verification_payload(verification_payload)
            self._emit_agent_event("business_memory.recurring_report_run_marked", context, {"report_id": report_id})
            self._log_audit_event(action, context, True, {"report_id": report_id})

            return result
        except Exception as exc:
            self.logger.exception("Failed to mark recurring report run.")
            self._log_audit_event(action, context, False, {"report_id": report_id, "error": str(exc)})
            return self._error_result(
                "Failed to mark recurring report run.",
                error=exc,
                metadata={"action": action, "report_id": report_id},
            )

    # -------------------------------------------------------------------------
    # Summary / export
    # -------------------------------------------------------------------------

    def export_business_memory_summary(self, context: JsonDict) -> ResultDict:
        """
        Export a scoped summary of business memory.

        This is safe for dashboards and Master Agent context preparation.
        It does not expose data across users/workspaces.
        """
        action = "export_business_memory_summary"

        valid, error = self._validate_task_context(context)
        if not valid:
            return self._error_result("Invalid task context.", error=error, metadata={"action": action})

        user_id = str(context["user_id"])
        workspace_id = str(context["workspace_id"])

        try:
            with self._lock:
                store = self._load_store(user_id, workspace_id)

            active_preferences = [
                item for item in store.get("preferences", {}).values()
                if bool(item.get("is_active", True))
            ]
            active_rules = [
                item for item in store.get("crm_rules", {}).values()
                if item.get("status") == "active"
            ]
            active_reports = [
                item for item in store.get("recurring_reports", {}).values()
                if item.get("status") == "active"
            ]

            summary = {
                "user_id": user_id,
                "workspace_id": workspace_id,
                "counts": {
                    "preferences_total": len(store.get("preferences", {})),
                    "preferences_active": len(active_preferences),
                    "crm_rules_total": len(store.get("crm_rules", {})),
                    "crm_rules_active": len(active_rules),
                    "recurring_reports_total": len(store.get("recurring_reports", {})),
                    "recurring_reports_active": len(active_reports),
                },
                "preference_categories": sorted(
                    {
                        str(item.get("category", "general"))
                        for item in active_preferences
                    }
                ),
                "crm_rule_targets": sorted(
                    {
                        str(item.get("applies_to", "lead"))
                        for item in active_rules
                    }
                ),
                "recurring_report_types": sorted(
                    {
                        str(item.get("report_type", "unknown"))
                        for item in active_reports
                    }
                ),
                "updated_at": store.get("updated_at"),
            }

            return self._safe_result(
                "Business memory summary exported successfully.",
                data={"summary": summary},
                metadata={"action": action},
            )
        except Exception as exc:
            self.logger.exception("Failed to export business memory summary.")
            return self._error_result(
                "Failed to export business memory summary.",
                error=exc,
                metadata={"action": action},
            )

    # -------------------------------------------------------------------------
    # Master Agent / Router compatibility
    # -------------------------------------------------------------------------

    async def handle_task(self, task: JsonDict) -> ResultDict:
        """
        Main async entrypoint for Master Agent, Agent Router, and Agent Loader.

        Expected task shape:
            {
                "action": "set_business_preference",
                "context": {"user_id": "...", "workspace_id": "..."},
                "payload": {...}
            }
        """
        return self.route_task(task)

    def route_task(self, task: JsonDict) -> ResultDict:
        """
        Synchronous router for BusinessMemory actions.

        This method keeps all public actions available through a single structured interface.
        """
        if not isinstance(task, dict):
            return self._error_result("Task must be a dictionary.", error="INVALID_TASK")

        action = str(task.get("action") or task.get("task_type") or "").strip()
        context = task.get("context") or {}
        payload = task.get("payload") or {}

        if action not in self.SUPPORTED_TASKS:
            return self._error_result(
                "Unsupported BusinessMemory task action.",
                error="UNSUPPORTED_ACTION",
                data={
                    "action": action,
                    "supported_actions": sorted(self.SUPPORTED_TASKS),
                },
            )

        if not isinstance(context, dict):
            return self._error_result("Task context must be a dictionary.", error="INVALID_CONTEXT", metadata={"action": action})

        if not isinstance(payload, dict):
            return self._error_result("Task payload must be a dictionary.", error="INVALID_PAYLOAD", metadata={"action": action})

        try:
            if action == "set_business_preference":
                return self.set_business_preference(context=context, **payload)

            if action == "get_business_preference":
                return self.get_business_preference(context=context, **payload)

            if action == "list_business_preferences":
                return self.list_business_preferences(context=context, **payload)

            if action == "delete_business_preference":
                return self.delete_business_preference(context=context, **payload)

            if action == "upsert_crm_rule":
                return self.upsert_crm_rule(context=context, **payload)

            if action == "get_crm_rule":
                return self.get_crm_rule(context=context, **payload)

            if action == "list_crm_rules":
                return self.list_crm_rules(context=context, **payload)

            if action == "delete_crm_rule":
                return self.delete_crm_rule(context=context, **payload)

            if action == "evaluate_crm_rules":
                return self.evaluate_crm_rules(context=context, **payload)

            if action == "create_recurring_report":
                return self.create_recurring_report(context=context, **payload)

            if action == "update_recurring_report":
                return self.update_recurring_report(context=context, **payload)

            if action == "get_recurring_report":
                return self.get_recurring_report(context=context, **payload)

            if action == "list_recurring_reports":
                return self.list_recurring_reports(context=context, **payload)

            if action == "delete_recurring_report":
                return self.delete_recurring_report(context=context, **payload)

            if action == "list_due_recurring_reports":
                return self.list_due_recurring_reports(context=context, **payload)

            if action == "mark_recurring_report_run":
                return self.mark_recurring_report_run(context=context, **payload)

            if action == "export_business_memory_summary":
                return self.export_business_memory_summary(context=context)

            return self._error_result(
                "BusinessMemory task route exists but no handler was executed.",
                error="ROUTE_HANDLER_MISSING",
                metadata={"action": action},
            )
        except TypeError as exc:
            self.logger.exception("Invalid payload for BusinessMemory task.")
            return self._error_result(
                "Invalid payload for BusinessMemory task.",
                error=exc,
                metadata={"action": action},
            )
        except Exception as exc:
            self.logger.exception("BusinessMemory task failed.")
            return self._error_result(
                "BusinessMemory task failed.",
                error=exc,
                metadata={"action": action},
            )

    def get_agent_manifest(self) -> JsonDict:
        """
        Return manifest for Agent Registry and Agent Loader.

        The registry can use this to discover capabilities without executing mutations.
        """
        return {
            "agent_name": self.AGENT_NAME,
            "agent_type": self.AGENT_TYPE,
            "module": self.MODULE,
            "file": self.FILE_NAME,
            "class_name": self.__class__.__name__,
            "version": "1.0.0",
            "description": "Stores business preferences, CRM rules, and recurring reports.",
            "supported_tasks": sorted(self.SUPPORTED_TASKS),
            "requires_user_id": True,
            "requires_workspace_id": True,
            "security_sensitive_actions": sorted(self.SENSITIVE_ACTIONS),
            "destructive_actions": sorted(self.DESTRUCTIVE_ACTIONS),
            "memory_agent_compatible": True,
            "verification_agent_compatible": True,
            "dashboard_ready": True,
            "fastapi_ready": True,
            "import_safe": True,
        }

    # -------------------------------------------------------------------------
    # Internal utility methods
    # -------------------------------------------------------------------------

    def _forward_memory_payload(self, payload: JsonDict) -> None:
        """Forward normalized payload to Memory Agent callback when configured."""
        if not self.memory_callback:
            return
        try:
            self.memory_callback(payload)
        except Exception:
            self.logger.exception("Failed to forward BusinessMemory payload to Memory Agent callback.")

    def _forward_verification_payload(self, payload: JsonDict) -> None:
        """Forward normalized payload to Verification Agent callback when configured."""
        if not self.verification_callback:
            return
        try:
            self.verification_callback(payload)
        except Exception:
            self.logger.exception("Failed to forward BusinessMemory payload to Verification Agent callback.")

    def _summarize_payload_for_security(self, payload: JsonDict) -> JsonDict:
        """Create a safe, compact security summary without leaking large values."""
        summary: JsonDict = {}
        for key, value in payload.items():
            if key in {"value", "conditions", "actions", "filters", "metadata"}:
                summary[key] = {
                    "type": type(value).__name__,
                    "size_chars": _json_size(value),
                }
            elif key in {"recipients"}:
                summary[key] = {
                    "count": len(value) if isinstance(value, list) else 0,
                }
            else:
                summary[key] = value
        return summary

    def _normalize_recipients(self, recipients: List[Any]) -> List[str]:
        """
        Normalize report recipients.

        This accepts emails or internal recipient identifiers. Validation is intentionally
        moderate because future notification channels may use non-email IDs.
        """
        normalized: List[str] = []
        for item in recipients:
            value = str(item).strip()
            if value and value not in normalized:
                normalized.append(value[:254])
        return normalized[: self.max_report_recipients]

    def _parse_iso_datetime(self, value: str) -> datetime:
        """Parse ISO datetime and normalize to UTC when timezone is missing."""
        if not value:
            raise ValueError("Datetime value is empty.")

        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    def _calculate_next_run_at(
        self,
        frequency: ReportFrequency,
        schedule: JsonDict,
        from_dt: Optional[datetime] = None,
    ) -> str:
        """
        Calculate a simple next run timestamp.

        Production scheduler can later replace this with advanced timezone-aware RRULE logic.
        This method keeps safe defaults:
            - daily: +1 day
            - weekly: +7 days
            - monthly: +30 days
            - quarterly: +90 days

        If schedule contains {"next_run_at": "..."} and it is in the future, that is respected.
        """
        now = from_dt or _utcnow()

        explicit_next = schedule.get("next_run_at") if isinstance(schedule, dict) else None
        if explicit_next:
            try:
                explicit_dt = self._parse_iso_datetime(str(explicit_next))
                if explicit_dt > now:
                    return explicit_dt.isoformat()
            except Exception:
                pass

        if frequency == "daily":
            next_dt = now + timedelta(days=1)
        elif frequency == "weekly":
            next_dt = now + timedelta(days=7)
        elif frequency == "monthly":
            next_dt = now + timedelta(days=30)
        elif frequency == "quarterly":
            next_dt = now + timedelta(days=90)
        else:
            next_dt = now + timedelta(days=1)

        time_value = str(schedule.get("time", "")).strip() if isinstance(schedule, dict) else ""
        if re.match(r"^\d{2}:\d{2}$", time_value):
            try:
                hour, minute = [int(part) for part in time_value.split(":")]
                if 0 <= hour <= 23 and 0 <= minute <= 59:
                    next_dt = next_dt.replace(hour=hour, minute=minute, second=0, microsecond=0)
            except Exception:
                pass

        return next_dt.astimezone(timezone.utc).isoformat()

    def _rule_matches(self, entity: JsonDict, conditions: List[JsonDict]) -> bool:
        """
        Evaluate CRM rule conditions against an entity.

        Supported operators:
            - equals / ==
            - not_equals / !=
            - contains
            - not_contains
            - in
            - not_in
            - >=, >, <=, <
            - exists
            - missing

        Condition shape:
            {"field": "lead_score", "operator": ">=", "value": 80}
        """
        for condition in conditions:
            field_name = str(condition.get("field", "")).strip()
            operator = str(condition.get("operator", "equals")).strip().lower()
            expected = condition.get("value")

            if not field_name:
                return False

            actual = self._get_nested_value(entity, field_name)
            exists = actual is not None

            if operator in {"exists"}:
                if not exists:
                    return False
                continue

            if operator in {"missing", "not_exists"}:
                if exists:
                    return False
                continue

            if operator in {"equals", "=="}:
                if actual != expected:
                    return False
            elif operator in {"not_equals", "!="}:
                if actual == expected:
                    return False
            elif operator == "contains":
                if actual is None or str(expected).lower() not in str(actual).lower():
                    return False
            elif operator == "not_contains":
                if actual is not None and str(expected).lower() in str(actual).lower():
                    return False
            elif operator == "in":
                if not isinstance(expected, list) or actual not in expected:
                    return False
            elif operator == "not_in":
                if isinstance(expected, list) and actual in expected:
                    return False
            elif operator in {">=", ">", "<=", "<"}:
                if not self._compare_numeric(actual, expected, operator):
                    return False
            else:
                return False

        return True

    def _get_nested_value(self, data: JsonDict, dotted_field: str) -> Any:
        """Get nested dict value using dotted path syntax."""
        current: Any = data
        for part in dotted_field.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        return current

    def _compare_numeric(self, actual: Any, expected: Any, operator: str) -> bool:
        """Safely compare numeric values."""
        try:
            actual_float = float(actual)
            expected_float = float(expected)
        except Exception:
            return False

        if operator == ">=":
            return actual_float >= expected_float
        if operator == ">":
            return actual_float > expected_float
        if operator == "<=":
            return actual_float <= expected_float
        if operator == "<":
            return actual_float < expected_float
        return False


__all__ = [
    "BusinessMemory",
    "BusinessPreference",
    "CrmRule",
    "RecurringReport",
]


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    memory = BusinessMemory()
    demo_context = {
        "user_id": "demo_user",
        "workspace_id": "demo_workspace",
        "actor_id": "demo_user",
        "security_approved": True,
    }

    print(
        json.dumps(
            memory.set_business_preference(
                context=demo_context,
                key="preferred_report_tone",
                value="executive",
                category="reports",
                description="Default tone for recurring business reports.",
                tags=["reports", "tone"],
            ),
            indent=2,
            ensure_ascii=False,
            default=str,
        )
    )

    print(
        json.dumps(
            memory.upsert_crm_rule(
                context=demo_context,
                name="Hot lead score rule",
                conditions=[
                    {"field": "lead_score", "operator": ">=", "value": 80},
                ],
                actions=[
                    {"type": "suggest_stage", "stage": "Hot Lead"},
                    {"type": "suggest_follow_up", "priority": "high"},
                ],
                priority=10,
                applies_to="lead",
                tags=["lead", "scoring"],
            ),
            indent=2,
            ensure_ascii=False,
            default=str,
        )
    )

    print(
        json.dumps(
            memory.create_recurring_report(
                context=demo_context,
                name="Weekly Business Summary",
                report_type="weekly_business_summary",
                frequency="weekly",
                schedule={"day_of_week": "monday", "time": "09:00"},
                recipients=["owner@example.com"],
                delivery_channels=["dashboard", "email"],
                filters={"include_revenue": True, "include_leads": True},
            ),
            indent=2,
            ensure_ascii=False,
            default=str,
        )
    )

    print(
        json.dumps(
            memory.export_business_memory_summary(context=demo_context),
            indent=2,
            ensure_ascii=False,
            default=str,
        )
    )