"""
agents/workflow_agent/crm_connector.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
Workflow Agent CRM Connector

Purpose:
    Creates and updates CRM contacts, deals, tags, notes, tasks, and pipeline stages
    in a SaaS-safe, user/workspace-isolated way.

Architecture Compatibility:
    - BaseAgent compatible with safe fallback if BaseAgent is not available yet.
    - Master Agent / Agent Router compatible through structured public methods.
    - Security Agent compatible through permission/security approval hooks.
    - Verification Agent compatible through verification payload preparation.
    - Memory Agent compatible through memory payload preparation.
    - Dashboard/API compatible through structured dict responses.
    - Agent Registry / Agent Loader safe because this file is import-safe.

Important Safety Rules:
    - No hardcoded secrets.
    - No real external CRM API calls are executed directly.
    - All tenant data is isolated by user_id and workspace_id.
    - Every public action validates task context.
    - Sensitive/destructive actions must go through security hooks.
    - Results follow success/message/data/error/metadata structure.

Notes:
    This connector includes a production-ready in-memory backend for local testing,
    development, and workflow simulation. Later, real CRM providers such as HubSpot,
    GoHighLevel, Salesforce, Zoho, Pipedrive, or custom CRMs can be connected behind
    the same public methods without changing Master Agent routing.
"""

from __future__ import annotations

import copy
import logging
import re
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Safe optional BaseAgent import
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for early project bootstrapping
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps crm_connector.py import-safe even before the real BaseAgent
        exists. The real William/Jarvis BaseAgent can override these methods
        without breaking this connector.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_type = kwargs.get("agent_type", "workflow_agent")
            self.logger = logging.getLogger(self.agent_name)

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback emit_event: %s | %s", event_name, payload)

        def log_audit_event(self, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback audit_event: %s", payload)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Enums / Constants
# ---------------------------------------------------------------------------

class CRMEntityType(str, Enum):
    CONTACT = "contact"
    DEAL = "deal"
    TAG = "tag"
    NOTE = "note"
    TASK = "task"
    PIPELINE_STAGE = "pipeline_stage"


class CRMAction(str, Enum):
    CREATE_CONTACT = "create_contact"
    UPDATE_CONTACT = "update_contact"
    UPSERT_CONTACT = "upsert_contact"

    CREATE_DEAL = "create_deal"
    UPDATE_DEAL = "update_deal"
    UPSERT_DEAL = "upsert_deal"

    CREATE_TAG = "create_tag"
    UPDATE_TAG = "update_tag"
    ASSIGN_TAG = "assign_tag"
    REMOVE_TAG = "remove_tag"

    CREATE_NOTE = "create_note"
    UPDATE_NOTE = "update_note"

    CREATE_TASK = "create_task"
    UPDATE_TASK = "update_task"

    CREATE_PIPELINE_STAGE = "create_pipeline_stage"
    UPDATE_PIPELINE_STAGE = "update_pipeline_stage"

    SEARCH_CONTACTS = "search_contacts"
    SEARCH_DEALS = "search_deals"
    GET_RECORD = "get_record"


class CRMTaskStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class CRMDealStatus(str, Enum):
    OPEN = "open"
    WON = "won"
    LOST = "lost"
    ARCHIVED = "archived"


class CRMPriority(str, Enum):
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


DEFAULT_PIPELINE_NAME = "Default Pipeline"
DEFAULT_STAGE_NAME = "New Lead"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def _new_id(prefix: str) -> str:
    """Create stable human-readable IDs for internal CRM records."""
    return f"{prefix}_{uuid.uuid4().hex}"


def _normalize_text(value: Any) -> str:
    """Normalize text for comparisons and deduplication."""
    if value is None:
        return ""
    return str(value).strip()


def _normalize_email(email: Any) -> str:
    """Normalize email for contact matching."""
    return _normalize_text(email).lower()


def _normalize_phone(phone: Any) -> str:
    """Normalize phone by keeping digits and leading plus when available."""
    raw = _normalize_text(phone)
    if not raw:
        return ""
    if raw.startswith("+"):
        return "+" + re.sub(r"\D+", "", raw)
    return re.sub(r"\D+", "", raw)


def _deepcopy_json_safe(value: Any) -> Any:
    """
    Return a deep copy for safe result payloads.

    This prevents callers from accidentally mutating connector internal state.
    """
    return copy.deepcopy(value)


def _clean_dict(data: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    """Convert an optional mapping into a plain dict and remove None values."""
    if not data:
        return {}
    return {str(k): v for k, v in dict(data).items() if v is not None}


def _listify(value: Optional[Union[str, Iterable[str]]]) -> List[str]:
    """Normalize tag/ID values into unique string list."""
    if value is None:
        return []
    if isinstance(value, str):
        values = [value]
    else:
        values = list(value)

    output: List[str] = []
    seen = set()
    for item in values:
        text = _normalize_text(item)
        if text and text not in seen:
            output.append(text)
            seen.add(text)
    return output


def _matches_query(record: Mapping[str, Any], query: str) -> bool:
    """Basic full-text search across primitive fields."""
    if not query:
        return True

    needle = query.lower().strip()
    if not needle:
        return True

    def walk(value: Any) -> Iterable[str]:
        if isinstance(value, Mapping):
            for child in value.values():
                yield from walk(child)
        elif isinstance(value, list):
            for child in value:
                yield from walk(child)
        elif value is not None:
            yield str(value)

    return any(needle in item.lower() for item in walk(record))


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class CRMContext:
    """
    SaaS execution context.

    Every CRM operation must include user_id and workspace_id to prevent
    cross-tenant memory, files, CRM data, logs, audit events, or analytics leaks.
    """

    user_id: str
    workspace_id: str
    role: Optional[str] = None
    subscription_id: Optional[str] = None
    request_id: Optional[str] = None
    task_id: Optional[str] = None
    source_agent: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CRMContact:
    id: str
    user_id: str
    workspace_id: str
    first_name: str = ""
    last_name: str = ""
    full_name: str = ""
    email: str = ""
    phone: str = ""
    company: str = ""
    title: str = ""
    source: str = ""
    status: str = "lead"
    tags: List[str] = field(default_factory=list)
    custom_fields: Dict[str, Any] = field(default_factory=dict)
    owner_id: Optional[str] = None
    created_at: str = field(default_factory=_utc_now)
    updated_at: str = field(default_factory=_utc_now)


@dataclass
class CRMDeal:
    id: str
    user_id: str
    workspace_id: str
    title: str
    contact_id: Optional[str] = None
    value: Optional[float] = None
    currency: str = "USD"
    pipeline_id: Optional[str] = None
    stage_id: Optional[str] = None
    status: str = CRMDealStatus.OPEN.value
    probability: Optional[float] = None
    expected_close_date: Optional[str] = None
    source: str = ""
    tags: List[str] = field(default_factory=list)
    custom_fields: Dict[str, Any] = field(default_factory=dict)
    owner_id: Optional[str] = None
    created_at: str = field(default_factory=_utc_now)
    updated_at: str = field(default_factory=_utc_now)


@dataclass
class CRMTag:
    id: str
    user_id: str
    workspace_id: str
    name: str
    color: Optional[str] = None
    description: str = ""
    created_at: str = field(default_factory=_utc_now)
    updated_at: str = field(default_factory=_utc_now)


@dataclass
class CRMNote:
    id: str
    user_id: str
    workspace_id: str
    entity_type: str
    entity_id: str
    body: str
    title: str = ""
    visibility: str = "workspace"
    created_by: Optional[str] = None
    created_at: str = field(default_factory=_utc_now)
    updated_at: str = field(default_factory=_utc_now)


@dataclass
class CRMTask:
    id: str
    user_id: str
    workspace_id: str
    title: str
    description: str = ""
    entity_type: Optional[str] = None
    entity_id: Optional[str] = None
    assignee_id: Optional[str] = None
    due_at: Optional[str] = None
    status: str = CRMTaskStatus.OPEN.value
    priority: str = CRMPriority.NORMAL.value
    created_by: Optional[str] = None
    completed_at: Optional[str] = None
    created_at: str = field(default_factory=_utc_now)
    updated_at: str = field(default_factory=_utc_now)


@dataclass
class CRMPipelineStage:
    id: str
    user_id: str
    workspace_id: str
    name: str
    pipeline_name: str = DEFAULT_PIPELINE_NAME
    order: int = 0
    probability: Optional[float] = None
    color: Optional[str] = None
    is_won_stage: bool = False
    is_lost_stage: bool = False
    created_at: str = field(default_factory=_utc_now)
    updated_at: str = field(default_factory=_utc_now)


@dataclass
class CRMOperationResult:
    """
    Internal normalized operation result.

    Public methods return dicts through _safe_result / _error_result, but this
    dataclass helps provider adapters keep a clear internal contract.
    """

    success: bool
    message: str
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# In-memory tenant-isolated CRM backend
# ---------------------------------------------------------------------------

class InMemoryCRMStore:
    """
    Thread-safe in-memory CRM store.

    This is intentionally tenant-scoped by user_id + workspace_id. It gives the
    Workflow Agent a testable CRM layer before real CRM providers are connected.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._store: Dict[str, Dict[str, Dict[str, Dict[str, Any]]]] = {}

    @staticmethod
    def tenant_key(user_id: str, workspace_id: str) -> str:
        return f"{user_id}::{workspace_id}"

    def _tenant(self, user_id: str, workspace_id: str) -> Dict[str, Dict[str, Dict[str, Any]]]:
        key = self.tenant_key(user_id, workspace_id)
        if key not in self._store:
            self._store[key] = {
                CRMEntityType.CONTACT.value: {},
                CRMEntityType.DEAL.value: {},
                CRMEntityType.TAG.value: {},
                CRMEntityType.NOTE.value: {},
                CRMEntityType.TASK.value: {},
                CRMEntityType.PIPELINE_STAGE.value: {},
            }
        return self._store[key]

    def save(
        self,
        user_id: str,
        workspace_id: str,
        entity_type: CRMEntityType,
        record: Mapping[str, Any],
    ) -> Dict[str, Any]:
        with self._lock:
            tenant = self._tenant(user_id, workspace_id)
            payload = _deepcopy_json_safe(dict(record))
            tenant[entity_type.value][payload["id"]] = payload
            return _deepcopy_json_safe(payload)

    def get(
        self,
        user_id: str,
        workspace_id: str,
        entity_type: CRMEntityType,
        record_id: str,
    ) -> Optional[Dict[str, Any]]:
        with self._lock:
            tenant = self._tenant(user_id, workspace_id)
            record = tenant[entity_type.value].get(record_id)
            return _deepcopy_json_safe(record) if record else None

    def list_records(
        self,
        user_id: str,
        workspace_id: str,
        entity_type: CRMEntityType,
    ) -> List[Dict[str, Any]]:
        with self._lock:
            tenant = self._tenant(user_id, workspace_id)
            return [_deepcopy_json_safe(v) for v in tenant[entity_type.value].values()]

    def update(
        self,
        user_id: str,
        workspace_id: str,
        entity_type: CRMEntityType,
        record_id: str,
        updates: Mapping[str, Any],
    ) -> Optional[Dict[str, Any]]:
        with self._lock:
            tenant = self._tenant(user_id, workspace_id)
            current = tenant[entity_type.value].get(record_id)
            if not current:
                return None

            cleaned = _clean_dict(updates)
            current.update(cleaned)
            current["updated_at"] = _utc_now()
            tenant[entity_type.value][record_id] = current
            return _deepcopy_json_safe(current)

    def find_one(
        self,
        user_id: str,
        workspace_id: str,
        entity_type: CRMEntityType,
        predicate: Callable[[Dict[str, Any]], bool],
    ) -> Optional[Dict[str, Any]]:
        with self._lock:
            records = self.list_records(user_id, workspace_id, entity_type)
            for record in records:
                if predicate(record):
                    return record
            return None

    def search(
        self,
        user_id: str,
        workspace_id: str,
        entity_type: CRMEntityType,
        query: str = "",
        filters: Optional[Mapping[str, Any]] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        with self._lock:
            filters = _clean_dict(filters)
            records = self.list_records(user_id, workspace_id, entity_type)

            def passes_filters(record: Mapping[str, Any]) -> bool:
                for key, expected in filters.items():
                    actual = record.get(key)
                    if isinstance(expected, list):
                        if actual not in expected:
                            return False
                    elif actual != expected:
                        return False
                return True

            matched = [
                record
                for record in records
                if _matches_query(record, query) and passes_filters(record)
            ]

            matched.sort(key=lambda item: item.get("updated_at", ""), reverse=True)
            total = len(matched)
            safe_limit = max(1, min(int(limit or 50), 200))
            safe_offset = max(0, int(offset or 0))
            return matched[safe_offset:safe_offset + safe_limit], total


# ---------------------------------------------------------------------------
# CRM Connector
# ---------------------------------------------------------------------------

class CRMConnector(BaseAgent):
    """
    Workflow Agent CRM connector.

    Public methods are designed for Master Agent / Workflow Agent / Action Router
    calls and return structured dict responses.

    This connector does not directly call external CRMs without permission and
    configuration. Its built-in in-memory backend makes the module immediately
    testable and safe to import in incomplete deployments.
    """

    agent_name = "workflow_crm_connector"
    agent_type = "workflow_agent"
    module_name = "crm_connector"
    version = "1.0.0"

    def __init__(
        self,
        provider_name: str = "memory",
        config: Optional[Mapping[str, Any]] = None,
        security_client: Optional[Any] = None,
        verification_client: Optional[Any] = None,
        memory_client: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        event_emitter: Optional[Any] = None,
        store: Optional[InMemoryCRMStore] = None,
        logger_instance: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            agent_name=self.agent_name,
            agent_type=self.agent_type,
            **kwargs,
        )
        self.provider_name = provider_name or "memory"
        self.config = _clean_dict(config)
        self.security_client = security_client
        self.verification_client = verification_client
        self.memory_client = memory_client
        self.audit_logger = audit_logger
        self.event_emitter = event_emitter
        self.store = store or InMemoryCRMStore()
        self.logger = logger_instance or logging.getLogger(
            "william.workflow_agent.crm_connector"
        )

    # ------------------------------------------------------------------
    # Required compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(self, context: Mapping[str, Any]) -> CRMContext:
        """
        Validate SaaS execution context.

        Raises:
            ValueError: If user_id or workspace_id is missing.
        """
        if not isinstance(context, Mapping):
            raise ValueError("context must be a mapping with user_id and workspace_id")

        user_id = _normalize_text(context.get("user_id"))
        workspace_id = _normalize_text(context.get("workspace_id"))

        if not user_id:
            raise ValueError("user_id is required for CRMConnector operations")
        if not workspace_id:
            raise ValueError("workspace_id is required for CRMConnector operations")

        permissions = context.get("permissions") or []
        if isinstance(permissions, str):
            permissions = [permissions]

        metadata = context.get("metadata") or {}
        if not isinstance(metadata, Mapping):
            metadata = {"raw_metadata": metadata}

        return CRMContext(
            user_id=user_id,
            workspace_id=workspace_id,
            role=_normalize_text(context.get("role")) or None,
            subscription_id=_normalize_text(context.get("subscription_id")) or None,
            request_id=_normalize_text(context.get("request_id")) or None,
            task_id=_normalize_text(context.get("task_id")) or None,
            source_agent=_normalize_text(context.get("source_agent")) or None,
            permissions=[_normalize_text(p) for p in permissions if _normalize_text(p)],
            metadata=dict(metadata),
        )

    def _requires_security_check(
        self,
        action: Union[str, CRMAction],
        payload: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Decide whether an action needs Security Agent approval.

        Creating/updating CRM records is allowed by default for the in-memory
        provider. Real external provider writes, high-value deals, won/lost deal
        transitions, and tag removals are treated as sensitive.
        """
        action_value = action.value if isinstance(action, CRMAction) else str(action)
        payload = payload or {}

        if self.provider_name != "memory":
            return True

        sensitive_actions = {
            CRMAction.REMOVE_TAG.value,
        }
        if action_value in sensitive_actions:
            return True

        if action_value in {CRMAction.UPDATE_DEAL.value, CRMAction.UPSERT_DEAL.value}:
            status = _normalize_text(payload.get("status")).lower()
            if status in {CRMDealStatus.WON.value, CRMDealStatus.LOST.value, CRMDealStatus.ARCHIVED.value}:
                return True

            try:
                value = float(payload.get("value") or 0)
                threshold = float(self.config.get("high_value_deal_threshold", 10000))
                if value >= threshold:
                    return True
            except Exception:
                return False

        return False

    def _request_security_approval(
        self,
        ctx: CRMContext,
        action: Union[str, CRMAction],
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request permission from Security Agent/client.

        If no security client is configured, memory-provider safe actions pass.
        Sensitive actions without a security client are denied by default.
        """
        action_value = action.value if isinstance(action, CRMAction) else str(action)
        payload = _clean_dict(payload)

        approval_payload = {
            "agent": self.agent_name,
            "module": self.module_name,
            "action": action_value,
            "user_id": ctx.user_id,
            "workspace_id": ctx.workspace_id,
            "request_id": ctx.request_id,
            "task_id": ctx.task_id,
            "provider_name": self.provider_name,
            "payload_summary": self._summarize_payload_for_security(payload),
            "created_at": _utc_now(),
        }

        if self.security_client and hasattr(self.security_client, "approve_action"):
            try:
                response = self.security_client.approve_action(approval_payload)
                if isinstance(response, Mapping):
                    approved = bool(response.get("approved") or response.get("success"))
                    return {
                        "approved": approved,
                        "message": str(response.get("message") or "Security check completed."),
                        "data": dict(response),
                    }
            except Exception as exc:
                self.logger.exception("Security approval failed: %s", exc)
                return {
                    "approved": False,
                    "message": "Security approval failed.",
                    "data": {"exception": str(exc)},
                }

        if self._requires_security_check(action_value, payload):
            return {
                "approved": False,
                "message": "Security approval required but no Security Agent/client is configured.",
                "data": approval_payload,
            }

        return {
            "approved": True,
            "message": "Security approval not required for this safe local operation.",
            "data": approval_payload,
        }

    def _prepare_verification_payload(
        self,
        ctx: CRMContext,
        action: Union[str, CRMAction],
        result: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare payload for Verification Agent.

        Verification Agent can use this to confirm created/updated IDs, CRM
        entity type, workspace isolation, and result consistency.
        """
        action_value = action.value if isinstance(action, CRMAction) else str(action)
        data = result.get("data") if isinstance(result.get("data"), Mapping) else {}

        return {
            "verification_type": "crm_operation",
            "agent": self.agent_name,
            "module": self.module_name,
            "action": action_value,
            "provider_name": self.provider_name,
            "user_id": ctx.user_id,
            "workspace_id": ctx.workspace_id,
            "request_id": ctx.request_id,
            "task_id": ctx.task_id,
            "success": bool(result.get("success")),
            "record_id": data.get("id") or data.get("record_id"),
            "entity_type": data.get("entity_type"),
            "created_at": _utc_now(),
            "metadata": {
                "message": result.get("message"),
                "error": result.get("error"),
            },
        }

    def _prepare_memory_payload(
        self,
        ctx: CRMContext,
        action: Union[str, CRMAction],
        result: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare CRM memory summary for Memory Agent.

        This does not store sensitive CRM internals by default. It stores useful
        task context only, scoped to user/workspace.
        """
        action_value = action.value if isinstance(action, CRMAction) else str(action)
        data = result.get("data") if isinstance(result.get("data"), Mapping) else {}

        return {
            "memory_type": "workflow_crm_event",
            "agent": self.agent_name,
            "module": self.module_name,
            "action": action_value,
            "user_id": ctx.user_id,
            "workspace_id": ctx.workspace_id,
            "request_id": ctx.request_id,
            "task_id": ctx.task_id,
            "summary": result.get("message"),
            "entity_type": data.get("entity_type"),
            "record_id": data.get("id") or data.get("record_id"),
            "created_at": _utc_now(),
            "metadata": {
                "provider_name": self.provider_name,
                "success": bool(result.get("success")),
            },
        }

    def _emit_agent_event(
        self,
        event_name: str,
        payload: Mapping[str, Any],
    ) -> None:
        """
        Emit an event for dashboard/API/agent monitoring.

        Works with injected event emitter, real BaseAgent emit_event, or fallback
        logger.
        """
        safe_payload = _deepcopy_json_safe(dict(payload))
        try:
            if self.event_emitter and hasattr(self.event_emitter, "emit"):
                self.event_emitter.emit(event_name, safe_payload)
                return

            if hasattr(super(), "emit_event"):
                try:
                    super().emit_event(event_name, safe_payload)  # type: ignore[misc]
                    return
                except Exception:
                    pass

            self.logger.debug("Agent event emitted: %s | %s", event_name, safe_payload)
        except Exception as exc:
            self.logger.warning("Failed to emit CRM agent event %s: %s", event_name, exc)

    def _log_audit_event(
        self,
        ctx: CRMContext,
        action: Union[str, CRMAction],
        payload: Optional[Mapping[str, Any]] = None,
        result: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Log audit event.

        Audit events are tenant-scoped and avoid storing raw secrets.
        """
        action_value = action.value if isinstance(action, CRMAction) else str(action)
        audit_payload = {
            "agent": self.agent_name,
            "module": self.module_name,
            "action": action_value,
            "provider_name": self.provider_name,
            "user_id": ctx.user_id,
            "workspace_id": ctx.workspace_id,
            "request_id": ctx.request_id,
            "task_id": ctx.task_id,
            "source_agent": ctx.source_agent,
            "payload_summary": self._summarize_payload_for_security(payload or {}),
            "success": bool(result.get("success")) if result else None,
            "message": result.get("message") if result else None,
            "error": result.get("error") if result else None,
            "created_at": _utc_now(),
        }

        try:
            if self.audit_logger and hasattr(self.audit_logger, "log"):
                self.audit_logger.log(audit_payload)
                return

            if hasattr(super(), "log_audit_event"):
                try:
                    super().log_audit_event(audit_payload)  # type: ignore[misc]
                    return
                except Exception:
                    pass

            self.logger.info("CRM audit event: %s", audit_payload)
        except Exception as exc:
            self.logger.warning("Failed to log CRM audit event: %s", exc)

    def _safe_result(
        self,
        success: bool = True,
        message: str = "CRM operation completed.",
        data: Optional[Mapping[str, Any]] = None,
        error: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard William/Jarvis structured result."""
        return {
            "success": bool(success),
            "message": message,
            "data": _deepcopy_json_safe(dict(data or {})),
            "error": _deepcopy_json_safe(dict(error or {})) if error else None,
            "metadata": {
                "agent": self.agent_name,
                "module": self.module_name,
                "provider_name": self.provider_name,
                "timestamp": _utc_now(),
                **_clean_dict(metadata),
            },
        }

    def _error_result(
        self,
        message: str,
        error_code: str = "crm_connector_error",
        details: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard structured error result."""
        return self._safe_result(
            success=False,
            message=message,
            data={},
            error={
                "code": error_code,
                "details": _deepcopy_json_safe(dict(details or {})),
            },
            metadata=metadata,
        )

    # ------------------------------------------------------------------
    # Public Contact Methods
    # ------------------------------------------------------------------

    def create_contact(
        self,
        context: Mapping[str, Any],
        contact: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Create a CRM contact scoped to user_id/workspace_id."""
        return self._execute(
            context=context,
            action=CRMAction.CREATE_CONTACT,
            payload=contact,
            operation=lambda ctx: self._create_contact(ctx, contact),
        )

    def update_contact(
        self,
        context: Mapping[str, Any],
        contact_id: str,
        updates: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Update an existing CRM contact scoped to user_id/workspace_id."""
        payload = {"contact_id": contact_id, **_clean_dict(updates)}
        return self._execute(
            context=context,
            action=CRMAction.UPDATE_CONTACT,
            payload=payload,
            operation=lambda ctx: self._update_contact(ctx, contact_id, updates),
        )

    def upsert_contact(
        self,
        context: Mapping[str, Any],
        contact: Mapping[str, Any],
        match_by: Optional[Iterable[str]] = None,
    ) -> Dict[str, Any]:
        """
        Create or update contact.

        Default match order:
            1. email
            2. phone
            3. full_name + company
        """
        payload = {"contact": _clean_dict(contact), "match_by": _listify(match_by)}
        return self._execute(
            context=context,
            action=CRMAction.UPSERT_CONTACT,
            payload=payload,
            operation=lambda ctx: self._upsert_contact(ctx, contact, match_by),
        )

    def search_contacts(
        self,
        context: Mapping[str, Any],
        query: str = "",
        filters: Optional[Mapping[str, Any]] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """Search CRM contacts within a single user/workspace tenant."""
        payload = {
            "query": query,
            "filters": _clean_dict(filters),
            "limit": limit,
            "offset": offset,
        }
        return self._execute(
            context=context,
            action=CRMAction.SEARCH_CONTACTS,
            payload=payload,
            operation=lambda ctx: self._search_records(
                ctx,
                CRMEntityType.CONTACT,
                query=query,
                filters=filters,
                limit=limit,
                offset=offset,
            ),
        )

    # ------------------------------------------------------------------
    # Public Deal Methods
    # ------------------------------------------------------------------

    def create_deal(
        self,
        context: Mapping[str, Any],
        deal: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Create a CRM deal."""
        return self._execute(
            context=context,
            action=CRMAction.CREATE_DEAL,
            payload=deal,
            operation=lambda ctx: self._create_deal(ctx, deal),
        )

    def update_deal(
        self,
        context: Mapping[str, Any],
        deal_id: str,
        updates: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Update a CRM deal."""
        payload = {"deal_id": deal_id, **_clean_dict(updates)}
        return self._execute(
            context=context,
            action=CRMAction.UPDATE_DEAL,
            payload=payload,
            operation=lambda ctx: self._update_deal(ctx, deal_id, updates),
        )

    def upsert_deal(
        self,
        context: Mapping[str, Any],
        deal: Mapping[str, Any],
        match_by: Optional[Iterable[str]] = None,
    ) -> Dict[str, Any]:
        """Create or update a CRM deal."""
        payload = {"deal": _clean_dict(deal), "match_by": _listify(match_by)}
        return self._execute(
            context=context,
            action=CRMAction.UPSERT_DEAL,
            payload=payload,
            operation=lambda ctx: self._upsert_deal(ctx, deal, match_by),
        )

    def search_deals(
        self,
        context: Mapping[str, Any],
        query: str = "",
        filters: Optional[Mapping[str, Any]] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """Search CRM deals within a single user/workspace tenant."""
        payload = {
            "query": query,
            "filters": _clean_dict(filters),
            "limit": limit,
            "offset": offset,
        }
        return self._execute(
            context=context,
            action=CRMAction.SEARCH_DEALS,
            payload=payload,
            operation=lambda ctx: self._search_records(
                ctx,
                CRMEntityType.DEAL,
                query=query,
                filters=filters,
                limit=limit,
                offset=offset,
            ),
        )

    # ------------------------------------------------------------------
    # Public Tag Methods
    # ------------------------------------------------------------------

    def create_tag(
        self,
        context: Mapping[str, Any],
        name: str,
        color: Optional[str] = None,
        description: str = "",
    ) -> Dict[str, Any]:
        """Create a CRM tag."""
        payload = {"name": name, "color": color, "description": description}
        return self._execute(
            context=context,
            action=CRMAction.CREATE_TAG,
            payload=payload,
            operation=lambda ctx: self._create_tag(ctx, name, color, description),
        )

    def update_tag(
        self,
        context: Mapping[str, Any],
        tag_id: str,
        updates: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Update a CRM tag."""
        payload = {"tag_id": tag_id, **_clean_dict(updates)}
        return self._execute(
            context=context,
            action=CRMAction.UPDATE_TAG,
            payload=payload,
            operation=lambda ctx: self._update_record(
                ctx,
                CRMEntityType.TAG,
                tag_id,
                updates,
            ),
        )

    def assign_tag(
        self,
        context: Mapping[str, Any],
        entity_type: str,
        entity_id: str,
        tag: str,
    ) -> Dict[str, Any]:
        """Assign a tag to a contact or deal."""
        payload = {
            "entity_type": entity_type,
            "entity_id": entity_id,
            "tag": tag,
        }
        return self._execute(
            context=context,
            action=CRMAction.ASSIGN_TAG,
            payload=payload,
            operation=lambda ctx: self._assign_or_remove_tag(
                ctx,
                entity_type=entity_type,
                entity_id=entity_id,
                tag=tag,
                remove=False,
            ),
        )

    def remove_tag(
        self,
        context: Mapping[str, Any],
        entity_type: str,
        entity_id: str,
        tag: str,
    ) -> Dict[str, Any]:
        """Remove a tag from a contact or deal. Security approval may be required."""
        payload = {
            "entity_type": entity_type,
            "entity_id": entity_id,
            "tag": tag,
        }
        return self._execute(
            context=context,
            action=CRMAction.REMOVE_TAG,
            payload=payload,
            operation=lambda ctx: self._assign_or_remove_tag(
                ctx,
                entity_type=entity_type,
                entity_id=entity_id,
                tag=tag,
                remove=True,
            ),
        )

    # ------------------------------------------------------------------
    # Public Note Methods
    # ------------------------------------------------------------------

    def create_note(
        self,
        context: Mapping[str, Any],
        entity_type: str,
        entity_id: str,
        body: str,
        title: str = "",
        visibility: str = "workspace",
    ) -> Dict[str, Any]:
        """Create a note against a CRM entity."""
        payload = {
            "entity_type": entity_type,
            "entity_id": entity_id,
            "body": body,
            "title": title,
            "visibility": visibility,
        }
        return self._execute(
            context=context,
            action=CRMAction.CREATE_NOTE,
            payload=payload,
            operation=lambda ctx: self._create_note(
                ctx,
                entity_type=entity_type,
                entity_id=entity_id,
                body=body,
                title=title,
                visibility=visibility,
            ),
        )

    def update_note(
        self,
        context: Mapping[str, Any],
        note_id: str,
        updates: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Update a CRM note."""
        payload = {"note_id": note_id, **_clean_dict(updates)}
        return self._execute(
            context=context,
            action=CRMAction.UPDATE_NOTE,
            payload=payload,
            operation=lambda ctx: self._update_record(
                ctx,
                CRMEntityType.NOTE,
                note_id,
                updates,
            ),
        )

    # ------------------------------------------------------------------
    # Public Task Methods
    # ------------------------------------------------------------------

    def create_task(
        self,
        context: Mapping[str, Any],
        title: str,
        description: str = "",
        entity_type: Optional[str] = None,
        entity_id: Optional[str] = None,
        assignee_id: Optional[str] = None,
        due_at: Optional[str] = None,
        priority: str = CRMPriority.NORMAL.value,
    ) -> Dict[str, Any]:
        """Create a CRM follow-up task."""
        payload = {
            "title": title,
            "description": description,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "assignee_id": assignee_id,
            "due_at": due_at,
            "priority": priority,
        }
        return self._execute(
            context=context,
            action=CRMAction.CREATE_TASK,
            payload=payload,
            operation=lambda ctx: self._create_task(
                ctx,
                title=title,
                description=description,
                entity_type=entity_type,
                entity_id=entity_id,
                assignee_id=assignee_id,
                due_at=due_at,
                priority=priority,
            ),
        )

    def update_task(
        self,
        context: Mapping[str, Any],
        task_id: str,
        updates: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Update CRM task status, due date, priority, assignee, or description."""
        payload = {"task_id": task_id, **_clean_dict(updates)}
        return self._execute(
            context=context,
            action=CRMAction.UPDATE_TASK,
            payload=payload,
            operation=lambda ctx: self._update_task(ctx, task_id, updates),
        )

    # ------------------------------------------------------------------
    # Public Pipeline Stage Methods
    # ------------------------------------------------------------------

    def create_pipeline_stage(
        self,
        context: Mapping[str, Any],
        name: str,
        pipeline_name: str = DEFAULT_PIPELINE_NAME,
        order: int = 0,
        probability: Optional[float] = None,
        color: Optional[str] = None,
        is_won_stage: bool = False,
        is_lost_stage: bool = False,
    ) -> Dict[str, Any]:
        """Create a CRM pipeline stage."""
        payload = {
            "name": name,
            "pipeline_name": pipeline_name,
            "order": order,
            "probability": probability,
            "color": color,
            "is_won_stage": is_won_stage,
            "is_lost_stage": is_lost_stage,
        }
        return self._execute(
            context=context,
            action=CRMAction.CREATE_PIPELINE_STAGE,
            payload=payload,
            operation=lambda ctx: self._create_pipeline_stage(
                ctx,
                name=name,
                pipeline_name=pipeline_name,
                order=order,
                probability=probability,
                color=color,
                is_won_stage=is_won_stage,
                is_lost_stage=is_lost_stage,
            ),
        )

    def update_pipeline_stage(
        self,
        context: Mapping[str, Any],
        stage_id: str,
        updates: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Update a CRM pipeline stage."""
        payload = {"stage_id": stage_id, **_clean_dict(updates)}
        return self._execute(
            context=context,
            action=CRMAction.UPDATE_PIPELINE_STAGE,
            payload=payload,
            operation=lambda ctx: self._update_record(
                ctx,
                CRMEntityType.PIPELINE_STAGE,
                stage_id,
                updates,
            ),
        )

    # ------------------------------------------------------------------
    # Public Generic Methods
    # ------------------------------------------------------------------

    def get_record(
        self,
        context: Mapping[str, Any],
        entity_type: str,
        record_id: str,
    ) -> Dict[str, Any]:
        """Fetch one CRM record by type and ID with tenant isolation."""
        payload = {"entity_type": entity_type, "record_id": record_id}
        return self._execute(
            context=context,
            action=CRMAction.GET_RECORD,
            payload=payload,
            operation=lambda ctx: self._get_record(ctx, entity_type, record_id),
        )

    def health_check(self) -> Dict[str, Any]:
        """Return connector health status for dashboard/API checks."""
        return self._safe_result(
            success=True,
            message="CRMConnector is healthy.",
            data={
                "agent": self.agent_name,
                "module": self.module_name,
                "version": self.version,
                "provider_name": self.provider_name,
                "storage": "in_memory" if self.provider_name == "memory" else "external_provider_pending_adapter",
            },
            metadata={"operation": "health_check"},
        )

    def get_capabilities(self) -> Dict[str, Any]:
        """
        Return capability map for Agent Registry / Agent Loader / Master Agent.
        """
        return self._safe_result(
            success=True,
            message="CRMConnector capabilities loaded.",
            data={
                "agent": self.agent_name,
                "module": self.module_name,
                "version": self.version,
                "supported_entities": [entity.value for entity in CRMEntityType],
                "supported_actions": [action.value for action in CRMAction],
                "requires_context": ["user_id", "workspace_id"],
                "safe_import": True,
                "provider_name": self.provider_name,
                "master_agent_routes": [
                    "workflow.crm.create_contact",
                    "workflow.crm.update_contact",
                    "workflow.crm.upsert_contact",
                    "workflow.crm.create_deal",
                    "workflow.crm.update_deal",
                    "workflow.crm.upsert_deal",
                    "workflow.crm.create_tag",
                    "workflow.crm.assign_tag",
                    "workflow.crm.create_note",
                    "workflow.crm.create_task",
                    "workflow.crm.create_pipeline_stage",
                    "workflow.crm.search_contacts",
                    "workflow.crm.search_deals",
                ],
            },
            metadata={"operation": "get_capabilities"},
        )

    # ------------------------------------------------------------------
    # Execution wrapper
    # ------------------------------------------------------------------

    def _execute(
        self,
        context: Mapping[str, Any],
        action: CRMAction,
        payload: Mapping[str, Any],
        operation: Callable[[CRMContext], Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Shared operation wrapper.

        Responsibilities:
            - Validate tenant context.
            - Run security checks.
            - Execute action.
            - Prepare verification payload.
            - Prepare memory payload.
            - Emit events.
            - Log audit.
            - Return structured result.
        """
        ctx: Optional[CRMContext] = None
        result: Dict[str, Any]

        try:
            ctx = self._validate_task_context(context)

            security = self._request_security_approval(ctx, action, payload)
            if not security.get("approved"):
                result = self._error_result(
                    message=security.get("message", "Security approval denied."),
                    error_code="security_approval_denied",
                    details=security.get("data") if isinstance(security.get("data"), Mapping) else {},
                    metadata={
                        "action": action.value,
                        "user_id": ctx.user_id,
                        "workspace_id": ctx.workspace_id,
                    },
                )
                self._log_audit_event(ctx, action, payload, result)
                self._emit_agent_event(
                    "workflow.crm.security_denied",
                    {
                        "action": action.value,
                        "user_id": ctx.user_id,
                        "workspace_id": ctx.workspace_id,
                        "result": result,
                    },
                )
                return result

            result = operation(ctx)

            verification_payload = self._prepare_verification_payload(ctx, action, result)
            memory_payload = self._prepare_memory_payload(ctx, action, result)

            result.setdefault("metadata", {})
            if isinstance(result["metadata"], dict):
                result["metadata"]["verification_payload"] = verification_payload
                result["metadata"]["memory_payload"] = memory_payload

            self._send_optional_verification(verification_payload)
            self._send_optional_memory(memory_payload)

            self._emit_agent_event(
                "workflow.crm.operation_completed",
                {
                    "action": action.value,
                    "user_id": ctx.user_id,
                    "workspace_id": ctx.workspace_id,
                    "success": result.get("success"),
                    "record_id": result.get("data", {}).get("id") if isinstance(result.get("data"), Mapping) else None,
                },
            )
            self._log_audit_event(ctx, action, payload, result)
            return result

        except Exception as exc:
            self.logger.exception("CRMConnector operation failed: %s", exc)
            result = self._error_result(
                message="CRM operation failed.",
                error_code="crm_operation_failed",
                details={"exception": str(exc), "action": action.value},
                metadata={"action": action.value},
            )
            if ctx is not None:
                self._log_audit_event(ctx, action, payload, result)
                self._emit_agent_event(
                    "workflow.crm.operation_failed",
                    {
                        "action": action.value,
                        "user_id": ctx.user_id,
                        "workspace_id": ctx.workspace_id,
                        "error": str(exc),
                    },
                )
            return result

    # ------------------------------------------------------------------
    # Internal Contact Operations
    # ------------------------------------------------------------------

    def _create_contact(
        self,
        ctx: CRMContext,
        contact: Mapping[str, Any],
    ) -> Dict[str, Any]:
        cleaned = _clean_dict(contact)
        first_name = _normalize_text(cleaned.get("first_name"))
        last_name = _normalize_text(cleaned.get("last_name"))
        full_name = _normalize_text(cleaned.get("full_name"))

        if not full_name:
            full_name = " ".join([part for part in [first_name, last_name] if part]).strip()

        email = _normalize_email(cleaned.get("email"))
        phone = _normalize_phone(cleaned.get("phone"))

        if not any([full_name, email, phone]):
            return self._error_result(
                "Contact requires at least full_name, email, or phone.",
                "invalid_contact_payload",
                {"required_any": ["full_name", "email", "phone"]},
            )

        existing = self._find_contact_match(ctx, {"email": email, "phone": phone, "full_name": full_name})
        if existing:
            return self._error_result(
                "Contact already exists. Use upsert_contact or update_contact.",
                "contact_already_exists",
                {"existing_contact_id": existing["id"]},
            )

        model = CRMContact(
            id=_new_id("contact"),
            user_id=ctx.user_id,
            workspace_id=ctx.workspace_id,
            first_name=first_name,
            last_name=last_name,
            full_name=full_name,
            email=email,
            phone=phone,
            company=_normalize_text(cleaned.get("company")),
            title=_normalize_text(cleaned.get("title")),
            source=_normalize_text(cleaned.get("source")),
            status=_normalize_text(cleaned.get("status")) or "lead",
            tags=_listify(cleaned.get("tags")),
            custom_fields=dict(cleaned.get("custom_fields") or {}),
            owner_id=_normalize_text(cleaned.get("owner_id")) or None,
        )

        saved = self.store.save(ctx.user_id, ctx.workspace_id, CRMEntityType.CONTACT, asdict(model))
        saved["entity_type"] = CRMEntityType.CONTACT.value

        return self._safe_result(
            success=True,
            message="CRM contact created successfully.",
            data=saved,
            metadata={
                "action": CRMAction.CREATE_CONTACT.value,
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
            },
        )

    def _update_contact(
        self,
        ctx: CRMContext,
        contact_id: str,
        updates: Mapping[str, Any],
    ) -> Dict[str, Any]:
        clean_id = _normalize_text(contact_id)
        if not clean_id:
            return self._error_result("contact_id is required.", "missing_contact_id")

        normalized_updates = self._normalize_contact_updates(updates)
        updated = self.store.update(
            ctx.user_id,
            ctx.workspace_id,
            CRMEntityType.CONTACT,
            clean_id,
            normalized_updates,
        )

        if not updated:
            return self._error_result(
                "CRM contact not found in this workspace.",
                "contact_not_found",
                {"contact_id": clean_id},
            )

        updated["entity_type"] = CRMEntityType.CONTACT.value
        return self._safe_result(
            success=True,
            message="CRM contact updated successfully.",
            data=updated,
            metadata={
                "action": CRMAction.UPDATE_CONTACT.value,
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
            },
        )

    def _upsert_contact(
        self,
        ctx: CRMContext,
        contact: Mapping[str, Any],
        match_by: Optional[Iterable[str]] = None,
    ) -> Dict[str, Any]:
        cleaned = _clean_dict(contact)
        match_fields = _listify(match_by) or ["email", "phone", "full_name_company"]

        existing = self._find_contact_match(ctx, cleaned, match_fields=match_fields)
        if existing:
            contact_id = existing["id"]
            update_result = self._update_contact(ctx, contact_id, cleaned)
            if update_result.get("success"):
                update_result["message"] = "CRM contact upserted successfully using existing contact."
                update_result["metadata"]["upsert_mode"] = "updated"
            return update_result

        create_result = self._create_contact(ctx, cleaned)
        if create_result.get("success"):
            create_result["message"] = "CRM contact upserted successfully using new contact."
            create_result["metadata"]["upsert_mode"] = "created"
        return create_result

    def _normalize_contact_updates(self, updates: Mapping[str, Any]) -> Dict[str, Any]:
        cleaned = _clean_dict(updates)
        output: Dict[str, Any] = {}

        passthrough = {
            "first_name",
            "last_name",
            "full_name",
            "company",
            "title",
            "source",
            "status",
            "custom_fields",
            "owner_id",
        }
        for key in passthrough:
            if key in cleaned:
                output[key] = cleaned[key]

        if "email" in cleaned:
            output["email"] = _normalize_email(cleaned.get("email"))
        if "phone" in cleaned:
            output["phone"] = _normalize_phone(cleaned.get("phone"))
        if "tags" in cleaned:
            output["tags"] = _listify(cleaned.get("tags"))

        output["updated_at"] = _utc_now()
        return output

    def _find_contact_match(
        self,
        ctx: CRMContext,
        contact: Mapping[str, Any],
        match_fields: Optional[Iterable[str]] = None,
    ) -> Optional[Dict[str, Any]]:
        match_fields_list = _listify(match_fields) or ["email", "phone", "full_name_company"]

        email = _normalize_email(contact.get("email"))
        phone = _normalize_phone(contact.get("phone"))
        full_name = _normalize_text(contact.get("full_name"))
        company = _normalize_text(contact.get("company")).lower()

        if not full_name:
            first = _normalize_text(contact.get("first_name"))
            last = _normalize_text(contact.get("last_name"))
            full_name = " ".join([p for p in [first, last] if p]).strip()

        def predicate(record: Dict[str, Any]) -> bool:
            if "email" in match_fields_list and email:
                if _normalize_email(record.get("email")) == email:
                    return True

            if "phone" in match_fields_list and phone:
                if _normalize_phone(record.get("phone")) == phone:
                    return True

            if "full_name_company" in match_fields_list and full_name and company:
                record_name = _normalize_text(record.get("full_name")).lower()
                record_company = _normalize_text(record.get("company")).lower()
                if record_name == full_name.lower() and record_company == company:
                    return True

            return False

        return self.store.find_one(ctx.user_id, ctx.workspace_id, CRMEntityType.CONTACT, predicate)

    # ------------------------------------------------------------------
    # Internal Deal Operations
    # ------------------------------------------------------------------

    def _create_deal(
        self,
        ctx: CRMContext,
        deal: Mapping[str, Any],
    ) -> Dict[str, Any]:
        cleaned = _clean_dict(deal)
        title = _normalize_text(cleaned.get("title") or cleaned.get("name"))

        if not title:
            return self._error_result(
                "Deal requires title.",
                "invalid_deal_payload",
                {"required": ["title"]},
            )

        contact_id = _normalize_text(cleaned.get("contact_id")) or None
        if contact_id:
            contact = self.store.get(ctx.user_id, ctx.workspace_id, CRMEntityType.CONTACT, contact_id)
            if not contact:
                return self._error_result(
                    "Deal contact_id does not exist in this workspace.",
                    "deal_contact_not_found",
                    {"contact_id": contact_id},
                )

        stage_id = _normalize_text(cleaned.get("stage_id")) or None
        pipeline_id = _normalize_text(cleaned.get("pipeline_id")) or None

        if not stage_id:
            default_stage = self._ensure_default_pipeline_stage(ctx)
            stage_id = default_stage.get("id")

        model = CRMDeal(
            id=_new_id("deal"),
            user_id=ctx.user_id,
            workspace_id=ctx.workspace_id,
            title=title,
            contact_id=contact_id,
            value=self._safe_float(cleaned.get("value")),
            currency=_normalize_text(cleaned.get("currency")) or "USD",
            pipeline_id=pipeline_id,
            stage_id=stage_id,
            status=self._normalize_deal_status(cleaned.get("status")),
            probability=self._safe_float(cleaned.get("probability")),
            expected_close_date=_normalize_text(cleaned.get("expected_close_date")) or None,
            source=_normalize_text(cleaned.get("source")),
            tags=_listify(cleaned.get("tags")),
            custom_fields=dict(cleaned.get("custom_fields") or {}),
            owner_id=_normalize_text(cleaned.get("owner_id")) or None,
        )

        saved = self.store.save(ctx.user_id, ctx.workspace_id, CRMEntityType.DEAL, asdict(model))
        saved["entity_type"] = CRMEntityType.DEAL.value

        return self._safe_result(
            success=True,
            message="CRM deal created successfully.",
            data=saved,
            metadata={
                "action": CRMAction.CREATE_DEAL.value,
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
            },
        )

    def _update_deal(
        self,
        ctx: CRMContext,
        deal_id: str,
        updates: Mapping[str, Any],
    ) -> Dict[str, Any]:
        clean_id = _normalize_text(deal_id)
        if not clean_id:
            return self._error_result("deal_id is required.", "missing_deal_id")

        normalized_updates = self._normalize_deal_updates(ctx, updates)
        if normalized_updates.get("_error"):
            err = normalized_updates.pop("_error")
            return self._error_result(
                err.get("message", "Invalid deal update."),
                err.get("code", "invalid_deal_update"),
                err.get("details", {}),
            )

        updated = self.store.update(
            ctx.user_id,
            ctx.workspace_id,
            CRMEntityType.DEAL,
            clean_id,
            normalized_updates,
        )

        if not updated:
            return self._error_result(
                "CRM deal not found in this workspace.",
                "deal_not_found",
                {"deal_id": clean_id},
            )

        updated["entity_type"] = CRMEntityType.DEAL.value
        return self._safe_result(
            success=True,
            message="CRM deal updated successfully.",
            data=updated,
            metadata={
                "action": CRMAction.UPDATE_DEAL.value,
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
            },
        )

    def _upsert_deal(
        self,
        ctx: CRMContext,
        deal: Mapping[str, Any],
        match_by: Optional[Iterable[str]] = None,
    ) -> Dict[str, Any]:
        cleaned = _clean_dict(deal)
        match_fields = _listify(match_by) or ["id", "title_contact"]

        existing = self._find_deal_match(ctx, cleaned, match_fields=match_fields)
        if existing:
            deal_id = existing["id"]
            update_result = self._update_deal(ctx, deal_id, cleaned)
            if update_result.get("success"):
                update_result["message"] = "CRM deal upserted successfully using existing deal."
                update_result["metadata"]["upsert_mode"] = "updated"
            return update_result

        create_result = self._create_deal(ctx, cleaned)
        if create_result.get("success"):
            create_result["message"] = "CRM deal upserted successfully using new deal."
            create_result["metadata"]["upsert_mode"] = "created"
        return create_result

    def _normalize_deal_updates(self, ctx: CRMContext, updates: Mapping[str, Any]) -> Dict[str, Any]:
        cleaned = _clean_dict(updates)
        output: Dict[str, Any] = {}

        passthrough = {
            "title",
            "pipeline_id",
            "expected_close_date",
            "source",
            "custom_fields",
            "owner_id",
        }

        for key in passthrough:
            if key in cleaned:
                output[key] = cleaned[key]

        if "name" in cleaned and "title" not in output:
            output["title"] = cleaned["name"]

        if "contact_id" in cleaned:
            contact_id = _normalize_text(cleaned.get("contact_id"))
            if contact_id:
                contact = self.store.get(ctx.user_id, ctx.workspace_id, CRMEntityType.CONTACT, contact_id)
                if not contact:
                    output["_error"] = {
                        "message": "Deal contact_id does not exist in this workspace.",
                        "code": "deal_contact_not_found",
                        "details": {"contact_id": contact_id},
                    }
                    return output
                output["contact_id"] = contact_id
            else:
                output["contact_id"] = None

        if "stage_id" in cleaned:
            stage_id = _normalize_text(cleaned.get("stage_id"))
            if stage_id:
                stage = self.store.get(ctx.user_id, ctx.workspace_id, CRMEntityType.PIPELINE_STAGE, stage_id)
                if not stage:
                    output["_error"] = {
                        "message": "Pipeline stage does not exist in this workspace.",
                        "code": "pipeline_stage_not_found",
                        "details": {"stage_id": stage_id},
                    }
                    return output
                output["stage_id"] = stage_id
            else:
                output["stage_id"] = None

        if "value" in cleaned:
            output["value"] = self._safe_float(cleaned.get("value"))
        if "currency" in cleaned:
            output["currency"] = _normalize_text(cleaned.get("currency")) or "USD"
        if "status" in cleaned:
            output["status"] = self._normalize_deal_status(cleaned.get("status"))
        if "probability" in cleaned:
            output["probability"] = self._safe_float(cleaned.get("probability"))
        if "tags" in cleaned:
            output["tags"] = _listify(cleaned.get("tags"))

        output["updated_at"] = _utc_now()
        return output

    def _find_deal_match(
        self,
        ctx: CRMContext,
        deal: Mapping[str, Any],
        match_fields: Optional[Iterable[str]] = None,
    ) -> Optional[Dict[str, Any]]:
        match_fields_list = _listify(match_fields) or ["id", "title_contact"]
        deal_id = _normalize_text(deal.get("id"))
        title = _normalize_text(deal.get("title") or deal.get("name")).lower()
        contact_id = _normalize_text(deal.get("contact_id"))

        def predicate(record: Dict[str, Any]) -> bool:
            if "id" in match_fields_list and deal_id:
                if record.get("id") == deal_id:
                    return True

            if "title_contact" in match_fields_list and title:
                record_title = _normalize_text(record.get("title")).lower()
                record_contact_id = _normalize_text(record.get("contact_id"))
                if record_title == title and record_contact_id == contact_id:
                    return True

            return False

        return self.store.find_one(ctx.user_id, ctx.workspace_id, CRMEntityType.DEAL, predicate)

    # ------------------------------------------------------------------
    # Internal Tag / Note / Task / Stage Operations
    # ------------------------------------------------------------------

    def _create_tag(
        self,
        ctx: CRMContext,
        name: str,
        color: Optional[str],
        description: str,
    ) -> Dict[str, Any]:
        clean_name = _normalize_text(name)
        if not clean_name:
            return self._error_result("Tag name is required.", "missing_tag_name")

        existing = self.store.find_one(
            ctx.user_id,
            ctx.workspace_id,
            CRMEntityType.TAG,
            lambda record: _normalize_text(record.get("name")).lower() == clean_name.lower(),
        )

        if existing:
            existing["entity_type"] = CRMEntityType.TAG.value
            return self._safe_result(
                success=True,
                message="CRM tag already exists.",
                data=existing,
                metadata={"action": CRMAction.CREATE_TAG.value, "deduplicated": True},
            )

        model = CRMTag(
            id=_new_id("tag"),
            user_id=ctx.user_id,
            workspace_id=ctx.workspace_id,
            name=clean_name,
            color=_normalize_text(color) or None,
            description=_normalize_text(description),
        )

        saved = self.store.save(ctx.user_id, ctx.workspace_id, CRMEntityType.TAG, asdict(model))
        saved["entity_type"] = CRMEntityType.TAG.value

        return self._safe_result(
            success=True,
            message="CRM tag created successfully.",
            data=saved,
            metadata={"action": CRMAction.CREATE_TAG.value},
        )

    def _assign_or_remove_tag(
        self,
        ctx: CRMContext,
        entity_type: str,
        entity_id: str,
        tag: str,
        remove: bool,
    ) -> Dict[str, Any]:
        entity = self._parse_entity_type(entity_type)
        if entity not in {CRMEntityType.CONTACT, CRMEntityType.DEAL}:
            return self._error_result(
                "Tags can only be assigned to contacts or deals.",
                "unsupported_tag_entity",
                {"entity_type": entity_type},
            )

        clean_id = _normalize_text(entity_id)
        clean_tag = _normalize_text(tag)
        if not clean_id:
            return self._error_result("entity_id is required.", "missing_entity_id")
        if not clean_tag:
            return self._error_result("tag is required.", "missing_tag")

        record = self.store.get(ctx.user_id, ctx.workspace_id, entity, clean_id)
        if not record:
            return self._error_result(
                "CRM entity not found in this workspace.",
                "entity_not_found",
                {"entity_type": entity.value, "entity_id": clean_id},
            )

        tags = _listify(record.get("tags"))
        if remove:
            tags = [existing for existing in tags if existing.lower() != clean_tag.lower()]
            message = "CRM tag removed successfully."
        else:
            if clean_tag.lower() not in {existing.lower() for existing in tags}:
                tags.append(clean_tag)
            self._create_tag(ctx, clean_tag, color=None, description="")
            message = "CRM tag assigned successfully."

        updated = self.store.update(
            ctx.user_id,
            ctx.workspace_id,
            entity,
            clean_id,
            {"tags": tags, "updated_at": _utc_now()},
        )
        if not updated:
            return self._error_result("CRM entity update failed.", "entity_update_failed")

        updated["entity_type"] = entity.value
        return self._safe_result(
            success=True,
            message=message,
            data=updated,
            metadata={
                "action": CRMAction.REMOVE_TAG.value if remove else CRMAction.ASSIGN_TAG.value,
                "tag": clean_tag,
            },
        )

    def _create_note(
        self,
        ctx: CRMContext,
        entity_type: str,
        entity_id: str,
        body: str,
        title: str,
        visibility: str,
    ) -> Dict[str, Any]:
        entity = self._parse_entity_type(entity_type)
        if entity not in {CRMEntityType.CONTACT, CRMEntityType.DEAL, CRMEntityType.TASK}:
            return self._error_result(
                "Notes can be attached to contacts, deals, or tasks.",
                "unsupported_note_entity",
                {"entity_type": entity_type},
            )

        clean_id = _normalize_text(entity_id)
        clean_body = _normalize_text(body)

        if not clean_id:
            return self._error_result("entity_id is required.", "missing_entity_id")
        if not clean_body:
            return self._error_result("Note body is required.", "missing_note_body")

        record = self.store.get(ctx.user_id, ctx.workspace_id, entity, clean_id)
        if not record:
            return self._error_result(
                "Note entity not found in this workspace.",
                "note_entity_not_found",
                {"entity_type": entity.value, "entity_id": clean_id},
            )

        model = CRMNote(
            id=_new_id("note"),
            user_id=ctx.user_id,
            workspace_id=ctx.workspace_id,
            entity_type=entity.value,
            entity_id=clean_id,
            body=clean_body,
            title=_normalize_text(title),
            visibility=_normalize_text(visibility) or "workspace",
            created_by=ctx.user_id,
        )

        saved = self.store.save(ctx.user_id, ctx.workspace_id, CRMEntityType.NOTE, asdict(model))
        saved["entity_type"] = CRMEntityType.NOTE.value

        return self._safe_result(
            success=True,
            message="CRM note created successfully.",
            data=saved,
            metadata={"action": CRMAction.CREATE_NOTE.value},
        )

    def _create_task(
        self,
        ctx: CRMContext,
        title: str,
        description: str,
        entity_type: Optional[str],
        entity_id: Optional[str],
        assignee_id: Optional[str],
        due_at: Optional[str],
        priority: str,
    ) -> Dict[str, Any]:
        clean_title = _normalize_text(title)
        if not clean_title:
            return self._error_result("Task title is required.", "missing_task_title")

        parsed_entity: Optional[CRMEntityType] = None
        clean_entity_id = _normalize_text(entity_id) or None

        if entity_type:
            parsed_entity = self._parse_entity_type(entity_type)
            if parsed_entity not in {CRMEntityType.CONTACT, CRMEntityType.DEAL}:
                return self._error_result(
                    "Tasks can be attached to contacts or deals.",
                    "unsupported_task_entity",
                    {"entity_type": entity_type},
                )

            if not clean_entity_id:
                return self._error_result(
                    "entity_id is required when entity_type is provided.",
                    "missing_entity_id",
                )

            record = self.store.get(ctx.user_id, ctx.workspace_id, parsed_entity, clean_entity_id)
            if not record:
                return self._error_result(
                    "Task entity not found in this workspace.",
                    "task_entity_not_found",
                    {"entity_type": parsed_entity.value, "entity_id": clean_entity_id},
                )

        model = CRMTask(
            id=_new_id("task"),
            user_id=ctx.user_id,
            workspace_id=ctx.workspace_id,
            title=clean_title,
            description=_normalize_text(description),
            entity_type=parsed_entity.value if parsed_entity else None,
            entity_id=clean_entity_id,
            assignee_id=_normalize_text(assignee_id) or None,
            due_at=_normalize_text(due_at) or None,
            priority=self._normalize_priority(priority),
            created_by=ctx.user_id,
        )

        saved = self.store.save(ctx.user_id, ctx.workspace_id, CRMEntityType.TASK, asdict(model))
        saved["entity_type"] = CRMEntityType.TASK.value

        return self._safe_result(
            success=True,
            message="CRM task created successfully.",
            data=saved,
            metadata={"action": CRMAction.CREATE_TASK.value},
        )

    def _update_task(
        self,
        ctx: CRMContext,
        task_id: str,
        updates: Mapping[str, Any],
    ) -> Dict[str, Any]:
        clean_id = _normalize_text(task_id)
        if not clean_id:
            return self._error_result("task_id is required.", "missing_task_id")

        cleaned = _clean_dict(updates)
        normalized: Dict[str, Any] = {}

        for key in ["title", "description", "assignee_id", "due_at"]:
            if key in cleaned:
                normalized[key] = cleaned[key]

        if "status" in cleaned:
            normalized["status"] = self._normalize_task_status(cleaned.get("status"))
            if normalized["status"] == CRMTaskStatus.COMPLETED.value:
                normalized["completed_at"] = _utc_now()
            elif normalized["status"] in {
                CRMTaskStatus.OPEN.value,
                CRMTaskStatus.IN_PROGRESS.value,
                CRMTaskStatus.CANCELLED.value,
            }:
                normalized["completed_at"] = None

        if "priority" in cleaned:
            normalized["priority"] = self._normalize_priority(cleaned.get("priority"))

        normalized["updated_at"] = _utc_now()

        updated = self.store.update(
            ctx.user_id,
            ctx.workspace_id,
            CRMEntityType.TASK,
            clean_id,
            normalized,
        )
        if not updated:
            return self._error_result(
                "CRM task not found in this workspace.",
                "task_not_found",
                {"task_id": clean_id},
            )

        updated["entity_type"] = CRMEntityType.TASK.value
        return self._safe_result(
            success=True,
            message="CRM task updated successfully.",
            data=updated,
            metadata={"action": CRMAction.UPDATE_TASK.value},
        )

    def _create_pipeline_stage(
        self,
        ctx: CRMContext,
        name: str,
        pipeline_name: str,
        order: int,
        probability: Optional[float],
        color: Optional[str],
        is_won_stage: bool,
        is_lost_stage: bool,
    ) -> Dict[str, Any]:
        clean_name = _normalize_text(name)
        clean_pipeline = _normalize_text(pipeline_name) or DEFAULT_PIPELINE_NAME

        if not clean_name:
            return self._error_result("Pipeline stage name is required.", "missing_pipeline_stage_name")

        existing = self.store.find_one(
            ctx.user_id,
            ctx.workspace_id,
            CRMEntityType.PIPELINE_STAGE,
            lambda record: (
                _normalize_text(record.get("name")).lower() == clean_name.lower()
                and _normalize_text(record.get("pipeline_name")).lower() == clean_pipeline.lower()
            ),
        )

        if existing:
            existing["entity_type"] = CRMEntityType.PIPELINE_STAGE.value
            return self._safe_result(
                success=True,
                message="CRM pipeline stage already exists.",
                data=existing,
                metadata={
                    "action": CRMAction.CREATE_PIPELINE_STAGE.value,
                    "deduplicated": True,
                },
            )

        if is_won_stage and is_lost_stage:
            return self._error_result(
                "Pipeline stage cannot be both won and lost.",
                "invalid_pipeline_stage_flags",
            )

        model = CRMPipelineStage(
            id=_new_id("stage"),
            user_id=ctx.user_id,
            workspace_id=ctx.workspace_id,
            name=clean_name,
            pipeline_name=clean_pipeline,
            order=int(order or 0),
            probability=self._safe_float(probability),
            color=_normalize_text(color) or None,
            is_won_stage=bool(is_won_stage),
            is_lost_stage=bool(is_lost_stage),
        )

        saved = self.store.save(ctx.user_id, ctx.workspace_id, CRMEntityType.PIPELINE_STAGE, asdict(model))
        saved["entity_type"] = CRMEntityType.PIPELINE_STAGE.value

        return self._safe_result(
            success=True,
            message="CRM pipeline stage created successfully.",
            data=saved,
            metadata={"action": CRMAction.CREATE_PIPELINE_STAGE.value},
        )

    # ------------------------------------------------------------------
    # Generic Internal Operations
    # ------------------------------------------------------------------

    def _get_record(
        self,
        ctx: CRMContext,
        entity_type: str,
        record_id: str,
    ) -> Dict[str, Any]:
        entity = self._parse_entity_type(entity_type)
        clean_id = _normalize_text(record_id)

        if not clean_id:
            return self._error_result("record_id is required.", "missing_record_id")

        record = self.store.get(ctx.user_id, ctx.workspace_id, entity, clean_id)
        if not record:
            return self._error_result(
                "CRM record not found in this workspace.",
                "record_not_found",
                {"entity_type": entity.value, "record_id": clean_id},
            )

        record["entity_type"] = entity.value
        return self._safe_result(
            success=True,
            message="CRM record fetched successfully.",
            data=record,
            metadata={"action": CRMAction.GET_RECORD.value},
        )

    def _update_record(
        self,
        ctx: CRMContext,
        entity_type: CRMEntityType,
        record_id: str,
        updates: Mapping[str, Any],
    ) -> Dict[str, Any]:
        clean_id = _normalize_text(record_id)
        if not clean_id:
            return self._error_result("record_id is required.", "missing_record_id")

        cleaned = _clean_dict(updates)
        cleaned["updated_at"] = _utc_now()

        updated = self.store.update(
            ctx.user_id,
            ctx.workspace_id,
            entity_type,
            clean_id,
            cleaned,
        )

        if not updated:
            return self._error_result(
                "CRM record not found in this workspace.",
                "record_not_found",
                {"entity_type": entity_type.value, "record_id": clean_id},
            )

        updated["entity_type"] = entity_type.value
        return self._safe_result(
            success=True,
            message="CRM record updated successfully.",
            data=updated,
            metadata={"entity_type": entity_type.value},
        )

    def _search_records(
        self,
        ctx: CRMContext,
        entity_type: CRMEntityType,
        query: str = "",
        filters: Optional[Mapping[str, Any]] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Dict[str, Any]:
        records, total = self.store.search(
            ctx.user_id,
            ctx.workspace_id,
            entity_type,
            query=query,
            filters=filters,
            limit=limit,
            offset=offset,
        )

        for record in records:
            record["entity_type"] = entity_type.value

        return self._safe_result(
            success=True,
            message=f"CRM {entity_type.value} search completed successfully.",
            data={
                "records": records,
                "total": total,
                "limit": max(1, min(int(limit or 50), 200)),
                "offset": max(0, int(offset or 0)),
                "entity_type": entity_type.value,
            },
            metadata={
                "query": query,
                "filters": _clean_dict(filters),
            },
        )

    # ------------------------------------------------------------------
    # Utility Methods
    # ------------------------------------------------------------------

    def _ensure_default_pipeline_stage(self, ctx: CRMContext) -> Dict[str, Any]:
        """Create or return the default pipeline stage for this workspace."""
        existing = self.store.find_one(
            ctx.user_id,
            ctx.workspace_id,
            CRMEntityType.PIPELINE_STAGE,
            lambda record: (
                _normalize_text(record.get("name")).lower() == DEFAULT_STAGE_NAME.lower()
                and _normalize_text(record.get("pipeline_name")).lower() == DEFAULT_PIPELINE_NAME.lower()
            ),
        )

        if existing:
            return existing

        model = CRMPipelineStage(
            id=_new_id("stage"),
            user_id=ctx.user_id,
            workspace_id=ctx.workspace_id,
            name=DEFAULT_STAGE_NAME,
            pipeline_name=DEFAULT_PIPELINE_NAME,
            order=0,
            probability=10.0,
        )
        return self.store.save(
            ctx.user_id,
            ctx.workspace_id,
            CRMEntityType.PIPELINE_STAGE,
            asdict(model),
        )

    def _parse_entity_type(self, entity_type: Union[str, CRMEntityType]) -> CRMEntityType:
        """Parse and validate CRM entity type."""
        if isinstance(entity_type, CRMEntityType):
            return entity_type

        value = _normalize_text(entity_type).lower()
        aliases = {
            "contacts": CRMEntityType.CONTACT,
            "contact": CRMEntityType.CONTACT,
            "deals": CRMEntityType.DEAL,
            "deal": CRMEntityType.DEAL,
            "tags": CRMEntityType.TAG,
            "tag": CRMEntityType.TAG,
            "notes": CRMEntityType.NOTE,
            "note": CRMEntityType.NOTE,
            "tasks": CRMEntityType.TASK,
            "task": CRMEntityType.TASK,
            "pipeline_stage": CRMEntityType.PIPELINE_STAGE,
            "pipeline_stages": CRMEntityType.PIPELINE_STAGE,
            "stage": CRMEntityType.PIPELINE_STAGE,
            "stages": CRMEntityType.PIPELINE_STAGE,
        }

        if value in aliases:
            return aliases[value]

        raise ValueError(f"Unsupported CRM entity_type: {entity_type}")

    @staticmethod
    def _safe_float(value: Any) -> Optional[float]:
        """Convert numeric value safely."""
        if value is None or value == "":
            return None
        try:
            return float(value)
        except Exception:
            return None

    @staticmethod
    def _normalize_deal_status(value: Any) -> str:
        """Normalize deal status."""
        raw = _normalize_text(value).lower()
        allowed = {item.value for item in CRMDealStatus}
        return raw if raw in allowed else CRMDealStatus.OPEN.value

    @staticmethod
    def _normalize_task_status(value: Any) -> str:
        """Normalize task status."""
        raw = _normalize_text(value).lower()
        allowed = {item.value for item in CRMTaskStatus}
        return raw if raw in allowed else CRMTaskStatus.OPEN.value

    @staticmethod
    def _normalize_priority(value: Any) -> str:
        """Normalize task priority."""
        raw = _normalize_text(value).lower()
        allowed = {item.value for item in CRMPriority}
        return raw if raw in allowed else CRMPriority.NORMAL.value

    @staticmethod
    def _summarize_payload_for_security(payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Create a safe payload summary for Security Agent and audit logs.

        Does not expose secrets or large raw bodies.
        """
        secret_keywords = {
            "secret",
            "token",
            "password",
            "api_key",
            "apikey",
            "access_token",
            "refresh_token",
            "authorization",
        }
        summary: Dict[str, Any] = {}

        for key, value in dict(payload).items():
            key_str = str(key)
            key_lower = key_str.lower()

            if any(secret in key_lower for secret in secret_keywords):
                summary[key_str] = "***redacted***"
            elif isinstance(value, Mapping):
                summary[key_str] = {
                    child_key: "***redacted***"
                    if any(secret in str(child_key).lower() for secret in secret_keywords)
                    else CRMConnector._truncate_for_summary(child_value)
                    for child_key, child_value in value.items()
                }
            else:
                summary[key_str] = CRMConnector._truncate_for_summary(value)

        return summary

    @staticmethod
    def _truncate_for_summary(value: Any, max_length: int = 160) -> Any:
        """Truncate long values for safe audit/security summaries."""
        if isinstance(value, (int, float, bool)) or value is None:
            return value
        if isinstance(value, list):
            return [CRMConnector._truncate_for_summary(item, max_length=60) for item in value[:10]]
        text = str(value)
        if len(text) > max_length:
            return text[:max_length] + "...[truncated]"
        return text

    def _send_optional_verification(self, verification_payload: Mapping[str, Any]) -> None:
        """Send verification payload if Verification Agent/client is configured."""
        if not self.verification_client:
            return
        try:
            if hasattr(self.verification_client, "submit"):
                self.verification_client.submit(dict(verification_payload))
            elif hasattr(self.verification_client, "verify"):
                self.verification_client.verify(dict(verification_payload))
        except Exception as exc:
            self.logger.warning("Verification payload send failed: %s", exc)

    def _send_optional_memory(self, memory_payload: Mapping[str, Any]) -> None:
        """Send memory payload if Memory Agent/client is configured."""
        if not self.memory_client:
            return
        try:
            if hasattr(self.memory_client, "store"):
                self.memory_client.store(dict(memory_payload))
            elif hasattr(self.memory_client, "remember"):
                self.memory_client.remember(dict(memory_payload))
        except Exception as exc:
            self.logger.warning("Memory payload send failed: %s", exc)


# ---------------------------------------------------------------------------
# Module-level factory for Agent Loader / Registry convenience
# ---------------------------------------------------------------------------

def create_crm_connector(
    provider_name: str = "memory",
    config: Optional[Mapping[str, Any]] = None,
    **kwargs: Any,
) -> CRMConnector:
    """
    Factory used by Agent Loader / Registry / Dashboard tests.

    Example:
        connector = create_crm_connector()
    """
    return CRMConnector(provider_name=provider_name, config=config, **kwargs)


def get_module_metadata() -> Dict[str, Any]:
    """
    Lightweight metadata for import-time registry discovery.

    Does not instantiate external clients or perform CRM/network actions.
    """
    return {
        "agent": CRMConnector.agent_name,
        "agent_type": CRMConnector.agent_type,
        "module": CRMConnector.module_name,
        "class_name": "CRMConnector",
        "version": CRMConnector.version,
        "file_path": "agents/workflow_agent/crm_connector.py",
        "safe_import": True,
        "purpose": "Creates/updates CRM contacts, deals, tags, notes, tasks, pipeline stages.",
        "requires_context": ["user_id", "workspace_id"],
        "supported_entities": [entity.value for entity in CRMEntityType],
        "supported_actions": [action.value for action in CRMAction],
    }


__all__ = [
    "CRMConnector",
    "CRMContext",
    "CRMContact",
    "CRMDeal",
    "CRMTag",
    "CRMNote",
    "CRMTask",
    "CRMPipelineStage",
    "CRMOperationResult",
    "CRMEntityType",
    "CRMAction",
    "CRMTaskStatus",
    "CRMDealStatus",
    "CRMPriority",
    "InMemoryCRMStore",
    "create_crm_connector",
    "get_module_metadata",
]