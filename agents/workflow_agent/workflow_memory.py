"""
agents/workflow_agent/workflow_memory.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
Workflow Agent - Workflow Memory

Purpose:
    Stores workflow preferences, mappings, connected tools, and reusable templates
    in a SaaS-safe, user/workspace-isolated way.

This module is designed to be:
    - Import-safe even if the rest of William/Jarvis is not created yet.
    - Compatible with BaseAgent, Agent Registry, Agent Loader, Agent Router,
      Master Agent routing, Security Agent, Memory Agent, Verification Agent,
      Dashboard/API, and future persistence layers.
    - Safe by default: no real external calls, no hardcoded secrets, no destructive
      actions without explicit permission/security hooks.
    - Structured-result first: every public operation returns a dict with:
      success, message, data, error, metadata.

Core responsibilities:
    1. Store and retrieve workflow preferences.
    2. Store and retrieve field mappings between forms, CRM, sheets, email, etc.
    3. Store metadata for connected tools without exposing secrets.
    4. Store reusable workflow templates.
    5. Support export/import for dashboard/API integration.
    6. Prepare Memory Agent and Verification Agent compatible payloads.
    7. Enforce user_id/workspace_id isolation for every user-specific operation.

Important:
    This file stores lightweight workflow memory metadata. It does not execute
    workflows, send messages, perform browser actions, update CRMs, or call real
    third-party tools directly.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import os
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple, Union


# =============================================================================
# Safe optional BaseAgent import
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for import-safety
    class BaseAgent:  # type: ignore
        """
        Minimal fallback BaseAgent stub.

        This allows workflow_memory.py to import safely before the full William /
        Jarvis BaseAgent exists. The real BaseAgent should override/extend these
        behaviors in production.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())
            self.logger = logging.getLogger(self.agent_name)

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback emit_event: %s | %s", event_name, payload)

        def log_audit_event(self, payload: Dict[str, Any]) -> None:
            self.logger.info("Fallback audit_event: %s", payload)


# =============================================================================
# Constants
# =============================================================================

MODULE_NAME = "workflow_memory"
AGENT_NAME = "WorkflowMemory"
AGENT_MODULE = "Workflow Agent"
DEFAULT_SCHEMA_VERSION = "1.0.0"
DEFAULT_MAX_KEY_LENGTH = 128
DEFAULT_MAX_TEXT_LENGTH = 25_000
DEFAULT_MAX_TEMPLATE_STEPS = 250
DEFAULT_MAX_MAPPING_FIELDS = 500
DEFAULT_MAX_CONNECTED_TOOLS = 500
DEFAULT_MAX_PREFERENCES = 1_000
DEFAULT_MAX_TEMPLATES = 500

SENSITIVE_KEYWORDS = {
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "client_secret",
    "access_token",
    "refresh_token",
    "bearer",
    "auth",
    "credential",
    "credentials",
    "webhook_secret",
    "signing_secret",
}

PUBLIC_TOOL_FIELDS = {
    "tool_id",
    "tool_name",
    "tool_type",
    "provider",
    "status",
    "scopes",
    "connected_at",
    "updated_at",
    "created_at",
    "metadata",
    "health",
    "last_verified_at",
    "connection_mode",
    "requires_approval",
    "security_level",
}

SUPPORTED_MEMORY_TYPES = {
    "preference",
    "mapping",
    "connected_tool",
    "template",
}


# =============================================================================
# Dataclasses
# =============================================================================

@dataclass
class WorkflowMemoryRecord:
    """
    Generic record container for workflow memory entries.

    Every entry belongs to exactly one user_id and workspace_id to prevent data
    mixing across SaaS tenants.
    """

    record_id: str
    record_type: str
    user_id: str
    workspace_id: str
    key: str
    value: Dict[str, Any]
    created_at: str
    updated_at: str
    created_by: Optional[str] = None
    updated_by: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    schema_version: str = DEFAULT_SCHEMA_VERSION

    def to_dict(self, redact_sensitive: bool = True) -> Dict[str, Any]:
        data = asdict(self)
        if redact_sensitive:
            data["value"] = WorkflowMemorySanitizer.redact_sensitive(data.get("value", {}))
            data["metadata"] = WorkflowMemorySanitizer.redact_sensitive(data.get("metadata", {}))
        return data


@dataclass
class WorkflowConnectedTool:
    """
    Metadata-only representation of a connected tool.

    Secrets must never be stored in clear text. If a future secure vault exists,
    this record may store vault reference IDs only.
    """

    tool_id: str
    tool_name: str
    tool_type: str
    provider: str
    status: str = "inactive"
    scopes: List[str] = field(default_factory=list)
    connection_mode: str = "metadata_only"
    requires_approval: bool = True
    security_level: str = "medium"
    created_at: str = field(default_factory=lambda: utc_now_iso())
    connected_at: Optional[str] = None
    updated_at: Optional[str] = None
    last_verified_at: Optional[str] = None
    health: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_public_dict(self) -> Dict[str, Any]:
        return WorkflowMemorySanitizer.redact_sensitive(asdict(self))


@dataclass
class WorkflowTemplateDefinition:
    """
    Reusable workflow template definition.

    Templates are stored as reusable metadata and step definitions. Execution is
    handled by Workflow Builder, Trigger Engine, Action Router, and Scheduler.
    """

    template_id: str
    name: str
    description: str
    category: str
    version: str = "1.0.0"
    steps: List[Dict[str, Any]] = field(default_factory=list)
    triggers: List[Dict[str, Any]] = field(default_factory=list)
    variables: Dict[str, Any] = field(default_factory=dict)
    required_tools: List[str] = field(default_factory=list)
    default_preferences: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    is_active: bool = True
    created_at: str = field(default_factory=lambda: utc_now_iso())
    updated_at: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self, redact_sensitive: bool = True) -> Dict[str, Any]:
        data = asdict(self)
        if redact_sensitive:
            return WorkflowMemorySanitizer.redact_sensitive(data)
        return data


# =============================================================================
# Utility helpers
# =============================================================================

def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def safe_json_dumps(data: Any) -> str:
    """Safely serialize JSON for hashing/logging without crashing."""
    try:
        return json.dumps(data, sort_keys=True, default=str, ensure_ascii=False)
    except Exception:
        return str(data)


def stable_hash(data: Any) -> str:
    """Create a stable short hash for dictionaries and other serializable data."""
    raw = safe_json_dumps(data).encode("utf-8", errors="ignore")
    return hashlib.sha256(raw).hexdigest()


def normalize_key(value: str) -> str:
    """Normalize keys used for preferences, mappings, tools, and templates."""
    value = str(value or "").strip()
    value = value.replace(" ", "_")
    value = value.lower()
    return value


def is_sensitive_key(key: str) -> bool:
    """Check whether a key name appears sensitive."""
    key_l = str(key or "").lower()
    return any(word in key_l for word in SENSITIVE_KEYWORDS)


def deep_merge_dict(base: Dict[str, Any], updates: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deep merge two dictionaries.

    Values in updates override values in base.
    """
    merged = copy.deepcopy(base)
    for key, value in updates.items():
        if (
            isinstance(value, dict)
            and isinstance(merged.get(key), dict)
        ):
            merged[key] = deep_merge_dict(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


class WorkflowMemorySanitizer:
    """
    Sanitizes workflow memory payloads before storage, logging, verification,
    dashboard display, or Memory Agent handoff.
    """

    @staticmethod
    def redact_sensitive(data: Any) -> Any:
        """
        Redact sensitive keys recursively.

        This prevents accidental secret exposure in structured results, events,
        audit logs, Memory Agent payloads, and dashboard/API output.
        """
        if isinstance(data, dict):
            redacted: Dict[str, Any] = {}
            for key, value in data.items():
                if is_sensitive_key(str(key)):
                    redacted[key] = "***REDACTED***"
                else:
                    redacted[key] = WorkflowMemorySanitizer.redact_sensitive(value)
            return redacted

        if isinstance(data, list):
            return [WorkflowMemorySanitizer.redact_sensitive(item) for item in data]

        if isinstance(data, tuple):
            return tuple(WorkflowMemorySanitizer.redact_sensitive(item) for item in data)

        return data

    @staticmethod
    def remove_sensitive_for_storage(data: Any) -> Any:
        """
        Remove direct secrets from data before storage.

        For connected tools, future secure vault integrations should store only
        vault references. This method keeps metadata safe by removing raw secrets.
        """
        if isinstance(data, dict):
            cleaned: Dict[str, Any] = {}
            for key, value in data.items():
                if is_sensitive_key(str(key)):
                    continue
                cleaned[key] = WorkflowMemorySanitizer.remove_sensitive_for_storage(value)
            return cleaned

        if isinstance(data, list):
            return [WorkflowMemorySanitizer.remove_sensitive_for_storage(item) for item in data]

        if isinstance(data, tuple):
            return tuple(WorkflowMemorySanitizer.remove_sensitive_for_storage(item) for item in data)

        return data


# =============================================================================
# Storage backend
# =============================================================================

class WorkflowMemoryStore:
    """
    Lightweight thread-safe storage backend.

    By default this store is in-memory. If storage_path is provided, records are
    persisted to a JSON file. This is intentionally simple and import-safe. In
    production, this can be replaced by Postgres, Redis, Supabase, Firestore, or
    another SaaS-aware persistence layer.

    Storage shape:
        {
            "schema_version": "1.0.0",
            "updated_at": "...",
            "records": {
                "<tenant_key>": {
                    "preference": {"key": record_dict},
                    "mapping": {"key": record_dict},
                    "connected_tool": {"key": record_dict},
                    "template": {"key": record_dict}
                }
            }
        }

    tenant_key = sha256(user_id + "::" + workspace_id)
    """

    def __init__(
        self,
        storage_path: Optional[Union[str, Path]] = None,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.storage_path = Path(storage_path).expanduser().resolve() if storage_path else None
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        self._lock = threading.RLock()
        self._data: Dict[str, Any] = {
            "schema_version": DEFAULT_SCHEMA_VERSION,
            "updated_at": utc_now_iso(),
            "records": {},
        }
        self._load_from_disk()

    def _load_from_disk(self) -> None:
        """Load JSON storage if configured and available."""
        if not self.storage_path:
            return

        with self._lock:
            try:
                if not self.storage_path.exists():
                    self.storage_path.parent.mkdir(parents=True, exist_ok=True)
                    self._persist_to_disk()
                    return

                raw = self.storage_path.read_text(encoding="utf-8")
                if not raw.strip():
                    self._persist_to_disk()
                    return

                loaded = json.loads(raw)
                if isinstance(loaded, dict) and "records" in loaded:
                    self._data = loaded
                else:
                    self.logger.warning("Invalid workflow memory storage shape. Resetting safely.")
                    self._persist_to_disk()
            except Exception as exc:
                self.logger.exception("Failed to load workflow memory storage: %s", exc)
                self._data = {
                    "schema_version": DEFAULT_SCHEMA_VERSION,
                    "updated_at": utc_now_iso(),
                    "records": {},
                }

    def _persist_to_disk(self) -> None:
        """Persist JSON storage if storage_path is configured."""
        if not self.storage_path:
            return

        with self._lock:
            try:
                self.storage_path.parent.mkdir(parents=True, exist_ok=True)
                self._data["updated_at"] = utc_now_iso()

                temp_path = self.storage_path.with_suffix(self.storage_path.suffix + ".tmp")
                temp_path.write_text(
                    json.dumps(self._data, indent=2, sort_keys=True, ensure_ascii=False, default=str),
                    encoding="utf-8",
                )
                os.replace(temp_path, self.storage_path)
            except Exception as exc:
                self.logger.exception("Failed to persist workflow memory storage: %s", exc)
                raise

    @staticmethod
    def tenant_key(user_id: str, workspace_id: str) -> str:
        """Create stable tenant key without exposing raw user/workspace IDs in storage indexes."""
        return stable_hash({"user_id": user_id, "workspace_id": workspace_id})

    def ensure_bucket(self, user_id: str, workspace_id: str) -> Dict[str, Any]:
        """Ensure tenant bucket exists."""
        tenant_key = self.tenant_key(user_id, workspace_id)

        with self._lock:
            records = self._data.setdefault("records", {})
            bucket = records.setdefault(
                tenant_key,
                {
                    "preference": {},
                    "mapping": {},
                    "connected_tool": {},
                    "template": {},
                },
            )

            for memory_type in SUPPORTED_MEMORY_TYPES:
                bucket.setdefault(memory_type, {})

            return bucket

    def upsert_record(self, record: WorkflowMemoryRecord) -> WorkflowMemoryRecord:
        """Insert or update one record."""
        with self._lock:
            bucket = self.ensure_bucket(record.user_id, record.workspace_id)
            bucket[record.record_type][record.key] = record.to_dict(redact_sensitive=False)
            self._persist_to_disk()
            return record

    def get_record(
        self,
        user_id: str,
        workspace_id: str,
        record_type: str,
        key: str,
    ) -> Optional[WorkflowMemoryRecord]:
        """Retrieve a record by tenant, type, and key."""
        key = normalize_key(key)

        with self._lock:
            bucket = self.ensure_bucket(user_id, workspace_id)
            raw = bucket.get(record_type, {}).get(key)

            if not isinstance(raw, dict):
                return None

            return WorkflowMemoryRecord(**raw)

    def delete_record(
        self,
        user_id: str,
        workspace_id: str,
        record_type: str,
        key: str,
    ) -> bool:
        """Delete a record by tenant, type, and key."""
        key = normalize_key(key)

        with self._lock:
            bucket = self.ensure_bucket(user_id, workspace_id)
            existed = key in bucket.get(record_type, {})

            if existed:
                del bucket[record_type][key]
                self._persist_to_disk()

            return existed

    def list_records(
        self,
        user_id: str,
        workspace_id: str,
        record_type: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> List[WorkflowMemoryRecord]:
        """List records for one tenant, optionally filtered by type and tags."""
        tags_set = set(tags or [])

        with self._lock:
            bucket = self.ensure_bucket(user_id, workspace_id)
            types = [record_type] if record_type else list(SUPPORTED_MEMORY_TYPES)
            output: List[WorkflowMemoryRecord] = []

            for current_type in types:
                for raw in bucket.get(current_type, {}).values():
                    if not isinstance(raw, dict):
                        continue

                    record = WorkflowMemoryRecord(**raw)

                    if tags_set and not tags_set.intersection(set(record.tags or [])):
                        continue

                    output.append(record)

            output.sort(key=lambda item: item.updated_at or item.created_at, reverse=True)
            return output

    def clear_tenant(
        self,
        user_id: str,
        workspace_id: str,
        record_type: Optional[str] = None,
    ) -> int:
        """Clear all records for a tenant or only one record type."""
        with self._lock:
            bucket = self.ensure_bucket(user_id, workspace_id)

            if record_type:
                count = len(bucket.get(record_type, {}))
                bucket[record_type] = {}
            else:
                count = sum(len(bucket.get(rt, {})) for rt in SUPPORTED_MEMORY_TYPES)
                for rt in SUPPORTED_MEMORY_TYPES:
                    bucket[rt] = {}

            self._persist_to_disk()
            return count

    def export_tenant(self, user_id: str, workspace_id: str) -> Dict[str, Any]:
        """Export tenant data."""
        with self._lock:
            bucket = copy.deepcopy(self.ensure_bucket(user_id, workspace_id))
            return {
                "schema_version": DEFAULT_SCHEMA_VERSION,
                "exported_at": utc_now_iso(),
                "tenant_hash": self.tenant_key(user_id, workspace_id),
                "records": bucket,
            }

    def import_tenant(
        self,
        user_id: str,
        workspace_id: str,
        payload: Mapping[str, Any],
        merge: bool = True,
    ) -> int:
        """Import tenant data from an export-compatible payload."""
        records = payload.get("records", {})
        if not isinstance(records, Mapping):
            raise ValueError("Invalid import payload: records must be a mapping.")

        imported_count = 0

        with self._lock:
            bucket = self.ensure_bucket(user_id, workspace_id)

            if not merge:
                for rt in SUPPORTED_MEMORY_TYPES:
                    bucket[rt] = {}

            for record_type in SUPPORTED_MEMORY_TYPES:
                type_records = records.get(record_type, {})
                if not isinstance(type_records, Mapping):
                    continue

                for key, raw in type_records.items():
                    if not isinstance(raw, Mapping):
                        continue

                    safe_raw = dict(raw)
                    safe_raw["user_id"] = user_id
                    safe_raw["workspace_id"] = workspace_id
                    safe_raw["record_type"] = record_type
                    safe_raw["key"] = normalize_key(str(safe_raw.get("key") or key))
                    safe_raw["updated_at"] = utc_now_iso()

                    if not safe_raw.get("record_id"):
                        safe_raw["record_id"] = str(uuid.uuid4())

                    if not safe_raw.get("created_at"):
                        safe_raw["created_at"] = utc_now_iso()

                    record = WorkflowMemoryRecord(**safe_raw)
                    bucket[record_type][record.key] = record.to_dict(redact_sensitive=False)
                    imported_count += 1

            self._persist_to_disk()
            return imported_count


# =============================================================================
# WorkflowMemory
# =============================================================================

class WorkflowMemory(BaseAgent):
    """
    Workflow memory manager for the Workflow Agent.

    Master Agent:
        Can route memory operations here, such as:
            - save_workflow_preference
            - get_workflow_mapping
            - register_connected_tool
            - save_workflow_template

    Security Agent:
        Sensitive operations, such as storing connected tool metadata, importing
        memory, clearing memory, or changing tool status, pass through
        _requires_security_check() and _request_security_approval().

    Memory Agent:
        Every useful context update can generate a payload via
        _prepare_memory_payload().

    Verification Agent:
        Completed operations prepare a structured payload via
        _prepare_verification_payload().

    Dashboard/API:
        All public methods return JSON-safe dict structures ready for FastAPI or
        dashboard integration.

    Registry/Loader:
        The class is import-safe, has stable public methods, exposes capability
        metadata, and does not require external services at import time.
    """

    agent_name = AGENT_NAME
    agent_module = AGENT_MODULE
    module_name = MODULE_NAME
    version = DEFAULT_SCHEMA_VERSION

    def __init__(
        self,
        storage_path: Optional[Union[str, Path]] = None,
        security_approval_callback: Optional[Callable[[Dict[str, Any]], bool]] = None,
        event_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        audit_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        logger: Optional[logging.Logger] = None,
        strict_security: bool = False,
        max_preferences: int = DEFAULT_MAX_PREFERENCES,
        max_mapping_fields: int = DEFAULT_MAX_MAPPING_FIELDS,
        max_connected_tools: int = DEFAULT_MAX_CONNECTED_TOOLS,
        max_templates: int = DEFAULT_MAX_TEMPLATES,
    ) -> None:
        """
        Initialize WorkflowMemory.

        Args:
            storage_path:
                Optional JSON path for lightweight persistence.
            security_approval_callback:
                Optional callback used to request approval for sensitive actions.
                It receives a payload dict and returns True/False.
            event_callback:
                Optional event bus callback for dashboard/agent events.
            audit_callback:
                Optional audit log callback.
            logger:
                Optional logger instance.
            strict_security:
                If True, sensitive operations fail unless approved by callback.
                If False, safe fallback approval is allowed for metadata-only ops.
            max_preferences:
                Max preference records per tenant.
            max_mapping_fields:
                Max fields inside one mapping.
            max_connected_tools:
                Max connected tool records per tenant.
            max_templates:
                Max template records per tenant.
        """
        try:
            super().__init__(agent_name=AGENT_NAME, agent_id=MODULE_NAME)
        except TypeError:
            super().__init__()

        self.logger = logger or getattr(self, "logger", logging.getLogger(AGENT_NAME))
        self.store = WorkflowMemoryStore(storage_path=storage_path, logger=self.logger)
        self.security_approval_callback = security_approval_callback
        self.event_callback = event_callback
        self.audit_callback = audit_callback
        self.strict_security = strict_security

        self.max_preferences = max_preferences
        self.max_mapping_fields = max_mapping_fields
        self.max_connected_tools = max_connected_tools
        self.max_templates = max_templates

    # -------------------------------------------------------------------------
    # Compatibility metadata
    # -------------------------------------------------------------------------

    def get_agent_manifest(self) -> Dict[str, Any]:
        """
        Return registry/loader friendly metadata.

        Agent Registry and Master Agent may use this to discover supported
        actions without importing unrelated Workflow Agent files.
        """
        return {
            "success": True,
            "message": "WorkflowMemory manifest loaded.",
            "data": {
                "agent_name": self.agent_name,
                "agent_module": self.agent_module,
                "module_name": self.module_name,
                "version": self.version,
                "class_name": self.__class__.__name__,
                "capabilities": [
                    "store_workflow_preferences",
                    "store_field_mappings",
                    "store_connected_tool_metadata",
                    "store_reusable_templates",
                    "export_workflow_memory",
                    "import_workflow_memory",
                    "prepare_memory_agent_payload",
                    "prepare_verification_payload",
                ],
                "supported_memory_types": sorted(SUPPORTED_MEMORY_TYPES),
                "sensitive_actions": [
                    "save_connected_tool",
                    "delete_connected_tool",
                    "clear_memory",
                    "import_memory",
                    "set_tool_status",
                ],
                "saas_isolation_required": True,
                "requires_user_id": True,
                "requires_workspace_id": True,
            },
            "error": None,
            "metadata": self._result_metadata(action="get_agent_manifest"),
        }

    def get_supported_actions(self) -> Dict[str, Any]:
        """Return supported public actions for routers and API controllers."""
        actions = [
            "save_preference",
            "get_preference",
            "list_preferences",
            "delete_preference",
            "save_mapping",
            "get_mapping",
            "list_mappings",
            "delete_mapping",
            "save_connected_tool",
            "get_connected_tool",
            "list_connected_tools",
            "delete_connected_tool",
            "set_tool_status",
            "save_template",
            "get_template",
            "list_templates",
            "delete_template",
            "export_memory",
            "import_memory",
            "clear_memory",
            "search_memory",
            "route_action",
        ]
        return self._safe_result(
            message="Supported WorkflowMemory actions loaded.",
            data={"actions": actions},
            metadata=self._result_metadata(action="get_supported_actions"),
        )

    # -------------------------------------------------------------------------
    # Required compatibility hooks
    # -------------------------------------------------------------------------

    def _validate_task_context(self, context: Mapping[str, Any]) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """
        Validate SaaS user/workspace context.

        Every user-specific workflow memory action must include user_id and
        workspace_id. This prevents mixing memory, preferences, mappings, tools,
        templates, logs, or analytics across tenants.
        """
        if not isinstance(context, Mapping):
            return False, "context must be a mapping/dict.", {}

        user_id = str(context.get("user_id") or "").strip()
        workspace_id = str(context.get("workspace_id") or "").strip()

        if not user_id:
            return False, "user_id is required for WorkflowMemory operations.", {}

        if not workspace_id:
            return False, "workspace_id is required for WorkflowMemory operations.", {}

        normalized = dict(context)
        normalized["user_id"] = user_id
        normalized["workspace_id"] = workspace_id
        normalized.setdefault("request_id", str(uuid.uuid4()))
        normalized.setdefault("actor_id", context.get("actor_id") or user_id)

        return True, None, normalized

    def _requires_security_check(self, action: str, payload: Optional[Mapping[str, Any]] = None) -> bool:
        """
        Decide whether an action requires Security Agent approval.

        Connected tools, imports, clears, and status changes are sensitive because
        they can affect integrations or workspace-wide memory.
        """
        action = str(action or "").strip().lower()

        if action in {
            "save_connected_tool",
            "delete_connected_tool",
            "set_tool_status",
            "clear_memory",
            "import_memory",
        }:
            return True

        payload = payload or {}
        if self._contains_sensitive_keys(payload):
            return True

        return False

    def _request_security_approval(
        self,
        action: str,
        context: Mapping[str, Any],
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request approval for sensitive operations.

        In production this should call Security Agent. This fallback supports:
            - explicit context approval flags,
            - optional callback,
            - strict security mode.
        """
        approval_payload = {
            "action": action,
            "agent": self.agent_name,
            "module": self.module_name,
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "actor_id": context.get("actor_id"),
            "request_id": context.get("request_id"),
            "timestamp": utc_now_iso(),
            "payload_hash": stable_hash(WorkflowMemorySanitizer.redact_sensitive(payload or {})),
            "redacted_payload": WorkflowMemorySanitizer.redact_sensitive(payload or {}),
            "reason": "WorkflowMemory sensitive operation requires approval.",
        }

        approved = False
        approval_source = "none"

        try:
            if context.get("security_approved") is True:
                approved = True
                approval_source = "context.security_approved"

            elif callable(self.security_approval_callback):
                approved = bool(self.security_approval_callback(approval_payload))
                approval_source = "security_approval_callback"

            elif not self.strict_security:
                # Safe fallback: metadata-only operations can continue in local/dev
                # mode, but the approval payload is still produced and audited.
                approved = True
                approval_source = "safe_fallback_non_strict_mode"

            else:
                approved = False
                approval_source = "strict_security_requires_callback"

        except Exception as exc:
            self.logger.exception("Security approval callback failed: %s", exc)
            approved = False
            approval_source = "callback_error"

        approval_payload["approved"] = approved
        approval_payload["approval_source"] = approval_source

        self._log_audit_event(
            {
                "event": "security_approval_requested",
                "approved": approved,
                "approval_source": approval_source,
                "action": action,
                "user_id": context.get("user_id"),
                "workspace_id": context.get("workspace_id"),
                "request_id": context.get("request_id"),
                "payload_hash": approval_payload["payload_hash"],
                "timestamp": approval_payload["timestamp"],
            }
        )

        if approved:
            return self._safe_result(
                message="Security approval granted.",
                data=approval_payload,
                metadata=self._result_metadata(action="_request_security_approval"),
            )

        return self._error_result(
            message="Security approval denied.",
            error="SECURITY_APPROVAL_DENIED",
            data=approval_payload,
            metadata=self._result_metadata(action="_request_security_approval"),
        )

    def _prepare_verification_payload(
        self,
        action: str,
        context: Mapping[str, Any],
        result_data: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent compatible payload.

        The Verification Agent can use this to confirm the memory operation,
        audit tenant isolation, and check for safe data handling.
        """
        redacted_data = WorkflowMemorySanitizer.redact_sensitive(dict(result_data or {}))

        return {
            "verification_type": "workflow_memory_operation",
            "agent": self.agent_name,
            "module": self.module_name,
            "action": action,
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "actor_id": context.get("actor_id"),
            "request_id": context.get("request_id"),
            "timestamp": utc_now_iso(),
            "data_hash": stable_hash(redacted_data),
            "redacted_data": redacted_data,
            "checks": {
                "saas_context_present": bool(context.get("user_id") and context.get("workspace_id")),
                "secrets_redacted": True,
                "destructive_action": action in {"clear_memory", "delete_preference", "delete_mapping", "delete_connected_tool", "delete_template"},
                "external_action_executed": False,
            },
        }

    def _prepare_memory_payload(
        self,
        action: str,
        context: Mapping[str, Any],
        memory_type: str,
        key: str,
        value: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        This does not write to Memory Agent directly. It returns a payload that
        Workflow Agent, Master Agent, or Memory Agent can consume.
        """
        return {
            "memory_event_type": "workflow_memory_update",
            "agent": self.agent_name,
            "module": self.module_name,
            "action": action,
            "memory_type": memory_type,
            "key": normalize_key(key),
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "actor_id": context.get("actor_id"),
            "request_id": context.get("request_id"),
            "timestamp": utc_now_iso(),
            "value": WorkflowMemorySanitizer.redact_sensitive(dict(value or {})),
            "metadata": {
                "source": MODULE_NAME,
                "safe_for_long_term_memory": memory_type in {"preference", "mapping", "template", "connected_tool"},
                "contains_raw_secret": False,
            },
        }

    def _emit_agent_event(self, event_name: str, payload: Dict[str, Any]) -> None:
        """
        Emit an agent event for dashboard/API/event bus.

        Falls back safely to BaseAgent.emit_event or logger.
        """
        safe_payload = WorkflowMemorySanitizer.redact_sensitive(payload)

        try:
            if callable(self.event_callback):
                self.event_callback(event_name, safe_payload)
                return

            emit = getattr(super(), "emit_event", None)
            if callable(emit):
                emit(event_name, safe_payload)
                return

        except Exception as exc:
            self.logger.debug("Agent event emission failed: %s", exc)

        self.logger.debug("Agent event: %s | %s", event_name, safe_payload)

    def _log_audit_event(self, payload: Dict[str, Any]) -> None:
        """
        Log audit event with sensitive values redacted.

        In production this should be connected to an Audit Log service.
        """
        safe_payload = WorkflowMemorySanitizer.redact_sensitive(payload)

        try:
            if callable(self.audit_callback):
                self.audit_callback(safe_payload)
                return

            log_audit = getattr(super(), "log_audit_event", None)
            if callable(log_audit):
                log_audit(safe_payload)
                return

        except Exception as exc:
            self.logger.debug("Audit callback failed: %s", exc)

        self.logger.info("WorkflowMemory audit: %s", safe_payload)

    def _safe_result(
        self,
        message: str,
        data: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standardized success result."""
        return {
            "success": True,
            "message": message,
            "data": WorkflowMemorySanitizer.redact_sensitive(data if data is not None else {}),
            "error": None,
            "metadata": metadata or self._result_metadata(),
        }

    def _error_result(
        self,
        message: str,
        error: Union[str, Exception, Dict[str, Any]],
        data: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standardized error result."""
        if isinstance(error, Exception):
            error_value: Union[str, Dict[str, Any]] = {
                "type": error.__class__.__name__,
                "detail": str(error),
            }
        else:
            error_value = error

        return {
            "success": False,
            "message": message,
            "data": WorkflowMemorySanitizer.redact_sensitive(data if data is not None else {}),
            "error": WorkflowMemorySanitizer.redact_sensitive(error_value),
            "metadata": metadata or self._result_metadata(),
        }

    # -------------------------------------------------------------------------
    # Preferences
    # -------------------------------------------------------------------------

    def save_preference(
        self,
        context: Mapping[str, Any],
        key: str,
        value: Mapping[str, Any],
        tags: Optional[List[str]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        merge: bool = True,
    ) -> Dict[str, Any]:
        """
        Save workflow preference for one user/workspace.

        Examples:
            - preferred CRM pipeline
            - default lead score threshold
            - default WhatsApp alert recipient
            - report delivery time
            - preferred approval mode
        """
        valid, error, ctx = self._validate_task_context(context)
        if not valid:
            return self._error_result("Invalid task context.", error or "INVALID_CONTEXT")

        normalized_key = self._validate_key(key)
        if not normalized_key:
            return self._error_result("Invalid preference key.", "INVALID_KEY")

        if not isinstance(value, Mapping):
            return self._error_result("Preference value must be a mapping/dict.", "INVALID_VALUE")

        if self._count_records(ctx, "preference") >= self.max_preferences:
            existing = self.store.get_record(ctx["user_id"], ctx["workspace_id"], "preference", normalized_key)
            if not existing:
                return self._error_result("Preference limit reached for this workspace.", "PREFERENCE_LIMIT_REACHED")

        try:
            safe_value = self._validate_and_clean_payload(dict(value))
            existing_record = self.store.get_record(ctx["user_id"], ctx["workspace_id"], "preference", normalized_key)
            now = utc_now_iso()

            if existing_record and merge:
                final_value = deep_merge_dict(existing_record.value, safe_value)
                created_at = existing_record.created_at
                created_by = existing_record.created_by
                record_id = existing_record.record_id
            else:
                final_value = safe_value
                created_at = existing_record.created_at if existing_record else now
                created_by = existing_record.created_by if existing_record else ctx.get("actor_id")
                record_id = existing_record.record_id if existing_record else str(uuid.uuid4())

            record = WorkflowMemoryRecord(
                record_id=record_id,
                record_type="preference",
                user_id=ctx["user_id"],
                workspace_id=ctx["workspace_id"],
                key=normalized_key,
                value=final_value,
                created_at=created_at,
                updated_at=now,
                created_by=created_by,
                updated_by=ctx.get("actor_id"),
                tags=self._normalize_tags(tags),
                metadata=self._validate_and_clean_payload(dict(metadata or {})),
            )

            self.store.upsert_record(record)

            output = {
                "preference": record.to_dict(redact_sensitive=True),
                "memory_payload": self._prepare_memory_payload(
                    action="save_preference",
                    context=ctx,
                    memory_type="preference",
                    key=normalized_key,
                    value=record.value,
                ),
            }
            output["verification_payload"] = self._prepare_verification_payload("save_preference", ctx, output)

            self._emit_agent_event("workflow_memory.preference_saved", output)
            self._log_audit_event(
                {
                    "event": "workflow_memory.preference_saved",
                    "user_id": ctx["user_id"],
                    "workspace_id": ctx["workspace_id"],
                    "actor_id": ctx.get("actor_id"),
                    "key": normalized_key,
                    "request_id": ctx.get("request_id"),
                    "timestamp": now,
                }
            )

            return self._safe_result(
                message="Workflow preference saved.",
                data=output,
                metadata=self._result_metadata(action="save_preference", context=ctx),
            )

        except Exception as exc:
            self.logger.exception("Failed to save workflow preference.")
            return self._error_result(
                message="Failed to save workflow preference.",
                error=exc,
                metadata=self._result_metadata(action="save_preference", context=ctx),
            )

    def get_preference(
        self,
        context: Mapping[str, Any],
        key: str,
        default: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Get one workflow preference by key."""
        valid, error, ctx = self._validate_task_context(context)
        if not valid:
            return self._error_result("Invalid task context.", error or "INVALID_CONTEXT")

        normalized_key = self._validate_key(key)
        if not normalized_key:
            return self._error_result("Invalid preference key.", "INVALID_KEY")

        record = self.store.get_record(ctx["user_id"], ctx["workspace_id"], "preference", normalized_key)

        if not record:
            return self._safe_result(
                message="Workflow preference not found.",
                data={"key": normalized_key, "value": default, "found": False},
                metadata=self._result_metadata(action="get_preference", context=ctx),
            )

        return self._safe_result(
            message="Workflow preference loaded.",
            data={"preference": record.to_dict(redact_sensitive=True), "found": True},
            metadata=self._result_metadata(action="get_preference", context=ctx),
        )

    def list_preferences(
        self,
        context: Mapping[str, Any],
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """List workflow preferences for one user/workspace."""
        return self._list_by_type(context, "preference", tags, "Workflow preferences loaded.")

    def delete_preference(self, context: Mapping[str, Any], key: str) -> Dict[str, Any]:
        """Delete one workflow preference."""
        return self._delete_by_type(context, "preference", key, "Workflow preference deleted.")

    # -------------------------------------------------------------------------
    # Mappings
    # -------------------------------------------------------------------------

    def save_mapping(
        self,
        context: Mapping[str, Any],
        key: str,
        mapping: Mapping[str, Any],
        source: Optional[str] = None,
        target: Optional[str] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        merge: bool = True,
    ) -> Dict[str, Any]:
        """
        Save workflow field mapping.

        Examples:
            - form fields to CRM fields
            - webhook payload to sheet columns
            - CRM deal fields to email template variables
            - lead intake form to WhatsApp notification body
        """
        valid, error, ctx = self._validate_task_context(context)
        if not valid:
            return self._error_result("Invalid task context.", error or "INVALID_CONTEXT")

        normalized_key = self._validate_key(key)
        if not normalized_key:
            return self._error_result("Invalid mapping key.", "INVALID_KEY")

        if not isinstance(mapping, Mapping):
            return self._error_result("Mapping must be a mapping/dict.", "INVALID_MAPPING")

        if len(mapping) > self.max_mapping_fields:
            return self._error_result("Mapping has too many fields.", "MAPPING_FIELD_LIMIT_REACHED")

        try:
            safe_mapping = self._validate_and_clean_payload(dict(mapping))

            value = {
                "source": str(source or "").strip() or None,
                "target": str(target or "").strip() or None,
                "mapping": safe_mapping,
                "field_count": len(safe_mapping),
            }

            existing_record = self.store.get_record(ctx["user_id"], ctx["workspace_id"], "mapping", normalized_key)
            now = utc_now_iso()

            if existing_record and merge:
                final_value = deep_merge_dict(existing_record.value, value)
                created_at = existing_record.created_at
                created_by = existing_record.created_by
                record_id = existing_record.record_id
            else:
                final_value = value
                created_at = existing_record.created_at if existing_record else now
                created_by = existing_record.created_by if existing_record else ctx.get("actor_id")
                record_id = existing_record.record_id if existing_record else str(uuid.uuid4())

            record = WorkflowMemoryRecord(
                record_id=record_id,
                record_type="mapping",
                user_id=ctx["user_id"],
                workspace_id=ctx["workspace_id"],
                key=normalized_key,
                value=final_value,
                created_at=created_at,
                updated_at=now,
                created_by=created_by,
                updated_by=ctx.get("actor_id"),
                tags=self._normalize_tags(tags),
                metadata=self._validate_and_clean_payload(dict(metadata or {})),
            )

            self.store.upsert_record(record)

            output = {
                "mapping": record.to_dict(redact_sensitive=True),
                "memory_payload": self._prepare_memory_payload(
                    action="save_mapping",
                    context=ctx,
                    memory_type="mapping",
                    key=normalized_key,
                    value=record.value,
                ),
            }
            output["verification_payload"] = self._prepare_verification_payload("save_mapping", ctx, output)

            self._emit_agent_event("workflow_memory.mapping_saved", output)
            self._log_audit_event(
                {
                    "event": "workflow_memory.mapping_saved",
                    "user_id": ctx["user_id"],
                    "workspace_id": ctx["workspace_id"],
                    "actor_id": ctx.get("actor_id"),
                    "key": normalized_key,
                    "request_id": ctx.get("request_id"),
                    "timestamp": now,
                }
            )

            return self._safe_result(
                message="Workflow mapping saved.",
                data=output,
                metadata=self._result_metadata(action="save_mapping", context=ctx),
            )

        except Exception as exc:
            self.logger.exception("Failed to save workflow mapping.")
            return self._error_result(
                message="Failed to save workflow mapping.",
                error=exc,
                metadata=self._result_metadata(action="save_mapping", context=ctx),
            )

    def get_mapping(self, context: Mapping[str, Any], key: str) -> Dict[str, Any]:
        """Get one workflow mapping by key."""
        return self._get_by_type(context, "mapping", key, "Workflow mapping loaded.", "Workflow mapping not found.")

    def list_mappings(
        self,
        context: Mapping[str, Any],
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """List workflow mappings for one user/workspace."""
        return self._list_by_type(context, "mapping", tags, "Workflow mappings loaded.")

    def delete_mapping(self, context: Mapping[str, Any], key: str) -> Dict[str, Any]:
        """Delete one workflow mapping."""
        return self._delete_by_type(context, "mapping", key, "Workflow mapping deleted.")

    # -------------------------------------------------------------------------
    # Connected tools
    # -------------------------------------------------------------------------

    def save_connected_tool(
        self,
        context: Mapping[str, Any],
        tool_name: str,
        tool_type: str,
        provider: str,
        tool_id: Optional[str] = None,
        status: str = "inactive",
        scopes: Optional[List[str]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        health: Optional[Mapping[str, Any]] = None,
        connection_mode: str = "metadata_only",
        requires_approval: bool = True,
        security_level: str = "medium",
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Save connected tool metadata.

        This stores integration metadata only. Raw credentials, tokens, or secrets
        are removed before storage. Future secure vault references can be stored
        in metadata as non-secret IDs.
        """
        valid, error, ctx = self._validate_task_context(context)
        if not valid:
            return self._error_result("Invalid task context.", error or "INVALID_CONTEXT")

        if not str(tool_name or "").strip():
            return self._error_result("tool_name is required.", "INVALID_TOOL_NAME")

        if not str(tool_type or "").strip():
            return self._error_result("tool_type is required.", "INVALID_TOOL_TYPE")

        if not str(provider or "").strip():
            return self._error_result("provider is required.", "INVALID_PROVIDER")

        if self._count_records(ctx, "connected_tool") >= self.max_connected_tools:
            key_for_check = normalize_key(tool_id or tool_name)
            existing = self.store.get_record(ctx["user_id"], ctx["workspace_id"], "connected_tool", key_for_check)
            if not existing:
                return self._error_result("Connected tool limit reached for this workspace.", "CONNECTED_TOOL_LIMIT_REACHED")

        raw_payload = {
            "tool_name": tool_name,
            "tool_type": tool_type,
            "provider": provider,
            "tool_id": tool_id,
            "status": status,
            "scopes": scopes or [],
            "metadata": metadata or {},
            "health": health or {},
            "connection_mode": connection_mode,
            "requires_approval": requires_approval,
            "security_level": security_level,
        }

        if self._requires_security_check("save_connected_tool", raw_payload):
            approval = self._request_security_approval("save_connected_tool", ctx, raw_payload)
            if not approval["success"]:
                return approval

        try:
            now = utc_now_iso()
            safe_metadata = self._validate_and_clean_payload(
                WorkflowMemorySanitizer.remove_sensitive_for_storage(dict(metadata or {}))
            )
            safe_health = self._validate_and_clean_payload(dict(health or {}))
            normalized_tool_id = normalize_key(tool_id or tool_name)

            connected_tool = WorkflowConnectedTool(
                tool_id=normalized_tool_id,
                tool_name=str(tool_name).strip(),
                tool_type=normalize_key(tool_type),
                provider=normalize_key(provider),
                status=self._normalize_tool_status(status),
                scopes=self._normalize_scopes(scopes),
                connection_mode=normalize_key(connection_mode) or "metadata_only",
                requires_approval=bool(requires_approval),
                security_level=normalize_key(security_level) or "medium",
                created_at=now,
                connected_at=now if self._normalize_tool_status(status) == "active" else None,
                updated_at=now,
                health=safe_health,
                metadata=safe_metadata,
            )

            existing_record = self.store.get_record(
                ctx["user_id"],
                ctx["workspace_id"],
                "connected_tool",
                normalized_tool_id,
            )

            if existing_record:
                existing_value = existing_record.value
                merged_value = deep_merge_dict(existing_value, connected_tool.to_public_dict())
                created_at = existing_record.created_at
                created_by = existing_record.created_by
                record_id = existing_record.record_id
            else:
                merged_value = connected_tool.to_public_dict()
                created_at = now
                created_by = ctx.get("actor_id")
                record_id = str(uuid.uuid4())

            record = WorkflowMemoryRecord(
                record_id=record_id,
                record_type="connected_tool",
                user_id=ctx["user_id"],
                workspace_id=ctx["workspace_id"],
                key=normalized_tool_id,
                value=merged_value,
                created_at=created_at,
                updated_at=now,
                created_by=created_by,
                updated_by=ctx.get("actor_id"),
                tags=self._normalize_tags(tags),
                metadata={
                    "provider": connected_tool.provider,
                    "tool_type": connected_tool.tool_type,
                    "security_level": connected_tool.security_level,
                },
            )

            self.store.upsert_record(record)

            output = {
                "connected_tool": record.to_dict(redact_sensitive=True),
                "memory_payload": self._prepare_memory_payload(
                    action="save_connected_tool",
                    context=ctx,
                    memory_type="connected_tool",
                    key=normalized_tool_id,
                    value=record.value,
                ),
            }
            output["verification_payload"] = self._prepare_verification_payload("save_connected_tool", ctx, output)

            self._emit_agent_event("workflow_memory.connected_tool_saved", output)
            self._log_audit_event(
                {
                    "event": "workflow_memory.connected_tool_saved",
                    "user_id": ctx["user_id"],
                    "workspace_id": ctx["workspace_id"],
                    "actor_id": ctx.get("actor_id"),
                    "tool_id": normalized_tool_id,
                    "tool_type": connected_tool.tool_type,
                    "provider": connected_tool.provider,
                    "status": connected_tool.status,
                    "request_id": ctx.get("request_id"),
                    "timestamp": now,
                }
            )

            return self._safe_result(
                message="Connected tool metadata saved.",
                data=output,
                metadata=self._result_metadata(action="save_connected_tool", context=ctx),
            )

        except Exception as exc:
            self.logger.exception("Failed to save connected tool metadata.")
            return self._error_result(
                message="Failed to save connected tool metadata.",
                error=exc,
                metadata=self._result_metadata(action="save_connected_tool", context=ctx),
            )

    def get_connected_tool(self, context: Mapping[str, Any], tool_id: str) -> Dict[str, Any]:
        """Get one connected tool metadata record."""
        return self._get_by_type(
            context,
            "connected_tool",
            tool_id,
            "Connected tool metadata loaded.",
            "Connected tool not found.",
        )

    def list_connected_tools(
        self,
        context: Mapping[str, Any],
        tags: Optional[List[str]] = None,
        provider: Optional[str] = None,
        tool_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> Dict[str, Any]:
        """List connected tools with optional filters."""
        valid, error, ctx = self._validate_task_context(context)
        if not valid:
            return self._error_result("Invalid task context.", error or "INVALID_CONTEXT")

        records = self.store.list_records(ctx["user_id"], ctx["workspace_id"], "connected_tool", tags)
        filtered: List[Dict[str, Any]] = []

        provider_n = normalize_key(provider) if provider else None
        tool_type_n = normalize_key(tool_type) if tool_type else None
        status_n = self._normalize_tool_status(status) if status else None

        for record in records:
            value = record.value or {}

            if provider_n and normalize_key(value.get("provider", "")) != provider_n:
                continue

            if tool_type_n and normalize_key(value.get("tool_type", "")) != tool_type_n:
                continue

            if status_n and self._normalize_tool_status(value.get("status", "")) != status_n:
                continue

            filtered.append(record.to_dict(redact_sensitive=True))

        return self._safe_result(
            message="Connected tools loaded.",
            data={"items": filtered, "count": len(filtered)},
            metadata=self._result_metadata(action="list_connected_tools", context=ctx),
        )

    def set_tool_status(
        self,
        context: Mapping[str, Any],
        tool_id: str,
        status: str,
        health: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Update connected tool status.

        This does not connect/disconnect a real tool. It only changes stored
        metadata after Security Agent compatible approval.
        """
        valid, error, ctx = self._validate_task_context(context)
        if not valid:
            return self._error_result("Invalid task context.", error or "INVALID_CONTEXT")

        normalized_tool_id = self._validate_key(tool_id)
        if not normalized_tool_id:
            return self._error_result("Invalid tool_id.", "INVALID_TOOL_ID")

        new_status = self._normalize_tool_status(status)

        payload = {
            "tool_id": normalized_tool_id,
            "status": new_status,
            "health": health or {},
        }

        if self._requires_security_check("set_tool_status", payload):
            approval = self._request_security_approval("set_tool_status", ctx, payload)
            if not approval["success"]:
                return approval

        record = self.store.get_record(ctx["user_id"], ctx["workspace_id"], "connected_tool", normalized_tool_id)
        if not record:
            return self._error_result("Connected tool not found.", "CONNECTED_TOOL_NOT_FOUND")

        now = utc_now_iso()
        record.value["status"] = new_status
        record.value["updated_at"] = now

        if new_status == "active" and not record.value.get("connected_at"):
            record.value["connected_at"] = now

        if health is not None:
            record.value["health"] = self._validate_and_clean_payload(dict(health))

        record.updated_at = now
        record.updated_by = ctx.get("actor_id")

        self.store.upsert_record(record)

        output = {
            "connected_tool": record.to_dict(redact_sensitive=True),
            "memory_payload": self._prepare_memory_payload(
                action="set_tool_status",
                context=ctx,
                memory_type="connected_tool",
                key=normalized_tool_id,
                value=record.value,
            ),
        }
        output["verification_payload"] = self._prepare_verification_payload("set_tool_status", ctx, output)

        self._emit_agent_event("workflow_memory.connected_tool_status_updated", output)
        self._log_audit_event(
            {
                "event": "workflow_memory.connected_tool_status_updated",
                "user_id": ctx["user_id"],
                "workspace_id": ctx["workspace_id"],
                "actor_id": ctx.get("actor_id"),
                "tool_id": normalized_tool_id,
                "status": new_status,
                "request_id": ctx.get("request_id"),
                "timestamp": now,
            }
        )

        return self._safe_result(
            message="Connected tool status updated.",
            data=output,
            metadata=self._result_metadata(action="set_tool_status", context=ctx),
        )

    def delete_connected_tool(self, context: Mapping[str, Any], tool_id: str) -> Dict[str, Any]:
        """Delete one connected tool metadata record after security approval."""
        return self._delete_by_type(
            context,
            "connected_tool",
            tool_id,
            "Connected tool metadata deleted.",
            sensitive_action=True,
        )

    # -------------------------------------------------------------------------
    # Templates
    # -------------------------------------------------------------------------

    def save_template(
        self,
        context: Mapping[str, Any],
        name: str,
        description: str,
        category: str,
        steps: Optional[List[Mapping[str, Any]]] = None,
        triggers: Optional[List[Mapping[str, Any]]] = None,
        variables: Optional[Mapping[str, Any]] = None,
        required_tools: Optional[List[str]] = None,
        default_preferences: Optional[Mapping[str, Any]] = None,
        template_id: Optional[str] = None,
        version: str = "1.0.0",
        tags: Optional[List[str]] = None,
        is_active: bool = True,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Save reusable workflow template.

        Examples:
            - Form -> Validate -> Sheet -> CRM -> Email follow-up
            - New lead -> WhatsApp alert -> CRM task
            - Daily report -> Email -> Dashboard notification
        """
        valid, error, ctx = self._validate_task_context(context)
        if not valid:
            return self._error_result("Invalid task context.", error or "INVALID_CONTEXT")

        if not str(name or "").strip():
            return self._error_result("Template name is required.", "INVALID_TEMPLATE_NAME")

        if not str(category or "").strip():
            return self._error_result("Template category is required.", "INVALID_TEMPLATE_CATEGORY")

        steps_list = [dict(step) for step in (steps or [])]
        triggers_list = [dict(trigger) for trigger in (triggers or [])]

        if len(steps_list) > DEFAULT_MAX_TEMPLATE_STEPS:
            return self._error_result("Template has too many steps.", "TEMPLATE_STEP_LIMIT_REACHED")

        normalized_template_id = normalize_key(template_id or name)
        if not normalized_template_id:
            return self._error_result("Invalid template_id.", "INVALID_TEMPLATE_ID")

        if self._count_records(ctx, "template") >= self.max_templates:
            existing = self.store.get_record(ctx["user_id"], ctx["workspace_id"], "template", normalized_template_id)
            if not existing:
                return self._error_result("Template limit reached for this workspace.", "TEMPLATE_LIMIT_REACHED")

        try:
            now = utc_now_iso()
            existing_record = self.store.get_record(ctx["user_id"], ctx["workspace_id"], "template", normalized_template_id)

            template = WorkflowTemplateDefinition(
                template_id=normalized_template_id,
                name=str(name).strip(),
                description=str(description or "").strip(),
                category=normalize_key(category),
                version=str(version or "1.0.0").strip(),
                steps=self._validate_steps(steps_list),
                triggers=self._validate_steps(triggers_list),
                variables=self._validate_and_clean_payload(dict(variables or {})),
                required_tools=[normalize_key(item) for item in (required_tools or []) if str(item).strip()],
                default_preferences=self._validate_and_clean_payload(dict(default_preferences or {})),
                tags=self._normalize_tags(tags),
                is_active=bool(is_active),
                created_at=existing_record.created_at if existing_record else now,
                updated_at=now,
                metadata=self._validate_and_clean_payload(dict(metadata or {})),
            )

            record = WorkflowMemoryRecord(
                record_id=existing_record.record_id if existing_record else str(uuid.uuid4()),
                record_type="template",
                user_id=ctx["user_id"],
                workspace_id=ctx["workspace_id"],
                key=normalized_template_id,
                value=template.to_dict(redact_sensitive=False),
                created_at=existing_record.created_at if existing_record else now,
                updated_at=now,
                created_by=existing_record.created_by if existing_record else ctx.get("actor_id"),
                updated_by=ctx.get("actor_id"),
                tags=template.tags,
                metadata={
                    "category": template.category,
                    "version": template.version,
                    "is_active": template.is_active,
                    "required_tools": template.required_tools,
                },
            )

            self.store.upsert_record(record)

            output = {
                "template": record.to_dict(redact_sensitive=True),
                "memory_payload": self._prepare_memory_payload(
                    action="save_template",
                    context=ctx,
                    memory_type="template",
                    key=normalized_template_id,
                    value=record.value,
                ),
            }
            output["verification_payload"] = self._prepare_verification_payload("save_template", ctx, output)

            self._emit_agent_event("workflow_memory.template_saved", output)
            self._log_audit_event(
                {
                    "event": "workflow_memory.template_saved",
                    "user_id": ctx["user_id"],
                    "workspace_id": ctx["workspace_id"],
                    "actor_id": ctx.get("actor_id"),
                    "template_id": normalized_template_id,
                    "category": template.category,
                    "request_id": ctx.get("request_id"),
                    "timestamp": now,
                }
            )

            return self._safe_result(
                message="Workflow template saved.",
                data=output,
                metadata=self._result_metadata(action="save_template", context=ctx),
            )

        except Exception as exc:
            self.logger.exception("Failed to save workflow template.")
            return self._error_result(
                message="Failed to save workflow template.",
                error=exc,
                metadata=self._result_metadata(action="save_template", context=ctx),
            )

    def get_template(self, context: Mapping[str, Any], template_id: str) -> Dict[str, Any]:
        """Get one workflow template by template_id."""
        return self._get_by_type(
            context,
            "template",
            template_id,
            "Workflow template loaded.",
            "Workflow template not found.",
        )

    def list_templates(
        self,
        context: Mapping[str, Any],
        tags: Optional[List[str]] = None,
        category: Optional[str] = None,
        active_only: bool = False,
    ) -> Dict[str, Any]:
        """List workflow templates with optional filters."""
        valid, error, ctx = self._validate_task_context(context)
        if not valid:
            return self._error_result("Invalid task context.", error or "INVALID_CONTEXT")

        category_n = normalize_key(category) if category else None
        records = self.store.list_records(ctx["user_id"], ctx["workspace_id"], "template", tags)
        filtered: List[Dict[str, Any]] = []

        for record in records:
            value = record.value or {}

            if category_n and normalize_key(value.get("category", "")) != category_n:
                continue

            if active_only and not bool(value.get("is_active")):
                continue

            filtered.append(record.to_dict(redact_sensitive=True))

        return self._safe_result(
            message="Workflow templates loaded.",
            data={"items": filtered, "count": len(filtered)},
            metadata=self._result_metadata(action="list_templates", context=ctx),
        )

    def delete_template(self, context: Mapping[str, Any], template_id: str) -> Dict[str, Any]:
        """Delete one workflow template."""
        return self._delete_by_type(context, "template", template_id, "Workflow template deleted.")

    # -------------------------------------------------------------------------
    # Export, import, clear, search
    # -------------------------------------------------------------------------

    def export_memory(
        self,
        context: Mapping[str, Any],
        include_verification_payload: bool = True,
    ) -> Dict[str, Any]:
        """Export all workflow memory for one user/workspace."""
        valid, error, ctx = self._validate_task_context(context)
        if not valid:
            return self._error_result("Invalid task context.", error or "INVALID_CONTEXT")

        try:
            exported = self.store.export_tenant(ctx["user_id"], ctx["workspace_id"])
            redacted_export = WorkflowMemorySanitizer.redact_sensitive(exported)

            output: Dict[str, Any] = {
                "export": redacted_export,
                "record_counts": self._record_counts(ctx),
            }

            if include_verification_payload:
                output["verification_payload"] = self._prepare_verification_payload("export_memory", ctx, output)

            self._log_audit_event(
                {
                    "event": "workflow_memory.exported",
                    "user_id": ctx["user_id"],
                    "workspace_id": ctx["workspace_id"],
                    "actor_id": ctx.get("actor_id"),
                    "request_id": ctx.get("request_id"),
                    "timestamp": utc_now_iso(),
                    "record_counts": output["record_counts"],
                }
            )

            return self._safe_result(
                message="Workflow memory exported.",
                data=output,
                metadata=self._result_metadata(action="export_memory", context=ctx),
            )

        except Exception as exc:
            self.logger.exception("Failed to export workflow memory.")
            return self._error_result(
                message="Failed to export workflow memory.",
                error=exc,
                metadata=self._result_metadata(action="export_memory", context=ctx),
            )

    def import_memory(
        self,
        context: Mapping[str, Any],
        payload: Mapping[str, Any],
        merge: bool = True,
    ) -> Dict[str, Any]:
        """Import workflow memory into one user/workspace after security approval."""
        valid, error, ctx = self._validate_task_context(context)
        if not valid:
            return self._error_result("Invalid task context.", error or "INVALID_CONTEXT")

        if not isinstance(payload, Mapping):
            return self._error_result("Import payload must be a mapping/dict.", "INVALID_IMPORT_PAYLOAD")

        if self._requires_security_check("import_memory", payload):
            approval = self._request_security_approval("import_memory", ctx, payload)
            if not approval["success"]:
                return approval

        try:
            imported_count = self.store.import_tenant(ctx["user_id"], ctx["workspace_id"], payload, merge=merge)
            output = {
                "imported_count": imported_count,
                "merge": merge,
                "record_counts": self._record_counts(ctx),
            }
            output["verification_payload"] = self._prepare_verification_payload("import_memory", ctx, output)

            self._emit_agent_event("workflow_memory.imported", output)
            self._log_audit_event(
                {
                    "event": "workflow_memory.imported",
                    "user_id": ctx["user_id"],
                    "workspace_id": ctx["workspace_id"],
                    "actor_id": ctx.get("actor_id"),
                    "request_id": ctx.get("request_id"),
                    "timestamp": utc_now_iso(),
                    "imported_count": imported_count,
                    "merge": merge,
                }
            )

            return self._safe_result(
                message="Workflow memory imported.",
                data=output,
                metadata=self._result_metadata(action="import_memory", context=ctx),
            )

        except Exception as exc:
            self.logger.exception("Failed to import workflow memory.")
            return self._error_result(
                message="Failed to import workflow memory.",
                error=exc,
                metadata=self._result_metadata(action="import_memory", context=ctx),
            )

    def clear_memory(
        self,
        context: Mapping[str, Any],
        record_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Clear workflow memory for one tenant.

        This is sensitive and requires Security Agent compatible approval.
        """
        valid, error, ctx = self._validate_task_context(context)
        if not valid:
            return self._error_result("Invalid task context.", error or "INVALID_CONTEXT")

        if record_type is not None:
            record_type = normalize_key(record_type)
            if record_type not in SUPPORTED_MEMORY_TYPES:
                return self._error_result("Invalid record_type.", "INVALID_RECORD_TYPE")

        payload = {"record_type": record_type or "all"}

        if self._requires_security_check("clear_memory", payload):
            approval = self._request_security_approval("clear_memory", ctx, payload)
            if not approval["success"]:
                return approval

        try:
            deleted_count = self.store.clear_tenant(ctx["user_id"], ctx["workspace_id"], record_type)
            output = {
                "deleted_count": deleted_count,
                "record_type": record_type or "all",
                "record_counts": self._record_counts(ctx),
            }
            output["verification_payload"] = self._prepare_verification_payload("clear_memory", ctx, output)

            self._emit_agent_event("workflow_memory.cleared", output)
            self._log_audit_event(
                {
                    "event": "workflow_memory.cleared",
                    "user_id": ctx["user_id"],
                    "workspace_id": ctx["workspace_id"],
                    "actor_id": ctx.get("actor_id"),
                    "request_id": ctx.get("request_id"),
                    "timestamp": utc_now_iso(),
                    "record_type": record_type or "all",
                    "deleted_count": deleted_count,
                }
            )

            return self._safe_result(
                message="Workflow memory cleared.",
                data=output,
                metadata=self._result_metadata(action="clear_memory", context=ctx),
            )

        except Exception as exc:
            self.logger.exception("Failed to clear workflow memory.")
            return self._error_result(
                message="Failed to clear workflow memory.",
                error=exc,
                metadata=self._result_metadata(action="clear_memory", context=ctx),
            )

    def search_memory(
        self,
        context: Mapping[str, Any],
        query: str,
        record_type: Optional[str] = None,
        limit: int = 25,
    ) -> Dict[str, Any]:
        """
        Search workflow memory by key, tags, metadata, and redacted value text.

        This is intentionally lightweight. A future upgrade can route to the
        Memory Agent vector store or database full-text search.
        """
        valid, error, ctx = self._validate_task_context(context)
        if not valid:
            return self._error_result("Invalid task context.", error or "INVALID_CONTEXT")

        query_n = str(query or "").strip().lower()
        if not query_n:
            return self._error_result("Search query is required.", "INVALID_QUERY")

        if record_type:
            record_type = normalize_key(record_type)
            if record_type not in SUPPORTED_MEMORY_TYPES:
                return self._error_result("Invalid record_type.", "INVALID_RECORD_TYPE")

        records = self.store.list_records(ctx["user_id"], ctx["workspace_id"], record_type)
        matches: List[Dict[str, Any]] = []

        for record in records:
            redacted = record.to_dict(redact_sensitive=True)
            searchable = safe_json_dumps(redacted).lower()

            if query_n in searchable:
                matches.append(redacted)

            if len(matches) >= max(1, min(int(limit or 25), 100)):
                break

        return self._safe_result(
            message="Workflow memory search completed.",
            data={
                "items": matches,
                "count": len(matches),
                "query": query,
                "record_type": record_type,
            },
            metadata=self._result_metadata(action="search_memory", context=ctx),
        )

    # -------------------------------------------------------------------------
    # Router compatibility
    # -------------------------------------------------------------------------

    def route_action(
        self,
        action: str,
        context: Mapping[str, Any],
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Route generic Master Agent / Agent Router actions to public methods.

        This keeps WorkflowMemory compatible with centralized routers without
        requiring the router to know every method signature.
        """
        action_n = normalize_key(action)
        payload = dict(payload or {})

        route_map: Dict[str, Callable[..., Dict[str, Any]]] = {
            "save_preference": self.save_preference,
            "get_preference": self.get_preference,
            "list_preferences": self.list_preferences,
            "delete_preference": self.delete_preference,
            "save_mapping": self.save_mapping,
            "get_mapping": self.get_mapping,
            "list_mappings": self.list_mappings,
            "delete_mapping": self.delete_mapping,
            "save_connected_tool": self.save_connected_tool,
            "get_connected_tool": self.get_connected_tool,
            "list_connected_tools": self.list_connected_tools,
            "delete_connected_tool": self.delete_connected_tool,
            "set_tool_status": self.set_tool_status,
            "save_template": self.save_template,
            "get_template": self.get_template,
            "list_templates": self.list_templates,
            "delete_template": self.delete_template,
            "export_memory": self.export_memory,
            "import_memory": self.import_memory,
            "clear_memory": self.clear_memory,
            "search_memory": self.search_memory,
        }

        method = route_map.get(action_n)
        if not method:
            return self._error_result(
                message=f"Unsupported WorkflowMemory action: {action}",
                error="UNSUPPORTED_ACTION",
                metadata=self._result_metadata(action="route_action"),
            )

        try:
            return method(context=context, **payload)
        except TypeError as exc:
            return self._error_result(
                message="Invalid payload for WorkflowMemory action.",
                error={
                    "code": "INVALID_ACTION_PAYLOAD",
                    "detail": str(exc),
                    "action": action_n,
                },
                metadata=self._result_metadata(action="route_action"),
            )
        except Exception as exc:
            self.logger.exception("WorkflowMemory route_action failed.")
            return self._error_result(
                message="WorkflowMemory action failed.",
                error=exc,
                metadata=self._result_metadata(action="route_action"),
            )

    # -------------------------------------------------------------------------
    # Internal shared operations
    # -------------------------------------------------------------------------

    def _get_by_type(
        self,
        context: Mapping[str, Any],
        record_type: str,
        key: str,
        found_message: str,
        not_found_message: str,
    ) -> Dict[str, Any]:
        """Shared getter for mapping, connected_tool, and template."""
        valid, error, ctx = self._validate_task_context(context)
        if not valid:
            return self._error_result("Invalid task context.", error or "INVALID_CONTEXT")

        normalized_key = self._validate_key(key)
        if not normalized_key:
            return self._error_result("Invalid key.", "INVALID_KEY")

        record = self.store.get_record(ctx["user_id"], ctx["workspace_id"], record_type, normalized_key)

        if not record:
            return self._safe_result(
                message=not_found_message,
                data={"key": normalized_key, "found": False},
                metadata=self._result_metadata(action=f"get_{record_type}", context=ctx),
            )

        return self._safe_result(
            message=found_message,
            data={record_type: record.to_dict(redact_sensitive=True), "found": True},
            metadata=self._result_metadata(action=f"get_{record_type}", context=ctx),
        )

    def _list_by_type(
        self,
        context: Mapping[str, Any],
        record_type: str,
        tags: Optional[List[str]],
        message: str,
    ) -> Dict[str, Any]:
        """Shared list operation."""
        valid, error, ctx = self._validate_task_context(context)
        if not valid:
            return self._error_result("Invalid task context.", error or "INVALID_CONTEXT")

        records = self.store.list_records(ctx["user_id"], ctx["workspace_id"], record_type, tags)
        items = [record.to_dict(redact_sensitive=True) for record in records]

        return self._safe_result(
            message=message,
            data={"items": items, "count": len(items)},
            metadata=self._result_metadata(action=f"list_{record_type}", context=ctx),
        )

    def _delete_by_type(
        self,
        context: Mapping[str, Any],
        record_type: str,
        key: str,
        message: str,
        sensitive_action: bool = False,
    ) -> Dict[str, Any]:
        """Shared delete operation."""
        valid, error, ctx = self._validate_task_context(context)
        if not valid:
            return self._error_result("Invalid task context.", error or "INVALID_CONTEXT")

        normalized_key = self._validate_key(key)
        if not normalized_key:
            return self._error_result("Invalid key.", "INVALID_KEY")

        action = f"delete_{record_type}"
        payload = {"record_type": record_type, "key": normalized_key}

        if sensitive_action or self._requires_security_check(action, payload):
            approval = self._request_security_approval(action, ctx, payload)
            if not approval["success"]:
                return approval

        existed = self.store.delete_record(ctx["user_id"], ctx["workspace_id"], record_type, normalized_key)

        output = {
            "key": normalized_key,
            "record_type": record_type,
            "deleted": existed,
        }
        output["verification_payload"] = self._prepare_verification_payload(action, ctx, output)

        self._emit_agent_event(f"workflow_memory.{record_type}_deleted", output)
        self._log_audit_event(
            {
                "event": f"workflow_memory.{record_type}_deleted",
                "user_id": ctx["user_id"],
                "workspace_id": ctx["workspace_id"],
                "actor_id": ctx.get("actor_id"),
                "key": normalized_key,
                "deleted": existed,
                "request_id": ctx.get("request_id"),
                "timestamp": utc_now_iso(),
            }
        )

        return self._safe_result(
            message=message if existed else f"{record_type} not found.",
            data=output,
            metadata=self._result_metadata(action=action, context=ctx),
        )

    # -------------------------------------------------------------------------
    # Validation helpers
    # -------------------------------------------------------------------------

    def _validate_key(self, key: str) -> Optional[str]:
        """Validate and normalize record key."""
        normalized = normalize_key(key)

        if not normalized:
            return None

        if len(normalized) > DEFAULT_MAX_KEY_LENGTH:
            return None

        return normalized

    def _validate_and_clean_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Validate payload size and remove raw sensitive fields before storage."""
        cleaned = WorkflowMemorySanitizer.remove_sensitive_for_storage(payload)
        serialized = safe_json_dumps(cleaned)

        if len(serialized) > DEFAULT_MAX_TEXT_LENGTH:
            raise ValueError(f"Payload is too large. Max length: {DEFAULT_MAX_TEXT_LENGTH}")

        return cleaned

    def _validate_steps(self, steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Validate workflow template steps/triggers.

        The Workflow Builder and Action Router are responsible for deeper
        execution validation. This method keeps stored templates structurally safe.
        """
        clean_steps: List[Dict[str, Any]] = []

        for index, step in enumerate(steps):
            if not isinstance(step, Mapping):
                raise ValueError(f"Step at index {index} must be a mapping/dict.")

            clean_step = self._validate_and_clean_payload(dict(step))
            clean_step.setdefault("step_id", f"step_{index + 1}")
            clean_step.setdefault("type", "generic")
            clean_step.setdefault("name", clean_step.get("step_id"))
            clean_steps.append(clean_step)

        return clean_steps

    def _normalize_tags(self, tags: Optional[Iterable[str]]) -> List[str]:
        """Normalize tags and remove empties/duplicates."""
        output: List[str] = []
        seen = set()

        for tag in tags or []:
            normalized = normalize_key(str(tag))
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            output.append(normalized)

        return output[:50]

    def _normalize_scopes(self, scopes: Optional[Iterable[str]]) -> List[str]:
        """Normalize connected tool scopes."""
        output: List[str] = []
        seen = set()

        for scope in scopes or []:
            normalized = normalize_key(str(scope))
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            output.append(normalized)

        return output[:100]

    def _normalize_tool_status(self, status: Optional[str]) -> str:
        """Normalize connected tool status."""
        status_n = normalize_key(status or "inactive")
        allowed = {"active", "inactive", "pending", "error", "disabled", "revoked"}

        if status_n not in allowed:
            return "inactive"

        return status_n

    def _contains_sensitive_keys(self, payload: Any) -> bool:
        """Detect sensitive keys recursively."""
        if isinstance(payload, Mapping):
            for key, value in payload.items():
                if is_sensitive_key(str(key)):
                    return True
                if self._contains_sensitive_keys(value):
                    return True

        elif isinstance(payload, list):
            return any(self._contains_sensitive_keys(item) for item in payload)

        return False

    def _count_records(self, context: Mapping[str, Any], record_type: str) -> int:
        """Count records for one tenant/type."""
        return len(self.store.list_records(context["user_id"], context["workspace_id"], record_type))

    def _record_counts(self, context: Mapping[str, Any]) -> Dict[str, int]:
        """Return all record counts for one tenant."""
        return {
            record_type: self._count_records(context, record_type)
            for record_type in sorted(SUPPORTED_MEMORY_TYPES)
        }

    def _result_metadata(
        self,
        action: Optional[str] = None,
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Build standard result metadata."""
        context = context or {}

        return {
            "agent": self.agent_name,
            "module": self.module_name,
            "agent_module": self.agent_module,
            "version": self.version,
            "action": action,
            "timestamp": utc_now_iso(),
            "request_id": context.get("request_id"),
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "external_action_executed": False,
            "safe_to_import": True,
        }


# =============================================================================
# Optional module-level factory
# =============================================================================

def create_workflow_memory(
    storage_path: Optional[Union[str, Path]] = None,
    **kwargs: Any,
) -> WorkflowMemory:
    """
    Factory helper for Agent Loader / Registry.

    Example:
        memory = create_workflow_memory(storage_path="data/workflow_memory.json")
    """
    return WorkflowMemory(storage_path=storage_path, **kwargs)


# =============================================================================
# Self-test helper
# =============================================================================

def _self_test() -> Dict[str, Any]:
    """
    Lightweight self-test.

    This does not run automatically on import. It can be called manually by tests.
    """
    memory = WorkflowMemory()
    context = {
        "user_id": "test_user",
        "workspace_id": "test_workspace",
        "actor_id": "tester",
        "security_approved": True,
    }

    results = {
        "manifest": memory.get_agent_manifest(),
        "save_preference": memory.save_preference(
            context,
            key="default_lead_pipeline",
            value={"pipeline": "sales", "stage": "new"},
            tags=["crm", "lead"],
        ),
        "get_preference": memory.get_preference(context, "default_lead_pipeline"),
        "save_mapping": memory.save_mapping(
            context,
            key="form_to_crm",
            source="lead_form",
            target="crm_contact",
            mapping={
                "full_name": "contact.name",
                "phone": "contact.phone",
                "email": "contact.email",
            },
            tags=["form", "crm"],
        ),
        "save_connected_tool": memory.save_connected_tool(
            context,
            tool_name="HubSpot CRM",
            tool_type="crm",
            provider="hubspot",
            status="active",
            scopes=["contacts.read", "contacts.write"],
            metadata={
                "account_name": "Demo Account",
                "api_key": "SHOULD_NOT_BE_STORED",
                "vault_reference_id": "vault_ref_demo",
            },
            tags=["crm"],
        ),
        "save_template": memory.save_template(
            context,
            name="Lead Intake Follow Up",
            description="Capture lead, save to CRM, and send follow-up email.",
            category="lead_management",
            steps=[
                {"type": "validate", "name": "Validate Lead"},
                {"type": "crm_create_contact", "name": "Create CRM Contact"},
                {"type": "email_send", "name": "Send Follow-up Email"},
            ],
            required_tools=["crm", "email"],
            tags=["lead", "crm", "email"],
        ),
        "export_memory": memory.export_memory(context),
    }

    return results


__all__ = [
    "WorkflowMemory",
    "WorkflowMemoryStore",
    "WorkflowMemoryRecord",
    "WorkflowConnectedTool",
    "WorkflowTemplateDefinition",
    "WorkflowMemorySanitizer",
    "create_workflow_memory",
]