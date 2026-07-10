"""
agents/super_agents/business_agent/lead_tracker.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Tracks leads from forms, calls, ads, SEO, workflows, imports.

This module provides a production-ready, import-safe LeadTracker class for the
Business Agent. It is designed to work with:

    - Master Agent routing
    - BaseAgent compatibility
    - Agent Registry / Agent Loader
    - Security Agent approval hooks
    - Memory Agent payload preparation
    - Verification Agent payload preparation
    - Dashboard / FastAPI integration
    - SaaS user/workspace isolation
    - Future persistent database backends

Core guarantees:
    - Every user-specific operation requires user_id and workspace_id.
    - Leads are never mixed across users or workspaces.
    - Sensitive or destructive actions are gated through security hooks.
    - All public results follow structured dict style:
        {
            "success": bool,
            "message": str,
            "data": dict | list | None,
            "error": str | None,
            "metadata": dict
        }
    - The file is safe to import even if the wider William/Jarvis codebase
      is not fully created yet.

No secrets are hardcoded.
No real external calls are executed directly.
"""

from __future__ import annotations

import copy
import csv
import hashlib
import json
import logging
import re
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from io import StringIO
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Safe optional BaseAgent import
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for standalone import safety
    class BaseAgent:  # type: ignore
        """
        Import-safe fallback BaseAgent.

        The real William/Jarvis BaseAgent may provide richer runtime features.
        This fallback keeps this file importable and testable before the full
        system is assembled.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())
            self.config = kwargs.get("config", {}) or {}

        async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent does not implement run.",
                "data": None,
                "error": "BASE_AGENT_FALLBACK_RUN_NOT_IMPLEMENTED",
                "metadata": {
                    "agent": self.agent_name,
                    "agent_id": self.agent_id,
                },
            }


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOGGER = logging.getLogger(__name__)
if not LOGGER.handlers:
    LOGGER.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_AGENT_NAME = "BusinessLeadTracker"
DEFAULT_AGENT_ID = "business_agent.lead_tracker"
DEFAULT_VERSION = "1.0.0"

SYSTEM_SOURCES = {
    "form",
    "call",
    "ad",
    "seo",
    "workflow",
    "import",
    "manual",
    "api",
    "crm",
    "unknown",
}

SENSITIVE_ACTIONS = {
    "delete_lead",
    "archive_lead",
    "bulk_delete_leads",
    "bulk_archive_leads",
    "merge_leads",
    "export_leads",
    "import_leads",
    "assign_lead",
    "change_owner",
}

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PHONE_CLEAN_RE = re.compile(r"[^\d+]")
WHITESPACE_RE = re.compile(r"\s+")


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class LeadSource(str, Enum):
    FORM = "form"
    CALL = "call"
    AD = "ad"
    SEO = "seo"
    WORKFLOW = "workflow"
    IMPORT = "import"
    MANUAL = "manual"
    API = "api"
    CRM = "crm"
    UNKNOWN = "unknown"


class LeadStatus(str, Enum):
    NEW = "new"
    OPEN = "open"
    CONTACTED = "contacted"
    QUALIFIED = "qualified"
    UNQUALIFIED = "unqualified"
    WON = "won"
    LOST = "lost"
    ARCHIVED = "archived"


class LeadStage(str, Enum):
    CAPTURED = "captured"
    DISCOVERY = "discovery"
    QUALIFICATION = "qualification"
    PROPOSAL = "proposal"
    NEGOTIATION = "negotiation"
    CLOSED_WON = "closed_won"
    CLOSED_LOST = "closed_lost"
    NURTURE = "nurture"


class LeadPriority(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    URGENT = "urgent"


class LeadTemperature(str, Enum):
    COLD = "cold"
    WARM = "warm"
    HOT = "hot"


class ConsentStatus(str, Enum):
    UNKNOWN = "unknown"
    OPTED_IN = "opted_in"
    OPTED_OUT = "opted_out"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class LeadAttribution:
    """
    Marketing/source attribution for a lead.

    This is intentionally generic so it can support forms, ads, SEO,
    workflows, imports, calls, UTM tracking, and future campaign systems.
    """

    source: str = LeadSource.UNKNOWN.value
    channel: Optional[str] = None
    campaign_id: Optional[str] = None
    campaign_name: Optional[str] = None
    ad_platform: Optional[str] = None
    ad_account_id: Optional[str] = None
    ad_id: Optional[str] = None
    adset_id: Optional[str] = None
    keyword: Optional[str] = None
    landing_page: Optional[str] = None
    referrer: Optional[str] = None
    utm_source: Optional[str] = None
    utm_medium: Optional[str] = None
    utm_campaign: Optional[str] = None
    utm_term: Optional[str] = None
    utm_content: Optional[str] = None
    gclid: Optional[str] = None
    fbclid: Optional[str] = None
    msclkid: Optional[str] = None
    workflow_id: Optional[str] = None
    workflow_name: Optional[str] = None
    import_batch_id: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LeadContact:
    """
    Contact data for a lead.

    Keep this minimal but extensible. Sensitive PII must always remain scoped
    by user_id and workspace_id.
    """

    full_name: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    company: Optional[str] = None
    job_title: Optional[str] = None
    website: Optional[str] = None
    location: Optional[str] = None
    timezone: Optional[str] = None
    preferred_contact_method: Optional[str] = None
    consent_status: str = ConsentStatus.UNKNOWN.value


@dataclass
class LeadRecord:
    """
    Canonical lead object stored by LeadTracker.

    The storage here defaults to an isolated in-memory backend, but the shape
    is ready for database persistence via repository adapters later.
    """

    lead_id: str
    user_id: str
    workspace_id: str
    contact: LeadContact
    attribution: LeadAttribution

    status: str = LeadStatus.NEW.value
    stage: str = LeadStage.CAPTURED.value
    priority: str = LeadPriority.MEDIUM.value
    temperature: str = LeadTemperature.COLD.value
    score: int = 0

    owner_id: Optional[str] = None
    assigned_team_id: Optional[str] = None
    client_id: Optional[str] = None
    pipeline_id: Optional[str] = None

    service_interest: Optional[str] = None
    budget: Optional[Union[int, float, str]] = None
    urgency: Optional[str] = None
    lead_value: Optional[Union[int, float]] = None
    currency: str = "USD"

    notes: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    custom_fields: Dict[str, Any] = field(default_factory=dict)
    raw_payload: Dict[str, Any] = field(default_factory=dict)

    duplicate_key: Optional[str] = None
    duplicate_of: Optional[str] = None
    merged_into: Optional[str] = None

    created_at: str = field(default_factory=lambda: utc_now_iso())
    updated_at: str = field(default_factory=lambda: utc_now_iso())
    last_activity_at: Optional[str] = None
    next_follow_up_at: Optional[str] = None
    archived_at: Optional[str] = None

    created_by: Optional[str] = None
    updated_by: Optional[str] = None

    audit_history: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class LeadImportReport:
    batch_id: str
    total_rows: int = 0
    created: int = 0
    updated: int = 0
    duplicates: int = 0
    failed: int = 0
    errors: List[Dict[str, Any]] = field(default_factory=list)
    lead_ids: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def utc_now_iso() -> str:
    """Return current UTC time as ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def safe_json_dumps(value: Any) -> str:
    """Safely serialize a value to JSON string for hashing/logging."""
    try:
        return json.dumps(value, sort_keys=True, default=str, ensure_ascii=False)
    except Exception:
        return str(value)


def normalize_text(value: Any) -> Optional[str]:
    """Normalize free text safely."""
    if value is None:
        return None
    text = str(value).strip()
    text = WHITESPACE_RE.sub(" ", text)
    return text or None


def normalize_email(value: Any) -> Optional[str]:
    """Normalize and validate email address."""
    text = normalize_text(value)
    if not text:
        return None
    text = text.lower()
    return text if EMAIL_RE.match(text) else None


def normalize_phone(value: Any) -> Optional[str]:
    """Normalize phone value while preserving leading plus where provided."""
    text = normalize_text(value)
    if not text:
        return None
    cleaned = PHONE_CLEAN_RE.sub("", text)
    if not cleaned:
        return None
    if cleaned.count("+") > 1:
        cleaned = "+" + cleaned.replace("+", "")
    if "+" in cleaned and not cleaned.startswith("+"):
        cleaned = cleaned.replace("+", "")
    return cleaned or None


def normalize_tag(value: Any) -> Optional[str]:
    """Normalize tag labels."""
    text = normalize_text(value)
    if not text:
        return None
    return text.lower().replace(" ", "_")


def ensure_list(value: Any) -> List[Any]:
    """Convert common values to list safely."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, set):
        return list(value)
    return [value]


def parse_name(full_name: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """Best-effort first/last name parser."""
    if not full_name:
        return None, None
    parts = [p for p in full_name.split(" ") if p]
    if not parts:
        return None, None
    if len(parts) == 1:
        return parts[0], None
    return parts[0], " ".join(parts[1:])


def hash_key(parts: Sequence[Any]) -> str:
    """Create deterministic SHA256 hash from values."""
    raw = "|".join("" if p is None else str(p).strip().lower() for p in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def safe_int_score(value: Any, default: int = 0) -> int:
    """Clamp a value into lead score range 0-100."""
    try:
        score = int(float(value))
    except Exception:
        score = default
    return max(0, min(100, score))


def deep_copy_dict(value: Dict[str, Any]) -> Dict[str, Any]:
    """Safe deep copy for dict payloads."""
    try:
        return copy.deepcopy(value)
    except Exception:
        return dict(value)


# ---------------------------------------------------------------------------
# In-memory repository
# ---------------------------------------------------------------------------

class InMemoryLeadRepository:
    """
    Import-safe repository for isolated lead storage.

    This repository is intentionally simple but thread-safe. In production, it
    can be replaced with a database-backed repository that preserves the same
    method contracts.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._leads: Dict[Tuple[str, str, str], LeadRecord] = {}

    def save(self, lead: LeadRecord) -> LeadRecord:
        with self._lock:
            self._leads[(lead.user_id, lead.workspace_id, lead.lead_id)] = copy.deepcopy(lead)
            return copy.deepcopy(lead)

    def get(self, user_id: str, workspace_id: str, lead_id: str) -> Optional[LeadRecord]:
        with self._lock:
            lead = self._leads.get((user_id, workspace_id, lead_id))
            return copy.deepcopy(lead) if lead else None

    def delete(self, user_id: str, workspace_id: str, lead_id: str) -> bool:
        with self._lock:
            key = (user_id, workspace_id, lead_id)
            if key not in self._leads:
                return False
            del self._leads[key]
            return True

    def list_workspace(
        self,
        user_id: str,
        workspace_id: str,
        include_archived: bool = False,
    ) -> List[LeadRecord]:
        with self._lock:
            result = []
            for (uid, wid, _), lead in self._leads.items():
                if uid != user_id or wid != workspace_id:
                    continue
                if not include_archived and lead.status == LeadStatus.ARCHIVED.value:
                    continue
                result.append(copy.deepcopy(lead))
            return result

    def find_by_duplicate_key(
        self,
        user_id: str,
        workspace_id: str,
        duplicate_key: str,
    ) -> Optional[LeadRecord]:
        with self._lock:
            for (uid, wid, _), lead in self._leads.items():
                if uid == user_id and wid == workspace_id and lead.duplicate_key == duplicate_key:
                    return copy.deepcopy(lead)
            return None


# ---------------------------------------------------------------------------
# LeadTracker
# ---------------------------------------------------------------------------

class LeadTracker(BaseAgent):
    """
    Business Agent lead tracking component.

    Public methods are designed for direct calls from:
        - Master Agent
        - Business Agent controller
        - Dashboard/API layer
        - Workflow Agent
        - Call Agent
        - Browser/Form integrations
        - Ads/SEO ingestion jobs
        - CRM Manager

    This class does not perform real external system writes directly. Security,
    memory, verification, and audit operations are emitted as structured payloads
    so the wider William/Jarvis runtime can route them safely.
    """

    def __init__(
        self,
        repository: Optional[InMemoryLeadRepository] = None,
        config: Optional[Dict[str, Any]] = None,
        security_callback: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        audit_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        memory_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        verification_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            agent_name=kwargs.get("agent_name", DEFAULT_AGENT_NAME),
            agent_id=kwargs.get("agent_id", DEFAULT_AGENT_ID),
            config=config or kwargs.get("config", {}) or {},
        )

        self.agent_name = kwargs.get("agent_name", DEFAULT_AGENT_NAME)
        self.agent_id = kwargs.get("agent_id", DEFAULT_AGENT_ID)
        self.version = kwargs.get("version", DEFAULT_VERSION)
        self.repository = repository or InMemoryLeadRepository()

        self.security_callback = security_callback
        self.event_callback = event_callback
        self.audit_callback = audit_callback
        self.memory_callback = memory_callback
        self.verification_callback = verification_callback

        self.default_currency = self.config.get("default_currency", "USD") if hasattr(self, "config") else "USD"
        self.allow_auto_merge = bool(self.config.get("allow_auto_merge", False)) if hasattr(self, "config") else False
        self.default_lead_score = safe_int_score(self.config.get("default_lead_score", 0)) if hasattr(self, "config") else 0

    # ------------------------------------------------------------------
    # Master Agent / Router entrypoint
    # ------------------------------------------------------------------

    async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Async task router compatible with BaseAgent/MasterAgent patterns.

        Expected task shape:
            {
                "action": "create_lead" | "track_form_lead" | ...,
                "user_id": "...",
                "workspace_id": "...",
                "payload": {...}
            }
        """
        try:
            action = normalize_text(task.get("action")) or "create_lead"
            payload = task.get("payload") or {}

            context_result = self._validate_task_context(task)
            if not context_result["success"]:
                return context_result

            user_id = task["user_id"]
            workspace_id = task["workspace_id"]

            if self._requires_security_check(action, payload):
                approval = self._request_security_approval(
                    action=action,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    payload=payload,
                    actor_id=task.get("actor_id"),
                )
                if not approval.get("approved", False):
                    return self._error_result(
                        message="Security approval denied or unavailable.",
                        error="SECURITY_APPROVAL_REQUIRED",
                        metadata={
                            "action": action,
                            "approval": approval,
                            "user_id": user_id,
                            "workspace_id": workspace_id,
                        },
                    )

            if action in {"create_lead", "track_lead"}:
                return self.create_lead(user_id=user_id, workspace_id=workspace_id, payload=payload, actor_id=task.get("actor_id"))
            if action in {"track_form_lead", "ingest_form_lead"}:
                return self.track_form_lead(user_id=user_id, workspace_id=workspace_id, payload=payload, actor_id=task.get("actor_id"))
            if action in {"track_call_lead", "ingest_call_lead"}:
                return self.track_call_lead(user_id=user_id, workspace_id=workspace_id, payload=payload, actor_id=task.get("actor_id"))
            if action in {"track_ad_lead", "ingest_ad_lead"}:
                return self.track_ad_lead(user_id=user_id, workspace_id=workspace_id, payload=payload, actor_id=task.get("actor_id"))
            if action in {"track_seo_lead", "ingest_seo_lead"}:
                return self.track_seo_lead(user_id=user_id, workspace_id=workspace_id, payload=payload, actor_id=task.get("actor_id"))
            if action in {"track_workflow_lead", "ingest_workflow_lead"}:
                return self.track_workflow_lead(user_id=user_id, workspace_id=workspace_id, payload=payload, actor_id=task.get("actor_id"))
            if action == "import_leads":
                return self.import_leads(user_id=user_id, workspace_id=workspace_id, rows=payload.get("rows", []), actor_id=task.get("actor_id"))
            if action == "get_lead":
                return self.get_lead(user_id=user_id, workspace_id=workspace_id, lead_id=payload.get("lead_id"))
            if action == "search_leads":
                return self.search_leads(user_id=user_id, workspace_id=workspace_id, filters=payload)
            if action == "update_lead":
                return self.update_lead(user_id=user_id, workspace_id=workspace_id, lead_id=payload.get("lead_id"), updates=payload.get("updates", {}), actor_id=task.get("actor_id"))
            if action == "archive_lead":
                return self.archive_lead(user_id=user_id, workspace_id=workspace_id, lead_id=payload.get("lead_id"), actor_id=task.get("actor_id"))
            if action == "delete_lead":
                return self.delete_lead(user_id=user_id, workspace_id=workspace_id, lead_id=payload.get("lead_id"), actor_id=task.get("actor_id"))
            if action == "lead_metrics":
                return self.get_lead_metrics(user_id=user_id, workspace_id=workspace_id, filters=payload)

            return self._error_result(
                message=f"Unsupported lead tracker action: {action}",
                error="UNSUPPORTED_ACTION",
                metadata={"action": action},
            )
        except Exception as exc:
            LOGGER.exception("LeadTracker run failed.")
            return self._error_result(
                message="LeadTracker task failed.",
                error=str(exc),
                metadata={"agent": self.agent_id},
            )

    # ------------------------------------------------------------------
    # Public ingestion methods
    # ------------------------------------------------------------------

    def create_lead(
        self,
        user_id: str,
        workspace_id: str,
        payload: Dict[str, Any],
        actor_id: Optional[str] = None,
        dedupe: bool = True,
        update_existing: bool = False,
    ) -> Dict[str, Any]:
        """
        Create a canonical lead from any supported source payload.

        This is the core method used by all source-specific trackers.
        """
        context = self._validate_ids(user_id, workspace_id)
        if not context["success"]:
            return context

        try:
            clean_payload = deep_copy_dict(payload or {})
            lead = self._build_lead_record(
                user_id=user_id,
                workspace_id=workspace_id,
                payload=clean_payload,
                actor_id=actor_id,
            )

            validation = self._validate_lead_record(lead)
            if not validation["success"]:
                return validation

            existing = self.repository.find_by_duplicate_key(
                user_id=user_id,
                workspace_id=workspace_id,
                duplicate_key=lead.duplicate_key or "",
            ) if dedupe and lead.duplicate_key else None

            if existing:
                if update_existing:
                    merged_updates = self._merge_lead_payload(existing, clean_payload, actor_id=actor_id)
                    return self.update_lead(
                        user_id=user_id,
                        workspace_id=workspace_id,
                        lead_id=existing.lead_id,
                        updates=merged_updates,
                        actor_id=actor_id,
                        source_action="dedupe_update",
                    )

                existing.duplicate_of = existing.lead_id
                duplicate_data = {
                    "lead": self._serialize_lead(existing),
                    "duplicate_detected": True,
                    "duplicate_key": lead.duplicate_key,
                    "incoming_preview": self._serialize_lead(lead),
                }
                self._emit_agent_event("lead.duplicate_detected", user_id, workspace_id, duplicate_data)
                return self._safe_result(
                    success=True,
                    message="Duplicate lead detected. Existing lead returned.",
                    data=duplicate_data,
                    metadata={
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                        "action": "create_lead",
                        "dedupe": True,
                    },
                )

            lead.audit_history.append(
                self._audit_entry(
                    action="lead_created",
                    actor_id=actor_id,
                    details={
                        "source": lead.attribution.source,
                        "status": lead.status,
                        "stage": lead.stage,
                    },
                )
            )

            saved = self.repository.save(lead)
            data = {"lead": self._serialize_lead(saved)}

            self._emit_agent_event("lead.created", user_id, workspace_id, data)
            self._log_audit_event(
                action="lead_created",
                user_id=user_id,
                workspace_id=workspace_id,
                actor_id=actor_id,
                data=data,
            )
            self._send_memory_payload("lead_created", saved)
            self._send_verification_payload("lead_created", saved, data)

            return self._safe_result(
                success=True,
                message="Lead created successfully.",
                data=data,
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "lead_id": saved.lead_id,
                    "source": saved.attribution.source,
                },
            )
        except Exception as exc:
            LOGGER.exception("Failed to create lead.")
            return self._error_result(
                message="Failed to create lead.",
                error=str(exc),
                metadata={"user_id": user_id, "workspace_id": workspace_id},
            )

    def track_form_lead(
        self,
        user_id: str,
        workspace_id: str,
        payload: Dict[str, Any],
        actor_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Track a lead captured from a website form, landing page, or API form."""
        enriched = deep_copy_dict(payload or {})
        enriched.setdefault("source", LeadSource.FORM.value)
        enriched.setdefault("status", LeadStatus.NEW.value)
        enriched.setdefault("stage", LeadStage.CAPTURED.value)
        enriched.setdefault("tags", [])
        enriched["tags"] = list({*map(str, ensure_list(enriched.get("tags"))), "form_lead"})
        return self.create_lead(user_id, workspace_id, enriched, actor_id=actor_id, dedupe=True)

    def track_call_lead(
        self,
        user_id: str,
        workspace_id: str,
        payload: Dict[str, Any],
        actor_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Track a lead captured from inbound/outbound calls or receptionist mode."""
        enriched = deep_copy_dict(payload or {})
        enriched.setdefault("source", LeadSource.CALL.value)
        enriched.setdefault("status", LeadStatus.NEW.value)
        enriched.setdefault("stage", LeadStage.DISCOVERY.value)
        enriched.setdefault("preferred_contact_method", "phone")
        enriched.setdefault("tags", [])
        enriched["tags"] = list({*map(str, ensure_list(enriched.get("tags"))), "call_lead"})

        call_summary = enriched.get("call_summary") or enriched.get("summary")
        if call_summary:
            enriched.setdefault("notes", [])
            enriched["notes"] = ensure_list(enriched["notes"]) + [f"Call summary: {call_summary}"]

        return self.create_lead(user_id, workspace_id, enriched, actor_id=actor_id, dedupe=True)

    def track_ad_lead(
        self,
        user_id: str,
        workspace_id: str,
        payload: Dict[str, Any],
        actor_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Track a lead from Meta, Google, Microsoft, TikTok, LinkedIn, or ad forms."""
        enriched = deep_copy_dict(payload or {})
        enriched.setdefault("source", LeadSource.AD.value)
        enriched.setdefault("status", LeadStatus.NEW.value)
        enriched.setdefault("stage", LeadStage.CAPTURED.value)
        enriched.setdefault("tags", [])
        enriched["tags"] = list({*map(str, ensure_list(enriched.get("tags"))), "ad_lead"})

        score_boost = 10 if enriched.get("campaign_id") or enriched.get("campaign_name") else 5
        enriched["score"] = min(100, safe_int_score(enriched.get("score", self.default_lead_score)) + score_boost)

        return self.create_lead(user_id, workspace_id, enriched, actor_id=actor_id, dedupe=True)

    def track_seo_lead(
        self,
        user_id: str,
        workspace_id: str,
        payload: Dict[str, Any],
        actor_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Track an organic lead from SEO, blog, GMB, organic search, or referral."""
        enriched = deep_copy_dict(payload or {})
        enriched.setdefault("source", LeadSource.SEO.value)
        enriched.setdefault("status", LeadStatus.NEW.value)
        enriched.setdefault("stage", LeadStage.CAPTURED.value)
        enriched.setdefault("tags", [])
        enriched["tags"] = list({*map(str, ensure_list(enriched.get("tags"))), "seo_lead"})

        if enriched.get("keyword"):
            enriched["score"] = min(100, safe_int_score(enriched.get("score", self.default_lead_score)) + 8)

        return self.create_lead(user_id, workspace_id, enriched, actor_id=actor_id, dedupe=True)

    def track_workflow_lead(
        self,
        user_id: str,
        workspace_id: str,
        payload: Dict[str, Any],
        actor_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Track a lead created by Workflow Agent automations."""
        enriched = deep_copy_dict(payload or {})
        enriched.setdefault("source", LeadSource.WORKFLOW.value)
        enriched.setdefault("status", LeadStatus.NEW.value)
        enriched.setdefault("stage", LeadStage.CAPTURED.value)
        enriched.setdefault("tags", [])
        enriched["tags"] = list({*map(str, ensure_list(enriched.get("tags"))), "workflow_lead"})

        return self.create_lead(user_id, workspace_id, enriched, actor_id=actor_id, dedupe=True)

    def import_leads(
        self,
        user_id: str,
        workspace_id: str,
        rows: Sequence[Dict[str, Any]],
        actor_id: Optional[str] = None,
        update_existing: bool = False,
    ) -> Dict[str, Any]:
        """
        Import multiple leads safely.

        This method does not trust imported data. Every row is validated and
        stored under the supplied user_id/workspace_id only.
        """
        context = self._validate_ids(user_id, workspace_id)
        if not context["success"]:
            return context

        approval = self._request_security_approval(
            action="import_leads",
            user_id=user_id,
            workspace_id=workspace_id,
            payload={"row_count": len(rows or [])},
            actor_id=actor_id,
        )
        if not approval.get("approved", False):
            return self._error_result(
                message="Security approval required for lead import.",
                error="SECURITY_APPROVAL_REQUIRED",
                metadata={"approval": approval},
            )

        batch_id = f"import_{uuid.uuid4().hex}"
        report = LeadImportReport(batch_id=batch_id, total_rows=len(rows or []))

        for index, row in enumerate(rows or []):
            try:
                enriched = deep_copy_dict(row or {})
                enriched.setdefault("source", LeadSource.IMPORT.value)
                enriched.setdefault("import_batch_id", batch_id)
                result = self.create_lead(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    payload=enriched,
                    actor_id=actor_id,
                    dedupe=True,
                    update_existing=update_existing,
                )
                if not result["success"]:
                    report.failed += 1
                    report.errors.append({"row": index, "error": result.get("error"), "message": result.get("message")})
                    continue

                data = result.get("data") or {}
                lead = data.get("lead") or {}
                duplicate_detected = bool(data.get("duplicate_detected"))

                if duplicate_detected:
                    report.duplicates += 1
                elif result.get("metadata", {}).get("action") == "update_lead":
                    report.updated += 1
                else:
                    report.created += 1

                if lead.get("lead_id"):
                    report.lead_ids.append(lead["lead_id"])

            except Exception as exc:
                report.failed += 1
                report.errors.append({"row": index, "error": str(exc)})

        data = {"import_report": asdict(report)}

        self._emit_agent_event("lead.import_completed", user_id, workspace_id, data)
        self._log_audit_event(
            action="lead_import_completed",
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id,
            data=data,
        )

        return self._safe_result(
            success=True,
            message="Lead import completed.",
            data=data,
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "batch_id": batch_id,
            },
        )

    # ------------------------------------------------------------------
    # Public lead management methods
    # ------------------------------------------------------------------

    def get_lead(self, user_id: str, workspace_id: str, lead_id: Optional[str]) -> Dict[str, Any]:
        """Retrieve one lead by ID within the caller's workspace scope."""
        context = self._validate_ids(user_id, workspace_id)
        if not context["success"]:
            return context
        if not lead_id:
            return self._error_result("lead_id is required.", "MISSING_LEAD_ID")

        lead = self.repository.get(user_id, workspace_id, lead_id)
        if not lead:
            return self._error_result(
                message="Lead not found.",
                error="LEAD_NOT_FOUND",
                metadata={"user_id": user_id, "workspace_id": workspace_id, "lead_id": lead_id},
            )

        return self._safe_result(
            success=True,
            message="Lead retrieved successfully.",
            data={"lead": self._serialize_lead(lead)},
            metadata={"user_id": user_id, "workspace_id": workspace_id, "lead_id": lead_id},
        )

    def update_lead(
        self,
        user_id: str,
        workspace_id: str,
        lead_id: Optional[str],
        updates: Dict[str, Any],
        actor_id: Optional[str] = None,
        source_action: str = "update_lead",
    ) -> Dict[str, Any]:
        """Update a lead safely within user/workspace isolation."""
        context = self._validate_ids(user_id, workspace_id)
        if not context["success"]:
            return context
        if not lead_id:
            return self._error_result("lead_id is required.", "MISSING_LEAD_ID")

        lead = self.repository.get(user_id, workspace_id, lead_id)
        if not lead:
            return self._error_result("Lead not found.", "LEAD_NOT_FOUND", {"lead_id": lead_id})

        try:
            before = self._serialize_lead(lead)
            self._apply_updates(lead, updates or {}, actor_id=actor_id)
            validation = self._validate_lead_record(lead)
            if not validation["success"]:
                return validation

            lead.updated_at = utc_now_iso()
            lead.updated_by = actor_id
            lead.last_activity_at = utc_now_iso()
            lead.audit_history.append(
                self._audit_entry(
                    action=source_action,
                    actor_id=actor_id,
                    details={"updated_fields": sorted(list((updates or {}).keys()))},
                )
            )

            saved = self.repository.save(lead)
            after = self._serialize_lead(saved)

            data = {
                "lead": after,
                "before": before,
                "updated_fields": sorted(list((updates or {}).keys())),
            }

            self._emit_agent_event("lead.updated", user_id, workspace_id, data)
            self._log_audit_event(source_action, user_id, workspace_id, actor_id, data)
            self._send_memory_payload("lead_updated", saved)
            self._send_verification_payload("lead_updated", saved, data)

            return self._safe_result(
                success=True,
                message="Lead updated successfully.",
                data=data,
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "lead_id": lead_id,
                    "action": "update_lead",
                },
            )
        except Exception as exc:
            LOGGER.exception("Failed to update lead.")
            return self._error_result("Failed to update lead.", str(exc), {"lead_id": lead_id})

    def change_lead_status(
        self,
        user_id: str,
        workspace_id: str,
        lead_id: str,
        status: str,
        actor_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Change lead status with validation."""
        status = normalize_text(status) or ""
        if status not in {item.value for item in LeadStatus}:
            return self._error_result("Invalid lead status.", "INVALID_LEAD_STATUS", {"status": status})
        return self.update_lead(user_id, workspace_id, lead_id, {"status": status}, actor_id=actor_id)

    def change_lead_stage(
        self,
        user_id: str,
        workspace_id: str,
        lead_id: str,
        stage: str,
        actor_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Change lead stage with validation."""
        stage = normalize_text(stage) or ""
        if stage not in {item.value for item in LeadStage}:
            return self._error_result("Invalid lead stage.", "INVALID_LEAD_STAGE", {"stage": stage})
        return self.update_lead(user_id, workspace_id, lead_id, {"stage": stage}, actor_id=actor_id)

    def assign_lead(
        self,
        user_id: str,
        workspace_id: str,
        lead_id: str,
        owner_id: str,
        actor_id: Optional[str] = None,
        assigned_team_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Assign a lead to a user/team after security approval."""
        approval = self._request_security_approval(
            action="assign_lead",
            user_id=user_id,
            workspace_id=workspace_id,
            payload={"lead_id": lead_id, "owner_id": owner_id, "assigned_team_id": assigned_team_id},
            actor_id=actor_id,
        )
        if not approval.get("approved", False):
            return self._error_result("Security approval required for lead assignment.", "SECURITY_APPROVAL_REQUIRED")

        updates = {"owner_id": owner_id}
        if assigned_team_id:
            updates["assigned_team_id"] = assigned_team_id
        return self.update_lead(user_id, workspace_id, lead_id, updates, actor_id=actor_id, source_action="assign_lead")

    def archive_lead(
        self,
        user_id: str,
        workspace_id: str,
        lead_id: Optional[str],
        actor_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Archive a lead instead of hard deleting it."""
        if not lead_id:
            return self._error_result("lead_id is required.", "MISSING_LEAD_ID")

        approval = self._request_security_approval(
            action="archive_lead",
            user_id=user_id,
            workspace_id=workspace_id,
            payload={"lead_id": lead_id},
            actor_id=actor_id,
        )
        if not approval.get("approved", False):
            return self._error_result("Security approval required for archiving lead.", "SECURITY_APPROVAL_REQUIRED")

        return self.update_lead(
            user_id=user_id,
            workspace_id=workspace_id,
            lead_id=lead_id,
            updates={
                "status": LeadStatus.ARCHIVED.value,
                "archived_at": utc_now_iso(),
            },
            actor_id=actor_id,
            source_action="archive_lead",
        )

    def delete_lead(
        self,
        user_id: str,
        workspace_id: str,
        lead_id: Optional[str],
        actor_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Hard delete a lead.

        This is intentionally security-gated. Prefer archive_lead for normal use.
        """
        context = self._validate_ids(user_id, workspace_id)
        if not context["success"]:
            return context
        if not lead_id:
            return self._error_result("lead_id is required.", "MISSING_LEAD_ID")

        approval = self._request_security_approval(
            action="delete_lead",
            user_id=user_id,
            workspace_id=workspace_id,
            payload={"lead_id": lead_id},
            actor_id=actor_id,
        )
        if not approval.get("approved", False):
            return self._error_result("Security approval required for deleting lead.", "SECURITY_APPROVAL_REQUIRED")

        lead = self.repository.get(user_id, workspace_id, lead_id)
        if not lead:
            return self._error_result("Lead not found.", "LEAD_NOT_FOUND", {"lead_id": lead_id})

        deleted = self.repository.delete(user_id, workspace_id, lead_id)
        if not deleted:
            return self._error_result("Lead could not be deleted.", "DELETE_FAILED", {"lead_id": lead_id})

        data = {"lead_id": lead_id, "deleted": True}
        self._emit_agent_event("lead.deleted", user_id, workspace_id, data)
        self._log_audit_event("lead_deleted", user_id, workspace_id, actor_id, {"deleted_lead": self._serialize_lead(lead)})
        self._send_verification_payload("lead_deleted", lead, data)

        return self._safe_result(
            success=True,
            message="Lead deleted successfully.",
            data=data,
            metadata={"user_id": user_id, "workspace_id": workspace_id, "lead_id": lead_id},
        )

    # ------------------------------------------------------------------
    # Search, export, metrics
    # ------------------------------------------------------------------

    def search_leads(
        self,
        user_id: str,
        workspace_id: str,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 100,
        offset: int = 0,
        include_archived: bool = False,
    ) -> Dict[str, Any]:
        """Search leads within one user/workspace only."""
        context = self._validate_ids(user_id, workspace_id)
        if not context["success"]:
            return context

        filters = filters or {}
        limit = max(1, min(500, int(filters.get("limit", limit) or limit)))
        offset = max(0, int(filters.get("offset", offset) or offset))
        include_archived = bool(filters.get("include_archived", include_archived))

        leads = self.repository.list_workspace(user_id, workspace_id, include_archived=include_archived)
        matched = [lead for lead in leads if self._matches_filters(lead, filters)]
        matched.sort(key=lambda item: item.updated_at or item.created_at, reverse=True)

        page = matched[offset: offset + limit]

        return self._safe_result(
            success=True,
            message="Leads searched successfully.",
            data={
                "leads": [self._serialize_lead(lead) for lead in page],
                "total": len(matched),
                "limit": limit,
                "offset": offset,
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "filters": filters,
            },
        )

    def export_leads(
        self,
        user_id: str,
        workspace_id: str,
        filters: Optional[Dict[str, Any]] = None,
        format: str = "json",
        actor_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Export leads in JSON or CSV format after security approval."""
        approval = self._request_security_approval(
            action="export_leads",
            user_id=user_id,
            workspace_id=workspace_id,
            payload={"filters": filters or {}, "format": format},
            actor_id=actor_id,
        )
        if not approval.get("approved", False):
            return self._error_result("Security approval required for lead export.", "SECURITY_APPROVAL_REQUIRED")

        result = self.search_leads(user_id, workspace_id, filters=filters or {}, limit=500)
        if not result["success"]:
            return result

        leads = result["data"]["leads"]
        export_format = (format or "json").lower()

        if export_format == "json":
            payload: Union[str, List[Dict[str, Any]]] = leads
        elif export_format == "csv":
            payload = self._leads_to_csv(leads)
        else:
            return self._error_result("Unsupported export format.", "UNSUPPORTED_EXPORT_FORMAT", {"format": format})

        data = {
            "format": export_format,
            "count": len(leads),
            "payload": payload,
        }

        self._log_audit_event("leads_exported", user_id, workspace_id, actor_id, {"count": len(leads), "format": export_format})

        return self._safe_result(
            success=True,
            message="Leads exported successfully.",
            data=data,
            metadata={"user_id": user_id, "workspace_id": workspace_id},
        )

    def get_lead_metrics(
        self,
        user_id: str,
        workspace_id: str,
        filters: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return dashboard-ready lead metrics for one workspace."""
        context = self._validate_ids(user_id, workspace_id)
        if not context["success"]:
            return context

        filters = filters or {}
        leads = self.repository.list_workspace(
            user_id=user_id,
            workspace_id=workspace_id,
            include_archived=bool(filters.get("include_archived", False)),
        )
        leads = [lead for lead in leads if self._matches_filters(lead, filters)]

        by_status: Dict[str, int] = {}
        by_stage: Dict[str, int] = {}
        by_source: Dict[str, int] = {}
        by_priority: Dict[str, int] = {}
        score_total = 0
        value_total = 0.0
        won_count = 0
        lost_count = 0

        for lead in leads:
            by_status[lead.status] = by_status.get(lead.status, 0) + 1
            by_stage[lead.stage] = by_stage.get(lead.stage, 0) + 1
            by_source[lead.attribution.source] = by_source.get(lead.attribution.source, 0) + 1
            by_priority[lead.priority] = by_priority.get(lead.priority, 0) + 1
            score_total += safe_int_score(lead.score)

            if lead.status == LeadStatus.WON.value or lead.stage == LeadStage.CLOSED_WON.value:
                won_count += 1
            if lead.status == LeadStatus.LOST.value or lead.stage == LeadStage.CLOSED_LOST.value:
                lost_count += 1

            try:
                if lead.lead_value is not None:
                    value_total += float(lead.lead_value)
            except Exception:
                pass

        total = len(leads)
        average_score = round(score_total / total, 2) if total else 0
        conversion_rate = round((won_count / total) * 100, 2) if total else 0

        return self._safe_result(
            success=True,
            message="Lead metrics generated successfully.",
            data={
                "total_leads": total,
                "won_leads": won_count,
                "lost_leads": lost_count,
                "conversion_rate_percent": conversion_rate,
                "average_score": average_score,
                "estimated_pipeline_value": round(value_total, 2),
                "by_status": by_status,
                "by_stage": by_stage,
                "by_source": by_source,
                "by_priority": by_priority,
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "filters": filters,
            },
        )

    # ------------------------------------------------------------------
    # Compatibility hooks required by William/Jarvis prompt bible
    # ------------------------------------------------------------------

    def _validate_task_context(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Validate MasterAgent task context."""
        if not isinstance(task, dict):
            return self._error_result("Task must be a dictionary.", "INVALID_TASK")
        return self._validate_ids(task.get("user_id"), task.get("workspace_id"))

    def _requires_security_check(self, action: str, payload: Optional[Dict[str, Any]] = None) -> bool:
        """
        Determine if an action needs Security Agent approval.

        Sensitive actions include destructive operations, exports, imports,
        ownership changes, and merges.
        """
        normalized = normalize_text(action) or ""
        if normalized in SENSITIVE_ACTIONS:
            return True
        payload = payload or {}
        if payload.get("force") is True:
            return True
        return False

    def _request_security_approval(
        self,
        action: str,
        user_id: str,
        workspace_id: str,
        payload: Optional[Dict[str, Any]] = None,
        actor_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Prepare and optionally send a Security Agent approval request.

        If no callback is configured, safe non-destructive behavior is:
            - sensitive actions are approved in local/dev mode only when
              config.security_mode is not "strict"
            - strict mode denies by default
        """
        request = {
            "agent": self.agent_id,
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "actor_id": actor_id,
            "payload_summary": self._redact_sensitive(payload or {}),
            "requested_at": utc_now_iso(),
        }

        if self.security_callback:
            try:
                response = self.security_callback(request)
                if isinstance(response, dict):
                    return response
            except Exception as exc:
                LOGGER.exception("Security callback failed.")
                return {
                    "approved": False,
                    "reason": f"Security callback failed: {exc}",
                    "request": request,
                }

        security_mode = str(getattr(self, "config", {}).get("security_mode", "development")).lower()
        if security_mode == "strict" and action in SENSITIVE_ACTIONS:
            return {
                "approved": False,
                "reason": "Strict security mode requires external Security Agent approval.",
                "request": request,
            }

        return {
            "approved": True,
            "reason": "Local approval fallback. Replace with Security Agent in production.",
            "request": request,
        }

    def _prepare_verification_payload(
        self,
        action: str,
        lead: Optional[LeadRecord],
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create Verification Agent-compatible payload."""
        return {
            "type": "business_lead_verification",
            "agent": self.agent_id,
            "action": action,
            "lead_id": lead.lead_id if lead else None,
            "user_id": lead.user_id if lead else None,
            "workspace_id": lead.workspace_id if lead else None,
            "status": lead.status if lead else None,
            "stage": lead.stage if lead else None,
            "source": lead.attribution.source if lead else None,
            "data": data or {},
            "created_at": utc_now_iso(),
        }

    def _prepare_memory_payload(
        self,
        action: str,
        lead: LeadRecord,
    ) -> Dict[str, Any]:
        """
        Create Memory Agent-compatible payload.

        Only stores useful business context. It remains scoped by user_id and
        workspace_id to avoid cross-tenant leakage.
        """
        return {
            "type": "business_lead_memory",
            "agent": self.agent_id,
            "action": action,
            "user_id": lead.user_id,
            "workspace_id": lead.workspace_id,
            "lead_id": lead.lead_id,
            "memory_scope": "workspace",
            "summary": self._lead_memory_summary(lead),
            "entities": {
                "contact_name": lead.contact.full_name,
                "company": lead.contact.company,
                "service_interest": lead.service_interest,
                "source": lead.attribution.source,
                "stage": lead.stage,
                "status": lead.status,
                "priority": lead.priority,
            },
            "metadata": {
                "score": lead.score,
                "temperature": lead.temperature,
                "tags": lead.tags,
                "updated_at": lead.updated_at,
            },
            "created_at": utc_now_iso(),
        }

    def _emit_agent_event(
        self,
        event_type: str,
        user_id: str,
        workspace_id: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Emit event for Agent Registry, Dashboard, or internal event bus.

        If no callback is configured, this safely logs at debug level.
        """
        event = {
            "event_type": event_type,
            "agent": self.agent_id,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "data": data or {},
            "timestamp": utc_now_iso(),
        }
        if self.event_callback:
            try:
                self.event_callback(event)
                return
            except Exception:
                LOGGER.exception("Event callback failed.")
        LOGGER.debug("LeadTracker event: %s", safe_json_dumps(event))

    def _log_audit_event(
        self,
        action: str,
        user_id: str,
        workspace_id: str,
        actor_id: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Emit audit event.

        In production this should be wired to Audit Log storage through the
        Business Agent or System Agent.
        """
        audit = {
            "agent": self.agent_id,
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "actor_id": actor_id,
            "data": self._redact_sensitive(data or {}),
            "timestamp": utc_now_iso(),
        }
        if self.audit_callback:
            try:
                self.audit_callback(audit)
                return
            except Exception:
                LOGGER.exception("Audit callback failed.")
        LOGGER.info("LeadTracker audit: %s", safe_json_dumps(audit))

    def _safe_result(
        self,
        success: bool,
        message: str,
        data: Optional[Any] = None,
        error: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard structured result."""
        return {
            "success": bool(success),
            "message": message,
            "data": data,
            "error": error,
            "metadata": {
                "agent": self.agent_id,
                "agent_name": self.agent_name,
                "version": self.version,
                "timestamp": utc_now_iso(),
                **(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str,
        error: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard structured error result."""
        return self._safe_result(
            success=False,
            message=message,
            data=None,
            error=error,
            metadata=metadata or {},
        )

    # ------------------------------------------------------------------
    # Internal build / validation
    # ------------------------------------------------------------------

    def _validate_ids(self, user_id: Any, workspace_id: Any) -> Dict[str, Any]:
        """Validate SaaS isolation identifiers."""
        uid = normalize_text(user_id)
        wid = normalize_text(workspace_id)
        if not uid:
            return self._error_result("user_id is required.", "MISSING_USER_ID")
        if not wid:
            return self._error_result("workspace_id is required.", "MISSING_WORKSPACE_ID")
        return self._safe_result(
            success=True,
            message="Context validated.",
            data={"user_id": uid, "workspace_id": wid},
            metadata={"user_id": uid, "workspace_id": wid},
        )

    def _build_lead_record(
        self,
        user_id: str,
        workspace_id: str,
        payload: Dict[str, Any],
        actor_id: Optional[str] = None,
    ) -> LeadRecord:
        """Build canonical LeadRecord from flexible payload."""
        full_name = normalize_text(
            payload.get("full_name")
            or payload.get("name")
            or payload.get("contact_name")
            or payload.get("customer_name")
        )
        first_name = normalize_text(payload.get("first_name"))
        last_name = normalize_text(payload.get("last_name"))

        if full_name and (not first_name and not last_name):
            first_name, last_name = parse_name(full_name)
        if not full_name:
            full_name = normalize_text(" ".join([p for p in [first_name, last_name] if p]))

        contact = LeadContact(
            full_name=full_name,
            first_name=first_name,
            last_name=last_name,
            email=normalize_email(payload.get("email")),
            phone=normalize_phone(payload.get("phone") or payload.get("phone_number") or payload.get("mobile")),
            company=normalize_text(payload.get("company") or payload.get("business_name")),
            job_title=normalize_text(payload.get("job_title") or payload.get("title")),
            website=normalize_text(payload.get("website") or payload.get("domain")),
            location=normalize_text(payload.get("location") or payload.get("city") or payload.get("country")),
            timezone=normalize_text(payload.get("timezone")),
            preferred_contact_method=normalize_text(payload.get("preferred_contact_method")),
            consent_status=self._safe_enum_value(payload.get("consent_status"), ConsentStatus, ConsentStatus.UNKNOWN.value),
        )

        source = self._safe_source(payload.get("source"))
        attribution = LeadAttribution(
            source=source,
            channel=normalize_text(payload.get("channel")),
            campaign_id=normalize_text(payload.get("campaign_id")),
            campaign_name=normalize_text(payload.get("campaign_name")),
            ad_platform=normalize_text(payload.get("ad_platform") or payload.get("platform")),
            ad_account_id=normalize_text(payload.get("ad_account_id")),
            ad_id=normalize_text(payload.get("ad_id")),
            adset_id=normalize_text(payload.get("adset_id")),
            keyword=normalize_text(payload.get("keyword") or payload.get("search_term")),
            landing_page=normalize_text(payload.get("landing_page") or payload.get("page_url")),
            referrer=normalize_text(payload.get("referrer")),
            utm_source=normalize_text(payload.get("utm_source")),
            utm_medium=normalize_text(payload.get("utm_medium")),
            utm_campaign=normalize_text(payload.get("utm_campaign")),
            utm_term=normalize_text(payload.get("utm_term")),
            utm_content=normalize_text(payload.get("utm_content")),
            gclid=normalize_text(payload.get("gclid")),
            fbclid=normalize_text(payload.get("fbclid")),
            msclkid=normalize_text(payload.get("msclkid")),
            workflow_id=normalize_text(payload.get("workflow_id")),
            workflow_name=normalize_text(payload.get("workflow_name")),
            import_batch_id=normalize_text(payload.get("import_batch_id")),
            raw=deep_copy_dict(payload.get("attribution_raw") or {}),
        )

        notes = [n for n in [normalize_text(item) for item in ensure_list(payload.get("notes"))] if n]
        tags = sorted({tag for tag in [normalize_tag(item) for item in ensure_list(payload.get("tags"))] if tag})

        status = self._safe_enum_value(payload.get("status"), LeadStatus, LeadStatus.NEW.value)
        stage = self._safe_enum_value(payload.get("stage"), LeadStage, LeadStage.CAPTURED.value)
        priority = self._safe_enum_value(payload.get("priority"), LeadPriority, LeadPriority.MEDIUM.value)
        temperature = self._safe_enum_value(payload.get("temperature"), LeadTemperature, self._temperature_from_score(payload.get("score")))

        duplicate_key = self._make_duplicate_key(user_id, workspace_id, contact)

        return LeadRecord(
            lead_id=normalize_text(payload.get("lead_id")) or f"lead_{uuid.uuid4().hex}",
            user_id=user_id,
            workspace_id=workspace_id,
            contact=contact,
            attribution=attribution,
            status=status,
            stage=stage,
            priority=priority,
            temperature=temperature,
            score=safe_int_score(payload.get("score", self.default_lead_score)),
            owner_id=normalize_text(payload.get("owner_id")),
            assigned_team_id=normalize_text(payload.get("assigned_team_id")),
            client_id=normalize_text(payload.get("client_id")),
            pipeline_id=normalize_text(payload.get("pipeline_id")),
            service_interest=normalize_text(payload.get("service_interest") or payload.get("service")),
            budget=payload.get("budget"),
            urgency=normalize_text(payload.get("urgency")),
            lead_value=self._safe_float_or_none(payload.get("lead_value") or payload.get("value")),
            currency=normalize_text(payload.get("currency")) or self.default_currency,
            notes=notes,
            tags=tags,
            custom_fields=deep_copy_dict(payload.get("custom_fields") or {}),
            raw_payload=deep_copy_dict(payload),
            duplicate_key=duplicate_key,
            next_follow_up_at=normalize_text(payload.get("next_follow_up_at")),
            created_by=actor_id,
            updated_by=actor_id,
        )

    def _validate_lead_record(self, lead: LeadRecord) -> Dict[str, Any]:
        """Validate canonical lead before storage."""
        if not lead.user_id or not lead.workspace_id:
            return self._error_result("Lead missing SaaS isolation context.", "INVALID_LEAD_CONTEXT")
        if not lead.contact.email and not lead.contact.phone and not lead.contact.full_name and not lead.contact.company:
            return self._error_result(
                "Lead must include at least one identifier: email, phone, full_name, or company.",
                "INSUFFICIENT_LEAD_IDENTITY",
            )
        if lead.contact.email and not EMAIL_RE.match(lead.contact.email):
            return self._error_result("Invalid email address.", "INVALID_EMAIL")
        if lead.status not in {item.value for item in LeadStatus}:
            return self._error_result("Invalid lead status.", "INVALID_LEAD_STATUS")
        if lead.stage not in {item.value for item in LeadStage}:
            return self._error_result("Invalid lead stage.", "INVALID_LEAD_STAGE")
        if lead.attribution.source not in SYSTEM_SOURCES:
            return self._error_result("Invalid lead source.", "INVALID_LEAD_SOURCE")
        return self._safe_result(True, "Lead validated.", {"lead_id": lead.lead_id})

    def _apply_updates(self, lead: LeadRecord, updates: Dict[str, Any], actor_id: Optional[str] = None) -> None:
        """Apply safe update fields to a lead."""
        forbidden = {"user_id", "workspace_id", "lead_id", "created_at", "audit_history"}
        updates = updates or {}

        for key, value in updates.items():
            if key in forbidden:
                continue

            if key in {"full_name", "name", "contact_name"}:
                lead.contact.full_name = normalize_text(value)
                lead.contact.first_name, lead.contact.last_name = parse_name(lead.contact.full_name)
            elif key == "first_name":
                lead.contact.first_name = normalize_text(value)
            elif key == "last_name":
                lead.contact.last_name = normalize_text(value)
            elif key == "email":
                lead.contact.email = normalize_email(value)
            elif key in {"phone", "phone_number", "mobile"}:
                lead.contact.phone = normalize_phone(value)
            elif key in {"company", "business_name"}:
                lead.contact.company = normalize_text(value)
            elif key == "job_title":
                lead.contact.job_title = normalize_text(value)
            elif key == "website":
                lead.contact.website = normalize_text(value)
            elif key == "location":
                lead.contact.location = normalize_text(value)
            elif key == "timezone":
                lead.contact.timezone = normalize_text(value)
            elif key == "preferred_contact_method":
                lead.contact.preferred_contact_method = normalize_text(value)
            elif key == "consent_status":
                lead.contact.consent_status = self._safe_enum_value(value, ConsentStatus, lead.contact.consent_status)

            elif key == "source":
                lead.attribution.source = self._safe_source(value)
            elif hasattr(lead.attribution, key):
                setattr(lead.attribution, key, normalize_text(value) if not isinstance(value, dict) else deep_copy_dict(value))

            elif key == "status":
                lead.status = self._safe_enum_value(value, LeadStatus, lead.status)
            elif key == "stage":
                lead.stage = self._safe_enum_value(value, LeadStage, lead.stage)
            elif key == "priority":
                lead.priority = self._safe_enum_value(value, LeadPriority, lead.priority)
            elif key == "temperature":
                lead.temperature = self._safe_enum_value(value, LeadTemperature, lead.temperature)
            elif key == "score":
                lead.score = safe_int_score(value, lead.score)
                lead.temperature = self._temperature_from_score(lead.score)
            elif key == "notes":
                new_notes = [n for n in [normalize_text(item) for item in ensure_list(value)] if n]
                lead.notes.extend(new_notes)
            elif key == "tags":
                current = set(lead.tags)
                incoming = {tag for tag in [normalize_tag(item) for item in ensure_list(value)] if tag}
                lead.tags = sorted(current | incoming)
            elif key == "custom_fields":
                if isinstance(value, dict):
                    lead.custom_fields.update(deep_copy_dict(value))
            elif key == "lead_value":
                lead.lead_value = self._safe_float_or_none(value)
            elif hasattr(lead, key):
                setattr(lead, key, value)

        lead.duplicate_key = self._make_duplicate_key(lead.user_id, lead.workspace_id, lead.contact)
        lead.updated_by = actor_id

    def _merge_lead_payload(self, existing: LeadRecord, payload: Dict[str, Any], actor_id: Optional[str] = None) -> Dict[str, Any]:
        """Prepare safe update fields when an imported/incoming lead matches an existing lead."""
        updates: Dict[str, Any] = {}

        for key in [
            "full_name", "first_name", "last_name", "email", "phone", "company", "job_title",
            "website", "location", "timezone", "preferred_contact_method", "service_interest",
            "budget", "urgency", "lead_value", "currency", "owner_id", "assigned_team_id",
            "client_id", "pipeline_id", "next_follow_up_at",
        ]:
            if payload.get(key) not in (None, "", []):
                updates[key] = payload[key]

        incoming_notes = ensure_list(payload.get("notes"))
        if incoming_notes:
            updates["notes"] = incoming_notes

        incoming_tags = ensure_list(payload.get("tags"))
        if incoming_tags:
            updates["tags"] = incoming_tags

        custom_fields = payload.get("custom_fields")
        if isinstance(custom_fields, dict):
            updates["custom_fields"] = custom_fields

        incoming_score = payload.get("score")
        if incoming_score is not None:
            updates["score"] = max(existing.score, safe_int_score(incoming_score))

        updates["last_activity_at"] = utc_now_iso()
        return updates

    # ------------------------------------------------------------------
    # Matching and serialization
    # ------------------------------------------------------------------

    def _matches_filters(self, lead: LeadRecord, filters: Dict[str, Any]) -> bool:
        """Apply search filters to one lead."""
        if not filters:
            return True

        query = normalize_text(filters.get("query") or filters.get("q"))
        if query:
            haystack = " ".join(
                str(x or "")
                for x in [
                    lead.lead_id,
                    lead.contact.full_name,
                    lead.contact.email,
                    lead.contact.phone,
                    lead.contact.company,
                    lead.contact.website,
                    lead.service_interest,
                    lead.attribution.source,
                    lead.attribution.campaign_name,
                    " ".join(lead.tags),
                    " ".join(lead.notes),
                ]
            ).lower()
            if query.lower() not in haystack:
                return False

        exact_fields = {
            "status": lead.status,
            "stage": lead.stage,
            "priority": lead.priority,
            "temperature": lead.temperature,
            "source": lead.attribution.source,
            "owner_id": lead.owner_id,
            "client_id": lead.client_id,
            "pipeline_id": lead.pipeline_id,
            "campaign_id": lead.attribution.campaign_id,
            "campaign_name": lead.attribution.campaign_name,
        }

        for key, lead_value in exact_fields.items():
            expected = filters.get(key)
            if expected in (None, "", []):
                continue
            expected_values = {str(item).lower() for item in ensure_list(expected)}
            if str(lead_value or "").lower() not in expected_values:
                return False

        tag_filter = filters.get("tag") or filters.get("tags")
        if tag_filter:
            expected_tags = {normalize_tag(item) for item in ensure_list(tag_filter)}
            expected_tags = {tag for tag in expected_tags if tag}
            if expected_tags and not expected_tags.intersection(set(lead.tags)):
                return False

        min_score = filters.get("min_score")
        if min_score is not None and lead.score < safe_int_score(min_score):
            return False

        max_score = filters.get("max_score")
        if max_score is not None and lead.score > safe_int_score(max_score, 100):
            return False

        created_after = normalize_text(filters.get("created_after"))
        if created_after and lead.created_at < created_after:
            return False

        created_before = normalize_text(filters.get("created_before"))
        if created_before and lead.created_at > created_before:
            return False

        return True

    def _serialize_lead(self, lead: LeadRecord) -> Dict[str, Any]:
        """Serialize LeadRecord to dict."""
        return {
            "lead_id": lead.lead_id,
            "user_id": lead.user_id,
            "workspace_id": lead.workspace_id,
            "contact": asdict(lead.contact),
            "attribution": asdict(lead.attribution),
            "status": lead.status,
            "stage": lead.stage,
            "priority": lead.priority,
            "temperature": lead.temperature,
            "score": lead.score,
            "owner_id": lead.owner_id,
            "assigned_team_id": lead.assigned_team_id,
            "client_id": lead.client_id,
            "pipeline_id": lead.pipeline_id,
            "service_interest": lead.service_interest,
            "budget": lead.budget,
            "urgency": lead.urgency,
            "lead_value": lead.lead_value,
            "currency": lead.currency,
            "notes": list(lead.notes),
            "tags": list(lead.tags),
            "custom_fields": deep_copy_dict(lead.custom_fields),
            "duplicate_key": lead.duplicate_key,
            "duplicate_of": lead.duplicate_of,
            "merged_into": lead.merged_into,
            "created_at": lead.created_at,
            "updated_at": lead.updated_at,
            "last_activity_at": lead.last_activity_at,
            "next_follow_up_at": lead.next_follow_up_at,
            "archived_at": lead.archived_at,
            "created_by": lead.created_by,
            "updated_by": lead.updated_by,
            "audit_history": copy.deepcopy(lead.audit_history),
        }

    def _leads_to_csv(self, leads: List[Dict[str, Any]]) -> str:
        """Convert serialized leads to dashboard-friendly CSV."""
        output = StringIO()
        fieldnames = [
            "lead_id",
            "full_name",
            "email",
            "phone",
            "company",
            "source",
            "status",
            "stage",
            "priority",
            "temperature",
            "score",
            "service_interest",
            "budget",
            "lead_value",
            "currency",
            "owner_id",
            "created_at",
            "updated_at",
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for lead in leads:
            contact = lead.get("contact") or {}
            attribution = lead.get("attribution") or {}
            writer.writerow({
                "lead_id": lead.get("lead_id"),
                "full_name": contact.get("full_name"),
                "email": contact.get("email"),
                "phone": contact.get("phone"),
                "company": contact.get("company"),
                "source": attribution.get("source"),
                "status": lead.get("status"),
                "stage": lead.get("stage"),
                "priority": lead.get("priority"),
                "temperature": lead.get("temperature"),
                "score": lead.get("score"),
                "service_interest": lead.get("service_interest"),
                "budget": lead.get("budget"),
                "lead_value": lead.get("lead_value"),
                "currency": lead.get("currency"),
                "owner_id": lead.get("owner_id"),
                "created_at": lead.get("created_at"),
                "updated_at": lead.get("updated_at"),
            })

        return output.getvalue()

    # ------------------------------------------------------------------
    # Helper methods
    # ------------------------------------------------------------------

    def _safe_source(self, source: Any) -> str:
        """Return a valid lead source."""
        value = normalize_text(source)
        if not value:
            return LeadSource.UNKNOWN.value
        value = value.lower()
        return value if value in SYSTEM_SOURCES else LeadSource.UNKNOWN.value

    def _safe_enum_value(self, value: Any, enum_cls: Any, default: str) -> str:
        """Safely coerce a value into an enum value."""
        text = normalize_text(value)
        if not text:
            return default
        text = text.lower()
        allowed = {item.value for item in enum_cls}
        return text if text in allowed else default

    def _temperature_from_score(self, score: Any) -> str:
        """Infer lead temperature from score."""
        score_int = safe_int_score(score, self.default_lead_score)
        if score_int >= 75:
            return LeadTemperature.HOT.value
        if score_int >= 40:
            return LeadTemperature.WARM.value
        return LeadTemperature.COLD.value

    def _safe_float_or_none(self, value: Any) -> Optional[float]:
        """Safely parse float values."""
        if value in (None, ""):
            return None
        try:
            return float(value)
        except Exception:
            return None

    def _make_duplicate_key(self, user_id: str, workspace_id: str, contact: LeadContact) -> str:
        """
        Build a tenant-scoped duplicate key.

        user_id and workspace_id are included so dedupe can never cross tenants.
        """
        identity = contact.email or contact.phone or contact.website or contact.full_name or contact.company
        return hash_key([user_id, workspace_id, identity])

    def _audit_entry(self, action: str, actor_id: Optional[str], details: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Create embedded lead audit history entry."""
        return {
            "action": action,
            "actor_id": actor_id,
            "details": details or {},
            "timestamp": utc_now_iso(),
        }

    def _redact_sensitive(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Redact sensitive fields for audit/security summaries."""
        sensitive_keys = {
            "password",
            "secret",
            "token",
            "api_key",
            "authorization",
            "auth",
            "cookie",
        }
        redacted = {}
        for key, value in (data or {}).items():
            lower_key = str(key).lower()
            if any(s in lower_key for s in sensitive_keys):
                redacted[key] = "[REDACTED]"
            elif isinstance(value, dict):
                redacted[key] = self._redact_sensitive(value)
            elif isinstance(value, list):
                redacted[key] = [
                    self._redact_sensitive(item) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                redacted[key] = value
        return redacted

    def _lead_memory_summary(self, lead: LeadRecord) -> str:
        """Create compact memory summary for Memory Agent."""
        name = lead.contact.full_name or lead.contact.company or "Unknown lead"
        service = lead.service_interest or "unspecified service"
        source = lead.attribution.source
        return (
            f"Lead {name} from {source} is interested in {service}. "
            f"Status: {lead.status}, stage: {lead.stage}, priority: {lead.priority}, score: {lead.score}."
        )

    def _send_memory_payload(self, action: str, lead: LeadRecord) -> None:
        """Send memory payload if callback exists; otherwise log debug."""
        payload = self._prepare_memory_payload(action, lead)
        if self.memory_callback:
            try:
                self.memory_callback(payload)
                return
            except Exception:
                LOGGER.exception("Memory callback failed.")
        LOGGER.debug("Memory payload prepared: %s", safe_json_dumps(payload))

    def _send_verification_payload(self, action: str, lead: Optional[LeadRecord], data: Dict[str, Any]) -> None:
        """Send verification payload if callback exists; otherwise log debug."""
        payload = self._prepare_verification_payload(action, lead, data)
        if self.verification_callback:
            try:
                self.verification_callback(payload)
                return
            except Exception:
                LOGGER.exception("Verification callback failed.")
        LOGGER.debug("Verification payload prepared: %s", safe_json_dumps(payload))


# ---------------------------------------------------------------------------
# Module metadata for Agent Registry / Loader
# ---------------------------------------------------------------------------

AGENT_MODULE_INFO: Dict[str, Any] = {
    "agent_module": "Business Agent",
    "file": "lead_tracker.py",
    "class_name": "LeadTracker",
    "agent_id": DEFAULT_AGENT_ID,
    "agent_name": DEFAULT_AGENT_NAME,
    "version": DEFAULT_VERSION,
    "purpose": "Tracks leads from forms, calls, ads, SEO, workflows, imports.",
    "supports_user_workspace_isolation": True,
    "requires_security_for_sensitive_actions": True,
    "compatible_with": [
        "BaseAgent",
        "MasterAgent",
        "AgentRegistry",
        "AgentLoader",
        "AgentRouter",
        "SecurityAgent",
        "MemoryAgent",
        "VerificationAgent",
        "DashboardAPI",
    ],
    "public_methods": [
        "run",
        "create_lead",
        "track_form_lead",
        "track_call_lead",
        "track_ad_lead",
        "track_seo_lead",
        "track_workflow_lead",
        "import_leads",
        "get_lead",
        "update_lead",
        "change_lead_status",
        "change_lead_stage",
        "assign_lead",
        "archive_lead",
        "delete_lead",
        "search_leads",
        "export_leads",
        "get_lead_metrics",
    ],
}


def get_agent_module_info() -> Dict[str, Any]:
    """Return module metadata for registry/loader discovery."""
    return copy.deepcopy(AGENT_MODULE_INFO)


def create_agent(**kwargs: Any) -> LeadTracker:
    """
    Factory hook for Agent Loader.

    Example:
        tracker = create_agent(config={"security_mode": "strict"})
    """
    return LeadTracker(**kwargs)


__all__ = [
    "LeadTracker",
    "LeadRecord",
    "LeadContact",
    "LeadAttribution",
    "LeadImportReport",
    "LeadSource",
    "LeadStatus",
    "LeadStage",
    "LeadPriority",
    "LeadTemperature",
    "ConsentStatus",
    "InMemoryLeadRepository",
    "AGENT_MODULE_INFO",
    "get_agent_module_info",
    "create_agent",
]


# ---------------------------------------------------------------------------
# Lightweight self-test helper
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    tracker = LeadTracker(config={"security_mode": "development"})
    result = tracker.track_form_lead(
        user_id="demo_user",
        workspace_id="demo_workspace",
        payload={
            "full_name": "Jane Smith",
            "email": "jane@example.com",
            "phone": "+1 555 100 2000",
            "company": "Example Co",
            "service_interest": "AI automation",
            "landing_page": "https://example.com/ai-automation",
            "utm_source": "google",
            "score": 62,
            "tags": ["demo", "website"],
        },
        actor_id="demo_actor",
    )
    print(json.dumps(result, indent=2, default=str))

    metrics = tracker.get_lead_metrics("demo_user", "demo_workspace")
    print(json.dumps(metrics, indent=2, default=str))