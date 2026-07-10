"""
agents/super_agents/business_agent/crm_manager.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
Business Agent CRM Manager

Purpose:
    Manage contacts, deals, pipelines, tags, notes, and stages.

Architecture Compatibility:
    - Master Agent routing compatible through handle_task()
    - BaseAgent compatible with safe fallback if BaseAgent is unavailable
    - Security Agent compatible through approval hooks
    - Memory Agent compatible through prepared memory payloads
    - Verification Agent compatible through verification payloads
    - Dashboard/FastAPI ready through structured dict responses
    - SaaS-safe user_id/workspace_id isolation
    - Import-safe even if future William modules are not created yet

Important:
    This file uses an in-memory repository by default so it can import and test safely.
    Later, the repository layer can be replaced by a database-backed adapter without
    changing public CRMManager methods.
"""

from __future__ import annotations

import copy
import logging
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Tuple


# =============================================================================
# Safe optional imports
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for standalone import safety
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps the file import-safe before the full William/Jarvis framework
        is available. The real BaseAgent should provide richer lifecycle,
        registry, and routing behavior.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())
            self.metadata = kwargs.get("metadata", {})

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            return None


# =============================================================================
# Constants and configuration
# =============================================================================

CRM_MANAGER_VERSION = "1.0.0"
DEFAULT_PIPELINE_NAME = "Default Sales Pipeline"
DEFAULT_PIPELINE_STAGES = [
    "New",
    "Contacted",
    "Qualified",
    "Proposal Sent",
    "Negotiation",
    "Won",
    "Lost",
]

EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PHONE_SAFE_PATTERN = re.compile(r"^[0-9+\-().\s]{5,32}$")


# =============================================================================
# Enums
# =============================================================================

class CRMObjectType(str, Enum):
    CONTACT = "contact"
    DEAL = "deal"
    PIPELINE = "pipeline"
    STAGE = "stage"
    TAG = "tag"
    NOTE = "note"


class DealStatus(str, Enum):
    OPEN = "open"
    WON = "won"
    LOST = "lost"
    ARCHIVED = "archived"


class SensitiveAction(str, Enum):
    DELETE_CONTACT = "delete_contact"
    DELETE_DEAL = "delete_deal"
    DELETE_PIPELINE = "delete_pipeline"
    BULK_UPDATE = "bulk_update"
    EXPORT_DATA = "export_data"


# =============================================================================
# Dataclasses
# =============================================================================

@dataclass
class CRMContext:
    """
    Required SaaS execution context.

    Every user-specific CRM operation must provide user_id and workspace_id.
    This prevents mixing contacts, deals, pipelines, notes, and tags between
    tenants.
    """

    user_id: str
    workspace_id: str
    role: Optional[str] = None
    request_id: Optional[str] = None
    source: str = "business_agent"
    permissions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CRMTag:
    id: str
    user_id: str
    workspace_id: str
    name: str
    color: Optional[str] = None
    description: Optional[str] = None
    created_by: Optional[str] = None
    created_at: str = field(default_factory=lambda: utc_now_iso())
    updated_at: str = field(default_factory=lambda: utc_now_iso())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CRMNote:
    id: str
    user_id: str
    workspace_id: str
    object_type: str
    object_id: str
    content: str
    created_by: Optional[str] = None
    pinned: bool = False
    created_at: str = field(default_factory=lambda: utc_now_iso())
    updated_at: str = field(default_factory=lambda: utc_now_iso())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CRMContact:
    id: str
    user_id: str
    workspace_id: str
    full_name: str
    email: Optional[str] = None
    phone: Optional[str] = None
    company: Optional[str] = None
    title: Optional[str] = None
    source: Optional[str] = None
    status: str = "active"
    tags: List[str] = field(default_factory=list)
    custom_fields: Dict[str, Any] = field(default_factory=dict)
    created_by: Optional[str] = None
    created_at: str = field(default_factory=lambda: utc_now_iso())
    updated_at: str = field(default_factory=lambda: utc_now_iso())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CRMPipelineStage:
    id: str
    user_id: str
    workspace_id: str
    pipeline_id: str
    name: str
    order: int
    probability: float = 0.0
    is_won_stage: bool = False
    is_lost_stage: bool = False
    created_by: Optional[str] = None
    created_at: str = field(default_factory=lambda: utc_now_iso())
    updated_at: str = field(default_factory=lambda: utc_now_iso())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CRMPipeline:
    id: str
    user_id: str
    workspace_id: str
    name: str
    description: Optional[str] = None
    is_default: bool = False
    created_by: Optional[str] = None
    created_at: str = field(default_factory=lambda: utc_now_iso())
    updated_at: str = field(default_factory=lambda: utc_now_iso())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CRMDeal:
    id: str
    user_id: str
    workspace_id: str
    title: str
    value: float
    currency: str
    pipeline_id: str
    stage_id: str
    contact_id: Optional[str] = None
    company: Optional[str] = None
    status: str = DealStatus.OPEN.value
    expected_close_date: Optional[str] = None
    probability: Optional[float] = None
    tags: List[str] = field(default_factory=list)
    custom_fields: Dict[str, Any] = field(default_factory=dict)
    created_by: Optional[str] = None
    created_at: str = field(default_factory=lambda: utc_now_iso())
    updated_at: str = field(default_factory=lambda: utc_now_iso())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# =============================================================================
# Utility functions
# =============================================================================

def utc_now_iso() -> str:
    """Return current UTC datetime in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    """Generate a readable unique object ID."""
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


def normalize_tag_name(name: str) -> str:
    """Normalize tag names for consistent matching."""
    return " ".join(str(name).strip().split())


def normalize_email(email: Optional[str]) -> Optional[str]:
    if email is None:
        return None
    value = str(email).strip().lower()
    return value or None


def normalize_phone(phone: Optional[str]) -> Optional[str]:
    if phone is None:
        return None
    value = " ".join(str(phone).strip().split())
    return value or None


def deep_public_copy(value: Any) -> Any:
    """Return a deep copy safe for structured API responses."""
    return copy.deepcopy(value)


# =============================================================================
# In-memory tenant repository
# =============================================================================

class InMemoryCRMRepository:
    """
    Tenant-isolated in-memory CRM repository.

    Storage structure:
        workspace_key = "{workspace_id}"
        {
            "contacts": {contact_id: CRMContact},
            "deals": {deal_id: CRMDeal},
            "pipelines": {pipeline_id: CRMPipeline},
            "stages": {stage_id: CRMPipelineStage},
            "tags": {tag_id: CRMTag},
            "notes": {note_id: CRMNote},
        }

    This is intentionally simple and import-safe. Replace with a DB adapter later.
    """

    def __init__(self) -> None:
        self._store: Dict[str, Dict[str, Dict[str, Any]]] = {}

    def ensure_workspace(self, workspace_id: str) -> Dict[str, Dict[str, Any]]:
        if workspace_id not in self._store:
            self._store[workspace_id] = {
                "contacts": {},
                "deals": {},
                "pipelines": {},
                "stages": {},
                "tags": {},
                "notes": {},
            }
        return self._store[workspace_id]

    def get_bucket(self, workspace_id: str, bucket: str) -> Dict[str, Any]:
        workspace = self.ensure_workspace(workspace_id)
        if bucket not in workspace:
            workspace[bucket] = {}
        return workspace[bucket]

    def snapshot_workspace(self, workspace_id: str) -> Dict[str, Any]:
        workspace = self.ensure_workspace(workspace_id)
        return deep_public_copy(
            {
                bucket: {
                    object_id: item.to_dict() if hasattr(item, "to_dict") else asdict(item)
                    for object_id, item in values.items()
                }
                for bucket, values in workspace.items()
            }
        )


# =============================================================================
# CRM Manager
# =============================================================================

class CRMManager(BaseAgent):
    """
    Business Agent CRM Manager.

    Responsibilities:
        - Manage contacts
        - Manage deals
        - Manage pipelines and stages
        - Manage tags
        - Manage notes
        - Keep data isolated by user_id and workspace_id
        - Prepare payloads for Security, Memory, Verification, Dashboard/API
        - Provide Master Agent compatible task routing

    Public methods return structured dicts:
        {
            "success": bool,
            "message": str,
            "data": dict/list/None,
            "error": str/None,
            "metadata": dict
        }
    """

    def __init__(
        self,
        repository: Optional[InMemoryCRMRepository] = None,
        security_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        logger: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            agent_name=kwargs.get("agent_name", "CRMManager"),
            agent_id=kwargs.get("agent_id", "business_agent.crm_manager"),
            metadata=kwargs.get("metadata", {"version": CRM_MANAGER_VERSION}),
        )
        self.repository = repository or InMemoryCRMRepository()
        self.security_agent = security_agent
        self.memory_agent = memory_agent
        self.verification_agent = verification_agent
        self.event_bus = event_bus
        self.audit_logger = audit_logger
        self.logger = logger or logging.getLogger(__name__)

    # -------------------------------------------------------------------------
    # Core result helpers
    # -------------------------------------------------------------------------

    def _safe_result(
        self,
        success: bool,
        message: str,
        data: Optional[Any] = None,
        error: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "success": bool(success),
            "message": message,
            "data": deep_public_copy(data),
            "error": error,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        error_text = str(error) if error is not None else message
        self.logger.error("%s | error=%s", message, error_text)
        return self._safe_result(
            success=False,
            message=message,
            data=None,
            error=error_text,
            metadata=metadata or {},
        )

    # -------------------------------------------------------------------------
    # Context, security, audit, memory, verification hooks
    # -------------------------------------------------------------------------

    def _validate_task_context(self, context: Dict[str, Any]) -> Tuple[bool, Optional[CRMContext], Optional[str]]:
        """
        Validate SaaS execution context.

        Required:
            - user_id
            - workspace_id

        This method protects against cross-tenant CRM data leakage.
        """
        if not isinstance(context, dict):
            return False, None, "context must be a dictionary"

        user_id = str(context.get("user_id", "")).strip()
        workspace_id = str(context.get("workspace_id", "")).strip()

        if not user_id:
            return False, None, "user_id is required"
        if not workspace_id:
            return False, None, "workspace_id is required"

        permissions = context.get("permissions") or []
        if not isinstance(permissions, list):
            permissions = []

        crm_context = CRMContext(
            user_id=user_id,
            workspace_id=workspace_id,
            role=context.get("role"),
            request_id=context.get("request_id"),
            source=context.get("source", "business_agent"),
            permissions=[str(permission) for permission in permissions],
        )
        return True, crm_context, None

    def _requires_security_check(self, action: str, payload: Optional[Dict[str, Any]] = None) -> bool:
        """
        Determine whether an action needs Security Agent approval.

        Sensitive actions include deletes, bulk changes, exports, and destructive
        pipeline operations.
        """
        sensitive_actions = {item.value for item in SensitiveAction}
        return action in sensitive_actions

    def _request_security_approval(
        self,
        action: str,
        context: CRMContext,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        If no Security Agent is attached, safe local policy allows non-sensitive
        actions and blocks sensitive actions unless context permissions include:
            - crm:admin
            - crm:delete
            - crm:export
        """
        payload = payload or {}

        if not self._requires_security_check(action, payload):
            return {
                "approved": True,
                "reason": "security_check_not_required",
                "metadata": {"action": action},
            }

        if self.security_agent and hasattr(self.security_agent, "approve_action"):
            try:
                approval = self.security_agent.approve_action(
                    action=action,
                    user_id=context.user_id,
                    workspace_id=context.workspace_id,
                    payload=payload,
                )
                if isinstance(approval, dict):
                    return {
                        "approved": bool(approval.get("approved")),
                        "reason": approval.get("reason", "security_agent_response"),
                        "metadata": approval,
                    }
            except Exception as exc:
                self.logger.exception("Security approval failed for action=%s", action)
                return {
                    "approved": False,
                    "reason": f"security_agent_error: {exc}",
                    "metadata": {"action": action},
                }

        permissions = set(context.permissions)
        allowed = bool(
            "crm:admin" in permissions
            or (action in {SensitiveAction.DELETE_CONTACT.value, SensitiveAction.DELETE_DEAL.value, SensitiveAction.DELETE_PIPELINE.value} and "crm:delete" in permissions)
            or (action == SensitiveAction.EXPORT_DATA.value and "crm:export" in permissions)
        )

        return {
            "approved": allowed,
            "reason": "local_permission_policy" if allowed else "missing_required_permission",
            "metadata": {
                "action": action,
                "required_any": ["crm:admin", "crm:delete", "crm:export"],
            },
        }

    def _prepare_verification_payload(
        self,
        action: str,
        context: CRMContext,
        result_data: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Prepare payload for Verification Agent.

        Verification Agent can later verify object creation, updates, stage moves,
        and CRM data consistency.
        """
        return {
            "agent": "business_agent.crm_manager",
            "action": action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "timestamp": utc_now_iso(),
            "result_data": deep_public_copy(result_data),
        }

    def _prepare_memory_payload(
        self,
        action: str,
        context: CRMContext,
        useful_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        Memory Agent should store useful business context such as lead source,
        important contact notes, deal stage changes, and pipeline activity while
        preserving user/workspace isolation.
        """
        return {
            "agent": "business_agent.crm_manager",
            "action": action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "timestamp": utc_now_iso(),
            "memory_type": "business_crm_context",
            "context": deep_public_copy(useful_context or {}),
        }

    def _emit_agent_event(
        self,
        event_name: str,
        context: CRMContext,
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Emit event for dashboards, analytics, registry observers, or task history.
        """
        event_payload = {
            "event": event_name,
            "agent": "business_agent.crm_manager",
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "timestamp": utc_now_iso(),
            "payload": deep_public_copy(payload or {}),
        }

        try:
            if self.event_bus and hasattr(self.event_bus, "emit"):
                self.event_bus.emit(event_name, event_payload)
            elif hasattr(self, "emit_event"):
                self.emit_event(event_name, event_payload)
        except Exception:
            self.logger.exception("Failed to emit CRM event: %s", event_name)

    def _log_audit_event(
        self,
        action: str,
        context: CRMContext,
        payload: Optional[Dict[str, Any]] = None,
        success: bool = True,
    ) -> None:
        """
        Log audit event for sensitive and useful CRM actions.
        """
        audit_payload = {
            "agent": "business_agent.crm_manager",
            "action": action,
            "success": success,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "timestamp": utc_now_iso(),
            "payload": deep_public_copy(payload or {}),
        }

        try:
            if self.audit_logger and hasattr(self.audit_logger, "log"):
                self.audit_logger.log(audit_payload)
            else:
                self.logger.info("CRM_AUDIT %s", audit_payload)
        except Exception:
            self.logger.exception("Failed to write CRM audit event")

    def _after_success(
        self,
        action: str,
        context: CRMContext,
        data: Optional[Any] = None,
        memory_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Common post-success hook.

        Returns metadata containing verification and memory payloads so callers,
        Master Agent, API routes, or queues can forward them to other agents.
        """
        verification_payload = self._prepare_verification_payload(action, context, data)
        memory_payload = self._prepare_memory_payload(action, context, memory_context or {})

        self._emit_agent_event(f"crm.{action}", context, {"data": data})
        self._log_audit_event(action, context, {"data": data}, success=True)

        if self.memory_agent and hasattr(self.memory_agent, "store_context"):
            try:
                self.memory_agent.store_context(memory_payload)
            except Exception:
                self.logger.exception("Memory Agent store_context failed")

        if self.verification_agent and hasattr(self.verification_agent, "prepare_verification"):
            try:
                self.verification_agent.prepare_verification(verification_payload)
            except Exception:
                self.logger.exception("Verification Agent prepare_verification failed")

        return {
            "verification_payload": verification_payload,
            "memory_payload": memory_payload,
        }

    # -------------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------------

    def _bucket(self, context: CRMContext, name: str) -> Dict[str, Any]:
        return self.repository.get_bucket(context.workspace_id, name)

    def _validate_email(self, email: Optional[str]) -> Optional[str]:
        if email is None:
            return None
        email = normalize_email(email)
        if email and not EMAIL_PATTERN.match(email):
            raise ValueError("email format is invalid")
        return email

    def _validate_phone(self, phone: Optional[str]) -> Optional[str]:
        if phone is None:
            return None
        phone = normalize_phone(phone)
        if phone and not PHONE_SAFE_PATTERN.match(phone):
            raise ValueError("phone format is invalid")
        return phone

    def _validate_currency(self, currency: Optional[str]) -> str:
        value = str(currency or "USD").strip().upper()
        if not re.match(r"^[A-Z]{3}$", value):
            raise ValueError("currency must be a 3-letter ISO-style code")
        return value

    def _validate_probability(self, probability: Optional[float]) -> Optional[float]:
        if probability is None:
            return None
        value = float(probability)
        if value < 0 or value > 100:
            raise ValueError("probability must be between 0 and 100")
        return value

    def _get_contact_or_error(self, context: CRMContext, contact_id: str) -> CRMContact:
        contact = self._bucket(context, "contacts").get(contact_id)
        if not contact:
            raise KeyError("contact not found")
        if contact.user_id != context.user_id or contact.workspace_id != context.workspace_id:
            raise PermissionError("contact does not belong to this user/workspace context")
        return contact

    def _get_deal_or_error(self, context: CRMContext, deal_id: str) -> CRMDeal:
        deal = self._bucket(context, "deals").get(deal_id)
        if not deal:
            raise KeyError("deal not found")
        if deal.user_id != context.user_id or deal.workspace_id != context.workspace_id:
            raise PermissionError("deal does not belong to this user/workspace context")
        return deal

    def _get_pipeline_or_error(self, context: CRMContext, pipeline_id: str) -> CRMPipeline:
        pipeline = self._bucket(context, "pipelines").get(pipeline_id)
        if not pipeline:
            raise KeyError("pipeline not found")
        if pipeline.user_id != context.user_id or pipeline.workspace_id != context.workspace_id:
            raise PermissionError("pipeline does not belong to this user/workspace context")
        return pipeline

    def _get_stage_or_error(self, context: CRMContext, stage_id: str) -> CRMPipelineStage:
        stage = self._bucket(context, "stages").get(stage_id)
        if not stage:
            raise KeyError("stage not found")
        if stage.user_id != context.user_id or stage.workspace_id != context.workspace_id:
            raise PermissionError("stage does not belong to this user/workspace context")
        return stage

    def _ensure_default_pipeline(self, context: CRMContext) -> Dict[str, Any]:
        pipelines = self._bucket(context, "pipelines")
        existing_default = next(
            (
                pipeline
                for pipeline in pipelines.values()
                if pipeline.workspace_id == context.workspace_id
                and pipeline.user_id == context.user_id
                and pipeline.is_default
            ),
            None,
        )
        if existing_default:
            stages = self.list_stages(
                context=context.to_dict(),
                pipeline_id=existing_default.id,
            )
            return {
                "pipeline": existing_default.to_dict(),
                "stages": stages.get("data", []),
            }

        created = self.create_pipeline(
            context=context.to_dict(),
            name=DEFAULT_PIPELINE_NAME,
            description="Default pipeline created automatically for CRM deal tracking.",
            stage_names=DEFAULT_PIPELINE_STAGES,
            is_default=True,
        )
        if not created["success"]:
            raise RuntimeError(created["error"] or "failed to create default pipeline")
        return created["data"]

    def _resolve_pipeline_and_stage(
        self,
        context: CRMContext,
        pipeline_id: Optional[str],
        stage_id: Optional[str],
    ) -> Tuple[str, str]:
        if not pipeline_id:
            default_data = self._ensure_default_pipeline(context)
            pipeline_id = default_data["pipeline"]["id"]

        self._get_pipeline_or_error(context, pipeline_id)

        if stage_id:
            stage = self._get_stage_or_error(context, stage_id)
            if stage.pipeline_id != pipeline_id:
                raise ValueError("stage_id does not belong to pipeline_id")
            return pipeline_id, stage_id

        stages = [
            stage
            for stage in self._bucket(context, "stages").values()
            if stage.pipeline_id == pipeline_id
            and stage.user_id == context.user_id
            and stage.workspace_id == context.workspace_id
        ]
        if not stages:
            raise ValueError("pipeline has no stages")
        stages.sort(key=lambda item: item.order)
        return pipeline_id, stages[0].id

    def _find_or_create_tag(self, context: CRMContext, tag_name: str) -> CRMTag:
        tag_name = normalize_tag_name(tag_name)
        if not tag_name:
            raise ValueError("tag name cannot be empty")

        tags = self._bucket(context, "tags")
        for tag in tags.values():
            if (
                tag.user_id == context.user_id
                and tag.workspace_id == context.workspace_id
                and tag.name.lower() == tag_name.lower()
            ):
                return tag

        tag = CRMTag(
            id=new_id("tag"),
            user_id=context.user_id,
            workspace_id=context.workspace_id,
            name=tag_name,
            created_by=context.user_id,
        )
        tags[tag.id] = tag
        return tag

    def _serialize_many(self, items: Iterable[Any]) -> List[Dict[str, Any]]:
        return [item.to_dict() if hasattr(item, "to_dict") else asdict(item) for item in items]

    # -------------------------------------------------------------------------
    # Contact management
    # -------------------------------------------------------------------------

    def create_contact(
        self,
        context: Dict[str, Any],
        full_name: str,
        email: Optional[str] = None,
        phone: Optional[str] = None,
        company: Optional[str] = None,
        title: Optional[str] = None,
        source: Optional[str] = None,
        tags: Optional[List[str]] = None,
        custom_fields: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create a CRM contact inside the current user/workspace."""
        valid, crm_context, error = self._validate_task_context(context)
        if not valid or crm_context is None:
            return self._error_result("Invalid CRM context", error)

        try:
            clean_name = " ".join(str(full_name).strip().split())
            if not clean_name:
                raise ValueError("full_name is required")

            contact = CRMContact(
                id=new_id("contact"),
                user_id=crm_context.user_id,
                workspace_id=crm_context.workspace_id,
                full_name=clean_name,
                email=self._validate_email(email),
                phone=self._validate_phone(phone),
                company=str(company).strip() if company else None,
                title=str(title).strip() if title else None,
                source=str(source).strip() if source else None,
                tags=[],
                custom_fields=custom_fields or {},
                created_by=crm_context.user_id,
            )

            for tag_name in tags or []:
                tag = self._find_or_create_tag(crm_context, tag_name)
                contact.tags.append(tag.name)

            self._bucket(crm_context, "contacts")[contact.id] = contact
            data = contact.to_dict()

            metadata = self._after_success(
                "create_contact",
                crm_context,
                data,
                {
                    "contact_id": contact.id,
                    "full_name": contact.full_name,
                    "company": contact.company,
                    "source": contact.source,
                    "tags": contact.tags,
                },
            )

            return self._safe_result(
                True,
                "Contact created successfully.",
                data,
                metadata=metadata,
            )
        except Exception as exc:
            self._log_audit_event("create_contact", crm_context, {"full_name": full_name}, success=False)
            return self._error_result("Failed to create contact.", exc)

    def update_contact(
        self,
        context: Dict[str, Any],
        contact_id: str,
        updates: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Update contact fields safely."""
        valid, crm_context, error = self._validate_task_context(context)
        if not valid or crm_context is None:
            return self._error_result("Invalid CRM context", error)

        try:
            if not isinstance(updates, dict):
                raise ValueError("updates must be a dictionary")

            contact = self._get_contact_or_error(crm_context, contact_id)
            allowed_fields = {
                "full_name",
                "email",
                "phone",
                "company",
                "title",
                "source",
                "status",
                "custom_fields",
            }

            for key, value in updates.items():
                if key not in allowed_fields:
                    continue
                if key == "email":
                    value = self._validate_email(value)
                elif key == "phone":
                    value = self._validate_phone(value)
                elif key == "full_name":
                    value = " ".join(str(value).strip().split())
                    if not value:
                        raise ValueError("full_name cannot be empty")
                elif key == "custom_fields":
                    if value is None:
                        value = {}
                    if not isinstance(value, dict):
                        raise ValueError("custom_fields must be a dictionary")
                elif isinstance(value, str):
                    value = value.strip() or None
                setattr(contact, key, value)

            contact.updated_at = utc_now_iso()
            data = contact.to_dict()

            metadata = self._after_success(
                "update_contact",
                crm_context,
                data,
                {
                    "contact_id": contact.id,
                    "updated_fields": list(updates.keys()),
                    "full_name": contact.full_name,
                },
            )

            return self._safe_result(
                True,
                "Contact updated successfully.",
                data,
                metadata=metadata,
            )
        except Exception as exc:
            self._log_audit_event("update_contact", crm_context, {"contact_id": contact_id}, success=False)
            return self._error_result("Failed to update contact.", exc)

    def get_contact(self, context: Dict[str, Any], contact_id: str) -> Dict[str, Any]:
        """Get one contact by ID."""
        valid, crm_context, error = self._validate_task_context(context)
        if not valid or crm_context is None:
            return self._error_result("Invalid CRM context", error)

        try:
            contact = self._get_contact_or_error(crm_context, contact_id)
            return self._safe_result(True, "Contact retrieved successfully.", contact.to_dict())
        except Exception as exc:
            return self._error_result("Failed to retrieve contact.", exc)

    def list_contacts(
        self,
        context: Dict[str, Any],
        query: Optional[str] = None,
        tag: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """List contacts in the current workspace with optional query/tag filtering."""
        valid, crm_context, error = self._validate_task_context(context)
        if not valid or crm_context is None:
            return self._error_result("Invalid CRM context", error)

        try:
            limit = max(1, min(int(limit), 500))
            offset = max(0, int(offset))
            query_text = str(query or "").strip().lower()
            tag_text = normalize_tag_name(tag or "").lower()

            contacts = [
                contact
                for contact in self._bucket(crm_context, "contacts").values()
                if contact.user_id == crm_context.user_id
                and contact.workspace_id == crm_context.workspace_id
            ]

            if query_text:
                contacts = [
                    contact
                    for contact in contacts
                    if query_text in contact.full_name.lower()
                    or query_text in str(contact.email or "").lower()
                    or query_text in str(contact.phone or "").lower()
                    or query_text in str(contact.company or "").lower()
                ]

            if tag_text:
                contacts = [
                    contact
                    for contact in contacts
                    if tag_text in [item.lower() for item in contact.tags]
                ]

            contacts.sort(key=lambda item: item.updated_at, reverse=True)
            paginated = contacts[offset: offset + limit]

            return self._safe_result(
                True,
                "Contacts listed successfully.",
                self._serialize_many(paginated),
                metadata={
                    "total": len(contacts),
                    "limit": limit,
                    "offset": offset,
                },
            )
        except Exception as exc:
            return self._error_result("Failed to list contacts.", exc)

    def delete_contact(self, context: Dict[str, Any], contact_id: str) -> Dict[str, Any]:
        """
        Delete a contact after Security Agent approval.

        Deals are not deleted automatically. Existing deals keep their contact_id
        for audit history, but dashboard/API can show it as missing.
        """
        valid, crm_context, error = self._validate_task_context(context)
        if not valid or crm_context is None:
            return self._error_result("Invalid CRM context", error)

        approval = self._request_security_approval(
            SensitiveAction.DELETE_CONTACT.value,
            crm_context,
            {"contact_id": contact_id},
        )
        if not approval["approved"]:
            return self._safe_result(
                False,
                "Security approval denied for deleting contact.",
                data=None,
                error=approval["reason"],
                metadata={"security": approval},
            )

        try:
            contact = self._get_contact_or_error(crm_context, contact_id)
            deleted = contact.to_dict()
            del self._bucket(crm_context, "contacts")[contact_id]

            metadata = self._after_success(
                "delete_contact",
                crm_context,
                deleted,
                {"deleted_contact_id": contact_id, "full_name": contact.full_name},
            )

            return self._safe_result(
                True,
                "Contact deleted successfully.",
                deleted,
                metadata={**metadata, "security": approval},
            )
        except Exception as exc:
            self._log_audit_event("delete_contact", crm_context, {"contact_id": contact_id}, success=False)
            return self._error_result("Failed to delete contact.", exc, {"security": approval})

    # -------------------------------------------------------------------------
    # Tag management
    # -------------------------------------------------------------------------

    def create_tag(
        self,
        context: Dict[str, Any],
        name: str,
        color: Optional[str] = None,
        description: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create or return an existing CRM tag."""
        valid, crm_context, error = self._validate_task_context(context)
        if not valid or crm_context is None:
            return self._error_result("Invalid CRM context", error)

        try:
            tag_name = normalize_tag_name(name)
            if not tag_name:
                raise ValueError("tag name is required")

            existing = self._find_or_create_tag(crm_context, tag_name)
            existing.color = str(color).strip() if color else existing.color
            existing.description = str(description).strip() if description else existing.description
            existing.updated_at = utc_now_iso()

            data = existing.to_dict()
            metadata = self._after_success(
                "create_tag",
                crm_context,
                data,
                {"tag": existing.name},
            )
            return self._safe_result(True, "Tag created successfully.", data, metadata=metadata)
        except Exception as exc:
            return self._error_result("Failed to create tag.", exc)

    def list_tags(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """List tags for the current user/workspace."""
        valid, crm_context, error = self._validate_task_context(context)
        if not valid or crm_context is None:
            return self._error_result("Invalid CRM context", error)

        try:
            tags = [
                tag
                for tag in self._bucket(crm_context, "tags").values()
                if tag.user_id == crm_context.user_id
                and tag.workspace_id == crm_context.workspace_id
            ]
            tags.sort(key=lambda item: item.name.lower())
            return self._safe_result(True, "Tags listed successfully.", self._serialize_many(tags))
        except Exception as exc:
            return self._error_result("Failed to list tags.", exc)

    def add_tags_to_contact(
        self,
        context: Dict[str, Any],
        contact_id: str,
        tags: List[str],
    ) -> Dict[str, Any]:
        """Add tags to a contact, creating missing tags safely."""
        valid, crm_context, error = self._validate_task_context(context)
        if not valid or crm_context is None:
            return self._error_result("Invalid CRM context", error)

        try:
            contact = self._get_contact_or_error(crm_context, contact_id)
            current = {tag.lower(): tag for tag in contact.tags}

            for tag_name in tags:
                tag = self._find_or_create_tag(crm_context, tag_name)
                if tag.name.lower() not in current:
                    contact.tags.append(tag.name)
                    current[tag.name.lower()] = tag.name

            contact.updated_at = utc_now_iso()
            data = contact.to_dict()
            metadata = self._after_success(
                "add_tags_to_contact",
                crm_context,
                data,
                {"contact_id": contact.id, "tags": contact.tags},
            )
            return self._safe_result(True, "Tags added to contact successfully.", data, metadata=metadata)
        except Exception as exc:
            return self._error_result("Failed to add tags to contact.", exc)

    def add_tags_to_deal(
        self,
        context: Dict[str, Any],
        deal_id: str,
        tags: List[str],
    ) -> Dict[str, Any]:
        """Add tags to a deal, creating missing tags safely."""
        valid, crm_context, error = self._validate_task_context(context)
        if not valid or crm_context is None:
            return self._error_result("Invalid CRM context", error)

        try:
            deal = self._get_deal_or_error(crm_context, deal_id)
            current = {tag.lower(): tag for tag in deal.tags}

            for tag_name in tags:
                tag = self._find_or_create_tag(crm_context, tag_name)
                if tag.name.lower() not in current:
                    deal.tags.append(tag.name)
                    current[tag.name.lower()] = tag.name

            deal.updated_at = utc_now_iso()
            data = deal.to_dict()
            metadata = self._after_success(
                "add_tags_to_deal",
                crm_context,
                data,
                {"deal_id": deal.id, "tags": deal.tags},
            )
            return self._safe_result(True, "Tags added to deal successfully.", data, metadata=metadata)
        except Exception as exc:
            return self._error_result("Failed to add tags to deal.", exc)

    # -------------------------------------------------------------------------
    # Note management
    # -------------------------------------------------------------------------

    def add_note(
        self,
        context: Dict[str, Any],
        object_type: str,
        object_id: str,
        content: str,
        pinned: bool = False,
    ) -> Dict[str, Any]:
        """Add a note to a contact, deal, pipeline, or stage."""
        valid, crm_context, error = self._validate_task_context(context)
        if not valid or crm_context is None:
            return self._error_result("Invalid CRM context", error)

        try:
            object_type = str(object_type).strip().lower()
            if object_type not in {item.value for item in CRMObjectType}:
                raise ValueError("object_type is invalid")

            if object_type == CRMObjectType.CONTACT.value:
                self._get_contact_or_error(crm_context, object_id)
            elif object_type == CRMObjectType.DEAL.value:
                self._get_deal_or_error(crm_context, object_id)
            elif object_type == CRMObjectType.PIPELINE.value:
                self._get_pipeline_or_error(crm_context, object_id)
            elif object_type == CRMObjectType.STAGE.value:
                self._get_stage_or_error(crm_context, object_id)

            clean_content = str(content).strip()
            if not clean_content:
                raise ValueError("note content is required")

            note = CRMNote(
                id=new_id("note"),
                user_id=crm_context.user_id,
                workspace_id=crm_context.workspace_id,
                object_type=object_type,
                object_id=object_id,
                content=clean_content,
                pinned=bool(pinned),
                created_by=crm_context.user_id,
            )

            self._bucket(crm_context, "notes")[note.id] = note
            data = note.to_dict()

            metadata = self._after_success(
                "add_note",
                crm_context,
                data,
                {
                    "object_type": object_type,
                    "object_id": object_id,
                    "note_id": note.id,
                    "content_preview": clean_content[:160],
                },
            )

            return self._safe_result(True, "Note added successfully.", data, metadata=metadata)
        except Exception as exc:
            return self._error_result("Failed to add note.", exc)

    def list_notes(
        self,
        context: Dict[str, Any],
        object_type: Optional[str] = None,
        object_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """List notes for a workspace or a specific CRM object."""
        valid, crm_context, error = self._validate_task_context(context)
        if not valid or crm_context is None:
            return self._error_result("Invalid CRM context", error)

        try:
            notes = [
                note
                for note in self._bucket(crm_context, "notes").values()
                if note.user_id == crm_context.user_id
                and note.workspace_id == crm_context.workspace_id
            ]

            if object_type:
                notes = [note for note in notes if note.object_type == str(object_type).strip().lower()]
            if object_id:
                notes = [note for note in notes if note.object_id == object_id]

            notes.sort(key=lambda item: (not item.pinned, item.created_at), reverse=False)
            return self._safe_result(True, "Notes listed successfully.", self._serialize_many(notes))
        except Exception as exc:
            return self._error_result("Failed to list notes.", exc)

    # -------------------------------------------------------------------------
    # Pipeline and stage management
    # -------------------------------------------------------------------------

    def create_pipeline(
        self,
        context: Dict[str, Any],
        name: str,
        description: Optional[str] = None,
        stage_names: Optional[List[str]] = None,
        is_default: bool = False,
    ) -> Dict[str, Any]:
        """Create a CRM pipeline with stages."""
        valid, crm_context, error = self._validate_task_context(context)
        if not valid or crm_context is None:
            return self._error_result("Invalid CRM context", error)

        try:
            clean_name = " ".join(str(name).strip().split())
            if not clean_name:
                raise ValueError("pipeline name is required")

            pipeline_bucket = self._bucket(crm_context, "pipelines")
            stage_bucket = self._bucket(crm_context, "stages")

            if is_default:
                for pipeline in pipeline_bucket.values():
                    if (
                        pipeline.user_id == crm_context.user_id
                        and pipeline.workspace_id == crm_context.workspace_id
                    ):
                        pipeline.is_default = False
                        pipeline.updated_at = utc_now_iso()

            pipeline = CRMPipeline(
                id=new_id("pipeline"),
                user_id=crm_context.user_id,
                workspace_id=crm_context.workspace_id,
                name=clean_name,
                description=str(description).strip() if description else None,
                is_default=bool(is_default),
                created_by=crm_context.user_id,
            )
            pipeline_bucket[pipeline.id] = pipeline

            names = stage_names or DEFAULT_PIPELINE_STAGES
            stages: List[CRMPipelineStage] = []
            for index, stage_name in enumerate(names):
                clean_stage_name = " ".join(str(stage_name).strip().split())
                if not clean_stage_name:
                    continue

                is_won = clean_stage_name.lower() == "won"
                is_lost = clean_stage_name.lower() == "lost"
                probability = 100.0 if is_won else 0.0 if is_lost else min(index * 15.0, 90.0)

                stage = CRMPipelineStage(
                    id=new_id("stage"),
                    user_id=crm_context.user_id,
                    workspace_id=crm_context.workspace_id,
                    pipeline_id=pipeline.id,
                    name=clean_stage_name,
                    order=index,
                    probability=probability,
                    is_won_stage=is_won,
                    is_lost_stage=is_lost,
                    created_by=crm_context.user_id,
                )
                stage_bucket[stage.id] = stage
                stages.append(stage)

            data = {
                "pipeline": pipeline.to_dict(),
                "stages": self._serialize_many(stages),
            }

            metadata = self._after_success(
                "create_pipeline",
                crm_context,
                data,
                {"pipeline_id": pipeline.id, "pipeline_name": pipeline.name},
            )

            return self._safe_result(True, "Pipeline created successfully.", data, metadata=metadata)
        except Exception as exc:
            return self._error_result("Failed to create pipeline.", exc)

    def list_pipelines(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """List pipelines with their stages."""
        valid, crm_context, error = self._validate_task_context(context)
        if not valid or crm_context is None:
            return self._error_result("Invalid CRM context", error)

        try:
            pipelines = [
                pipeline
                for pipeline in self._bucket(crm_context, "pipelines").values()
                if pipeline.user_id == crm_context.user_id
                and pipeline.workspace_id == crm_context.workspace_id
            ]

            stages = [
                stage
                for stage in self._bucket(crm_context, "stages").values()
                if stage.user_id == crm_context.user_id
                and stage.workspace_id == crm_context.workspace_id
            ]

            data = []
            for pipeline in sorted(pipelines, key=lambda item: item.created_at):
                pipeline_stages = [
                    stage for stage in stages if stage.pipeline_id == pipeline.id
                ]
                pipeline_stages.sort(key=lambda item: item.order)
                data.append(
                    {
                        "pipeline": pipeline.to_dict(),
                        "stages": self._serialize_many(pipeline_stages),
                    }
                )

            return self._safe_result(True, "Pipelines listed successfully.", data)
        except Exception as exc:
            return self._error_result("Failed to list pipelines.", exc)

    def list_stages(
        self,
        context: Dict[str, Any],
        pipeline_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """List pipeline stages."""
        valid, crm_context, error = self._validate_task_context(context)
        if not valid or crm_context is None:
            return self._error_result("Invalid CRM context", error)

        try:
            stages = [
                stage
                for stage in self._bucket(crm_context, "stages").values()
                if stage.user_id == crm_context.user_id
                and stage.workspace_id == crm_context.workspace_id
            ]

            if pipeline_id:
                self._get_pipeline_or_error(crm_context, pipeline_id)
                stages = [stage for stage in stages if stage.pipeline_id == pipeline_id]

            stages.sort(key=lambda item: item.order)
            return self._safe_result(True, "Stages listed successfully.", self._serialize_many(stages))
        except Exception as exc:
            return self._error_result("Failed to list stages.", exc)

    def update_stage(
        self,
        context: Dict[str, Any],
        stage_id: str,
        updates: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Update a pipeline stage."""
        valid, crm_context, error = self._validate_task_context(context)
        if not valid or crm_context is None:
            return self._error_result("Invalid CRM context", error)

        try:
            stage = self._get_stage_or_error(crm_context, stage_id)

            if "name" in updates:
                name = " ".join(str(updates["name"]).strip().split())
                if not name:
                    raise ValueError("stage name cannot be empty")
                stage.name = name

            if "order" in updates:
                stage.order = int(updates["order"])

            if "probability" in updates:
                probability = float(updates["probability"])
                if probability < 0 or probability > 100:
                    raise ValueError("probability must be between 0 and 100")
                stage.probability = probability

            if "is_won_stage" in updates:
                stage.is_won_stage = bool(updates["is_won_stage"])

            if "is_lost_stage" in updates:
                stage.is_lost_stage = bool(updates["is_lost_stage"])

            stage.updated_at = utc_now_iso()
            data = stage.to_dict()

            metadata = self._after_success(
                "update_stage",
                crm_context,
                data,
                {"stage_id": stage.id, "stage_name": stage.name},
            )

            return self._safe_result(True, "Stage updated successfully.", data, metadata=metadata)
        except Exception as exc:
            return self._error_result("Failed to update stage.", exc)

    # -------------------------------------------------------------------------
    # Deal management
    # -------------------------------------------------------------------------

    def create_deal(
        self,
        context: Dict[str, Any],
        title: str,
        value: float,
        currency: str = "USD",
        pipeline_id: Optional[str] = None,
        stage_id: Optional[str] = None,
        contact_id: Optional[str] = None,
        company: Optional[str] = None,
        expected_close_date: Optional[str] = None,
        probability: Optional[float] = None,
        tags: Optional[List[str]] = None,
        custom_fields: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create a CRM deal."""
        valid, crm_context, error = self._validate_task_context(context)
        if not valid or crm_context is None:
            return self._error_result("Invalid CRM context", error)

        try:
            clean_title = " ".join(str(title).strip().split())
            if not clean_title:
                raise ValueError("deal title is required")

            deal_value = float(value)
            if deal_value < 0:
                raise ValueError("deal value cannot be negative")

            if contact_id:
                self._get_contact_or_error(crm_context, contact_id)

            resolved_pipeline_id, resolved_stage_id = self._resolve_pipeline_and_stage(
                crm_context,
                pipeline_id,
                stage_id,
            )

            stage = self._get_stage_or_error(crm_context, resolved_stage_id)
            status = DealStatus.OPEN.value
            if stage.is_won_stage:
                status = DealStatus.WON.value
            elif stage.is_lost_stage:
                status = DealStatus.LOST.value

            deal = CRMDeal(
                id=new_id("deal"),
                user_id=crm_context.user_id,
                workspace_id=crm_context.workspace_id,
                title=clean_title,
                value=deal_value,
                currency=self._validate_currency(currency),
                pipeline_id=resolved_pipeline_id,
                stage_id=resolved_stage_id,
                contact_id=contact_id,
                company=str(company).strip() if company else None,
                status=status,
                expected_close_date=str(expected_close_date).strip() if expected_close_date else None,
                probability=self._validate_probability(probability) if probability is not None else stage.probability,
                tags=[],
                custom_fields=custom_fields or {},
                created_by=crm_context.user_id,
            )

            for tag_name in tags or []:
                tag = self._find_or_create_tag(crm_context, tag_name)
                deal.tags.append(tag.name)

            self._bucket(crm_context, "deals")[deal.id] = deal
            data = deal.to_dict()

            metadata = self._after_success(
                "create_deal",
                crm_context,
                data,
                {
                    "deal_id": deal.id,
                    "title": deal.title,
                    "value": deal.value,
                    "currency": deal.currency,
                    "stage_id": deal.stage_id,
                    "pipeline_id": deal.pipeline_id,
                },
            )

            return self._safe_result(True, "Deal created successfully.", data, metadata=metadata)
        except Exception as exc:
            self._log_audit_event("create_deal", crm_context, {"title": title}, success=False)
            return self._error_result("Failed to create deal.", exc)

    def update_deal(
        self,
        context: Dict[str, Any],
        deal_id: str,
        updates: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Update deal fields safely."""
        valid, crm_context, error = self._validate_task_context(context)
        if not valid or crm_context is None:
            return self._error_result("Invalid CRM context", error)

        try:
            if not isinstance(updates, dict):
                raise ValueError("updates must be a dictionary")

            deal = self._get_deal_or_error(crm_context, deal_id)
            allowed_fields = {
                "title",
                "value",
                "currency",
                "contact_id",
                "company",
                "status",
                "expected_close_date",
                "probability",
                "custom_fields",
            }

            for key, value in updates.items():
                if key not in allowed_fields:
                    continue
                if key == "title":
                    value = " ".join(str(value).strip().split())
                    if not value:
                        raise ValueError("deal title cannot be empty")
                elif key == "value":
                    value = float(value)
                    if value < 0:
                        raise ValueError("deal value cannot be negative")
                elif key == "currency":
                    value = self._validate_currency(value)
                elif key == "contact_id":
                    if value:
                        self._get_contact_or_error(crm_context, str(value))
                    value = str(value) if value else None
                elif key == "probability":
                    value = self._validate_probability(value)
                elif key == "status":
                    value = str(value).strip().lower()
                    if value not in {item.value for item in DealStatus}:
                        raise ValueError("deal status is invalid")
                elif key == "custom_fields":
                    if value is None:
                        value = {}
                    if not isinstance(value, dict):
                        raise ValueError("custom_fields must be a dictionary")
                elif isinstance(value, str):
                    value = value.strip() or None

                setattr(deal, key, value)

            deal.updated_at = utc_now_iso()
            data = deal.to_dict()

            metadata = self._after_success(
                "update_deal",
                crm_context,
                data,
                {"deal_id": deal.id, "updated_fields": list(updates.keys())},
            )

            return self._safe_result(True, "Deal updated successfully.", data, metadata=metadata)
        except Exception as exc:
            self._log_audit_event("update_deal", crm_context, {"deal_id": deal_id}, success=False)
            return self._error_result("Failed to update deal.", exc)

    def move_deal_stage(
        self,
        context: Dict[str, Any],
        deal_id: str,
        stage_id: str,
    ) -> Dict[str, Any]:
        """Move a deal to another stage in the same pipeline."""
        valid, crm_context, error = self._validate_task_context(context)
        if not valid or crm_context is None:
            return self._error_result("Invalid CRM context", error)

        try:
            deal = self._get_deal_or_error(crm_context, deal_id)
            stage = self._get_stage_or_error(crm_context, stage_id)

            if stage.pipeline_id != deal.pipeline_id:
                raise ValueError("target stage must belong to the deal pipeline")

            old_stage_id = deal.stage_id
            deal.stage_id = stage.id
            deal.probability = stage.probability

            if stage.is_won_stage:
                deal.status = DealStatus.WON.value
            elif stage.is_lost_stage:
                deal.status = DealStatus.LOST.value
            elif deal.status in {DealStatus.WON.value, DealStatus.LOST.value}:
                deal.status = DealStatus.OPEN.value

            deal.updated_at = utc_now_iso()
            data = deal.to_dict()

            metadata = self._after_success(
                "move_deal_stage",
                crm_context,
                data,
                {
                    "deal_id": deal.id,
                    "old_stage_id": old_stage_id,
                    "new_stage_id": stage.id,
                    "new_stage_name": stage.name,
                    "status": deal.status,
                },
            )

            return self._safe_result(True, "Deal moved to new stage successfully.", data, metadata=metadata)
        except Exception as exc:
            self._log_audit_event("move_deal_stage", crm_context, {"deal_id": deal_id, "stage_id": stage_id}, success=False)
            return self._error_result("Failed to move deal stage.", exc)

    def get_deal(self, context: Dict[str, Any], deal_id: str) -> Dict[str, Any]:
        """Get one deal by ID."""
        valid, crm_context, error = self._validate_task_context(context)
        if not valid or crm_context is None:
            return self._error_result("Invalid CRM context", error)

        try:
            deal = self._get_deal_or_error(crm_context, deal_id)
            return self._safe_result(True, "Deal retrieved successfully.", deal.to_dict())
        except Exception as exc:
            return self._error_result("Failed to retrieve deal.", exc)

    def list_deals(
        self,
        context: Dict[str, Any],
        pipeline_id: Optional[str] = None,
        stage_id: Optional[str] = None,
        contact_id: Optional[str] = None,
        status: Optional[str] = None,
        query: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """List deals in the current workspace with filters."""
        valid, crm_context, error = self._validate_task_context(context)
        if not valid or crm_context is None:
            return self._error_result("Invalid CRM context", error)

        try:
            limit = max(1, min(int(limit), 500))
            offset = max(0, int(offset))
            query_text = str(query or "").strip().lower()
            status_text = str(status or "").strip().lower()

            deals = [
                deal
                for deal in self._bucket(crm_context, "deals").values()
                if deal.user_id == crm_context.user_id
                and deal.workspace_id == crm_context.workspace_id
            ]

            if pipeline_id:
                deals = [deal for deal in deals if deal.pipeline_id == pipeline_id]
            if stage_id:
                deals = [deal for deal in deals if deal.stage_id == stage_id]
            if contact_id:
                deals = [deal for deal in deals if deal.contact_id == contact_id]
            if status_text:
                deals = [deal for deal in deals if deal.status == status_text]
            if query_text:
                deals = [
                    deal
                    for deal in deals
                    if query_text in deal.title.lower()
                    or query_text in str(deal.company or "").lower()
                    or query_text in " ".join(deal.tags).lower()
                ]

            deals.sort(key=lambda item: item.updated_at, reverse=True)
            paginated = deals[offset: offset + limit]

            return self._safe_result(
                True,
                "Deals listed successfully.",
                self._serialize_many(paginated),
                metadata={
                    "total": len(deals),
                    "limit": limit,
                    "offset": offset,
                },
            )
        except Exception as exc:
            return self._error_result("Failed to list deals.", exc)

    def delete_deal(self, context: Dict[str, Any], deal_id: str) -> Dict[str, Any]:
        """Delete a deal after Security Agent approval."""
        valid, crm_context, error = self._validate_task_context(context)
        if not valid or crm_context is None:
            return self._error_result("Invalid CRM context", error)

        approval = self._request_security_approval(
            SensitiveAction.DELETE_DEAL.value,
            crm_context,
            {"deal_id": deal_id},
        )
        if not approval["approved"]:
            return self._safe_result(
                False,
                "Security approval denied for deleting deal.",
                data=None,
                error=approval["reason"],
                metadata={"security": approval},
            )

        try:
            deal = self._get_deal_or_error(crm_context, deal_id)
            deleted = deal.to_dict()
            del self._bucket(crm_context, "deals")[deal_id]

            metadata = self._after_success(
                "delete_deal",
                crm_context,
                deleted,
                {"deleted_deal_id": deal_id, "title": deal.title},
            )

            return self._safe_result(
                True,
                "Deal deleted successfully.",
                deleted,
                metadata={**metadata, "security": approval},
            )
        except Exception as exc:
            self._log_audit_event("delete_deal", crm_context, {"deal_id": deal_id}, success=False)
            return self._error_result("Failed to delete deal.", exc, {"security": approval})

    # -------------------------------------------------------------------------
    # Analytics and export-safe views
    # -------------------------------------------------------------------------

    def get_crm_summary(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Return dashboard-friendly CRM summary.

        Includes contacts count, deal count, pipeline count, open/won/lost values,
        and stage distribution.
        """
        valid, crm_context, error = self._validate_task_context(context)
        if not valid or crm_context is None:
            return self._error_result("Invalid CRM context", error)

        try:
            contacts = [
                contact
                for contact in self._bucket(crm_context, "contacts").values()
                if contact.user_id == crm_context.user_id
                and contact.workspace_id == crm_context.workspace_id
            ]
            deals = [
                deal
                for deal in self._bucket(crm_context, "deals").values()
                if deal.user_id == crm_context.user_id
                and deal.workspace_id == crm_context.workspace_id
            ]
            pipelines = [
                pipeline
                for pipeline in self._bucket(crm_context, "pipelines").values()
                if pipeline.user_id == crm_context.user_id
                and pipeline.workspace_id == crm_context.workspace_id
            ]
            stages = {
                stage.id: stage
                for stage in self._bucket(crm_context, "stages").values()
                if stage.user_id == crm_context.user_id
                and stage.workspace_id == crm_context.workspace_id
            }

            stage_distribution: Dict[str, Dict[str, Any]] = {}
            for deal in deals:
                stage = stages.get(deal.stage_id)
                stage_name = stage.name if stage else "Unknown"
                if stage_name not in stage_distribution:
                    stage_distribution[stage_name] = {
                        "stage_name": stage_name,
                        "deal_count": 0,
                        "total_value": 0.0,
                    }
                stage_distribution[stage_name]["deal_count"] += 1
                stage_distribution[stage_name]["total_value"] += deal.value

            data = {
                "contacts_count": len(contacts),
                "deals_count": len(deals),
                "pipelines_count": len(pipelines),
                "open_deals_count": len([deal for deal in deals if deal.status == DealStatus.OPEN.value]),
                "won_deals_count": len([deal for deal in deals if deal.status == DealStatus.WON.value]),
                "lost_deals_count": len([deal for deal in deals if deal.status == DealStatus.LOST.value]),
                "open_deal_value": sum(deal.value for deal in deals if deal.status == DealStatus.OPEN.value),
                "won_deal_value": sum(deal.value for deal in deals if deal.status == DealStatus.WON.value),
                "lost_deal_value": sum(deal.value for deal in deals if deal.status == DealStatus.LOST.value),
                "stage_distribution": list(stage_distribution.values()),
                "generated_at": utc_now_iso(),
            }

            return self._safe_result(True, "CRM summary generated successfully.", data)
        except Exception as exc:
            return self._error_result("Failed to generate CRM summary.", exc)

    def export_workspace_snapshot(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Export a workspace CRM snapshot after Security Agent approval.

        This does not write files or send data externally. It only returns a
        structured snapshot to the authorized caller.
        """
        valid, crm_context, error = self._validate_task_context(context)
        if not valid or crm_context is None:
            return self._error_result("Invalid CRM context", error)

        approval = self._request_security_approval(
            SensitiveAction.EXPORT_DATA.value,
            crm_context,
            {"scope": "crm_workspace_snapshot"},
        )
        if not approval["approved"]:
            return self._safe_result(
                False,
                "Security approval denied for CRM export.",
                data=None,
                error=approval["reason"],
                metadata={"security": approval},
            )

        try:
            snapshot = self.repository.snapshot_workspace(crm_context.workspace_id)

            filtered_snapshot: Dict[str, Any] = {}
            for bucket_name, objects in snapshot.items():
                filtered_snapshot[bucket_name] = {
                    object_id: item
                    for object_id, item in objects.items()
                    if item.get("user_id") == crm_context.user_id
                    and item.get("workspace_id") == crm_context.workspace_id
                }

            metadata = self._after_success(
                "export_workspace_snapshot",
                crm_context,
                {"object_counts": {key: len(value) for key, value in filtered_snapshot.items()}},
                {"export_scope": "crm_workspace_snapshot"},
            )

            return self._safe_result(
                True,
                "CRM workspace snapshot exported successfully.",
                filtered_snapshot,
                metadata={**metadata, "security": approval},
            )
        except Exception as exc:
            return self._error_result("Failed to export CRM workspace snapshot.", exc, {"security": approval})

    # -------------------------------------------------------------------------
    # Master Agent / Router compatibility
    # -------------------------------------------------------------------------

    def handle_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Master Agent compatible task router.

        Expected task structure:
            {
                "action": "create_contact",
                "context": {"user_id": "...", "workspace_id": "..."},
                "payload": {...}
            }

        Supported actions:
            - create_contact
            - update_contact
            - get_contact
            - list_contacts
            - delete_contact
            - create_tag
            - list_tags
            - add_tags_to_contact
            - add_tags_to_deal
            - add_note
            - list_notes
            - create_pipeline
            - list_pipelines
            - list_stages
            - update_stage
            - create_deal
            - update_deal
            - move_deal_stage
            - get_deal
            - list_deals
            - delete_deal
            - get_crm_summary
            - export_workspace_snapshot
        """
        if not isinstance(task, dict):
            return self._error_result("Invalid task.", "task must be a dictionary")

        action = str(task.get("action", "")).strip()
        context = task.get("context") or {}
        payload = task.get("payload") or {}

        if not action:
            return self._error_result("Invalid task.", "action is required")
        if not isinstance(payload, dict):
            return self._error_result("Invalid task.", "payload must be a dictionary")

        route_map = {
            "create_contact": self.create_contact,
            "update_contact": self.update_contact,
            "get_contact": self.get_contact,
            "list_contacts": self.list_contacts,
            "delete_contact": self.delete_contact,
            "create_tag": self.create_tag,
            "list_tags": self.list_tags,
            "add_tags_to_contact": self.add_tags_to_contact,
            "add_tags_to_deal": self.add_tags_to_deal,
            "add_note": self.add_note,
            "list_notes": self.list_notes,
            "create_pipeline": self.create_pipeline,
            "list_pipelines": self.list_pipelines,
            "list_stages": self.list_stages,
            "update_stage": self.update_stage,
            "create_deal": self.create_deal,
            "update_deal": self.update_deal,
            "move_deal_stage": self.move_deal_stage,
            "get_deal": self.get_deal,
            "list_deals": self.list_deals,
            "delete_deal": self.delete_deal,
            "get_crm_summary": self.get_crm_summary,
            "export_workspace_snapshot": self.export_workspace_snapshot,
        }

        handler = route_map.get(action)
        if not handler:
            return self._error_result(
                "Unsupported CRM task action.",
                f"unsupported action: {action}",
                metadata={"supported_actions": sorted(route_map.keys())},
            )

        try:
            return handler(context=context, **payload)
        except TypeError as exc:
            return self._error_result(
                "CRM task payload does not match action signature.",
                exc,
                metadata={"action": action},
            )
        except Exception as exc:
            return self._error_result(
                "CRM task failed unexpectedly.",
                exc,
                metadata={"action": action},
            )

    # -------------------------------------------------------------------------
    # Registry / loader metadata
    # -------------------------------------------------------------------------

    def get_agent_manifest(self) -> Dict[str, Any]:
        """
        Return metadata for Agent Registry and Agent Loader.
        """
        return {
            "agent": "business_agent.crm_manager",
            "class_name": "CRMManager",
            "version": CRM_MANAGER_VERSION,
            "module": "agents.super_agents.business_agent.crm_manager",
            "capabilities": [
                "manage_contacts",
                "manage_deals",
                "manage_pipelines",
                "manage_tags",
                "manage_notes",
                "manage_stages",
                "crm_summary",
                "workspace_snapshot_export",
            ],
            "requires_context": ["user_id", "workspace_id"],
            "security_sensitive_actions": [item.value for item in SensitiveAction],
            "structured_result": True,
            "import_safe": True,
            "master_agent_routable": True,
            "memory_agent_compatible": True,
            "verification_agent_compatible": True,
            "dashboard_api_ready": True,
        }


__all__ = [
    "CRMManager",
    "InMemoryCRMRepository",
    "CRMContext",
    "CRMContact",
    "CRMDeal",
    "CRMPipeline",
    "CRMPipelineStage",
    "CRMTag",
    "CRMNote",
    "CRMObjectType",
    "DealStatus",
    "SensitiveAction",
]