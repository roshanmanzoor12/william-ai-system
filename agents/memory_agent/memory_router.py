"""
agents/memory_agent/memory_router.py

William / Jarvis Multi-Agent AI SaaS System - Digital Promotix

Purpose:
    MemoryRouter decides:
    - Memory category
    - Importance score and label
    - Privacy level
    - Storage layer
    - Retention recommendation
    - Security review requirement
    - Verification payload
    - Memory payload for downstream storage

Architecture Role:
    This file is part of the Memory Agent module.

    It is designed to be called by:
    - Master Agent
    - Memory Agent
    - Agent Router
    - Agent Registry
    - Dashboard/API layer
    - Future storage services
    - Future privacy guard / memory cleaner / summarizer modules

Safety Rules:
    - Never mixes user/workspace memory.
    - Every user-specific routing request must include user_id and workspace_id.
    - Sensitive/private content is flagged before storage.
    - This file does not persist memory directly unless a future storage adapter is injected.
    - All output uses structured dict format:
        {
            "success": bool,
            "message": str,
            "data": dict,
            "error": dict | None,
            "metadata": dict
        }

Import Safety:
    - Safe to import even if BaseAgent or other William modules do not exist yet.
    - Contains fallback BaseAgent compatibility stub.
    - Does not require external services.
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------
# Safe Optional BaseAgent Import
# ---------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for standalone import safety
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This allows this file to import safely before the real William/Jarvis
        BaseAgent exists. The real BaseAgent should provide richer routing,
        registry, audit, permission, and lifecycle methods later.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())
            self.logger = logging.getLogger(self.agent_name)

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback emit_event: %s | %s", event_name, payload)

        def log_audit(self, event_name: str, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback log_audit: %s | %s", event_name, payload)


# ---------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------

class MemoryCategory(str, Enum):
    """
    High-level categories used by the Memory Agent.

    These categories are intentionally broad so future modules such as
    project_memory.py, client_memory.py, preference_manager.py, and
    knowledge_graph.py can consume the router result cleanly.
    """

    USER_PREFERENCE = "user_preference"
    PROJECT_CONTEXT = "project_context"
    CLIENT_CONTEXT = "client_context"
    TEAM_CONTEXT = "team_context"
    BUSINESS_CONTEXT = "business_context"
    TECHNICAL_CONTEXT = "technical_context"
    TASK_CONTEXT = "task_context"
    CONVERSATION_CONTEXT = "conversation_context"
    KNOWLEDGE_FACT = "knowledge_fact"
    SECURITY_CONTEXT = "security_context"
    FINANCIAL_CONTEXT = "financial_context"
    CREATIVE_CONTEXT = "creative_context"
    WORKFLOW_CONTEXT = "workflow_context"
    AGENT_CONFIGURATION = "agent_configuration"
    SYSTEM_CONFIGURATION = "system_configuration"
    PERSONAL_CONTEXT = "personal_context"
    TEMPORARY_NOTE = "temporary_note"
    UNKNOWN = "unknown"


class PrivacyLevel(str, Enum):
    """
    Privacy levels for storage and approval routing.

    PUBLIC:
        Safe non-sensitive business/general information.

    INTERNAL:
        Workspace/team-only information.

    PRIVATE:
        User-specific sensitive/private information.

    CONFIDENTIAL:
        Highly sensitive business, client, financial, operational, security,
        or credential-adjacent information.

    RESTRICTED:
        Information that should not be stored without explicit approval or
        a future PrivacyGuard/SecurityAgent decision.
    """

    PUBLIC = "public"
    INTERNAL = "internal"
    PRIVATE = "private"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class StorageLayer(str, Enum):
    """
    Recommended storage destination.

    This router only recommends the layer. Actual persistence should be handled
    by Memory Agent storage modules.
    """

    NONE = "none"
    SHORT_TERM = "short_term"
    LONG_TERM = "long_term"
    PROJECT_MEMORY = "project_memory"
    CLIENT_MEMORY = "client_memory"
    TEAM_MEMORY = "team_memory"
    PREFERENCE_MEMORY = "preference_memory"
    KNOWLEDGE_GRAPH = "knowledge_graph"
    SECURITY_VAULT = "security_vault"
    AUDIT_ONLY = "audit_only"
    REVIEW_QUEUE = "review_queue"


class ImportanceLabel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RetentionPolicy(str, Enum):
    DO_NOT_STORE = "do_not_store"
    SESSION_ONLY = "session_only"
    DAYS_7 = "7_days"
    DAYS_30 = "30_days"
    DAYS_90 = "90_days"
    LONG_TERM = "long_term"
    PERMANENT_UNTIL_USER_DELETES = "permanent_until_user_deletes"
    REVIEW_REQUIRED = "review_required"


class MemoryDecision(str, Enum):
    STORE = "store"
    DO_NOT_STORE = "do_not_store"
    REVIEW_BEFORE_STORE = "review_before_store"
    AUDIT_ONLY = "audit_only"


# ---------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------

@dataclass
class MemoryRouteInput:
    """
    Normalized input for routing memory.

    user_id and workspace_id are required for user/workspace-specific memory.
    """

    content: str
    user_id: Optional[str] = None
    workspace_id: Optional[str] = None
    source_agent: Optional[str] = None
    source_event: Optional[str] = None
    conversation_id: Optional[str] = None
    task_id: Optional[str] = None
    client_id: Optional[str] = None
    project_id: Optional[str] = None
    team_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    explicit_category: Optional[Union[str, MemoryCategory]] = None
    explicit_privacy_level: Optional[Union[str, PrivacyLevel]] = None
    explicit_storage_layer: Optional[Union[str, StorageLayer]] = None
    explicit_importance: Optional[Union[int, float, str, ImportanceLabel]] = None
    force_store: bool = False
    dry_run: bool = True


@dataclass
class MemoryRouteDecision:
    """
    Final routing decision.
    """

    decision_id: str
    memory_id: str
    category: MemoryCategory
    privacy_level: PrivacyLevel
    storage_layer: StorageLayer
    importance_score: float
    importance_label: ImportanceLabel
    retention_policy: RetentionPolicy
    decision: MemoryDecision
    should_store: bool
    requires_security_check: bool
    requires_user_approval: bool
    requires_workspace_scope: bool
    reasons: List[str]
    detected_entities: Dict[str, Any]
    normalized_content_hash: str
    created_at: str


# ---------------------------------------------------------------------
# Memory Router
# ---------------------------------------------------------------------

class MemoryRouter(BaseAgent):
    """
    Decides where and how a memory item should be handled.

    This class does not directly write to databases. It classifies and routes
    memory into structured decisions so storage modules can safely act later.

    Main public methods:
        - route_memory()
        - route_batch()
        - decide_category()
        - score_importance()
        - detect_privacy_level()
        - choose_storage_layer()
        - should_store_memory()
        - normalize_content()
        - build_memory_record()

    Compatibility hooks:
        - _validate_task_context()
        - _requires_security_check()
        - _request_security_approval()
        - _prepare_verification_payload()
        - _prepare_memory_payload()
        - _emit_agent_event()
        - _log_audit_event()
        - _safe_result()
        - _error_result()
    """

    DEFAULT_AGENT_NAME = "MemoryRouter"
    DEFAULT_AGENT_ID = "memory_router"

    VERSION = "1.0.0"

    CATEGORY_KEYWORDS: Dict[MemoryCategory, Tuple[str, ...]] = {
        MemoryCategory.USER_PREFERENCE: (
            "i prefer",
            "my preference",
            "remember that i like",
            "remember i like",
            "from now on",
            "going forward",
            "always use",
            "never use",
            "my style",
            "i want future",
            "save this preference",
            "remember this preference",
            "tone",
            "format",
            "writing style",
        ),
        MemoryCategory.PROJECT_CONTEXT: (
            "project",
            "module",
            "file path",
            "architecture",
            "repository",
            "roadmap",
            "milestone",
            "sprint",
            "feature",
            "build plan",
            "implementation",
            "requirements",
            "folder structure",
        ),
        MemoryCategory.CLIENT_CONTEXT: (
            "client",
            "customer",
            "lead",
            "proposal",
            "agreement",
            "account",
            "contact person",
            "business owner",
            "client requirement",
        ),
        MemoryCategory.TEAM_CONTEXT: (
            "team",
            "developer",
            "designer",
            "manager",
            "staff",
            "member",
            "department",
            "role",
            "assigned to",
        ),
        MemoryCategory.BUSINESS_CONTEXT: (
            "business",
            "agency",
            "brand",
            "service",
            "pricing",
            "package",
            "offer",
            "sales",
            "marketing",
            "revenue",
            "conversion",
            "digital promotix",
            "white label",
            "saas",
        ),
        MemoryCategory.TECHNICAL_CONTEXT: (
            "python",
            "fastapi",
            "api",
            "database",
            "postgres",
            "redis",
            "docker",
            "kotlin",
            "flutter",
            "backend",
            "frontend",
            "server",
            "deployment",
            "code",
            "function",
            "class",
            "method",
            "error",
            "bug",
            "logs",
        ),
        MemoryCategory.TASK_CONTEXT: (
            "task",
            "todo",
            "deadline",
            "next step",
            "status",
            "progress",
            "completed",
            "remaining",
            "pending",
            "priority",
        ),
        MemoryCategory.CONVERSATION_CONTEXT: (
            "we discussed",
            "earlier",
            "last time",
            "this chat",
            "conversation",
            "context",
            "recap",
            "summary",
        ),
        MemoryCategory.KNOWLEDGE_FACT: (
            "fact",
            "definition",
            "knowledge",
            "learned",
            "rule",
            "principle",
            "documentation",
            "note",
        ),
        MemoryCategory.SECURITY_CONTEXT: (
            "permission",
            "approval",
            "security",
            "access",
            "role",
            "policy",
            "audit",
            "risk",
            "token",
            "secret",
            "credential",
            "password",
            "api key",
            "private key",
        ),
        MemoryCategory.FINANCIAL_CONTEXT: (
            "payment",
            "invoice",
            "subscription",
            "billing",
            "budget",
            "profit",
            "loss",
            "cost",
            "revenue",
            "salary",
            "bank",
            "stripe",
            "paypal",
        ),
        MemoryCategory.CREATIVE_CONTEXT: (
            "script",
            "video",
            "veo",
            "prompt",
            "anime",
            "story",
            "scene",
            "character",
            "design",
            "thumbnail",
            "creative",
            "ad copy",
        ),
        MemoryCategory.WORKFLOW_CONTEXT: (
            "workflow",
            "automation",
            "pipeline",
            "process",
            "trigger",
            "schedule",
            "steps",
            "sequence",
            "integration",
            "zapier",
            "crm",
        ),
        MemoryCategory.AGENT_CONFIGURATION: (
            "agent",
            "master agent",
            "memory agent",
            "security agent",
            "verification agent",
            "agent router",
            "agent registry",
            "agent loader",
            "tool permission",
        ),
        MemoryCategory.SYSTEM_CONFIGURATION: (
            "config",
            "settings",
            "environment",
            "env",
            "system",
            "server config",
            "workspace config",
            "feature flag",
            "installation",
        ),
        MemoryCategory.PERSONAL_CONTEXT: (
            "my name",
            "i am",
            "i live",
            "my company",
            "my account",
            "my profile",
            "my location",
        ),
        MemoryCategory.TEMPORARY_NOTE: (
            "temporary",
            "for now",
            "just now",
            "only this time",
            "current session",
            "draft",
        ),
    }

    PRIVACY_PATTERNS: Dict[PrivacyLevel, Tuple[str, ...]] = {
        PrivacyLevel.RESTRICTED: (
            r"\bpassword\b",
            r"\bpasscode\b",
            r"\bprivate\s*key\b",
            r"\bsecret\s*key\b",
            r"\bapi\s*key\b",
            r"\baccess\s*token\b",
            r"\brefresh\s*token\b",
            r"\bbearer\s+[a-z0-9\.\-_]+\b",
            r"\bssh-rsa\b",
            r"\bBEGIN\s+(RSA|OPENSSH|PRIVATE)\s+KEY\b",
            r"\bcredit\s*card\b",
            r"\bcard\s*number\b",
            r"\bcvv\b",
            r"\botp\b",
            r"\b2fa\b",
        ),
        PrivacyLevel.CONFIDENTIAL: (
            r"\bclient\b",
            r"\bcontract\b",
            r"\bagreement\b",
            r"\binvoice\b",
            r"\bbilling\b",
            r"\bfinancial\b",
            r"\brevenue\b",
            r"\bprofit\b",
            r"\bbank\b",
            r"\bconfidential\b",
            r"\binternal only\b",
            r"\bsecurity\b",
            r"\baudit\b",
            r"\bpermission\b",
        ),
        PrivacyLevel.PRIVATE: (
            r"\bmy email\b",
            r"\bmy phone\b",
            r"\bmy address\b",
            r"\bmy name\b",
            r"\bpersonal\b",
            r"\bprivate\b",
            r"\bprofile\b",
            r"\baccount\b",
            r"\bidentity\b",
        ),
        PrivacyLevel.INTERNAL: (
            r"\bteam\b",
            r"\bworkspace\b",
            r"\binternal\b",
            r"\bproject\b",
            r"\bcompany\b",
            r"\bagency\b",
            r"\bworkflow\b",
            r"\bprocess\b",
        ),
        PrivacyLevel.PUBLIC: (
            r"\bgeneral\b",
            r"\bpublic\b",
            r"\bexample\b",
            r"\bdocumentation\b",
            r"\btutorial\b",
        ),
    }

    ENTITY_PATTERNS: Dict[str, str] = {
        "email": r"\b[a-zA-Z0-9_.+\-]+@[a-zA-Z0-9\-]+\.[a-zA-Z0-9.\-]+\b",
        "phone": r"(?<!\d)(?:\+?\d{1,3}[\s\-\.]?)?(?:\(?\d{2,4}\)?[\s\-\.]?)?\d{3,4}[\s\-\.]?\d{3,4}(?!\d)",
        "url": r"\bhttps?://[^\s]+|\b[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?",
        "ip_address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "money": r"(?<!\w)(?:\$|usd|pkr|rs\.?|gbp|eur|aed)\s?\d+(?:,\d{3})*(?:\.\d+)?\b",
        "file_path": r"\b(?:[a-zA-Z0-9_\-]+/)+[a-zA-Z0-9_\-]+\.[a-zA-Z0-9]+\b",
        "python_file": r"\b[a-zA-Z0-9_\-]+\.py\b",
        "secret_like": r"\b(?:sk|pk|api|key|token|secret)[_\-]?[a-zA-Z0-9]{16,}\b",
    }

    HIGH_IMPORTANCE_KEYWORDS: Tuple[str, ...] = (
        "remember",
        "always",
        "never",
        "must",
        "required",
        "critical",
        "important",
        "production",
        "final",
        "rule",
        "policy",
        "permission",
        "security",
        "client",
        "project",
        "architecture",
        "from now on",
        "going forward",
        "do not",
        "don't",
        "exact",
        "locked",
    )

    LOW_VALUE_PATTERNS: Tuple[str, ...] = (
        r"^\s*(ok|okay|thanks|thank you|nice|yes|no|hmm|lol)\s*[.!]?\s*$",
        r"^\s*(continue|go on|next)\s*[.!]?\s*$",
    )

    STORAGE_BY_CATEGORY: Dict[MemoryCategory, StorageLayer] = {
        MemoryCategory.USER_PREFERENCE: StorageLayer.PREFERENCE_MEMORY,
        MemoryCategory.PROJECT_CONTEXT: StorageLayer.PROJECT_MEMORY,
        MemoryCategory.CLIENT_CONTEXT: StorageLayer.CLIENT_MEMORY,
        MemoryCategory.TEAM_CONTEXT: StorageLayer.TEAM_MEMORY,
        MemoryCategory.BUSINESS_CONTEXT: StorageLayer.LONG_TERM,
        MemoryCategory.TECHNICAL_CONTEXT: StorageLayer.PROJECT_MEMORY,
        MemoryCategory.TASK_CONTEXT: StorageLayer.SHORT_TERM,
        MemoryCategory.CONVERSATION_CONTEXT: StorageLayer.SHORT_TERM,
        MemoryCategory.KNOWLEDGE_FACT: StorageLayer.KNOWLEDGE_GRAPH,
        MemoryCategory.SECURITY_CONTEXT: StorageLayer.SECURITY_VAULT,
        MemoryCategory.FINANCIAL_CONTEXT: StorageLayer.REVIEW_QUEUE,
        MemoryCategory.CREATIVE_CONTEXT: StorageLayer.PROJECT_MEMORY,
        MemoryCategory.WORKFLOW_CONTEXT: StorageLayer.LONG_TERM,
        MemoryCategory.AGENT_CONFIGURATION: StorageLayer.LONG_TERM,
        MemoryCategory.SYSTEM_CONFIGURATION: StorageLayer.REVIEW_QUEUE,
        MemoryCategory.PERSONAL_CONTEXT: StorageLayer.REVIEW_QUEUE,
        MemoryCategory.TEMPORARY_NOTE: StorageLayer.SHORT_TERM,
        MemoryCategory.UNKNOWN: StorageLayer.SHORT_TERM,
    }

    RETENTION_BY_STORAGE: Dict[StorageLayer, RetentionPolicy] = {
        StorageLayer.NONE: RetentionPolicy.DO_NOT_STORE,
        StorageLayer.SHORT_TERM: RetentionPolicy.SESSION_ONLY,
        StorageLayer.LONG_TERM: RetentionPolicy.LONG_TERM,
        StorageLayer.PROJECT_MEMORY: RetentionPolicy.LONG_TERM,
        StorageLayer.CLIENT_MEMORY: RetentionPolicy.LONG_TERM,
        StorageLayer.TEAM_MEMORY: RetentionPolicy.DAYS_90,
        StorageLayer.PREFERENCE_MEMORY: RetentionPolicy.PERMANENT_UNTIL_USER_DELETES,
        StorageLayer.KNOWLEDGE_GRAPH: RetentionPolicy.LONG_TERM,
        StorageLayer.SECURITY_VAULT: RetentionPolicy.REVIEW_REQUIRED,
        StorageLayer.AUDIT_ONLY: RetentionPolicy.DAYS_90,
        StorageLayer.REVIEW_QUEUE: RetentionPolicy.REVIEW_REQUIRED,
    }

    def __init__(
        self,
        *,
        agent_name: str = DEFAULT_AGENT_NAME,
        agent_id: str = DEFAULT_AGENT_ID,
        security_approval_callback: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        event_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        audit_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        strict_context_validation: bool = True,
        default_workspace_required: bool = True,
        logger_instance: Optional[logging.Logger] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Initialize MemoryRouter.

        Args:
            agent_name:
                Human-readable agent name.

            agent_id:
                Registry/router-safe agent identifier.

            security_approval_callback:
                Optional callback used to request Security Agent approval.

            event_callback:
                Optional event callback for dashboards/registry.

            audit_callback:
                Optional audit callback for audit logs.

            strict_context_validation:
                If True, user-specific memory requires user_id and workspace_id.

            default_workspace_required:
                If True, workspace_id is required for all normal memory routing.

            logger_instance:
                Optional injected logger.

            config:
                Optional future config dictionary.
        """

        try:
            super().__init__(agent_name=agent_name, agent_id=agent_id)
        except TypeError:
            super().__init__()

        self.agent_name = agent_name
        self.agent_id = agent_id
        self.security_approval_callback = security_approval_callback
        self.event_callback = event_callback
        self.audit_callback = audit_callback
        self.strict_context_validation = strict_context_validation
        self.default_workspace_required = default_workspace_required
        self.config = config or {}
        self.logger = logger_instance or logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    # -----------------------------------------------------------------
    # Public Main API
    # -----------------------------------------------------------------

    def route_memory(
        self,
        content: str,
        *,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        source_agent: Optional[str] = None,
        source_event: Optional[str] = None,
        conversation_id: Optional[str] = None,
        task_id: Optional[str] = None,
        client_id: Optional[str] = None,
        project_id: Optional[str] = None,
        team_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        explicit_category: Optional[Union[str, MemoryCategory]] = None,
        explicit_privacy_level: Optional[Union[str, PrivacyLevel]] = None,
        explicit_storage_layer: Optional[Union[str, StorageLayer]] = None,
        explicit_importance: Optional[Union[int, float, str, ImportanceLabel]] = None,
        force_store: bool = False,
        dry_run: bool = True,
    ) -> Dict[str, Any]:
        """
        Route a single memory candidate.

        Returns:
            Structured result with route decision, memory payload,
            verification payload, and metadata.
        """

        route_input = MemoryRouteInput(
            content=content,
            user_id=user_id,
            workspace_id=workspace_id,
            source_agent=source_agent,
            source_event=source_event,
            conversation_id=conversation_id,
            task_id=task_id,
            client_id=client_id,
            project_id=project_id,
            team_id=team_id,
            metadata=metadata or {},
            explicit_category=explicit_category,
            explicit_privacy_level=explicit_privacy_level,
            explicit_storage_layer=explicit_storage_layer,
            explicit_importance=explicit_importance,
            force_store=force_store,
            dry_run=dry_run,
        )

        validation = self._validate_task_context(route_input)
        if not validation["success"]:
            self._log_audit_event(
                "memory_router.validation_failed",
                {
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "source_agent": source_agent,
                    "reason": validation.get("error", {}).get("message"),
                },
            )
            return validation

        normalized_content = self.normalize_content(content)
        if not normalized_content:
            return self._error_result(
                message="Memory content is empty after normalization.",
                code="EMPTY_MEMORY_CONTENT",
                metadata=self._base_metadata(route_input),
            )

        low_value = self._is_low_value_content(normalized_content)
        detected_entities = self.detect_entities(normalized_content)

        category = self.decide_category(
            normalized_content,
            explicit_category=explicit_category,
            metadata=metadata or {},
        )

        privacy_level = self.detect_privacy_level(
            normalized_content,
            explicit_privacy_level=explicit_privacy_level,
            detected_entities=detected_entities,
            category=category,
        )

        importance_score, importance_label, importance_reasons = self.score_importance(
            normalized_content,
            explicit_importance=explicit_importance,
            category=category,
            privacy_level=privacy_level,
            metadata=metadata or {},
        )

        storage_layer = self.choose_storage_layer(
            category=category,
            privacy_level=privacy_level,
            importance_label=importance_label,
            explicit_storage_layer=explicit_storage_layer,
            force_store=force_store,
            low_value=low_value,
        )

        retention_policy = self.determine_retention_policy(
            storage_layer=storage_layer,
            privacy_level=privacy_level,
            importance_label=importance_label,
            low_value=low_value,
        )

        requires_security_check = self._requires_security_check(
            privacy_level=privacy_level,
            category=category,
            storage_layer=storage_layer,
            detected_entities=detected_entities,
        )

        requires_user_approval = self._requires_user_approval(
            privacy_level=privacy_level,
            storage_layer=storage_layer,
            detected_entities=detected_entities,
            force_store=force_store,
        )

        reasons = []
        reasons.extend(importance_reasons)
        reasons.extend(self._build_route_reasons(category, privacy_level, storage_layer, low_value))

        decision = self._decide_memory_action(
            storage_layer=storage_layer,
            privacy_level=privacy_level,
            requires_security_check=requires_security_check,
            requires_user_approval=requires_user_approval,
            low_value=low_value,
            force_store=force_store,
        )

        should_store = decision == MemoryDecision.STORE

        decision_obj = MemoryRouteDecision(
            decision_id=self._new_id("memroute"),
            memory_id=self._new_id("mem"),
            category=category,
            privacy_level=privacy_level,
            storage_layer=storage_layer,
            importance_score=importance_score,
            importance_label=importance_label,
            retention_policy=retention_policy,
            decision=decision,
            should_store=should_store,
            requires_security_check=requires_security_check,
            requires_user_approval=requires_user_approval,
            requires_workspace_scope=True,
            reasons=reasons,
            detected_entities=detected_entities,
            normalized_content_hash=self.hash_content(normalized_content),
            created_at=self._utc_now(),
        )

        security_result = None
        if requires_security_check:
            security_result = self._request_security_approval(route_input, decision_obj)

        memory_payload = self._prepare_memory_payload(
            route_input=route_input,
            decision=decision_obj,
            normalized_content=normalized_content,
        )

        verification_payload = self._prepare_verification_payload(
            route_input=route_input,
            decision=decision_obj,
            memory_payload=memory_payload,
            security_result=security_result,
        )

        event_payload = {
            "decision_id": decision_obj.decision_id,
            "memory_id": decision_obj.memory_id,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "category": decision_obj.category.value,
            "privacy_level": decision_obj.privacy_level.value,
            "storage_layer": decision_obj.storage_layer.value,
            "decision": decision_obj.decision.value,
            "importance_score": decision_obj.importance_score,
            "importance_label": decision_obj.importance_label.value,
            "requires_security_check": decision_obj.requires_security_check,
            "dry_run": dry_run,
        }

        self._emit_agent_event("memory_router.routed", event_payload)
        self._log_audit_event("memory_router.route_memory", event_payload)

        return self._safe_result(
            message="Memory routing decision prepared successfully.",
            data={
                "decision": self._decision_to_dict(decision_obj),
                "memory_payload": memory_payload,
                "verification_payload": verification_payload,
                "security_result": security_result,
                "dry_run": dry_run,
            },
            metadata=self._base_metadata(route_input),
        )

    def route_batch(
        self,
        items: Sequence[Union[str, Dict[str, Any], MemoryRouteInput]],
        *,
        default_user_id: Optional[str] = None,
        default_workspace_id: Optional[str] = None,
        default_source_agent: Optional[str] = None,
        default_metadata: Optional[Dict[str, Any]] = None,
        dry_run: bool = True,
    ) -> Dict[str, Any]:
        """
        Route multiple memory candidates.

        Each item can be:
            - str
            - dict compatible with route_memory arguments
            - MemoryRouteInput
        """

        routed: List[Dict[str, Any]] = []
        errors: List[Dict[str, Any]] = []

        for index, item in enumerate(items):
            try:
                kwargs = self._normalize_batch_item(
                    item,
                    default_user_id=default_user_id,
                    default_workspace_id=default_workspace_id,
                    default_source_agent=default_source_agent,
                    default_metadata=default_metadata or {},
                    dry_run=dry_run,
                )
                result = self.route_memory(**kwargs)
                routed.append(
                    {
                        "index": index,
                        "success": result.get("success", False),
                        "result": result,
                    }
                )
            except Exception as exc:
                error = {
                    "index": index,
                    "error": str(exc),
                    "error_type": exc.__class__.__name__,
                }
                errors.append(error)
                self.logger.exception("Failed to route batch memory item at index %s", index)

        success_count = sum(1 for item in routed if item.get("success"))
        failure_count = len(items) - success_count

        return self._safe_result(
            message="Batch memory routing completed.",
            data={
                "total": len(items),
                "success_count": success_count,
                "failure_count": failure_count,
                "items": routed,
                "errors": errors,
            },
            metadata={
                "agent": self.agent_name,
                "agent_id": self.agent_id,
                "version": self.VERSION,
                "dry_run": dry_run,
                "created_at": self._utc_now(),
            },
        )

    # -----------------------------------------------------------------
    # Public Classification Methods
    # -----------------------------------------------------------------

    def decide_category(
        self,
        content: str,
        *,
        explicit_category: Optional[Union[str, MemoryCategory]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> MemoryCategory:
        """
        Decide memory category using explicit override, metadata hints, and
        keyword scoring.
        """

        if explicit_category:
            return self._safe_enum(explicit_category, MemoryCategory, MemoryCategory.UNKNOWN)

        metadata = metadata or {}
        metadata_category = metadata.get("category") or metadata.get("memory_category")
        if metadata_category:
            return self._safe_enum(metadata_category, MemoryCategory, MemoryCategory.UNKNOWN)

        normalized = self.normalize_content(content).lower()
        scores: Dict[MemoryCategory, int] = {}

        for category, keywords in self.CATEGORY_KEYWORDS.items():
            score = 0
            for keyword in keywords:
                if keyword in normalized:
                    score += 3 if " " in keyword else 1
            if score:
                scores[category] = score

        if not scores:
            if self._looks_like_code_or_path(normalized):
                return MemoryCategory.TECHNICAL_CONTEXT
            if self._looks_like_business_copy(normalized):
                return MemoryCategory.BUSINESS_CONTEXT
            return MemoryCategory.UNKNOWN

        return max(scores.items(), key=lambda item: item[1])[0]

    def detect_privacy_level(
        self,
        content: str,
        *,
        explicit_privacy_level: Optional[Union[str, PrivacyLevel]] = None,
        detected_entities: Optional[Dict[str, Any]] = None,
        category: Optional[MemoryCategory] = None,
    ) -> PrivacyLevel:
        """
        Detect privacy level.

        Restricted patterns win over all other levels.
        """

        if explicit_privacy_level:
            return self._safe_enum(explicit_privacy_level, PrivacyLevel, PrivacyLevel.PRIVATE)

        normalized = self.normalize_content(content)
        lower_content = normalized.lower()
        detected_entities = detected_entities or self.detect_entities(normalized)

        for level in (
            PrivacyLevel.RESTRICTED,
            PrivacyLevel.CONFIDENTIAL,
            PrivacyLevel.PRIVATE,
            PrivacyLevel.INTERNAL,
            PrivacyLevel.PUBLIC,
        ):
            patterns = self.PRIVACY_PATTERNS.get(level, ())
            for pattern in patterns:
                if re.search(pattern, lower_content, flags=re.IGNORECASE):
                    return level

        if detected_entities.get("secret_like"):
            return PrivacyLevel.RESTRICTED

        if detected_entities.get("email") or detected_entities.get("phone"):
            return PrivacyLevel.PRIVATE

        if category in {
            MemoryCategory.CLIENT_CONTEXT,
            MemoryCategory.FINANCIAL_CONTEXT,
            MemoryCategory.SECURITY_CONTEXT,
            MemoryCategory.SYSTEM_CONFIGURATION,
        }:
            return PrivacyLevel.CONFIDENTIAL

        if category in {
            MemoryCategory.PROJECT_CONTEXT,
            MemoryCategory.TEAM_CONTEXT,
            MemoryCategory.BUSINESS_CONTEXT,
            MemoryCategory.TECHNICAL_CONTEXT,
            MemoryCategory.WORKFLOW_CONTEXT,
            MemoryCategory.AGENT_CONFIGURATION,
        }:
            return PrivacyLevel.INTERNAL

        return PrivacyLevel.INTERNAL

    def score_importance(
        self,
        content: str,
        *,
        explicit_importance: Optional[Union[int, float, str, ImportanceLabel]] = None,
        category: Optional[MemoryCategory] = None,
        privacy_level: Optional[PrivacyLevel] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[float, ImportanceLabel, List[str]]:
        """
        Return importance score from 0.0 to 1.0, label, and reasons.
        """

        reasons: List[str] = []
        metadata = metadata or {}

        explicit_score = self._parse_explicit_importance(explicit_importance)
        if explicit_score is not None:
            label = self._importance_label(explicit_score)
            return explicit_score, label, [f"Explicit importance set to {label.value}."]

        normalized = self.normalize_content(content).lower()
        score = 0.15

        word_count = len(normalized.split())
        if word_count >= 20:
            score += 0.08
            reasons.append("Content has enough detail to be useful.")
        if word_count >= 60:
            score += 0.08
            reasons.append("Content is detailed and context-rich.")

        for keyword in self.HIGH_IMPORTANCE_KEYWORDS:
            if keyword in normalized:
                score += 0.08 if " " in keyword else 0.04
                reasons.append(f"Contains high-importance signal: {keyword}")

        if category in {
            MemoryCategory.USER_PREFERENCE,
            MemoryCategory.PROJECT_CONTEXT,
            MemoryCategory.CLIENT_CONTEXT,
            MemoryCategory.BUSINESS_CONTEXT,
            MemoryCategory.AGENT_CONFIGURATION,
            MemoryCategory.SYSTEM_CONFIGURATION,
        }:
            score += 0.18
            reasons.append(f"Category {category.value if category else 'unknown'} is usually important.")

        if category in {
            MemoryCategory.TASK_CONTEXT,
            MemoryCategory.TEMPORARY_NOTE,
            MemoryCategory.CONVERSATION_CONTEXT,
        }:
            score += 0.03
            reasons.append("Category is useful but may be short-term.")

        if privacy_level in {PrivacyLevel.CONFIDENTIAL, PrivacyLevel.RESTRICTED}:
            score += 0.08
            reasons.append("Sensitive content needs careful tracking.")

        if metadata.get("pinned") is True:
            score += 0.25
            reasons.append("Metadata marks memory as pinned.")

        if metadata.get("source") in {"user_directive", "system_rule", "project_rule"}:
            score += 0.20
            reasons.append("Metadata source indicates a durable rule.")

        if self._is_low_value_content(normalized):
            score = min(score, 0.20)
            reasons.append("Content appears low-value or conversational only.")

        score = max(0.0, min(round(score, 3), 1.0))
        label = self._importance_label(score)

        if not reasons:
            reasons.append("Importance estimated from content length and category.")

        return score, label, reasons

    def choose_storage_layer(
        self,
        *,
        category: MemoryCategory,
        privacy_level: PrivacyLevel,
        importance_label: ImportanceLabel,
        explicit_storage_layer: Optional[Union[str, StorageLayer]] = None,
        force_store: bool = False,
        low_value: bool = False,
    ) -> StorageLayer:
        """
        Choose recommended storage layer.

        Restricted content goes to review/security handling unless explicitly
        forced. Even then, this router recommends a secure layer.
        """

        if explicit_storage_layer:
            layer = self._safe_enum(explicit_storage_layer, StorageLayer, StorageLayer.REVIEW_QUEUE)
            if privacy_level == PrivacyLevel.RESTRICTED and layer not in {
                StorageLayer.SECURITY_VAULT,
                StorageLayer.REVIEW_QUEUE,
                StorageLayer.AUDIT_ONLY,
                StorageLayer.NONE,
            }:
                return StorageLayer.REVIEW_QUEUE
            return layer

        if low_value and not force_store:
            return StorageLayer.NONE

        if privacy_level == PrivacyLevel.RESTRICTED:
            return StorageLayer.REVIEW_QUEUE

        if privacy_level == PrivacyLevel.CONFIDENTIAL and category in {
            MemoryCategory.SECURITY_CONTEXT,
            MemoryCategory.FINANCIAL_CONTEXT,
            MemoryCategory.SYSTEM_CONFIGURATION,
            MemoryCategory.PERSONAL_CONTEXT,
        }:
            return StorageLayer.REVIEW_QUEUE

        layer = self.STORAGE_BY_CATEGORY.get(category, StorageLayer.SHORT_TERM)

        if importance_label == ImportanceLabel.LOW and layer in {
            StorageLayer.LONG_TERM,
            StorageLayer.KNOWLEDGE_GRAPH,
        }:
            return StorageLayer.SHORT_TERM

        return layer

    def determine_retention_policy(
        self,
        *,
        storage_layer: StorageLayer,
        privacy_level: PrivacyLevel,
        importance_label: ImportanceLabel,
        low_value: bool = False,
    ) -> RetentionPolicy:
        """
        Determine retention policy.
        """

        if low_value:
            return RetentionPolicy.DO_NOT_STORE

        if privacy_level == PrivacyLevel.RESTRICTED:
            return RetentionPolicy.REVIEW_REQUIRED

        if storage_layer == StorageLayer.REVIEW_QUEUE:
            return RetentionPolicy.REVIEW_REQUIRED

        if storage_layer == StorageLayer.SECURITY_VAULT:
            return RetentionPolicy.REVIEW_REQUIRED

        if importance_label == ImportanceLabel.CRITICAL and storage_layer != StorageLayer.NONE:
            return RetentionPolicy.PERMANENT_UNTIL_USER_DELETES

        return self.RETENTION_BY_STORAGE.get(storage_layer, RetentionPolicy.SESSION_ONLY)

    def should_store_memory(
        self,
        content: str,
        *,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Lightweight helper to check whether memory should be stored.
        """

        result = self.route_memory(
            content,
            user_id=user_id,
            workspace_id=workspace_id,
            metadata=metadata or {},
            dry_run=True,
        )

        if not result.get("success"):
            return result

        decision = result.get("data", {}).get("decision", {})
        return self._safe_result(
            message="Memory storage recommendation prepared.",
            data={
                "should_store": decision.get("should_store", False),
                "decision": decision.get("decision"),
                "storage_layer": decision.get("storage_layer"),
                "privacy_level": decision.get("privacy_level"),
                "importance_label": decision.get("importance_label"),
                "requires_security_check": decision.get("requires_security_check"),
                "requires_user_approval": decision.get("requires_user_approval"),
                "reasons": decision.get("reasons", []),
            },
            metadata={
                "agent": self.agent_name,
                "agent_id": self.agent_id,
                "version": self.VERSION,
                "created_at": self._utc_now(),
            },
        )

    def build_memory_record(
        self,
        content: str,
        *,
        user_id: str,
        workspace_id: str,
        source_agent: Optional[str] = None,
        source_event: Optional[str] = None,
        conversation_id: Optional[str] = None,
        task_id: Optional[str] = None,
        client_id: Optional[str] = None,
        project_id: Optional[str] = None,
        team_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        dry_run: bool = True,
    ) -> Dict[str, Any]:
        """
        Build a storage-ready memory record without writing it.
        """

        result = self.route_memory(
            content,
            user_id=user_id,
            workspace_id=workspace_id,
            source_agent=source_agent,
            source_event=source_event,
            conversation_id=conversation_id,
            task_id=task_id,
            client_id=client_id,
            project_id=project_id,
            team_id=team_id,
            metadata=metadata or {},
            dry_run=dry_run,
        )

        if not result.get("success"):
            return result

        return self._safe_result(
            message="Storage-ready memory record prepared.",
            data={
                "record": result.get("data", {}).get("memory_payload"),
                "decision": result.get("data", {}).get("decision"),
                "verification_payload": result.get("data", {}).get("verification_payload"),
            },
            metadata=result.get("metadata", {}),
        )

    # -----------------------------------------------------------------
    # Normalization and Detection
    # -----------------------------------------------------------------

    def normalize_content(self, content: Any) -> str:
        """
        Normalize memory content for classification.

        Keeps the original meaning while removing excessive whitespace.
        """

        if content is None:
            return ""

        text = str(content)
        text = text.replace("\u0000", "")
        text = re.sub(r"\s+", " ", text).strip()
        return text

    def hash_content(self, content: str) -> str:
        """
        Hash normalized content for deduplication and safe references.
        """

        normalized = self.normalize_content(content)
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    def detect_entities(self, content: str) -> Dict[str, Any]:
        """
        Detect simple entities that influence privacy and routing.

        This does not expose raw secrets in audit logs. It returns counts and
        safe samples for low-risk entities.
        """

        normalized = self.normalize_content(content)
        entities: Dict[str, Any] = {}

        for entity_name, pattern in self.ENTITY_PATTERNS.items():
            matches = re.findall(pattern, normalized, flags=re.IGNORECASE)
            if matches:
                safe_values = []
                for match in matches[:5]:
                    value = match if isinstance(match, str) else " ".join(match)
                    safe_values.append(self._safe_entity_sample(entity_name, value))
                entities[entity_name] = {
                    "count": len(matches),
                    "samples": safe_values,
                }

        return entities

    # -----------------------------------------------------------------
    # Compatibility Hooks
    # -----------------------------------------------------------------

    def _validate_task_context(self, route_input: MemoryRouteInput) -> Dict[str, Any]:
        """
        Validate SaaS user/workspace isolation.

        Rules:
            - Content must be present.
            - If strict validation is enabled, user_id and workspace_id are
              required.
            - Prevent ambiguous storage scope.
        """

        if not self.normalize_content(route_input.content):
            return self._error_result(
                message="Content is required for memory routing.",
                code="MISSING_CONTENT",
                metadata=self._base_metadata(route_input),
            )

        if self.strict_context_validation:
            if not route_input.user_id:
                return self._error_result(
                    message="user_id is required for MemoryRouter to prevent cross-user memory mixing.",
                    code="MISSING_USER_ID",
                    metadata=self._base_metadata(route_input),
                )

            if self.default_workspace_required and not route_input.workspace_id:
                return self._error_result(
                    message="workspace_id is required for MemoryRouter to prevent cross-workspace memory mixing.",
                    code="MISSING_WORKSPACE_ID",
                    metadata=self._base_metadata(route_input),
                )

        if route_input.user_id and not self._is_safe_identifier(route_input.user_id):
            return self._error_result(
                message="Invalid user_id format.",
                code="INVALID_USER_ID",
                metadata=self._base_metadata(route_input),
            )

        if route_input.workspace_id and not self._is_safe_identifier(route_input.workspace_id):
            return self._error_result(
                message="Invalid workspace_id format.",
                code="INVALID_WORKSPACE_ID",
                metadata=self._base_metadata(route_input),
            )

        return self._safe_result(
            message="Task context validated.",
            data={"valid": True},
            metadata=self._base_metadata(route_input),
        )

    def _requires_security_check(
        self,
        *,
        privacy_level: PrivacyLevel,
        category: MemoryCategory,
        storage_layer: StorageLayer,
        detected_entities: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Decide if Security Agent review is needed.
        """

        detected_entities = detected_entities or {}

        if privacy_level in {PrivacyLevel.CONFIDENTIAL, PrivacyLevel.RESTRICTED}:
            return True

        if category in {
            MemoryCategory.SECURITY_CONTEXT,
            MemoryCategory.FINANCIAL_CONTEXT,
            MemoryCategory.SYSTEM_CONFIGURATION,
        }:
            return True

        if storage_layer in {
            StorageLayer.SECURITY_VAULT,
            StorageLayer.REVIEW_QUEUE,
        }:
            return True

        if detected_entities.get("secret_like"):
            return True

        return False

    def _request_security_approval(
        self,
        route_input: MemoryRouteInput,
        decision: MemoryRouteDecision,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        If a callback is injected, call it. Otherwise return a structured
        pending approval result. This keeps import/runtime safe before
        Security Agent exists.
        """

        request_payload = {
            "request_id": self._new_id("secapproval"),
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "action": "memory_route_security_review",
            "user_id": route_input.user_id,
            "workspace_id": route_input.workspace_id,
            "decision_id": decision.decision_id,
            "memory_id": decision.memory_id,
            "category": decision.category.value,
            "privacy_level": decision.privacy_level.value,
            "storage_layer": decision.storage_layer.value,
            "detected_entities": decision.detected_entities,
            "created_at": self._utc_now(),
        }

        if self.security_approval_callback:
            try:
                response = self.security_approval_callback(request_payload)
                if isinstance(response, dict):
                    return response
                return {
                    "success": False,
                    "status": "invalid_security_callback_response",
                    "request": request_payload,
                }
            except Exception as exc:
                self.logger.exception("Security approval callback failed.")
                return {
                    "success": False,
                    "status": "security_callback_error",
                    "error": {
                        "type": exc.__class__.__name__,
                        "message": str(exc),
                    },
                    "request": request_payload,
                }

        return {
            "success": True,
            "status": "review_pending",
            "message": "Security review required. No Security Agent callback is connected yet.",
            "request": request_payload,
        }

    def _prepare_verification_payload(
        self,
        *,
        route_input: MemoryRouteInput,
        decision: MemoryRouteDecision,
        memory_payload: Dict[str, Any],
        security_result: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        Verification Agent can use this to confirm:
            - Scope isolation
            - Storage recommendation
            - Privacy/security handling
            - Memory integrity
        """

        return {
            "verification_id": self._new_id("verify"),
            "type": "memory_route_verification",
            "source_agent": self.agent_name,
            "source_agent_id": self.agent_id,
            "user_id": route_input.user_id,
            "workspace_id": route_input.workspace_id,
            "conversation_id": route_input.conversation_id,
            "task_id": route_input.task_id,
            "decision_id": decision.decision_id,
            "memory_id": decision.memory_id,
            "checks": {
                "has_user_scope": bool(route_input.user_id),
                "has_workspace_scope": bool(route_input.workspace_id),
                "category_selected": decision.category != MemoryCategory.UNKNOWN,
                "privacy_level_selected": bool(decision.privacy_level),
                "storage_layer_selected": bool(decision.storage_layer),
                "security_check_required": decision.requires_security_check,
                "security_result_attached": security_result is not None,
                "content_hash_present": bool(decision.normalized_content_hash),
                "dry_run": route_input.dry_run,
            },
            "decision": self._decision_to_dict(decision),
            "memory_payload_preview": {
                "memory_id": memory_payload.get("memory_id"),
                "category": memory_payload.get("category"),
                "privacy_level": memory_payload.get("privacy_level"),
                "storage_layer": memory_payload.get("storage_layer"),
                "content_hash": memory_payload.get("content_hash"),
                "should_store": memory_payload.get("should_store"),
            },
            "security_result": security_result,
            "created_at": self._utc_now(),
        }

    def _prepare_memory_payload(
        self,
        *,
        route_input: MemoryRouteInput,
        decision: MemoryRouteDecision,
        normalized_content: str,
    ) -> Dict[str, Any]:
        """
        Prepare storage-ready memory payload.

        This payload can be consumed by:
            - short_term.py
            - long_term.py
            - project_memory.py
            - client_memory.py
            - team_memory.py
            - preference_manager.py
            - knowledge_graph.py
            - memory_backup.py
            - memory_sync.py
        """

        return {
            "memory_id": decision.memory_id,
            "decision_id": decision.decision_id,
            "user_id": route_input.user_id,
            "workspace_id": route_input.workspace_id,
            "client_id": route_input.client_id,
            "project_id": route_input.project_id,
            "team_id": route_input.team_id,
            "conversation_id": route_input.conversation_id,
            "task_id": route_input.task_id,
            "source_agent": route_input.source_agent,
            "source_event": route_input.source_event,
            "content": normalized_content,
            "content_hash": decision.normalized_content_hash,
            "category": decision.category.value,
            "privacy_level": decision.privacy_level.value,
            "storage_layer": decision.storage_layer.value,
            "importance_score": decision.importance_score,
            "importance_label": decision.importance_label.value,
            "retention_policy": decision.retention_policy.value,
            "decision": decision.decision.value,
            "should_store": decision.should_store,
            "requires_security_check": decision.requires_security_check,
            "requires_user_approval": decision.requires_user_approval,
            "detected_entities": decision.detected_entities,
            "reasons": decision.reasons,
            "metadata": {
                **(route_input.metadata or {}),
                "router_agent": self.agent_name,
                "router_agent_id": self.agent_id,
                "router_version": self.VERSION,
                "dry_run": route_input.dry_run,
            },
            "created_at": decision.created_at,
            "updated_at": decision.created_at,
        }

    def _emit_agent_event(self, event_name: str, payload: Dict[str, Any]) -> None:
        """
        Emit an agent event for Dashboard/API/Registry.

        Safe fallback:
            - Calls injected callback if available.
            - Calls BaseAgent emit_event if present.
            - Logs debug only if neither is available.
        """

        safe_payload = self._sanitize_event_payload(payload)

        try:
            if self.event_callback:
                self.event_callback(event_name, safe_payload)
                return
        except Exception:
            self.logger.exception("MemoryRouter event callback failed.")

        try:
            emit_event = getattr(super(), "emit_event", None)
            if callable(emit_event):
                emit_event(event_name, safe_payload)
                return
        except Exception:
            self.logger.debug("BaseAgent emit_event unavailable.", exc_info=True)

        self.logger.debug("Agent event: %s | %s", event_name, safe_payload)

    def _log_audit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
        """
        Log audit event.

        This method avoids logging raw content or secrets.
        """

        safe_payload = self._sanitize_event_payload(payload)

        try:
            if self.audit_callback:
                self.audit_callback(event_name, safe_payload)
                return
        except Exception:
            self.logger.exception("MemoryRouter audit callback failed.")

        try:
            log_audit = getattr(super(), "log_audit", None)
            if callable(log_audit):
                log_audit(event_name, safe_payload)
                return
        except Exception:
            self.logger.debug("BaseAgent log_audit unavailable.", exc_info=True)

        self.logger.info("Audit event: %s | %s", event_name, safe_payload)

    def _safe_result(
        self,
        *,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard success result.
        """

        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": metadata or {
                "agent": self.agent_name,
                "agent_id": self.agent_id,
                "version": self.VERSION,
                "created_at": self._utc_now(),
            },
        }

    def _error_result(
        self,
        *,
        message: str,
        code: str = "MEMORY_ROUTER_ERROR",
        details: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard error result.
        """

        return {
            "success": False,
            "message": message,
            "data": {},
            "error": {
                "code": code,
                "message": message,
                "details": details or {},
            },
            "metadata": metadata or {
                "agent": self.agent_name,
                "agent_id": self.agent_id,
                "version": self.VERSION,
                "created_at": self._utc_now(),
            },
        }

    # -----------------------------------------------------------------
    # Internal Decision Helpers
    # -----------------------------------------------------------------

    def _decide_memory_action(
        self,
        *,
        storage_layer: StorageLayer,
        privacy_level: PrivacyLevel,
        requires_security_check: bool,
        requires_user_approval: bool,
        low_value: bool,
        force_store: bool,
    ) -> MemoryDecision:
        """
        Decide final action.
        """

        if storage_layer == StorageLayer.NONE:
            if force_store and not low_value:
                return MemoryDecision.REVIEW_BEFORE_STORE
            return MemoryDecision.DO_NOT_STORE

        if storage_layer == StorageLayer.AUDIT_ONLY:
            return MemoryDecision.AUDIT_ONLY

        if privacy_level == PrivacyLevel.RESTRICTED:
            return MemoryDecision.REVIEW_BEFORE_STORE

        if requires_security_check or requires_user_approval:
            return MemoryDecision.REVIEW_BEFORE_STORE

        if low_value and not force_store:
            return MemoryDecision.DO_NOT_STORE

        return MemoryDecision.STORE

    def _requires_user_approval(
        self,
        *,
        privacy_level: PrivacyLevel,
        storage_layer: StorageLayer,
        detected_entities: Dict[str, Any],
        force_store: bool = False,
    ) -> bool:
        """
        Decide if user approval should be requested before storage.
        """

        if force_store:
            return False

        if privacy_level in {PrivacyLevel.PRIVATE, PrivacyLevel.CONFIDENTIAL, PrivacyLevel.RESTRICTED}:
            return True

        if storage_layer in {StorageLayer.REVIEW_QUEUE, StorageLayer.SECURITY_VAULT}:
            return True

        if detected_entities.get("email") or detected_entities.get("phone"):
            return True

        return False

    def _build_route_reasons(
        self,
        category: MemoryCategory,
        privacy_level: PrivacyLevel,
        storage_layer: StorageLayer,
        low_value: bool,
    ) -> List[str]:
        """
        Human-readable route reasons.
        """

        reasons = [
            f"Category selected: {category.value}.",
            f"Privacy level selected: {privacy_level.value}.",
            f"Storage layer recommended: {storage_layer.value}.",
        ]

        if low_value:
            reasons.append("Content appears low-value and is not recommended for storage.")

        if privacy_level == PrivacyLevel.RESTRICTED:
            reasons.append("Restricted content requires review before storage.")

        if storage_layer == StorageLayer.REVIEW_QUEUE:
            reasons.append("Memory should enter review queue before persistence.")

        return reasons

    def _is_low_value_content(self, content: str) -> bool:
        """
        Detect content that is unlikely to be useful as memory.
        """

        normalized = self.normalize_content(content).lower()

        if not normalized:
            return True

        if len(normalized) < 3:
            return True

        for pattern in self.LOW_VALUE_PATTERNS:
            if re.match(pattern, normalized, flags=re.IGNORECASE):
                return True

        return False

    def _looks_like_code_or_path(self, content: str) -> bool:
        """
        Detect technical/code-like memory.
        """

        technical_signals = (
            ".py",
            ".js",
            ".ts",
            ".php",
            ".html",
            "def ",
            "class ",
            "import ",
            "from ",
            "function ",
            "docker",
            "api",
            "endpoint",
            "traceback",
            "exception",
        )
        return any(signal in content for signal in technical_signals)

    def _looks_like_business_copy(self, content: str) -> bool:
        """
        Detect sales/marketing/business context.
        """

        business_signals = (
            "seo",
            "ppc",
            "lead",
            "client",
            "sales",
            "offer",
            "service",
            "conversion",
            "marketing",
            "agency",
            "proposal",
            "package",
        )
        return any(signal in content for signal in business_signals)

    def _importance_label(self, score: float) -> ImportanceLabel:
        """
        Convert numeric score to label.
        """

        if score >= 0.82:
            return ImportanceLabel.CRITICAL
        if score >= 0.62:
            return ImportanceLabel.HIGH
        if score >= 0.35:
            return ImportanceLabel.MEDIUM
        return ImportanceLabel.LOW

    def _parse_explicit_importance(
        self,
        explicit_importance: Optional[Union[int, float, str, ImportanceLabel]],
    ) -> Optional[float]:
        """
        Normalize explicit importance into score.
        """

        if explicit_importance is None:
            return None

        if isinstance(explicit_importance, ImportanceLabel):
            return {
                ImportanceLabel.LOW: 0.20,
                ImportanceLabel.MEDIUM: 0.45,
                ImportanceLabel.HIGH: 0.72,
                ImportanceLabel.CRITICAL: 0.92,
            }[explicit_importance]

        if isinstance(explicit_importance, (int, float)):
            value = float(explicit_importance)
            if value > 1:
                value = value / 100.0
            return max(0.0, min(round(value, 3), 1.0))

        if isinstance(explicit_importance, str):
            normalized = explicit_importance.strip().lower()
            mapping = {
                "low": 0.20,
                "medium": 0.45,
                "normal": 0.45,
                "high": 0.72,
                "critical": 0.92,
                "urgent": 0.90,
            }
            if normalized in mapping:
                return mapping[normalized]
            try:
                numeric = float(normalized)
                if numeric > 1:
                    numeric = numeric / 100.0
                return max(0.0, min(round(numeric, 3), 1.0))
            except ValueError:
                return None

        return None

    # -----------------------------------------------------------------
    # Utility Helpers
    # -----------------------------------------------------------------

    def _normalize_batch_item(
        self,
        item: Union[str, Dict[str, Any], MemoryRouteInput],
        *,
        default_user_id: Optional[str],
        default_workspace_id: Optional[str],
        default_source_agent: Optional[str],
        default_metadata: Dict[str, Any],
        dry_run: bool,
    ) -> Dict[str, Any]:
        """
        Normalize batch item into route_memory kwargs.
        """

        if isinstance(item, MemoryRouteInput):
            payload = asdict(item)
            payload.setdefault("user_id", default_user_id)
            payload.setdefault("workspace_id", default_workspace_id)
            payload.setdefault("source_agent", default_source_agent)
            payload["metadata"] = {
                **default_metadata,
                **(payload.get("metadata") or {}),
            }
            payload["dry_run"] = dry_run if payload.get("dry_run") is None else payload["dry_run"]
            return payload

        if isinstance(item, str):
            return {
                "content": item,
                "user_id": default_user_id,
                "workspace_id": default_workspace_id,
                "source_agent": default_source_agent,
                "metadata": default_metadata,
                "dry_run": dry_run,
            }

        if isinstance(item, dict):
            payload = dict(item)
            payload.setdefault("user_id", default_user_id)
            payload.setdefault("workspace_id", default_workspace_id)
            payload.setdefault("source_agent", default_source_agent)
            payload["metadata"] = {
                **default_metadata,
                **(payload.get("metadata") or {}),
            }
            payload.setdefault("dry_run", dry_run)

            if "content" not in payload:
                raise ValueError("Batch memory item dict must include 'content'.")

            return payload

        raise TypeError(f"Unsupported batch memory item type: {type(item).__name__}")

    def _safe_enum(
        self,
        value: Union[str, Enum],
        enum_class: Any,
        default: Any,
    ) -> Any:
        """
        Safely convert string/enum to target enum.
        """

        if isinstance(value, enum_class):
            return value

        if isinstance(value, str):
            normalized = value.strip().lower()
            for member in enum_class:
                if normalized == member.value.lower() or normalized == member.name.lower():
                    return member

        return default

    def _decision_to_dict(self, decision: MemoryRouteDecision) -> Dict[str, Any]:
        """
        Convert decision dataclass to JSON-safe dict.
        """

        data = asdict(decision)
        data["category"] = decision.category.value
        data["privacy_level"] = decision.privacy_level.value
        data["storage_layer"] = decision.storage_layer.value
        data["importance_label"] = decision.importance_label.value
        data["retention_policy"] = decision.retention_policy.value
        data["decision"] = decision.decision.value
        return data

    def _base_metadata(self, route_input: Optional[MemoryRouteInput] = None) -> Dict[str, Any]:
        """
        Base metadata for all structured results.
        """

        metadata = {
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "version": self.VERSION,
            "created_at": self._utc_now(),
        }

        if route_input:
            metadata.update(
                {
                    "user_id": route_input.user_id,
                    "workspace_id": route_input.workspace_id,
                    "conversation_id": route_input.conversation_id,
                    "task_id": route_input.task_id,
                    "source_agent": route_input.source_agent,
                    "dry_run": route_input.dry_run,
                }
            )

        return metadata

    def _sanitize_event_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Remove raw content and redact sensitive-looking values before logging.
        """

        sanitized: Dict[str, Any] = {}

        for key, value in payload.items():
            lowered = key.lower()

            if lowered in {"content", "raw_content", "text", "message"}:
                sanitized[key] = "[REDACTED_CONTENT]"
                continue

            if any(secret_key in lowered for secret_key in ("password", "secret", "token", "api_key", "private_key")):
                sanitized[key] = "[REDACTED_SECRET]"
                continue

            if isinstance(value, dict):
                sanitized[key] = self._sanitize_event_payload(value)
            elif isinstance(value, list):
                sanitized[key] = [
                    self._sanitize_event_payload(item) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                sanitized[key] = value

        return sanitized

    def _safe_entity_sample(self, entity_name: str, value: str) -> str:
        """
        Return safe sample for entity previews.
        """

        if entity_name in {"secret_like"}:
            return "[REDACTED_SECRET_LIKE]"

        if entity_name == "email":
            parts = value.split("@")
            if len(parts) == 2:
                name = parts[0]
                domain = parts[1]
                return f"{name[:2]}***@{domain}"
            return "[REDACTED_EMAIL]"

        if entity_name == "phone":
            digits = re.sub(r"\D", "", value)
            if len(digits) >= 4:
                return f"***{digits[-4:]}"
            return "[REDACTED_PHONE]"

        if len(value) > 80:
            return f"{value[:77]}..."

        return value

    def _is_safe_identifier(self, value: str) -> bool:
        """
        Validate safe SaaS identifiers.

        Allows UUIDs, slugs, database IDs, and simple external IDs.
        """

        return bool(re.match(r"^[a-zA-Z0-9_\-:.@]{1,128}$", value))

    def _utc_now(self) -> str:
        """
        UTC timestamp.
        """

        return datetime.now(timezone.utc).isoformat()

    def _new_id(self, prefix: str) -> str:
        """
        Generate stable-style unique ID.
        """

        return f"{prefix}_{uuid.uuid4().hex}"

    # -----------------------------------------------------------------
    # Registry / Health Helpers
    # -----------------------------------------------------------------

    def get_agent_manifest(self) -> Dict[str, Any]:
        """
        Return registry-compatible manifest.
        """

        return {
            "agent_name": self.agent_name,
            "agent_id": self.agent_id,
            "module": "agents.memory_agent.memory_router",
            "class": self.__class__.__name__,
            "version": self.VERSION,
            "capabilities": [
                "memory_category_routing",
                "memory_importance_scoring",
                "memory_privacy_detection",
                "memory_storage_layer_selection",
                "memory_retention_policy_recommendation",
                "security_review_flagging",
                "verification_payload_generation",
                "saas_scope_validation",
            ],
            "requires": {
                "user_id": self.strict_context_validation,
                "workspace_id": self.default_workspace_required,
            },
            "safe_to_import": True,
            "writes_to_storage": False,
            "created_at": self._utc_now(),
        }

    def health_check(self) -> Dict[str, Any]:
        """
        Lightweight health check for dashboard/API.
        """

        return self._safe_result(
            message="MemoryRouter is healthy.",
            data={
                "agent_name": self.agent_name,
                "agent_id": self.agent_id,
                "version": self.VERSION,
                "strict_context_validation": self.strict_context_validation,
                "default_workspace_required": self.default_workspace_required,
                "category_count": len(MemoryCategory),
                "privacy_level_count": len(PrivacyLevel),
                "storage_layer_count": len(StorageLayer),
                "has_security_callback": self.security_approval_callback is not None,
                "has_event_callback": self.event_callback is not None,
                "has_audit_callback": self.audit_callback is not None,
            },
            metadata={
                "agent": self.agent_name,
                "agent_id": self.agent_id,
                "version": self.VERSION,
                "created_at": self._utc_now(),
            },
        )


# ---------------------------------------------------------------------
# Optional Standalone Smoke Test
# ---------------------------------------------------------------------

def _smoke_test() -> Dict[str, Any]:
    """
    Internal smoke test.

    This does not run automatically unless this file is executed directly.
    """

    router = MemoryRouter(strict_context_validation=True)
    return router.route_memory(
        "Remember that this project must always keep user_id and workspace_id isolated.",
        user_id="user_demo",
        workspace_id="workspace_demo",
        source_agent="memory_agent",
        source_event="smoke_test",
        metadata={"source": "project_rule"},
        dry_run=True,
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    result = _smoke_test()
    print(result)


# FILE COMPLETE