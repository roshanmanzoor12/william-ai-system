"""
agents/memory_agent/privacy_guard.py

MemoryPrivacyGuard for William / Jarvis Multi-Agent AI SaaS System.

Purpose:
    Blocks sensitive memory storage, approval flows, forget/export controls.

This file is designed to be:
    - Production-ready
    - Import-safe
    - SaaS isolation compatible
    - BaseAgent compatible
    - Master Agent / Agent Registry compatible
    - Security Agent approval compatible
    - Verification Agent payload compatible
    - FastAPI/dashboard ready

Architecture connections:
    - Master Agent:
        Routes memory privacy tasks here before memory storage, export, or deletion.
    - Memory Agent:
        Calls this guard before storing, updating, exporting, or forgetting memory.
    - Security Agent:
        Receives approval payloads for sensitive or destructive actions.
    - Verification Agent:
        Receives verification payloads after privacy decisions.
    - Dashboard/API:
        Can expose public methods as service endpoints later.
    - Registry/Loader:
        Can safely import this file even if BaseAgent or other William modules
        are not available yet.
"""

from __future__ import annotations

import copy
import dataclasses
import enum
import hashlib
import json
import logging
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Safe optional imports / fallback stubs
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for early build stages
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        Keeps this file import-safe when the full William/Jarvis agent framework
        has not been generated yet.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
            return {
                "success": True,
                "message": "Fallback event emitted.",
                "data": {
                    "event_name": event_name,
                    "payload": payload,
                },
                "error": None,
                "metadata": {
                    "fallback": True,
                },
            }


try:
    from agents.security_agent.security_agent import SecurityAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for early build stages
    SecurityAgent = None  # type: ignore


try:
    from agents.verification_agent.verification_agent import VerificationAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for early build stages
    VerificationAgent = None  # type: ignore


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
if not logger.handlers:
    logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Enums / Data Structures
# ---------------------------------------------------------------------------

class PrivacyRiskLevel(str, enum.Enum):
    """Risk levels used by MemoryPrivacyGuard."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PrivacyAction(str, enum.Enum):
    """Supported privacy actions."""

    STORE = "store"
    UPDATE = "update"
    REDACT = "redact"
    BLOCK = "block"
    APPROVE = "approve"
    REJECT = "reject"
    FORGET = "forget"
    EXPORT = "export"
    REVIEW = "review"


class ApprovalStatus(str, enum.Enum):
    """Approval lifecycle status."""

    NOT_REQUIRED = "not_required"
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class SensitiveCategory(str, enum.Enum):
    """Sensitive data categories."""

    PASSWORD = "password"
    API_KEY = "api_key"
    TOKEN = "token"
    SECRET = "secret"
    PRIVATE_KEY = "private_key"
    CREDIT_CARD = "credit_card"
    BANK_ACCOUNT = "bank_account"
    IBAN = "iban"
    SSN = "ssn"
    PASSPORT = "passport"
    DRIVER_LICENSE = "driver_license"
    EMAIL = "email"
    PHONE = "phone"
    ADDRESS = "address"
    PRECISE_LOCATION = "precise_location"
    HEALTH = "health"
    BIOMETRIC = "biometric"
    POLITICAL = "political"
    RELIGION = "religion"
    ETHNICITY = "ethnicity"
    SEXUAL_ORIENTATION = "sexual_orientation"
    CRIMINAL_RECORD = "criminal_record"
    CHILD_DATA = "child_data"
    LEGAL = "legal"
    FINANCIAL = "financial"
    EMPLOYMENT_CONFIDENTIAL = "employment_confidential"
    CLIENT_CONFIDENTIAL = "client_confidential"
    UNKNOWN_SENSITIVE = "unknown_sensitive"


@dataclasses.dataclass(frozen=True)
class SensitiveMatch:
    """Represents one detected sensitive data match."""

    category: SensitiveCategory
    risk_level: PrivacyRiskLevel
    field_path: str
    matched_text_preview: str
    confidence: float
    reason: str


@dataclasses.dataclass
class PrivacyDecision:
    """Decision returned after inspecting a memory payload."""

    allowed: bool
    action: PrivacyAction
    risk_level: PrivacyRiskLevel
    approval_status: ApprovalStatus
    message: str
    matches: List[SensitiveMatch]
    redacted_payload: Optional[Dict[str, Any]] = None
    approval_id: Optional[str] = None


@dataclasses.dataclass
class ApprovalRecord:
    """In-memory approval record for review flows."""

    approval_id: str
    user_id: str
    workspace_id: str
    action: PrivacyAction
    requested_by: Optional[str]
    created_at: str
    expires_at_epoch: float
    status: ApprovalStatus
    reason: str
    payload_hash: str
    metadata: Dict[str, Any]


# ---------------------------------------------------------------------------
# Main Class
# ---------------------------------------------------------------------------

class MemoryPrivacyGuard(BaseAgent):
    """
    Privacy guard for William/Jarvis Memory Agent.

    Responsibilities:
        - Detect sensitive memory content.
        - Block critical sensitive storage by default.
        - Redact medium/high risk data when safe.
        - Request approval for risky or destructive memory actions.
        - Prepare structured Security Agent approval payloads.
        - Prepare Verification Agent payloads.
        - Provide forget/export control helpers.
        - Maintain strict user/workspace isolation.
        - Return William-style structured dict results.
    """

    DEFAULT_APPROVAL_TTL_SECONDS = 60 * 60 * 24
    MAX_EXPORT_ITEMS_DEFAULT = 10_000

    REDACTION_TEXT = "[REDACTED]"
    HASH_SALT_PREFIX = "william_memory_privacy_guard"

    def __init__(
        self,
        agent_name: str = "MemoryPrivacyGuard",
        security_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], None]] = None,
        event_emitter: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        strict_mode: bool = True,
        approval_ttl_seconds: int = DEFAULT_APPROVAL_TTL_SECONDS,
    ) -> None:
        """
        Initialize MemoryPrivacyGuard.

        Args:
            agent_name:
                Agent name for registry/loader compatibility.
            security_agent:
                Optional Security Agent instance.
            verification_agent:
                Optional Verification Agent instance.
            audit_logger:
                Optional callable for audit logs.
            event_emitter:
                Optional callable for agent events.
            strict_mode:
                If True, risky data is blocked more aggressively.
            approval_ttl_seconds:
                Default approval expiry window.
        """
        try:
            super().__init__(agent_name=agent_name)
        except TypeError:
            super().__init__()

        self.agent_name = agent_name
        self.security_agent = security_agent
        self.verification_agent = verification_agent
        self.audit_logger = audit_logger
        self.event_emitter = event_emitter
        self.strict_mode = strict_mode
        self.approval_ttl_seconds = max(300, int(approval_ttl_seconds))

        self._pending_approvals: Dict[str, ApprovalRecord] = {}

        self._compiled_patterns = self._build_sensitive_patterns()
        self._sensitive_keywords = self._build_sensitive_keywords()

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def inspect_memory_payload(
        self,
        payload: Mapping[str, Any],
        context: Mapping[str, Any],
        intended_action: Union[str, PrivacyAction] = PrivacyAction.STORE,
        allow_redaction: bool = True,
        require_approval_for_high_risk: bool = True,
    ) -> Dict[str, Any]:
        """
        Inspect a memory payload before storage/update.

        Args:
            payload:
                Memory data to inspect.
            context:
                Must include user_id and workspace_id.
            intended_action:
                store/update/redact/review.
            allow_redaction:
                Whether medium/high risk fields may be redacted.
            require_approval_for_high_risk:
                Whether high risk content should trigger approval.

        Returns:
            Structured William result containing privacy decision.
        """
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        action = self._normalize_action(intended_action)
        safe_payload = self._safe_dict(payload)

        try:
            matches = self.detect_sensitive_data(safe_payload)
            risk_level = self._calculate_overall_risk(matches)

            decision = self._make_storage_decision(
                payload=safe_payload,
                context=context,
                action=action,
                matches=matches,
                risk_level=risk_level,
                allow_redaction=allow_redaction,
                require_approval_for_high_risk=require_approval_for_high_risk,
            )

            self._log_audit_event(
                event_type="memory_privacy_inspection",
                user_id=str(context.get("user_id")),
                workspace_id=str(context.get("workspace_id")),
                action=str(action.value),
                risk_level=str(decision.risk_level.value),
                allowed=decision.allowed,
                approval_status=str(decision.approval_status.value),
                match_count=len(matches),
            )

            self._emit_agent_event(
                "memory.privacy.inspected",
                {
                    "user_id": context.get("user_id"),
                    "workspace_id": context.get("workspace_id"),
                    "action": action.value,
                    "risk_level": decision.risk_level.value,
                    "allowed": decision.allowed,
                    "match_count": len(matches),
                    "approval_status": decision.approval_status.value,
                },
            )

            verification_payload = self._prepare_verification_payload(
                action="inspect_memory_payload",
                context=context,
                success=True,
                decision=decision,
            )

            return self._safe_result(
                message=decision.message,
                data={
                    "allowed": decision.allowed,
                    "action": decision.action.value,
                    "risk_level": decision.risk_level.value,
                    "approval_status": decision.approval_status.value,
                    "approval_id": decision.approval_id,
                    "matches": [dataclasses.asdict(match) for match in decision.matches],
                    "redacted_payload": decision.redacted_payload,
                    "verification_payload": verification_payload,
                },
                metadata={
                    "agent": self.agent_name,
                    "strict_mode": self.strict_mode,
                    "match_count": len(matches),
                },
            )
        except Exception as exc:
            logger.exception("Memory privacy inspection failed.")
            return self._error_result(
                message="Memory privacy inspection failed.",
                error=str(exc),
                metadata={
                    "agent": self.agent_name,
                },
            )

    def guard_before_store(
        self,
        memory_payload: Mapping[str, Any],
        context: Mapping[str, Any],
        allow_redaction: bool = True,
    ) -> Dict[str, Any]:
        """
        Guard method intended to be called by Memory Agent before storage.

        This returns either:
            - allowed=True with safe payload
            - allowed=False with block/approval info
        """
        result = self.inspect_memory_payload(
            payload=memory_payload,
            context=context,
            intended_action=PrivacyAction.STORE,
            allow_redaction=allow_redaction,
            require_approval_for_high_risk=True,
        )

        if not result.get("success"):
            return result

        data = result.get("data", {})
        redacted_payload = data.get("redacted_payload")
        final_payload = redacted_payload if redacted_payload is not None else self._safe_dict(memory_payload)

        data["safe_memory_payload"] = final_payload

        return self._safe_result(
            message=result.get("message", "Memory storage guard completed."),
            data=data,
            metadata=result.get("metadata", {}),
        )

    def detect_sensitive_data(
        self,
        payload: Mapping[str, Any],
    ) -> List[SensitiveMatch]:
        """
        Detect sensitive data in a dictionary-like payload.

        Args:
            payload:
                Memory payload.

        Returns:
            List of SensitiveMatch objects.
        """
        matches: List[SensitiveMatch] = []
        flattened = self._flatten_mapping(payload)

        for field_path, value in flattened.items():
            text_value = self._stringify_value(value)
            if not text_value:
                continue

            lowered_path = field_path.lower()
            lowered_value = text_value.lower()

            matches.extend(self._detect_by_patterns(field_path, text_value))
            matches.extend(self._detect_by_field_name(lowered_path, text_value))
            matches.extend(self._detect_by_keywords(field_path, lowered_value, text_value))

        return self._deduplicate_matches(matches)

    def redact_payload(
        self,
        payload: Mapping[str, Any],
        matches: Optional[List[SensitiveMatch]] = None,
    ) -> Dict[str, Any]:
        """
        Redact sensitive fields from payload.

        Args:
            payload:
                Original memory payload.
            matches:
                Optional precomputed sensitive matches.

        Returns:
            Redacted payload dictionary.
        """
        safe_payload = self._safe_dict(payload)
        detected = matches if matches is not None else self.detect_sensitive_data(safe_payload)

        redacted = copy.deepcopy(safe_payload)

        for match in detected:
            self._set_nested_value(
                redacted,
                match.field_path,
                self.REDACTION_TEXT,
            )

        return redacted

    def request_memory_approval(
        self,
        payload: Mapping[str, Any],
        context: Mapping[str, Any],
        action: Union[str, PrivacyAction],
        reason: str,
        requested_by: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create a pending approval for sensitive memory action.

        This method prepares a Security Agent compatible approval request.
        It does not directly approve storage or deletion.
        """
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        normalized_action = self._normalize_action(action)

        if not self._requires_security_check(normalized_action, payload, context):
            return self._safe_result(
                message="Security approval is not required for this memory action.",
                data={
                    "approval_required": False,
                    "approval_status": ApprovalStatus.NOT_REQUIRED.value,
                },
                metadata={
                    "agent": self.agent_name,
                },
            )

        approval_result = self._request_security_approval(
            action=normalized_action,
            payload=payload,
            context=context,
            reason=reason,
            requested_by=requested_by,
            metadata=metadata,
        )

        return approval_result

    def approve_memory_action(
        self,
        approval_id: str,
        context: Mapping[str, Any],
        approved_by: Optional[str] = None,
        note: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Mark a pending memory approval as approved.

        Approval is scoped by user_id and workspace_id.
        """
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        record = self._pending_approvals.get(approval_id)
        if record is None:
            return self._error_result(
                message="Approval record was not found.",
                error="approval_not_found",
                metadata={
                    "approval_id": approval_id,
                },
            )

        isolation = self._check_approval_isolation(record, context)
        if not isolation["success"]:
            return isolation

        if self._is_approval_expired(record):
            record.status = ApprovalStatus.EXPIRED
            return self._error_result(
                message="Approval request has expired.",
                error="approval_expired",
                data={
                    "approval_id": approval_id,
                    "status": record.status.value,
                },
            )

        record.status = ApprovalStatus.APPROVED

        self._log_audit_event(
            event_type="memory_privacy_approval_approved",
            user_id=record.user_id,
            workspace_id=record.workspace_id,
            action=record.action.value,
            approval_id=approval_id,
            approved_by=approved_by,
            note=note,
        )

        self._emit_agent_event(
            "memory.privacy.approval.approved",
            {
                "approval_id": approval_id,
                "user_id": record.user_id,
                "workspace_id": record.workspace_id,
                "action": record.action.value,
            },
        )

        return self._safe_result(
            message="Memory action approval has been approved.",
            data={
                "approval_id": approval_id,
                "status": record.status.value,
                "approved_by": approved_by,
                "note": note,
            },
            metadata={
                "agent": self.agent_name,
            },
        )

    def reject_memory_action(
        self,
        approval_id: str,
        context: Mapping[str, Any],
        rejected_by: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Reject a pending memory approval.

        Approval is scoped by user_id and workspace_id.
        """
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        record = self._pending_approvals.get(approval_id)
        if record is None:
            return self._error_result(
                message="Approval record was not found.",
                error="approval_not_found",
                metadata={
                    "approval_id": approval_id,
                },
            )

        isolation = self._check_approval_isolation(record, context)
        if not isolation["success"]:
            return isolation

        record.status = ApprovalStatus.REJECTED

        self._log_audit_event(
            event_type="memory_privacy_approval_rejected",
            user_id=record.user_id,
            workspace_id=record.workspace_id,
            action=record.action.value,
            approval_id=approval_id,
            rejected_by=rejected_by,
            reason=reason,
        )

        self._emit_agent_event(
            "memory.privacy.approval.rejected",
            {
                "approval_id": approval_id,
                "user_id": record.user_id,
                "workspace_id": record.workspace_id,
                "action": record.action.value,
            },
        )

        return self._safe_result(
            message="Memory action approval has been rejected.",
            data={
                "approval_id": approval_id,
                "status": record.status.value,
                "rejected_by": rejected_by,
                "reason": reason,
            },
            metadata={
                "agent": self.agent_name,
            },
        )

    def get_approval_status(
        self,
        approval_id: str,
        context: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Return approval status with SaaS isolation checks.
        """
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        record = self._pending_approvals.get(approval_id)
        if record is None:
            return self._error_result(
                message="Approval record was not found.",
                error="approval_not_found",
            )

        isolation = self._check_approval_isolation(record, context)
        if not isolation["success"]:
            return isolation

        if self._is_approval_expired(record):
            record.status = ApprovalStatus.EXPIRED

        return self._safe_result(
            message="Approval status retrieved.",
            data={
                "approval_id": record.approval_id,
                "status": record.status.value,
                "action": record.action.value,
                "created_at": record.created_at,
                "expires_at_epoch": record.expires_at_epoch,
                "reason": record.reason,
                "metadata": record.metadata,
            },
            metadata={
                "agent": self.agent_name,
            },
        )

    def prepare_forget_request(
        self,
        context: Mapping[str, Any],
        memory_ids: Optional[Iterable[str]] = None,
        filters: Optional[Mapping[str, Any]] = None,
        requested_by: Optional[str] = None,
        reason: Optional[str] = None,
        require_security_approval: bool = True,
    ) -> Dict[str, Any]:
        """
        Prepare a memory forget request.

        This method does not delete memory directly.
        It returns a deletion/forget plan and optional approval request.
        """
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        ids = [str(item) for item in memory_ids] if memory_ids else []
        safe_filters = self._safe_dict(filters or {})

        if not ids and not safe_filters:
            return self._error_result(
                message="Forget request requires memory_ids or filters.",
                error="missing_forget_target",
            )

        forget_payload = {
            "memory_ids": ids,
            "filters": safe_filters,
            "scope": {
                "user_id": str(context.get("user_id")),
                "workspace_id": str(context.get("workspace_id")),
            },
            "requested_by": requested_by,
            "reason": reason or "User requested memory forget operation.",
            "destructive": True,
        }

        approval_data: Optional[Dict[str, Any]] = None
        if require_security_approval:
            approval = self.request_memory_approval(
                payload=forget_payload,
                context=context,
                action=PrivacyAction.FORGET,
                reason=reason or "Forget memory request requires approval.",
                requested_by=requested_by,
                metadata={
                    "memory_ids_count": len(ids),
                    "has_filters": bool(safe_filters),
                    "destructive": True,
                },
            )
            approval_data = approval.get("data", approval)

        verification_payload = self._prepare_verification_payload(
            action="prepare_forget_request",
            context=context,
            success=True,
            decision=None,
            extra={
                "memory_ids_count": len(ids),
                "has_filters": bool(safe_filters),
                "requires_security_approval": require_security_approval,
            },
        )

        self._log_audit_event(
            event_type="memory_privacy_forget_prepared",
            user_id=str(context.get("user_id")),
            workspace_id=str(context.get("workspace_id")),
            memory_ids_count=len(ids),
            has_filters=bool(safe_filters),
            requested_by=requested_by,
            reason=reason,
        )

        return self._safe_result(
            message="Forget request prepared. No memory was deleted by this guard.",
            data={
                "forget_payload": forget_payload,
                "approval": approval_data,
                "verification_payload": verification_payload,
                "execute_directly": False,
            },
            metadata={
                "agent": self.agent_name,
                "destructive_action_guarded": True,
            },
        )

    def prepare_export_request(
        self,
        context: Mapping[str, Any],
        filters: Optional[Mapping[str, Any]] = None,
        requested_by: Optional[str] = None,
        include_sensitive: bool = False,
        max_items: int = MAX_EXPORT_ITEMS_DEFAULT,
        require_security_approval: bool = True,
    ) -> Dict[str, Any]:
        """
        Prepare a memory export request.

        This method does not fetch or export memory directly.
        It returns a safe export plan for Memory Agent/API layer.
        """
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        safe_filters = self._safe_dict(filters or {})
        bounded_max_items = max(1, min(int(max_items), self.MAX_EXPORT_ITEMS_DEFAULT))

        export_payload = {
            "filters": safe_filters,
            "scope": {
                "user_id": str(context.get("user_id")),
                "workspace_id": str(context.get("workspace_id")),
            },
            "requested_by": requested_by,
            "include_sensitive": bool(include_sensitive),
            "max_items": bounded_max_items,
            "export_format": "json",
            "redact_sensitive_by_default": not include_sensitive,
        }

        approval_data: Optional[Dict[str, Any]] = None
        if require_security_approval or include_sensitive:
            approval = self.request_memory_approval(
                payload=export_payload,
                context=context,
                action=PrivacyAction.EXPORT,
                reason="Memory export request requires privacy approval.",
                requested_by=requested_by,
                metadata={
                    "include_sensitive": include_sensitive,
                    "max_items": bounded_max_items,
                    "has_filters": bool(safe_filters),
                },
            )
            approval_data = approval.get("data", approval)

        verification_payload = self._prepare_verification_payload(
            action="prepare_export_request",
            context=context,
            success=True,
            decision=None,
            extra={
                "include_sensitive": include_sensitive,
                "max_items": bounded_max_items,
                "requires_security_approval": require_security_approval or include_sensitive,
            },
        )

        self._log_audit_event(
            event_type="memory_privacy_export_prepared",
            user_id=str(context.get("user_id")),
            workspace_id=str(context.get("workspace_id")),
            requested_by=requested_by,
            include_sensitive=include_sensitive,
            max_items=bounded_max_items,
        )

        return self._safe_result(
            message="Export request prepared. No memory was exported by this guard.",
            data={
                "export_payload": export_payload,
                "approval": approval_data,
                "verification_payload": verification_payload,
                "execute_directly": False,
            },
            metadata={
                "agent": self.agent_name,
                "export_guarded": True,
            },
        )

    def apply_export_redaction(
        self,
        memory_items: Iterable[Mapping[str, Any]],
        context: Mapping[str, Any],
        include_sensitive: bool = False,
    ) -> Dict[str, Any]:
        """
        Apply privacy redaction to exported memory items.

        Args:
            memory_items:
                Iterable of memory records.
            context:
                SaaS context.
            include_sensitive:
                If False, detected sensitive fields are redacted.

        Returns:
            Safe export items.
        """
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        safe_items: List[Dict[str, Any]] = []
        total_matches = 0

        for item in memory_items:
            safe_item = self._safe_dict(item)
            self._assert_item_scope(safe_item, context)

            if include_sensitive:
                safe_items.append(safe_item)
                continue

            matches = self.detect_sensitive_data(safe_item)
            total_matches += len(matches)
            safe_items.append(self.redact_payload(safe_item, matches))

        self._log_audit_event(
            event_type="memory_privacy_export_redacted",
            user_id=str(context.get("user_id")),
            workspace_id=str(context.get("workspace_id")),
            item_count=len(safe_items),
            include_sensitive=include_sensitive,
            redacted_match_count=total_matches,
        )

        return self._safe_result(
            message="Export redaction completed.",
            data={
                "items": safe_items,
                "item_count": len(safe_items),
                "redacted_match_count": total_matches,
                "include_sensitive": include_sensitive,
            },
            metadata={
                "agent": self.agent_name,
            },
        )

    def can_store_memory(
        self,
        payload: Mapping[str, Any],
        context: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Simple boolean-style guard for callers that only need storage permission.
        """
        result = self.inspect_memory_payload(
            payload=payload,
            context=context,
            intended_action=PrivacyAction.STORE,
        )

        if not result.get("success"):
            return result

        data = result.get("data", {})
        allowed = bool(data.get("allowed"))
        approval_status = data.get("approval_status")

        return self._safe_result(
            message="Memory storage permission evaluated.",
            data={
                "can_store": allowed and approval_status in {
                    ApprovalStatus.NOT_REQUIRED.value,
                    ApprovalStatus.APPROVED.value,
                },
                "allowed": allowed,
                "approval_status": approval_status,
                "risk_level": data.get("risk_level"),
                "approval_id": data.get("approval_id"),
            },
            metadata={
                "agent": self.agent_name,
            },
        )

    def list_pending_approvals(
        self,
        context: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        List pending approvals scoped to user_id/workspace_id.
        """
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        user_id = str(context.get("user_id"))
        workspace_id = str(context.get("workspace_id"))

        records: List[Dict[str, Any]] = []
        for record in self._pending_approvals.values():
            if record.user_id != user_id or record.workspace_id != workspace_id:
                continue

            if self._is_approval_expired(record):
                record.status = ApprovalStatus.EXPIRED

            if record.status == ApprovalStatus.PENDING:
                records.append(
                    {
                        "approval_id": record.approval_id,
                        "action": record.action.value,
                        "status": record.status.value,
                        "created_at": record.created_at,
                        "expires_at_epoch": record.expires_at_epoch,
                        "reason": record.reason,
                        "metadata": record.metadata,
                    }
                )

        return self._safe_result(
            message="Pending approvals retrieved.",
            data={
                "approvals": records,
                "count": len(records),
            },
            metadata={
                "agent": self.agent_name,
            },
        )

    def purge_expired_approvals(self) -> Dict[str, Any]:
        """
        Remove expired approvals from local in-memory approval store.

        Useful for API maintenance jobs.
        """
        expired_ids = [
            approval_id
            for approval_id, record in self._pending_approvals.items()
            if self._is_approval_expired(record)
        ]

        for approval_id in expired_ids:
            self._pending_approvals.pop(approval_id, None)

        return self._safe_result(
            message="Expired approvals purged.",
            data={
                "purged_count": len(expired_ids),
                "purged_ids": expired_ids,
            },
            metadata={
                "agent": self.agent_name,
            },
        )

    # -----------------------------------------------------------------------
    # Required compatibility hooks
    # -----------------------------------------------------------------------

    def _validate_task_context(self, context: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Validate SaaS isolation context.

        Required keys:
            - user_id
            - workspace_id
        """
        if not isinstance(context, Mapping):
            return self._error_result(
                message="Invalid task context.",
                error="context_must_be_mapping",
            )

        user_id = context.get("user_id")
        workspace_id = context.get("workspace_id")

        if user_id is None or str(user_id).strip() == "":
            return self._error_result(
                message="Task context missing user_id.",
                error="missing_user_id",
            )

        if workspace_id is None or str(workspace_id).strip() == "":
            return self._error_result(
                message="Task context missing workspace_id.",
                error="missing_workspace_id",
            )

        return self._safe_result(
            message="Task context validated.",
            data={
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
                "tenant_safe": True,
            },
            metadata={
                "agent": self.agent_name,
            },
        )

    def _requires_security_check(
        self,
        action: Union[str, PrivacyAction],
        payload: Optional[Mapping[str, Any]] = None,
        context: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Determine if Security Agent approval is required.
        """
        normalized = self._normalize_action(action)

        if normalized in {
            PrivacyAction.FORGET,
            PrivacyAction.EXPORT,
            PrivacyAction.BLOCK,
            PrivacyAction.APPROVE,
            PrivacyAction.REJECT,
        }:
            return True

        if payload:
            matches = self.detect_sensitive_data(payload)
            risk_level = self._calculate_overall_risk(matches)
            if risk_level in {PrivacyRiskLevel.HIGH, PrivacyRiskLevel.CRITICAL}:
                return True

        if context and context.get("force_security_check"):
            return True

        return False

    def _request_security_approval(
        self,
        action: PrivacyAction,
        payload: Mapping[str, Any],
        context: Mapping[str, Any],
        reason: str,
        requested_by: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare and optionally send approval request to Security Agent.

        This method is safe if Security Agent does not exist yet.
        """
        approval_id = self._new_id("approval")
        now_epoch = time.time()
        created_at = self._utc_now_iso()
        expires_at = now_epoch + self.approval_ttl_seconds
        payload_hash = self._hash_payload(payload)

        record = ApprovalRecord(
            approval_id=approval_id,
            user_id=str(context.get("user_id")),
            workspace_id=str(context.get("workspace_id")),
            action=action,
            requested_by=requested_by,
            created_at=created_at,
            expires_at_epoch=expires_at,
            status=ApprovalStatus.PENDING,
            reason=reason,
            payload_hash=payload_hash,
            metadata=self._safe_dict(metadata or {}),
        )

        self._pending_approvals[approval_id] = record

        security_payload = {
            "approval_id": approval_id,
            "agent": self.agent_name,
            "target_agent": "MemoryAgent",
            "action": action.value,
            "reason": reason,
            "requested_by": requested_by,
            "user_id": record.user_id,
            "workspace_id": record.workspace_id,
            "payload_hash": payload_hash,
            "created_at": created_at,
            "expires_at_epoch": expires_at,
            "metadata": record.metadata,
            "requires_human_or_policy_approval": True,
        }

        security_response: Optional[Any] = None
        if self.security_agent is not None:
            security_response = self._call_security_agent(security_payload)

        self._log_audit_event(
            event_type="memory_privacy_approval_requested",
            user_id=record.user_id,
            workspace_id=record.workspace_id,
            action=action.value,
            approval_id=approval_id,
            reason=reason,
            requested_by=requested_by,
        )

        self._emit_agent_event(
            "memory.privacy.approval.requested",
            {
                "approval_id": approval_id,
                "user_id": record.user_id,
                "workspace_id": record.workspace_id,
                "action": action.value,
            },
        )

        return self._safe_result(
            message="Security approval requested for memory action.",
            data={
                "approval_required": True,
                "approval_id": approval_id,
                "approval_status": ApprovalStatus.PENDING.value,
                "security_payload": security_payload,
                "security_response": security_response,
            },
            metadata={
                "agent": self.agent_name,
                "security_agent_available": self.security_agent is not None,
            },
        )

    def _prepare_verification_payload(
        self,
        action: str,
        context: Mapping[str, Any],
        success: bool,
        decision: Optional[PrivacyDecision] = None,
        extra: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent compatible payload.
        """
        payload: Dict[str, Any] = {
            "verification_id": self._new_id("verify"),
            "agent": self.agent_name,
            "target_agent": "VerificationAgent",
            "source_module": "agents.memory_agent.privacy_guard",
            "action": action,
            "success": bool(success),
            "timestamp": self._utc_now_iso(),
            "user_id": str(context.get("user_id")),
            "workspace_id": str(context.get("workspace_id")),
            "checks": {
                "context_validated": True,
                "saas_isolation_checked": True,
                "privacy_guard_applied": True,
                "security_approval_considered": True,
            },
        }

        if decision is not None:
            payload["decision"] = {
                "allowed": decision.allowed,
                "action": decision.action.value,
                "risk_level": decision.risk_level.value,
                "approval_status": decision.approval_status.value,
                "approval_id": decision.approval_id,
                "match_count": len(decision.matches),
            }

        if extra:
            payload["extra"] = self._safe_dict(extra)

        return payload

    def _prepare_memory_payload(
        self,
        payload: Mapping[str, Any],
        context: Mapping[str, Any],
        privacy_decision: Optional[PrivacyDecision] = None,
    ) -> Dict[str, Any]:
        """
        Prepare a Memory Agent compatible payload after privacy checks.
        """
        safe_payload = self._safe_dict(payload)

        if privacy_decision and privacy_decision.redacted_payload is not None:
            safe_payload = privacy_decision.redacted_payload

        return {
            "user_id": str(context.get("user_id")),
            "workspace_id": str(context.get("workspace_id")),
            "payload": safe_payload,
            "privacy": {
                "guarded_by": self.agent_name,
                "guarded_at": self._utc_now_iso(),
                "allowed": privacy_decision.allowed if privacy_decision else True,
                "risk_level": privacy_decision.risk_level.value if privacy_decision else PrivacyRiskLevel.NONE.value,
                "approval_status": privacy_decision.approval_status.value if privacy_decision else ApprovalStatus.NOT_REQUIRED.value,
                "approval_id": privacy_decision.approval_id if privacy_decision else None,
            },
        }

    def _emit_agent_event(
        self,
        event_name: str,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Emit agent event safely.

        Compatible with future event bus, BaseAgent emit_event, or callable emitter.
        """
        safe_payload = self._safe_dict(payload)

        try:
            if self.event_emitter is not None:
                self.event_emitter(event_name, safe_payload)
                return self._safe_result(
                    message="Agent event emitted.",
                    data={
                        "event_name": event_name,
                    },
                )

            if hasattr(super(), "emit_event"):
                try:
                    response = super().emit_event(event_name, safe_payload)  # type: ignore[misc]
                    return self._safe_result(
                        message="Agent event emitted via BaseAgent.",
                        data={
                            "event_name": event_name,
                            "response": response,
                        },
                    )
                except Exception:
                    pass

            logger.debug("Agent event: %s %s", event_name, safe_payload)
            return self._safe_result(
                message="Agent event logged locally.",
                data={
                    "event_name": event_name,
                    "payload": safe_payload,
                },
                metadata={
                    "local_only": True,
                },
            )
        except Exception as exc:
            logger.warning("Failed to emit agent event: %s", exc)
            return self._error_result(
                message="Failed to emit agent event.",
                error=str(exc),
            )

    def _log_audit_event(self, event_type: str, **kwargs: Any) -> Dict[str, Any]:
        """
        Log audit event safely.

        This guard never writes destructive state directly. It emits structured
        audit events that can later be consumed by the Dashboard/API/AuditLog.
        """
        event = {
            "audit_id": self._new_id("audit"),
            "event_type": event_type,
            "agent": self.agent_name,
            "timestamp": self._utc_now_iso(),
            "data": self._safe_dict(kwargs),
        }

        try:
            if self.audit_logger is not None:
                self.audit_logger(event)
            else:
                logger.info("Audit event: %s", json.dumps(event, default=str))
            return self._safe_result(
                message="Audit event logged.",
                data=event,
            )
        except Exception as exc:
            logger.warning("Failed to log audit event: %s", exc)
            return self._error_result(
                message="Failed to log audit event.",
                error=str(exc),
                data=event,
            )

    def _safe_result(
        self,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard William success result.
        """
        return {
            "success": True,
            "message": message,
            "data": self._safe_dict(data or {}),
            "error": None,
            "metadata": self._safe_dict(metadata or {}),
        }

    def _error_result(
        self,
        message: str,
        error: Union[str, Exception, None] = None,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard William error result.
        """
        return {
            "success": False,
            "message": message,
            "data": self._safe_dict(data or {}),
            "error": str(error) if error is not None else "unknown_error",
            "metadata": self._safe_dict(metadata or {}),
        }

    # -----------------------------------------------------------------------
    # Decision logic
    # -----------------------------------------------------------------------

    def _make_storage_decision(
        self,
        payload: Mapping[str, Any],
        context: Mapping[str, Any],
        action: PrivacyAction,
        matches: List[SensitiveMatch],
        risk_level: PrivacyRiskLevel,
        allow_redaction: bool,
        require_approval_for_high_risk: bool,
    ) -> PrivacyDecision:
        """
        Convert detected sensitive matches into a storage decision.
        """
        if risk_level == PrivacyRiskLevel.NONE:
            return PrivacyDecision(
                allowed=True,
                action=action,
                risk_level=risk_level,
                approval_status=ApprovalStatus.NOT_REQUIRED,
                message="Memory payload is safe to store.",
                matches=matches,
                redacted_payload=self._safe_dict(payload),
            )

        if risk_level == PrivacyRiskLevel.LOW:
            redacted = self.redact_payload(payload, matches) if allow_redaction else self._safe_dict(payload)
            return PrivacyDecision(
                allowed=True,
                action=PrivacyAction.REDACT if allow_redaction else action,
                risk_level=risk_level,
                approval_status=ApprovalStatus.NOT_REQUIRED,
                message="Low-risk sensitive memory detected and handled.",
                matches=matches,
                redacted_payload=redacted,
            )

        if risk_level == PrivacyRiskLevel.MEDIUM:
            if allow_redaction:
                return PrivacyDecision(
                    allowed=True,
                    action=PrivacyAction.REDACT,
                    risk_level=risk_level,
                    approval_status=ApprovalStatus.NOT_REQUIRED,
                    message="Medium-risk sensitive memory detected and redacted.",
                    matches=matches,
                    redacted_payload=self.redact_payload(payload, matches),
                )

            approval = self._request_security_approval(
                action=action,
                payload=payload,
                context=context,
                reason="Medium-risk memory storage without redaction requires approval.",
                requested_by=str(context.get("requested_by")) if context.get("requested_by") else None,
                metadata={
                    "risk_level": risk_level.value,
                    "match_count": len(matches),
                },
            )
            return PrivacyDecision(
                allowed=False,
                action=PrivacyAction.REVIEW,
                risk_level=risk_level,
                approval_status=ApprovalStatus.PENDING,
                message="Medium-risk sensitive memory requires approval because redaction is disabled.",
                matches=matches,
                approval_id=approval.get("data", {}).get("approval_id"),
            )

        if risk_level == PrivacyRiskLevel.HIGH:
            if require_approval_for_high_risk:
                approval = self._request_security_approval(
                    action=action,
                    payload=payload,
                    context=context,
                    reason="High-risk memory storage requires Security Agent approval.",
                    requested_by=str(context.get("requested_by")) if context.get("requested_by") else None,
                    metadata={
                        "risk_level": risk_level.value,
                        "match_count": len(matches),
                    },
                )
                return PrivacyDecision(
                    allowed=False,
                    action=PrivacyAction.REVIEW,
                    risk_level=risk_level,
                    approval_status=ApprovalStatus.PENDING,
                    message="High-risk sensitive memory blocked pending approval.",
                    matches=matches,
                    redacted_payload=self.redact_payload(payload, matches) if allow_redaction else None,
                    approval_id=approval.get("data", {}).get("approval_id"),
                )

            if allow_redaction and not self.strict_mode:
                return PrivacyDecision(
                    allowed=True,
                    action=PrivacyAction.REDACT,
                    risk_level=risk_level,
                    approval_status=ApprovalStatus.NOT_REQUIRED,
                    message="High-risk sensitive memory redacted because approval was not required.",
                    matches=matches,
                    redacted_payload=self.redact_payload(payload, matches),
                )

        return PrivacyDecision(
            allowed=False,
            action=PrivacyAction.BLOCK,
            risk_level=risk_level,
            approval_status=ApprovalStatus.REJECTED,
            message="Critical or unsafe sensitive memory storage was blocked.",
            matches=matches,
            redacted_payload=self.redact_payload(payload, matches) if allow_redaction else None,
        )

    def _calculate_overall_risk(
        self,
        matches: List[SensitiveMatch],
    ) -> PrivacyRiskLevel:
        """
        Calculate overall risk from detected matches.
        """
        if not matches:
            return PrivacyRiskLevel.NONE

        rank = {
            PrivacyRiskLevel.NONE: 0,
            PrivacyRiskLevel.LOW: 1,
            PrivacyRiskLevel.MEDIUM: 2,
            PrivacyRiskLevel.HIGH: 3,
            PrivacyRiskLevel.CRITICAL: 4,
        }

        highest = PrivacyRiskLevel.NONE
        for match in matches:
            if rank[match.risk_level] > rank[highest]:
                highest = match.risk_level

        critical_categories = {
            SensitiveCategory.PASSWORD,
            SensitiveCategory.API_KEY,
            SensitiveCategory.TOKEN,
            SensitiveCategory.SECRET,
            SensitiveCategory.PRIVATE_KEY,
            SensitiveCategory.CREDIT_CARD,
            SensitiveCategory.SSN,
            SensitiveCategory.PASSPORT,
            SensitiveCategory.BANK_ACCOUNT,
            SensitiveCategory.IBAN,
        }

        if any(match.category in critical_categories for match in matches):
            return PrivacyRiskLevel.CRITICAL if self.strict_mode else PrivacyRiskLevel.HIGH

        high_count = sum(1 for match in matches if match.risk_level == PrivacyRiskLevel.HIGH)
        medium_count = sum(1 for match in matches if match.risk_level == PrivacyRiskLevel.MEDIUM)

        if high_count >= 2:
            return PrivacyRiskLevel.CRITICAL if self.strict_mode else PrivacyRiskLevel.HIGH

        if medium_count >= 5:
            return PrivacyRiskLevel.HIGH

        return highest

    # -----------------------------------------------------------------------
    # Sensitive detection
    # -----------------------------------------------------------------------

    def _build_sensitive_patterns(self) -> Dict[SensitiveCategory, List[Tuple[re.Pattern[str], PrivacyRiskLevel, str]]]:
        """
        Compile sensitive data regex patterns.
        """
        return {
            SensitiveCategory.EMAIL: [
                (
                    re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
                    PrivacyRiskLevel.LOW,
                    "Email address detected.",
                )
            ],
            SensitiveCategory.PHONE: [
                (
                    re.compile(r"(?<!\d)(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?)?\d{3,4}[\s.-]?\d{4}(?!\d)"),
                    PrivacyRiskLevel.LOW,
                    "Phone number-like value detected.",
                )
            ],
            SensitiveCategory.CREDIT_CARD: [
                (
                    re.compile(r"(?<!\d)(?:\d[ -]*?){13,19}(?!\d)"),
                    PrivacyRiskLevel.CRITICAL,
                    "Credit card-like number detected.",
                )
            ],
            SensitiveCategory.SSN: [
                (
                    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
                    PrivacyRiskLevel.CRITICAL,
                    "SSN-like value detected.",
                )
            ],
            SensitiveCategory.IBAN: [
                (
                    re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", re.IGNORECASE),
                    PrivacyRiskLevel.CRITICAL,
                    "IBAN-like value detected.",
                )
            ],
            SensitiveCategory.API_KEY: [
                (
                    re.compile(r"\b(?:sk|pk|rk|api|key|token)[-_]?[A-Za-z0-9]{16,}\b", re.IGNORECASE),
                    PrivacyRiskLevel.CRITICAL,
                    "API key-like value detected.",
                ),
                (
                    re.compile(r"\b[A-Za-z0-9_\-]{32,}\b"),
                    PrivacyRiskLevel.HIGH,
                    "Long token-like value detected.",
                ),
            ],
            SensitiveCategory.PRIVATE_KEY: [
                (
                    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", re.IGNORECASE),
                    PrivacyRiskLevel.CRITICAL,
                    "Private key block detected.",
                )
            ],
            SensitiveCategory.PASSWORD: [
                (
                    re.compile(r"(?i)\b(password|passwd|pwd)\b\s*[:=]\s*['\"]?[^'\"\s]{6,}"),
                    PrivacyRiskLevel.CRITICAL,
                    "Password assignment detected.",
                )
            ],
            SensitiveCategory.PRECISE_LOCATION: [
                (
                    re.compile(r"\b-?\d{1,2}\.\d{5,}\s*,\s*-?\d{1,3}\.\d{5,}\b"),
                    PrivacyRiskLevel.HIGH,
                    "Precise latitude/longitude detected.",
                )
            ],
        }

    def _build_sensitive_keywords(self) -> Dict[SensitiveCategory, Tuple[List[str], PrivacyRiskLevel, str]]:
        """
        Keyword-based sensitive category detection.
        """
        return {
            SensitiveCategory.HEALTH: (
                [
                    "diagnosis",
                    "medical condition",
                    "mental health",
                    "therapy notes",
                    "prescription",
                    "medication",
                    "blood test",
                    "disease",
                    "illness",
                    "patient record",
                ],
                PrivacyRiskLevel.HIGH,
                "Health-related sensitive information detected.",
            ),
            SensitiveCategory.POLITICAL: (
                [
                    "political affiliation",
                    "party membership",
                    "voting preference",
                    "campaign donation",
                    "political opinion",
                ],
                PrivacyRiskLevel.HIGH,
                "Political sensitive information detected.",
            ),
            SensitiveCategory.RELIGION: (
                [
                    "religious belief",
                    "religion",
                    "mosque",
                    "church membership",
                    "temple membership",
                    "synagogue membership",
                ],
                PrivacyRiskLevel.HIGH,
                "Religion-related sensitive information detected.",
            ),
            SensitiveCategory.ETHNICITY: (
                [
                    "ethnicity",
                    "race",
                    "racial background",
                    "tribe",
                    "caste",
                ],
                PrivacyRiskLevel.HIGH,
                "Race or ethnicity sensitive information detected.",
            ),
            SensitiveCategory.SEXUAL_ORIENTATION: (
                [
                    "sexual orientation",
                    "lgbtq",
                    "gay",
                    "lesbian",
                    "bisexual",
                    "transgender",
                ],
                PrivacyRiskLevel.HIGH,
                "Sexual orientation sensitive information detected.",
            ),
            SensitiveCategory.CRIMINAL_RECORD: (
                [
                    "criminal record",
                    "conviction",
                    "arrest record",
                    "felony",
                    "parole",
                    "probation",
                ],
                PrivacyRiskLevel.HIGH,
                "Criminal record sensitive information detected.",
            ),
            SensitiveCategory.CHILD_DATA: (
                [
                    "minor child",
                    "under 13",
                    "child passport",
                    "school id",
                    "student record",
                ],
                PrivacyRiskLevel.HIGH,
                "Child-related sensitive information detected.",
            ),
            SensitiveCategory.CLIENT_CONFIDENTIAL: (
                [
                    "client secret",
                    "confidential client",
                    "nda",
                    "private proposal",
                    "unreleased campaign",
                ],
                PrivacyRiskLevel.MEDIUM,
                "Client confidential information detected.",
            ),
            SensitiveCategory.FINANCIAL: (
                [
                    "bank balance",
                    "income statement",
                    "tax id",
                    "salary",
                    "invoice account",
                    "routing number",
                ],
                PrivacyRiskLevel.HIGH,
                "Financial sensitive information detected.",
            ),
            SensitiveCategory.LEGAL: (
                [
                    "legal case",
                    "lawsuit",
                    "attorney privileged",
                    "court order",
                    "settlement agreement",
                ],
                PrivacyRiskLevel.HIGH,
                "Legal sensitive information detected.",
            ),
        }

    def _detect_by_patterns(
        self,
        field_path: str,
        text_value: str,
    ) -> List[SensitiveMatch]:
        matches: List[SensitiveMatch] = []

        for category, pattern_entries in self._compiled_patterns.items():
            for pattern, risk_level, reason in pattern_entries:
                for match in pattern.finditer(text_value):
                    raw = match.group(0)

                    if category == SensitiveCategory.CREDIT_CARD and not self._looks_like_credit_card(raw):
                        continue

                    matches.append(
                        SensitiveMatch(
                            category=category,
                            risk_level=risk_level,
                            field_path=field_path,
                            matched_text_preview=self._preview_sensitive(raw),
                            confidence=0.86,
                            reason=reason,
                        )
                    )

        return matches

    def _detect_by_field_name(
        self,
        lowered_path: str,
        text_value: str,
    ) -> List[SensitiveMatch]:
        field_rules: List[Tuple[List[str], SensitiveCategory, PrivacyRiskLevel, str]] = [
            (["password", "passwd", "pwd"], SensitiveCategory.PASSWORD, PrivacyRiskLevel.CRITICAL, "Sensitive password field name detected."),
            (["api_key", "apikey", "secret_key", "access_key"], SensitiveCategory.API_KEY, PrivacyRiskLevel.CRITICAL, "Sensitive API key field name detected."),
            (["token", "access_token", "refresh_token", "bearer"], SensitiveCategory.TOKEN, PrivacyRiskLevel.CRITICAL, "Sensitive token field name detected."),
            (["secret", "client_secret"], SensitiveCategory.SECRET, PrivacyRiskLevel.CRITICAL, "Secret field name detected."),
            (["private_key", "pem_key"], SensitiveCategory.PRIVATE_KEY, PrivacyRiskLevel.CRITICAL, "Private key field name detected."),
            (["credit_card", "card_number", "cc_number"], SensitiveCategory.CREDIT_CARD, PrivacyRiskLevel.CRITICAL, "Credit card field name detected."),
            (["ssn", "social_security"], SensitiveCategory.SSN, PrivacyRiskLevel.CRITICAL, "SSN field name detected."),
            (["passport"], SensitiveCategory.PASSPORT, PrivacyRiskLevel.CRITICAL, "Passport field name detected."),
            (["iban"], SensitiveCategory.IBAN, PrivacyRiskLevel.CRITICAL, "IBAN field name detected."),
            (["bank_account", "account_number", "routing_number"], SensitiveCategory.BANK_ACCOUNT, PrivacyRiskLevel.CRITICAL, "Bank account field name detected."),
            (["address", "home_address", "street_address"], SensitiveCategory.ADDRESS, PrivacyRiskLevel.MEDIUM, "Address field name detected."),
            (["latitude", "longitude", "gps", "coordinates"], SensitiveCategory.PRECISE_LOCATION, PrivacyRiskLevel.HIGH, "Precise location field name detected."),
            (["medical", "health", "diagnosis"], SensitiveCategory.HEALTH, PrivacyRiskLevel.HIGH, "Health field name detected."),
        ]

        found: List[SensitiveMatch] = []
        if text_value.strip() == "":
            return found

        for keywords, category, risk, reason in field_rules:
            if any(keyword in lowered_path for keyword in keywords):
                found.append(
                    SensitiveMatch(
                        category=category,
                        risk_level=risk,
                        field_path=lowered_path,
                        matched_text_preview=self._preview_sensitive(text_value),
                        confidence=0.92,
                        reason=reason,
                    )
                )

        return found

    def _detect_by_keywords(
        self,
        field_path: str,
        lowered_value: str,
        original_value: str,
    ) -> List[SensitiveMatch]:
        found: List[SensitiveMatch] = []

        for category, (keywords, risk, reason) in self._sensitive_keywords.items():
            if any(keyword in lowered_value for keyword in keywords):
                found.append(
                    SensitiveMatch(
                        category=category,
                        risk_level=risk,
                        field_path=field_path,
                        matched_text_preview=self._preview_sensitive(original_value),
                        confidence=0.72,
                        reason=reason,
                    )
                )

        return found

    def _deduplicate_matches(
        self,
        matches: List[SensitiveMatch],
    ) -> List[SensitiveMatch]:
        seen = set()
        unique: List[SensitiveMatch] = []

        for match in matches:
            key = (
                match.category.value,
                match.field_path,
                match.matched_text_preview,
                match.reason,
            )
            if key in seen:
                continue
            seen.add(key)
            unique.append(match)

        return unique

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def _normalize_action(
        self,
        action: Union[str, PrivacyAction],
    ) -> PrivacyAction:
        if isinstance(action, PrivacyAction):
            return action

        text = str(action).strip().lower()
        for item in PrivacyAction:
            if item.value == text:
                return item

        return PrivacyAction.REVIEW

    def _safe_dict(self, value: Any) -> Dict[str, Any]:
        """
        Convert arbitrary mapping-like value into JSON-safe dict.
        """
        if value is None:
            return {}

        if dataclasses.is_dataclass(value):
            value = dataclasses.asdict(value)

        if isinstance(value, Mapping):
            result: Dict[str, Any] = {}
            for key, item in value.items():
                safe_key = str(key)
                result[safe_key] = self._safe_json_value(item)
            return result

        return {
            "value": self._safe_json_value(value),
        }

    def _safe_json_value(self, value: Any) -> Any:
        if dataclasses.is_dataclass(value):
            return self._safe_dict(dataclasses.asdict(value))

        if isinstance(value, Mapping):
            return {str(k): self._safe_json_value(v) for k, v in value.items()}

        if isinstance(value, (list, tuple, set)):
            return [self._safe_json_value(item) for item in value]

        if isinstance(value, enum.Enum):
            return value.value

        if isinstance(value, (str, int, float, bool)) or value is None:
            return value

        return str(value)

    def _flatten_mapping(
        self,
        mapping: Mapping[str, Any],
        parent_key: str = "",
    ) -> Dict[str, Any]:
        items: Dict[str, Any] = {}

        for key, value in mapping.items():
            new_key = f"{parent_key}.{key}" if parent_key else str(key)

            if isinstance(value, Mapping):
                items.update(self._flatten_mapping(value, new_key))
            elif isinstance(value, list):
                for index, item in enumerate(value):
                    list_key = f"{new_key}.{index}"
                    if isinstance(item, Mapping):
                        items.update(self._flatten_mapping(item, list_key))
                    else:
                        items[list_key] = item
            else:
                items[new_key] = value

        return items

    def _set_nested_value(
        self,
        target: Dict[str, Any],
        dotted_path: str,
        value: Any,
    ) -> None:
        parts = dotted_path.split(".")
        current: Any = target

        for index, part in enumerate(parts):
            is_last = index == len(parts) - 1

            if isinstance(current, list):
                try:
                    list_index = int(part)
                except ValueError:
                    return

                if list_index < 0 or list_index >= len(current):
                    return

                if is_last:
                    current[list_index] = value
                    return

                current = current[list_index]
                continue

            if not isinstance(current, dict):
                return

            if is_last:
                current[part] = value
                return

            if part not in current:
                return

            current = current[part]

    def _stringify_value(self, value: Any) -> str:
        if value is None:
            return ""

        if isinstance(value, str):
            return value

        try:
            return json.dumps(value, default=str, ensure_ascii=False)
        except Exception:
            return str(value)

    def _preview_sensitive(self, text: str, max_length: int = 48) -> str:
        cleaned = str(text).replace("\n", " ").replace("\r", " ").strip()

        if len(cleaned) <= 6:
            return "*" * len(cleaned)

        prefix = cleaned[:2]
        suffix = cleaned[-2:]
        middle = "*" * min(12, max(4, len(cleaned) - 4))
        preview = f"{prefix}{middle}{suffix}"

        if len(preview) > max_length:
            preview = preview[:max_length] + "..."

        return preview

    def _looks_like_credit_card(self, raw: str) -> bool:
        digits = re.sub(r"\D", "", raw)
        if len(digits) < 13 or len(digits) > 19:
            return False

        return self._luhn_check(digits)

    def _luhn_check(self, digits: str) -> bool:
        try:
            total = 0
            reverse_digits = digits[::-1]

            for index, char in enumerate(reverse_digits):
                number = int(char)
                if index % 2 == 1:
                    number *= 2
                    if number > 9:
                        number -= 9
                total += number

            return total % 10 == 0
        except Exception:
            return False

    def _hash_payload(self, payload: Mapping[str, Any]) -> str:
        normalized = json.dumps(
            self._safe_dict(payload),
            sort_keys=True,
            ensure_ascii=False,
            default=str,
        )
        digest = hashlib.sha256(
            f"{self.HASH_SALT_PREFIX}:{normalized}".encode("utf-8")
        ).hexdigest()
        return digest

    def _new_id(self, prefix: str) -> str:
        return f"{prefix}_{uuid.uuid4().hex}"

    def _utc_now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _is_approval_expired(self, record: ApprovalRecord) -> bool:
        return time.time() > record.expires_at_epoch

    def _check_approval_isolation(
        self,
        record: ApprovalRecord,
        context: Mapping[str, Any],
    ) -> Dict[str, Any]:
        user_id = str(context.get("user_id"))
        workspace_id = str(context.get("workspace_id"))

        if record.user_id != user_id or record.workspace_id != workspace_id:
            self._log_audit_event(
                event_type="memory_privacy_isolation_violation",
                approval_id=record.approval_id,
                expected_user_id=record.user_id,
                expected_workspace_id=record.workspace_id,
                actual_user_id=user_id,
                actual_workspace_id=workspace_id,
            )
            return self._error_result(
                message="Approval record does not belong to this user/workspace.",
                error="approval_isolation_violation",
            )

        return self._safe_result(
            message="Approval isolation validated.",
            data={
                "approval_id": record.approval_id,
                "isolated": True,
            },
        )

    def _assert_item_scope(
        self,
        item: Mapping[str, Any],
        context: Mapping[str, Any],
    ) -> None:
        """
        Raise if exported item appears to belong to another tenant.

        If the item does not contain user/workspace fields, we allow it because
        some memory backends may wrap scope externally.
        """
        expected_user_id = str(context.get("user_id"))
        expected_workspace_id = str(context.get("workspace_id"))

        item_user_id = item.get("user_id")
        item_workspace_id = item.get("workspace_id")

        if item_user_id is not None and str(item_user_id) != expected_user_id:
            raise PermissionError("Memory item user_id isolation violation.")

        if item_workspace_id is not None and str(item_workspace_id) != expected_workspace_id:
            raise PermissionError("Memory item workspace_id isolation violation.")

    def _call_security_agent(self, security_payload: Mapping[str, Any]) -> Any:
        """
        Call Security Agent using common future-compatible method names.
        """
        agent = self.security_agent
        if agent is None:
            return None

        method_names = [
            "request_approval",
            "review_sensitive_action",
            "authorize_action",
            "handle_approval_request",
        ]

        for method_name in method_names:
            method = getattr(agent, method_name, None)
            if callable(method):
                try:
                    return method(self._safe_dict(security_payload))
                except TypeError:
                    try:
                        return method(**self._safe_dict(security_payload))
                    except Exception as exc:
                        logger.warning("Security Agent method %s failed: %s", method_name, exc)
                except Exception as exc:
                    logger.warning("Security Agent method %s failed: %s", method_name, exc)

        return {
            "success": False,
            "message": "Security Agent exists but no compatible approval method was found.",
            "error": "missing_security_agent_method",
        }


# ---------------------------------------------------------------------------
# Standalone smoke test helper
# ---------------------------------------------------------------------------

def _self_test() -> Dict[str, Any]:
    """
    Lightweight import-safe smoke test.

    This does not execute destructive actions.
    """
    guard = MemoryPrivacyGuard()
    context = {
        "user_id": "test_user",
        "workspace_id": "test_workspace",
    }
    payload = {
        "note": "Client prefers short replies.",
        "email": "client@example.com",
        "api_key": "<redacted_demo_api_key>",
    }

    return guard.guard_before_store(payload, context)


if __name__ == "__main__":
    print(json.dumps(_self_test(), indent=2, default=str))