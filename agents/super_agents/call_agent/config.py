"""
agents/super_agents/call_agent/config.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Call settings, recording permissions, auto-answer flags, consent/legal safety,
    SaaS isolation, and Call Agent configuration helpers.

This file is intentionally import-safe:
    - No real calls are made.
    - No recordings are started.
    - No external services are required.
    - Missing William/Jarvis framework modules are handled with fallback stubs.

Connections:
    - Master Agent / Router:
        Exposes registry metadata and structured callable methods.
    - Security Agent:
        Sensitive changes such as recording enablement, auto-answer, retention,
        and jurisdiction changes are routed through security approval hooks.
    - Memory Agent:
        Can prepare safe preference/config context payloads.
    - Verification Agent:
        Can prepare verification payloads after config changes/evaluations.
    - Dashboard / API:
        Public methods return structured dict results:
        success, message, data, error, metadata.
"""

from __future__ import annotations

import copy
import dataclasses
import enum
import logging
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple


# ---------------------------------------------------------------------------
# Safe optional BaseAgent compatibility
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for standalone import safety
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps the file import-safe even when the full William/Jarvis
        framework has not been generated yet.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)

        async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent run() is not implemented.",
                "data": {},
                "error": "BASE_AGENT_NOT_AVAILABLE",
                "metadata": {},
            }


LOGGER = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ConsentMode(str, enum.Enum):
    """Consent model used before recording/transcription/note-taking."""

    DISABLED = "disabled"
    ONE_PARTY = "one_party"
    TWO_PARTY = "two_party"
    ALL_PARTY = "all_party"
    EXPLICIT_OPT_IN = "explicit_opt_in"


class RecordingMode(str, enum.Enum):
    """Recording behavior."""

    DISABLED = "disabled"
    CONSENT_REQUIRED = "consent_required"
    MANUAL_ONLY = "manual_only"
    INTERNAL_NOTES_ONLY = "internal_notes_only"


class AutoAnswerMode(str, enum.Enum):
    """Auto-answer behavior."""

    DISABLED = "disabled"
    BUSINESS_HOURS_ONLY = "business_hours_only"
    APPROVED_CONTACTS_ONLY = "approved_contacts_only"
    VOICEMAIL_ONLY = "voicemail_only"


class CallDirection(str, enum.Enum):
    """Supported call directions."""

    INBOUND = "inbound"
    OUTBOUND = "outbound"


class CallerType(str, enum.Enum):
    """Caller classification used by policy checks."""

    UNKNOWN = "unknown"
    APPROVED_CONTACT = "approved_contact"
    CUSTOMER = "customer"
    LEAD = "lead"
    INTERNAL_TEAM = "internal_team"
    BLOCKED = "blocked"


class RiskLevel(str, enum.Enum):
    """Risk level returned by config evaluation."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    BLOCKED = "blocked"


class SecurityAction(str, enum.Enum):
    """Sensitive actions requiring possible Security Agent approval."""

    ENABLE_RECORDING = "enable_recording"
    CHANGE_CONSENT_MODE = "change_consent_mode"
    ENABLE_AUTO_ANSWER = "enable_auto_answer"
    CHANGE_RETENTION = "change_retention"
    EXPORT_CONFIG = "export_config"
    IMPORT_CONFIG = "import_config"
    OVERRIDE_SAFETY = "override_safety"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class BusinessHours:
    """
    Business hours in local workspace timezone.

    closed_days uses ISO weekday values:
        Monday=1 ... Sunday=7
    """

    enabled: bool = True
    timezone_name: str = "America/New_York"
    start_time: str = "09:00"
    end_time: str = "21:00"
    closed_days: Tuple[int, ...] = (6, 7)

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class RecordingPolicy:
    """Recording, transcription, notice, and retention policy."""

    recording_mode: RecordingMode = RecordingMode.CONSENT_REQUIRED
    consent_mode: ConsentMode = ConsentMode.EXPLICIT_OPT_IN
    require_recording_notice: bool = True
    require_transcription_notice: bool = True
    allow_live_transcription: bool = False
    allow_internal_notes: bool = True
    allow_sentiment_analysis: bool = False
    allow_ai_summary: bool = True
    allow_storage: bool = False
    retention_days: int = 30
    min_retention_days: int = 0
    max_retention_days: int = 365
    redact_sensitive_data: bool = True
    block_payment_card_capture: bool = True
    block_government_id_capture: bool = True
    block_health_data_capture: bool = True
    block_minor_recording_without_guardian: bool = True

    def to_dict(self) -> Dict[str, Any]:
        data = dataclasses.asdict(self)
        data["recording_mode"] = self.recording_mode.value
        data["consent_mode"] = self.consent_mode.value
        return data


@dataclasses.dataclass(frozen=True)
class AutoAnswerPolicy:
    """Auto-answer settings and caller safety controls."""

    auto_answer_mode: AutoAnswerMode = AutoAnswerMode.DISABLED
    max_auto_answer_per_hour: int = 20
    require_approved_script: bool = True
    require_caller_disclosure: bool = True
    disclose_ai_assistant: bool = True
    allow_outbound_auto_call: bool = False
    block_unknown_callers: bool = False
    block_after_hours: bool = True
    route_unknown_to_voicemail: bool = True
    emergency_call_detection_enabled: bool = True
    human_handoff_enabled: bool = True
    human_handoff_keywords: Tuple[str, ...] = (
        "human",
        "agent",
        "representative",
        "manager",
        "owner",
        "complaint",
        "emergency",
        "urgent",
        "legal",
        "lawyer",
        "attorney",
        "police",
        "medical",
    )

    def to_dict(self) -> Dict[str, Any]:
        data = dataclasses.asdict(self)
        data["auto_answer_mode"] = self.auto_answer_mode.value
        data["human_handoff_keywords"] = list(self.human_handoff_keywords)
        return data


@dataclasses.dataclass(frozen=True)
class LegalSafetyPolicy:
    """
    Legal and consent guardrails.

    This is a safety configuration layer, not legal advice. Production teams
    should map these settings to local laws, counsel review, and provider rules.
    """

    enabled: bool = True
    default_country_code: str = "US"
    default_region_code: str = ""
    strictest_consent_wins: bool = True
    require_location_based_policy: bool = True
    require_ai_identity_disclosure: bool = True
    require_business_identity_disclosure: bool = True
    require_opt_out_phrase: bool = True
    opt_out_phrases: Tuple[str, ...] = (
        "stop calling me",
        "do not call",
        "remove me",
        "unsubscribe",
        "opt out",
    )
    blocked_topics: Tuple[str, ...] = (
        "payment card number",
        "credit card number",
        "cvv",
        "social security number",
        "passport number",
        "medical diagnosis",
        "health condition",
        "minor private information",
        "password",
        "one time passcode",
        "otp",
        "2fa code",
    )
    allow_emergency_handling: bool = False
    emergency_redirect_message: str = (
        "This assistant cannot handle emergencies. "
        "Please contact your local emergency services immediately."
    )

    def to_dict(self) -> Dict[str, Any]:
        data = dataclasses.asdict(self)
        data["opt_out_phrases"] = list(self.opt_out_phrases)
        data["blocked_topics"] = list(self.blocked_topics)
        return data


@dataclasses.dataclass(frozen=True)
class CallProviderPolicy:
    """
    Provider-neutral call integration settings.

    No secrets are stored here. Provider credentials must live in a secrets
    manager or environment variables outside this file.
    """

    provider_name: str = "provider_neutral"
    allowed_provider_names: Tuple[str, ...] = (
        "provider_neutral",
        "twilio",
        "plivo",
        "vonage",
        "telnyx",
        "custom_sip",
    )
    caller_id_required: bool = True
    verified_caller_id_only: bool = True
    allow_number_rotation: bool = False
    max_numbers_per_workspace: int = 10
    webhook_signature_required: bool = True
    provider_timeout_seconds: int = 20

    def to_dict(self) -> Dict[str, Any]:
        data = dataclasses.asdict(self)
        data["allowed_provider_names"] = list(self.allowed_provider_names)
        return data


@dataclasses.dataclass(frozen=True)
class CallConfigState:
    """Full immutable config state for one user/workspace scope."""

    user_id: str
    workspace_id: str
    config_id: str
    enabled: bool = True
    business_hours: BusinessHours = dataclasses.field(default_factory=BusinessHours)
    recording_policy: RecordingPolicy = dataclasses.field(default_factory=RecordingPolicy)
    auto_answer_policy: AutoAnswerPolicy = dataclasses.field(default_factory=AutoAnswerPolicy)
    legal_safety_policy: LegalSafetyPolicy = dataclasses.field(default_factory=LegalSafetyPolicy)
    provider_policy: CallProviderPolicy = dataclasses.field(default_factory=CallProviderPolicy)
    approved_contact_ids: Tuple[str, ...] = ()
    blocked_contact_ids: Tuple[str, ...] = ()
    approved_scripts: Tuple[str, ...] = ()
    tags: Tuple[str, ...] = ()
    created_at: str = dataclasses.field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = dataclasses.field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    version: str = "1.0.0"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "config_id": self.config_id,
            "enabled": self.enabled,
            "business_hours": self.business_hours.to_dict(),
            "recording_policy": self.recording_policy.to_dict(),
            "auto_answer_policy": self.auto_answer_policy.to_dict(),
            "legal_safety_policy": self.legal_safety_policy.to_dict(),
            "provider_policy": self.provider_policy.to_dict(),
            "approved_contact_ids": list(self.approved_contact_ids),
            "blocked_contact_ids": list(self.blocked_contact_ids),
            "approved_scripts": list(self.approved_scripts),
            "tags": list(self.tags),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "version": self.version,
        }


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class CallConfig(BaseAgent):
    """
    Call Agent configuration manager.

    Responsibilities:
        - Maintain safe call settings.
        - Validate SaaS user/workspace context.
        - Prevent unsafe recording/auto-answer defaults.
        - Provide legal/consent guardrails.
        - Prepare Security, Verification, Memory, Dashboard, and Registry payloads.
        - Return structured dict results for API/FastAPI integration.
    """

    AGENT_NAME = "call_config"
    AGENT_MODULE = "call_agent"
    FILE_PATH = "agents/super_agents/call_agent/config.py"
    VERSION = "1.0.0"

    SAFE_DEFAULT_RECORDING_POLICY = RecordingPolicy()
    SAFE_DEFAULT_AUTO_ANSWER_POLICY = AutoAnswerPolicy()
    SAFE_DEFAULT_LEGAL_POLICY = LegalSafetyPolicy()
    SAFE_DEFAULT_PROVIDER_POLICY = CallProviderPolicy()

    TWO_PARTY_US_REGIONS = frozenset(
        {
            "CA",
            "CT",
            "FL",
            "IL",
            "MD",
            "MA",
            "MT",
            "NV",
            "NH",
            "PA",
            "WA",
        }
    )

    def __init__(
        self,
        default_user_id: Optional[str] = None,
        default_workspace_id: Optional[str] = None,
        logger: Optional[logging.Logger] = None,
        strict_mode: bool = True,
    ) -> None:
        super().__init__(agent_name=self.AGENT_NAME)
        self.default_user_id = default_user_id
        self.default_workspace_id = default_workspace_id
        self.strict_mode = strict_mode
        self.logger = logger or LOGGER
        self._configs: Dict[Tuple[str, str], CallConfigState] = {}

    # ------------------------------------------------------------------
    # Public registry / router methods
    # ------------------------------------------------------------------

    def get_registry_metadata(self) -> Dict[str, Any]:
        """Return metadata compatible with Agent Registry and Agent Loader."""
        return {
            "success": True,
            "message": "CallConfig registry metadata prepared.",
            "data": {
                "agent_name": self.AGENT_NAME,
                "agent_module": self.AGENT_MODULE,
                "class_name": self.__class__.__name__,
                "file_path": self.FILE_PATH,
                "version": self.VERSION,
                "capabilities": [
                    "call_settings",
                    "recording_permissions",
                    "auto_answer_flags",
                    "legal_safety",
                    "consent_policy",
                    "provider_policy",
                    "dashboard_config",
                    "security_approval_payloads",
                    "verification_payloads",
                    "memory_payloads",
                ],
                "safe_to_import": True,
                "requires_network": False,
                "performs_real_calls": False,
                "performs_recording": False,
            },
            "error": None,
            "metadata": self._base_metadata(),
        }

    async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Master Agent compatible entrypoint.

        Supported task actions:
            - get_config
            - create_default_config
            - update_config
            - evaluate_call_permission
            - evaluate_recording_permission
            - export_config
            - reset_config
            - registry_metadata
        """
        context_result = self._validate_task_context(task)
        if not context_result["success"]:
            return context_result

        action = str(task.get("action", "get_config")).strip().lower()
        user_id = str(task["user_id"])
        workspace_id = str(task["workspace_id"])

        try:
            if action == "registry_metadata":
                return self.get_registry_metadata()

            if action == "create_default_config":
                return self.create_default_config(user_id=user_id, workspace_id=workspace_id)

            if action == "get_config":
                return self.get_config(user_id=user_id, workspace_id=workspace_id)

            if action == "update_config":
                updates = task.get("updates", {})
                if not isinstance(updates, Mapping):
                    return self._error_result(
                        message="Config updates must be a dictionary.",
                        error="INVALID_UPDATES",
                        metadata={"action": action},
                    )
                return self.update_config(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    updates=dict(updates),
                    actor_id=str(task.get("actor_id") or user_id),
                    reason=str(task.get("reason") or "config_update"),
                )

            if action == "evaluate_call_permission":
                return self.evaluate_call_permission(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    call_context=dict(task.get("call_context") or {}),
                )

            if action == "evaluate_recording_permission":
                return self.evaluate_recording_permission(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    call_context=dict(task.get("call_context") or {}),
                )

            if action == "export_config":
                return self.export_config(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    actor_id=str(task.get("actor_id") or user_id),
                )

            if action == "reset_config":
                return self.reset_config(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    actor_id=str(task.get("actor_id") or user_id),
                    reason=str(task.get("reason") or "reset_config"),
                )

            return self._error_result(
                message=f"Unsupported CallConfig action: {action}",
                error="UNSUPPORTED_ACTION",
                metadata={"action": action},
            )

        except Exception as exc:
            self.logger.exception("CallConfig task failed.")
            return self._error_result(
                message="CallConfig task failed safely.",
                error=str(exc),
                metadata={"action": action},
            )

    # ------------------------------------------------------------------
    # Public config methods
    # ------------------------------------------------------------------

    def create_default_config(
        self,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create or replace a safe default config for a user/workspace."""
        user_id, workspace_id = self._resolve_scope(user_id, workspace_id)
        scope_result = self._validate_scope(user_id, workspace_id)
        if not scope_result["success"]:
            return scope_result

        state = CallConfigState(
            user_id=user_id,
            workspace_id=workspace_id,
            config_id=self._new_config_id(),
        )
        self._configs[(user_id, workspace_id)] = state

        self._emit_agent_event(
            event_name="call_config.created",
            user_id=user_id,
            workspace_id=workspace_id,
            data={"config_id": state.config_id},
        )
        self._log_audit_event(
            event_type="CONFIG_CREATED",
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=user_id,
            details={"config_id": state.config_id, "safe_defaults": True},
        )

        return self._safe_result(
            message="Safe default Call Agent config created.",
            data={"config": state.to_dict()},
            metadata={
                "verification": self._prepare_verification_payload(
                    action="create_default_config",
                    user_id=user_id,
                    workspace_id=workspace_id,
                    before=None,
                    after=state.to_dict(),
                ),
                "memory": self._prepare_memory_payload(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    config=state,
                    reason="default_config_created",
                ),
            },
        )

    def get_config(
        self,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        create_if_missing: bool = True,
    ) -> Dict[str, Any]:
        """Return current config for a user/workspace."""
        user_id, workspace_id = self._resolve_scope(user_id, workspace_id)
        scope_result = self._validate_scope(user_id, workspace_id)
        if not scope_result["success"]:
            return scope_result

        state = self._configs.get((user_id, workspace_id))
        if state is None and create_if_missing:
            return self.create_default_config(user_id=user_id, workspace_id=workspace_id)

        if state is None:
            return self._error_result(
                message="No Call Agent config exists for this user/workspace.",
                error="CONFIG_NOT_FOUND",
                metadata={"user_id": user_id, "workspace_id": workspace_id},
            )

        return self._safe_result(
            message="Call Agent config loaded.",
            data={"config": state.to_dict()},
            metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
        )

    def update_config(
        self,
        user_id: Optional[str],
        workspace_id: Optional[str],
        updates: Dict[str, Any],
        actor_id: Optional[str] = None,
        reason: str = "config_update",
    ) -> Dict[str, Any]:
        """
        Safely update config.

        Sensitive updates trigger Security Agent approval payload generation.
        This method does not execute external approval calls directly; it prepares
        a structured payload that the Security Agent or Master Agent can consume.
        """
        user_id, workspace_id = self._resolve_scope(user_id, workspace_id)
        actor_id = actor_id or user_id

        scope_result = self._validate_scope(user_id, workspace_id)
        if not scope_result["success"]:
            return scope_result

        current_result = self.get_config(user_id=user_id, workspace_id=workspace_id)
        if not current_result["success"]:
            return current_result

        current_state = self._configs[(user_id, workspace_id)]
        before = current_state.to_dict()

        validation_result = self._validate_update_payload(updates)
        if not validation_result["success"]:
            return validation_result

        sensitive_actions = self._requires_security_check(updates)
        approval_payload = None
        if sensitive_actions:
            approval_payload = self._request_security_approval(
                user_id=user_id,
                workspace_id=workspace_id,
                actor_id=actor_id,
                action="update_call_config",
                requested_changes=updates,
                sensitive_actions=sensitive_actions,
                reason=reason,
            )

            if self.strict_mode and not approval_payload.get("approved", False):
                return self._error_result(
                    message=(
                        "Sensitive Call Agent config update requires Security Agent approval. "
                        "No config changes were applied."
                    ),
                    error="SECURITY_APPROVAL_REQUIRED",
                    data={"security_approval": approval_payload},
                    metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
                )

        new_state = self._apply_updates(current_state, updates)
        self._configs[(user_id, workspace_id)] = new_state
        after = new_state.to_dict()

        verification_payload = self._prepare_verification_payload(
            action="update_config",
            user_id=user_id,
            workspace_id=workspace_id,
            before=before,
            after=after,
            actor_id=actor_id,
            reason=reason,
        )
        memory_payload = self._prepare_memory_payload(
            user_id=user_id,
            workspace_id=workspace_id,
            config=new_state,
            reason=reason,
        )

        self._emit_agent_event(
            event_name="call_config.updated",
            user_id=user_id,
            workspace_id=workspace_id,
            data={
                "config_id": new_state.config_id,
                "sensitive_actions": [item.value for item in sensitive_actions],
            },
        )
        self._log_audit_event(
            event_type="CONFIG_UPDATED",
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id,
            details={
                "reason": reason,
                "sensitive_actions": [item.value for item in sensitive_actions],
                "updated_fields": sorted(updates.keys()),
            },
        )

        return self._safe_result(
            message="Call Agent config updated safely.",
            data={
                "config": after,
                "security_approval": approval_payload,
            },
            metadata={
                **self._base_metadata(user_id=user_id, workspace_id=workspace_id),
                "verification": verification_payload,
                "memory": memory_payload,
            },
        )

    def reset_config(
        self,
        user_id: Optional[str],
        workspace_id: Optional[str],
        actor_id: Optional[str] = None,
        reason: str = "reset_config",
    ) -> Dict[str, Any]:
        """Reset config to safe defaults."""
        user_id, workspace_id = self._resolve_scope(user_id, workspace_id)
        actor_id = actor_id or user_id

        current_state = self._configs.get((user_id, workspace_id))
        before = current_state.to_dict() if current_state else None

        new_state = CallConfigState(
            user_id=user_id,
            workspace_id=workspace_id,
            config_id=self._new_config_id(),
        )
        self._configs[(user_id, workspace_id)] = new_state

        self._emit_agent_event(
            event_name="call_config.reset",
            user_id=user_id,
            workspace_id=workspace_id,
            data={"config_id": new_state.config_id},
        )
        self._log_audit_event(
            event_type="CONFIG_RESET",
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id,
            details={"reason": reason},
        )

        return self._safe_result(
            message="Call Agent config reset to safe defaults.",
            data={"config": new_state.to_dict()},
            metadata={
                **self._base_metadata(user_id=user_id, workspace_id=workspace_id),
                "verification": self._prepare_verification_payload(
                    action="reset_config",
                    user_id=user_id,
                    workspace_id=workspace_id,
                    before=before,
                    after=new_state.to_dict(),
                    actor_id=actor_id,
                    reason=reason,
                ),
            },
        )

    def export_config(
        self,
        user_id: Optional[str],
        workspace_id: Optional[str],
        actor_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Export config without secrets.

        This is safe because provider secrets are not stored in this file.
        """
        user_id, workspace_id = self._resolve_scope(user_id, workspace_id)
        actor_id = actor_id or user_id

        state = self._configs.get((user_id, workspace_id))
        if state is None:
            return self._error_result(
                message="No config available to export.",
                error="CONFIG_NOT_FOUND",
                metadata={"user_id": user_id, "workspace_id": workspace_id},
            )

        approval = self._request_security_approval(
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id,
            action="export_call_config",
            requested_changes={},
            sensitive_actions=[SecurityAction.EXPORT_CONFIG],
            reason="export_config",
        )

        if self.strict_mode and not approval.get("approved", False):
            return self._error_result(
                message="Export requires Security Agent approval.",
                error="SECURITY_APPROVAL_REQUIRED",
                data={"security_approval": approval},
                metadata=self._base_metadata(user_id=user_id, workspace_id=workspace_id),
            )

        export_data = state.to_dict()
        export_data["exported_at"] = datetime.now(timezone.utc).isoformat()
        export_data["contains_secrets"] = False

        self._log_audit_event(
            event_type="CONFIG_EXPORTED",
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id,
            details={"config_id": state.config_id},
        )

        return self._safe_result(
            message="Call Agent config exported safely.",
            data={"config_export": export_data},
            metadata={
                **self._base_metadata(user_id=user_id, workspace_id=workspace_id),
                "security_approval": approval,
            },
        )

    # ------------------------------------------------------------------
    # Permission evaluation
    # ------------------------------------------------------------------

    def evaluate_call_permission(
        self,
        user_id: Optional[str],
        workspace_id: Optional[str],
        call_context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Evaluate whether Call Agent may answer/handle a call.

        This method only evaluates config. It does not answer calls.
        """
        user_id, workspace_id = self._resolve_scope(user_id, workspace_id)
        config_result = self.get_config(user_id=user_id, workspace_id=workspace_id)
        if not config_result["success"]:
            return config_result

        state = self._configs[(user_id, workspace_id)]
        direction = self._coerce_enum(
            CallDirection,
            call_context.get("direction", CallDirection.INBOUND.value),
            CallDirection.INBOUND,
        )
        caller_type = self._coerce_enum(
            CallerType,
            call_context.get("caller_type", CallerType.UNKNOWN.value),
            CallerType.UNKNOWN,
        )
        contact_id = str(call_context.get("contact_id") or "")
        is_after_hours = bool(call_context.get("is_after_hours", False))
        script_id = str(call_context.get("script_id") or "")
        text_signal = str(call_context.get("text_signal") or "").lower()

        reasons: List[str] = []
        warnings: List[str] = []
        allowed = True
        risk = RiskLevel.LOW

        if not state.enabled:
            allowed = False
            risk = RiskLevel.BLOCKED
            reasons.append("Call Agent config is disabled.")

        if caller_type == CallerType.BLOCKED or contact_id in state.blocked_contact_ids:
            allowed = False
            risk = RiskLevel.BLOCKED
            reasons.append("Caller/contact is blocked.")

        auto_policy = state.auto_answer_policy

        if auto_policy.auto_answer_mode == AutoAnswerMode.DISABLED:
            allowed = False
            risk = RiskLevel.MEDIUM
            reasons.append("Auto-answer is disabled.")

        if direction == CallDirection.OUTBOUND and not auto_policy.allow_outbound_auto_call:
            allowed = False
            risk = RiskLevel.BLOCKED
            reasons.append("Outbound auto-calling is disabled.")

        if auto_policy.block_after_hours and is_after_hours:
            allowed = False
            risk = RiskLevel.MEDIUM
            reasons.append("Call is outside business hours.")

        if auto_policy.block_unknown_callers and caller_type == CallerType.UNKNOWN:
            allowed = False
            risk = RiskLevel.MEDIUM
            reasons.append("Unknown callers are blocked by policy.")

        if auto_policy.auto_answer_mode == AutoAnswerMode.APPROVED_CONTACTS_ONLY:
            if contact_id not in state.approved_contact_ids:
                allowed = False
                risk = RiskLevel.MEDIUM
                reasons.append("Auto-answer is limited to approved contacts.")

        if auto_policy.require_approved_script and script_id:
            if script_id not in state.approved_scripts:
                allowed = False
                risk = RiskLevel.HIGH
                reasons.append("Script is not approved for automated call handling.")

        if auto_policy.require_caller_disclosure:
            warnings.append("Caller disclosure must be included before assistance continues.")

        if auto_policy.disclose_ai_assistant:
            warnings.append("AI assistant identity disclosure is required.")

        handoff_required = self._detect_human_handoff_required(
            text_signal=text_signal,
            keywords=auto_policy.human_handoff_keywords,
        )
        if handoff_required:
            warnings.append("Human handoff should be offered or triggered.")

        legal_findings = self._evaluate_legal_text_safety(state, text_signal)
        if legal_findings["blocked"]:
            allowed = False
            risk = RiskLevel.BLOCKED
            reasons.extend(legal_findings["reasons"])
        warnings.extend(legal_findings["warnings"])

        return self._safe_result(
            message="Call permission evaluated.",
            data={
                "allowed": allowed,
                "risk_level": risk.value,
                "reasons": reasons,
                "warnings": warnings,
                "human_handoff_required": handoff_required,
                "recommended_route": self._recommended_route(
                    allowed=allowed,
                    risk=risk,
                    auto_policy=auto_policy,
                    caller_type=caller_type,
                ),
                "policy_snapshot": {
                    "auto_answer_mode": auto_policy.auto_answer_mode.value,
                    "direction": direction.value,
                    "caller_type": caller_type.value,
                    "is_after_hours": is_after_hours,
                },
            },
            metadata={
                **self._base_metadata(user_id=user_id, workspace_id=workspace_id),
                "verification": self._prepare_verification_payload(
                    action="evaluate_call_permission",
                    user_id=user_id,
                    workspace_id=workspace_id,
                    before=None,
                    after={
                        "allowed": allowed,
                        "risk_level": risk.value,
                        "reasons": reasons,
                    },
                ),
            },
        )

    def evaluate_recording_permission(
        self,
        user_id: Optional[str],
        workspace_id: Optional[str],
        call_context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Evaluate whether recording/transcription/storage is allowed.

        This method only evaluates. It does not record or transcribe.
        """
        user_id, workspace_id = self._resolve_scope(user_id, workspace_id)
        config_result = self.get_config(user_id=user_id, workspace_id=workspace_id)
        if not config_result["success"]:
            return config_result

        state = self._configs[(user_id, workspace_id)]
        policy = state.recording_policy
        legal_policy = state.legal_safety_policy

        country_code = str(call_context.get("country_code") or legal_policy.default_country_code).upper()
        region_code = str(call_context.get("region_code") or legal_policy.default_region_code).upper()
        consent_captured = bool(call_context.get("consent_captured", False))
        transcription_consent_captured = bool(call_context.get("transcription_consent_captured", False))
        caller_is_minor = bool(call_context.get("caller_is_minor", False))
        guardian_consent_captured = bool(call_context.get("guardian_consent_captured", False))
        text_signal = str(call_context.get("text_signal") or "").lower()

        reasons: List[str] = []
        warnings: List[str] = []
        allowed_recording = True
        allowed_transcription = True
        allowed_storage = policy.allow_storage
        risk = RiskLevel.LOW

        if policy.recording_mode == RecordingMode.DISABLED:
            allowed_recording = False
            allowed_transcription = False
            allowed_storage = False
            risk = RiskLevel.LOW
            reasons.append("Recording mode is disabled.")

        if policy.recording_mode in {RecordingMode.CONSENT_REQUIRED, RecordingMode.MANUAL_ONLY}:
            if not consent_captured:
                allowed_recording = False
                risk = RiskLevel.MEDIUM
                reasons.append("Recording consent has not been captured.")

        required_consent = self._determine_required_consent_mode(
            configured_mode=policy.consent_mode,
            country_code=country_code,
            region_code=region_code,
            strictest=legal_policy.strictest_consent_wins,
        )

        if required_consent in {
            ConsentMode.TWO_PARTY,
            ConsentMode.ALL_PARTY,
            ConsentMode.EXPLICIT_OPT_IN,
        } and not consent_captured:
            allowed_recording = False
            risk = RiskLevel.HIGH
            reasons.append(f"{required_consent.value} consent is required before recording.")

        if policy.require_transcription_notice and not transcription_consent_captured:
            allowed_transcription = False
            risk = RiskLevel.MEDIUM
            reasons.append("Transcription notice/consent has not been captured.")

        if policy.block_minor_recording_without_guardian and caller_is_minor and not guardian_consent_captured:
            allowed_recording = False
            allowed_transcription = False
            allowed_storage = False
            risk = RiskLevel.BLOCKED
            reasons.append("Minor recording requires guardian consent.")

        text_findings = self._evaluate_legal_text_safety(state, text_signal)
        if text_findings["blocked"]:
            allowed_recording = False
            allowed_transcription = False
            allowed_storage = False
            risk = RiskLevel.BLOCKED
            reasons.extend(text_findings["reasons"])
        warnings.extend(text_findings["warnings"])

        if policy.redact_sensitive_data:
            warnings.append("Sensitive data redaction must be applied before storage or summaries.")

        if allowed_storage and policy.retention_days > policy.max_retention_days:
            allowed_storage = False
            risk = RiskLevel.HIGH
            reasons.append("Retention period exceeds maximum allowed policy.")

        return self._safe_result(
            message="Recording permission evaluated.",
            data={
                "allowed_recording": allowed_recording,
                "allowed_transcription": allowed_transcription,
                "allowed_storage": allowed_storage,
                "risk_level": risk.value,
                "required_consent_mode": required_consent.value,
                "reasons": reasons,
                "warnings": warnings,
                "retention_days": policy.retention_days if allowed_storage else 0,
                "policy_snapshot": {
                    "recording_mode": policy.recording_mode.value,
                    "configured_consent_mode": policy.consent_mode.value,
                    "country_code": country_code,
                    "region_code": region_code,
                    "consent_captured": consent_captured,
                    "transcription_consent_captured": transcription_consent_captured,
                },
            },
            metadata={
                **self._base_metadata(user_id=user_id, workspace_id=workspace_id),
                "verification": self._prepare_verification_payload(
                    action="evaluate_recording_permission",
                    user_id=user_id,
                    workspace_id=workspace_id,
                    before=None,
                    after={
                        "allowed_recording": allowed_recording,
                        "allowed_transcription": allowed_transcription,
                        "allowed_storage": allowed_storage,
                        "risk_level": risk.value,
                    },
                ),
            },
        )

    # ------------------------------------------------------------------
    # Compatibility hooks required by William/Jarvis architecture
    # ------------------------------------------------------------------

    def _validate_task_context(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """Validate task context for SaaS isolation."""
        if not isinstance(task, Mapping):
            return self._error_result(
                message="Task must be a dictionary.",
                error="INVALID_TASK",
                metadata=self._base_metadata(),
            )

        user_id = task.get("user_id") or self.default_user_id
        workspace_id = task.get("workspace_id") or self.default_workspace_id

        if not self._is_valid_identifier(user_id):
            return self._error_result(
                message="Valid user_id is required for CallConfig task.",
                error="MISSING_OR_INVALID_USER_ID",
                metadata=self._base_metadata(),
            )

        if not self._is_valid_identifier(workspace_id):
            return self._error_result(
                message="Valid workspace_id is required for CallConfig task.",
                error="MISSING_OR_INVALID_WORKSPACE_ID",
                metadata=self._base_metadata(user_id=str(user_id) if user_id else None),
            )

        task["user_id"] = str(user_id)  # type: ignore[index]
        task["workspace_id"] = str(workspace_id)  # type: ignore[index]
        return self._safe_result(
            message="Task context validated.",
            data={"user_id": str(user_id), "workspace_id": str(workspace_id)},
            metadata=self._base_metadata(user_id=str(user_id), workspace_id=str(workspace_id)),
        )

    def _requires_security_check(self, updates: Mapping[str, Any]) -> List[SecurityAction]:
        """Determine if updates include sensitive changes."""
        actions: List[SecurityAction] = []

        recording_updates = updates.get("recording_policy")
        if isinstance(recording_updates, Mapping):
            if "recording_mode" in recording_updates:
                mode = str(recording_updates["recording_mode"])
                if mode != RecordingMode.DISABLED.value:
                    actions.append(SecurityAction.ENABLE_RECORDING)
            if "consent_mode" in recording_updates:
                actions.append(SecurityAction.CHANGE_CONSENT_MODE)
            if "retention_days" in recording_updates or "allow_storage" in recording_updates:
                actions.append(SecurityAction.CHANGE_RETENTION)

        auto_updates = updates.get("auto_answer_policy")
        if isinstance(auto_updates, Mapping):
            if "auto_answer_mode" in auto_updates:
                mode = str(auto_updates["auto_answer_mode"])
                if mode != AutoAnswerMode.DISABLED.value:
                    actions.append(SecurityAction.ENABLE_AUTO_ANSWER)
            if "allow_outbound_auto_call" in auto_updates and bool(auto_updates["allow_outbound_auto_call"]):
                actions.append(SecurityAction.ENABLE_AUTO_ANSWER)

        legal_updates = updates.get("legal_safety_policy")
        if isinstance(legal_updates, Mapping):
            if "strictest_consent_wins" in legal_updates and not bool(legal_updates["strictest_consent_wins"]):
                actions.append(SecurityAction.OVERRIDE_SAFETY)
            if "default_country_code" in legal_updates or "default_region_code" in legal_updates:
                actions.append(SecurityAction.CHANGE_CONSENT_MODE)

        provider_updates = updates.get("provider_policy")
        if isinstance(provider_updates, Mapping):
            if "allow_number_rotation" in provider_updates and bool(provider_updates["allow_number_rotation"]):
                actions.append(SecurityAction.OVERRIDE_SAFETY)
            if "verified_caller_id_only" in provider_updates and not bool(provider_updates["verified_caller_id_only"]):
                actions.append(SecurityAction.OVERRIDE_SAFETY)

        unique: List[SecurityAction] = []
        for action in actions:
            if action not in unique:
                unique.append(action)
        return unique

    def _request_security_approval(
        self,
        user_id: str,
        workspace_id: str,
        actor_id: str,
        action: str,
        requested_changes: Mapping[str, Any],
        sensitive_actions: Iterable[SecurityAction],
        reason: str,
    ) -> Dict[str, Any]:
        """
        Prepare Security Agent approval payload.

        In strict standalone mode this returns approved=False so the Master Agent
        or Security Agent must explicitly approve before sensitive changes apply.
        """
        payload = {
            "approval_id": f"sec_{uuid.uuid4().hex}",
            "required": True,
            "approved": False,
            "action": action,
            "sensitive_actions": [item.value for item in sensitive_actions],
            "user_id": user_id,
            "workspace_id": workspace_id,
            "actor_id": actor_id,
            "reason": reason,
            "requested_changes": self._redact_for_logs(dict(requested_changes)),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "target_agent": "security_agent",
            "source_agent": self.AGENT_NAME,
            "message": "Security Agent approval required for sensitive Call Agent config change.",
        }
        self._emit_agent_event(
            event_name="call_config.security_approval_requested",
            user_id=user_id,
            workspace_id=workspace_id,
            data={
                "approval_id": payload["approval_id"],
                "action": action,
                "sensitive_actions": payload["sensitive_actions"],
            },
        )
        return payload

    def _prepare_verification_payload(
        self,
        action: str,
        user_id: str,
        workspace_id: str,
        before: Optional[Dict[str, Any]],
        after: Optional[Dict[str, Any]],
        actor_id: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Prepare Verification Agent-compatible payload."""
        return {
            "verification_id": f"ver_{uuid.uuid4().hex}",
            "target_agent": "verification_agent",
            "source_agent": self.AGENT_NAME,
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "actor_id": actor_id or user_id,
            "reason": reason,
            "before": self._redact_for_logs(before) if before is not None else None,
            "after": self._redact_for_logs(after) if after is not None else None,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "requires_human_review": action in {
                "update_config",
                "reset_config",
                "evaluate_recording_permission",
            },
        }

    def _prepare_memory_payload(
        self,
        user_id: str,
        workspace_id: str,
        config: CallConfigState,
        reason: str,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent-compatible payload.

        Only safe preference/config summaries are included.
        No call audio, transcripts, secrets, or private caller details are stored.
        """
        return {
            "memory_id": f"mem_{uuid.uuid4().hex}",
            "target_agent": "memory_agent",
            "source_agent": self.AGENT_NAME,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "memory_type": "call_config_preference",
            "reason": reason,
            "safe_to_store": True,
            "contains_call_content": False,
            "contains_audio": False,
            "contains_secret": False,
            "data": {
                "auto_answer_mode": config.auto_answer_policy.auto_answer_mode.value,
                "recording_mode": config.recording_policy.recording_mode.value,
                "consent_mode": config.recording_policy.consent_mode.value,
                "business_hours": config.business_hours.to_dict(),
                "legal_country": config.legal_safety_policy.default_country_code,
                "legal_region": config.legal_safety_policy.default_region_code,
                "retention_days": config.recording_policy.retention_days,
            },
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

    def _emit_agent_event(
        self,
        event_name: str,
        user_id: Optional[str],
        workspace_id: Optional[str],
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Emit safe local event payload for future event bus/dashboard integration."""
        event = {
            "event_id": f"evt_{uuid.uuid4().hex}",
            "event_name": event_name,
            "agent": self.AGENT_NAME,
            "module": self.AGENT_MODULE,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "data": self._redact_for_logs(data or {}),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self.logger.info("Agent event: %s", event)
        return event

    def _log_audit_event(
        self,
        event_type: str,
        user_id: str,
        workspace_id: str,
        actor_id: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Prepare and log audit event for future audit store integration."""
        audit = {
            "audit_id": f"aud_{uuid.uuid4().hex}",
            "event_type": event_type,
            "agent": self.AGENT_NAME,
            "module": self.AGENT_MODULE,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "actor_id": actor_id,
            "details": self._redact_for_logs(details or {}),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self.logger.info("Audit event: %s", audit)
        return audit

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard success result."""
        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": metadata or self._base_metadata(),
        }

    def _error_result(
        self,
        message: str,
        error: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard error result."""
        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": error,
            "metadata": metadata or self._base_metadata(),
        }

    # ------------------------------------------------------------------
    # Validation helpers
    # ------------------------------------------------------------------

    def _validate_scope(self, user_id: Optional[str], workspace_id: Optional[str]) -> Dict[str, Any]:
        """Validate SaaS tenant scope."""
        if not self._is_valid_identifier(user_id):
            return self._error_result(
                message="Valid user_id is required.",
                error="MISSING_OR_INVALID_USER_ID",
                metadata=self._base_metadata(),
            )
        if not self._is_valid_identifier(workspace_id):
            return self._error_result(
                message="Valid workspace_id is required.",
                error="MISSING_OR_INVALID_WORKSPACE_ID",
                metadata=self._base_metadata(user_id=str(user_id)),
            )
        return self._safe_result(
            message="Scope validated.",
            data={"user_id": str(user_id), "workspace_id": str(workspace_id)},
            metadata=self._base_metadata(user_id=str(user_id), workspace_id=str(workspace_id)),
        )

    def _validate_update_payload(self, updates: Mapping[str, Any]) -> Dict[str, Any]:
        """Validate supported config update structure."""
        allowed_top_level = {
            "enabled",
            "business_hours",
            "recording_policy",
            "auto_answer_policy",
            "legal_safety_policy",
            "provider_policy",
            "approved_contact_ids",
            "blocked_contact_ids",
            "approved_scripts",
            "tags",
        }

        unknown = set(updates.keys()) - allowed_top_level
        if unknown:
            return self._error_result(
                message=f"Unsupported config update fields: {sorted(unknown)}",
                error="UNSUPPORTED_CONFIG_FIELDS",
            )

        for section in (
            "business_hours",
            "recording_policy",
            "auto_answer_policy",
            "legal_safety_policy",
            "provider_policy",
        ):
            if section in updates and not isinstance(updates[section], Mapping):
                return self._error_result(
                    message=f"{section} must be a dictionary.",
                    error="INVALID_CONFIG_SECTION",
                )

        if "business_hours" in updates:
            result = self._validate_business_hours(dict(updates["business_hours"]))
            if not result["success"]:
                return result

        if "recording_policy" in updates:
            result = self._validate_recording_policy(dict(updates["recording_policy"]))
            if not result["success"]:
                return result

        if "auto_answer_policy" in updates:
            result = self._validate_auto_answer_policy(dict(updates["auto_answer_policy"]))
            if not result["success"]:
                return result

        if "legal_safety_policy" in updates:
            result = self._validate_legal_policy(dict(updates["legal_safety_policy"]))
            if not result["success"]:
                return result

        if "provider_policy" in updates:
            result = self._validate_provider_policy(dict(updates["provider_policy"]))
            if not result["success"]:
                return result

        for list_field in ("approved_contact_ids", "blocked_contact_ids", "approved_scripts", "tags"):
            if list_field in updates:
                if not isinstance(updates[list_field], (list, tuple, set)):
                    return self._error_result(
                        message=f"{list_field} must be a list, tuple, or set.",
                        error="INVALID_LIST_FIELD",
                    )

        return self._safe_result(message="Update payload validated.")

    def _validate_business_hours(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate business hours updates."""
        if "start_time" in data and not self._is_hhmm(str(data["start_time"])):
            return self._error_result("start_time must be HH:MM.", "INVALID_START_TIME")
        if "end_time" in data and not self._is_hhmm(str(data["end_time"])):
            return self._error_result("end_time must be HH:MM.", "INVALID_END_TIME")
        if "closed_days" in data:
            if not isinstance(data["closed_days"], (list, tuple, set)):
                return self._error_result("closed_days must be a list/tuple/set.", "INVALID_CLOSED_DAYS")
            if any(int(day) < 1 or int(day) > 7 for day in data["closed_days"]):
                return self._error_result("closed_days values must be 1-7.", "INVALID_CLOSED_DAYS")
        return self._safe_result("Business hours validated.")

    def _validate_recording_policy(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate recording policy updates."""
        if "recording_mode" in data:
            if not self._is_enum_value(RecordingMode, data["recording_mode"]):
                return self._error_result("Invalid recording_mode.", "INVALID_RECORDING_MODE")
        if "consent_mode" in data:
            if not self._is_enum_value(ConsentMode, data["consent_mode"]):
                return self._error_result("Invalid consent_mode.", "INVALID_CONSENT_MODE")
        if "retention_days" in data:
            retention = int(data["retention_days"])
            if retention < 0 or retention > 3650:
                return self._error_result("retention_days must be between 0 and 3650.", "INVALID_RETENTION_DAYS")
        return self._safe_result("Recording policy validated.")

    def _validate_auto_answer_policy(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate auto-answer policy updates."""
        if "auto_answer_mode" in data:
            if not self._is_enum_value(AutoAnswerMode, data["auto_answer_mode"]):
                return self._error_result("Invalid auto_answer_mode.", "INVALID_AUTO_ANSWER_MODE")
        if "max_auto_answer_per_hour" in data:
            value = int(data["max_auto_answer_per_hour"])
            if value < 0 or value > 1000:
                return self._error_result(
                    "max_auto_answer_per_hour must be between 0 and 1000.",
                    "INVALID_AUTO_ANSWER_LIMIT",
                )
        return self._safe_result("Auto-answer policy validated.")

    def _validate_legal_policy(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate legal safety policy updates."""
        if "default_country_code" in data:
            country = str(data["default_country_code"]).upper()
            if not re.fullmatch(r"[A-Z]{2}", country):
                return self._error_result("default_country_code must be ISO-like 2 letters.", "INVALID_COUNTRY_CODE")
        if "default_region_code" in data:
            region = str(data["default_region_code"]).upper()
            if region and not re.fullmatch(r"[A-Z0-9_-]{1,10}", region):
                return self._error_result("default_region_code is invalid.", "INVALID_REGION_CODE")
        return self._safe_result("Legal safety policy validated.")

    def _validate_provider_policy(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate provider policy updates."""
        if "provider_name" in data:
            provider_name = str(data["provider_name"])
            allowed = self.SAFE_DEFAULT_PROVIDER_POLICY.allowed_provider_names
            if provider_name not in allowed:
                return self._error_result(
                    f"provider_name must be one of: {list(allowed)}",
                    "INVALID_PROVIDER_NAME",
                )
        if "max_numbers_per_workspace" in data:
            value = int(data["max_numbers_per_workspace"])
            if value < 1 or value > 10000:
                return self._error_result(
                    "max_numbers_per_workspace must be between 1 and 10000.",
                    "INVALID_PROVIDER_NUMBER_LIMIT",
                )
        return self._safe_result("Provider policy validated.")

    # ------------------------------------------------------------------
    # Internal config mutation helpers
    # ------------------------------------------------------------------

    def _apply_updates(self, state: CallConfigState, updates: Mapping[str, Any]) -> CallConfigState:
        """Apply validated updates immutably."""
        data = state.to_dict()

        if "enabled" in updates:
            data["enabled"] = bool(updates["enabled"])

        for section_name, dataclass_type in (
            ("business_hours", BusinessHours),
            ("recording_policy", RecordingPolicy),
            ("auto_answer_policy", AutoAnswerPolicy),
            ("legal_safety_policy", LegalSafetyPolicy),
            ("provider_policy", CallProviderPolicy),
        ):
            if section_name in updates:
                section_data = copy.deepcopy(data[section_name])
                section_data.update(dict(updates[section_name]))
                data[section_name] = self._construct_section(dataclass_type, section_data).to_dict()

        for list_field in ("approved_contact_ids", "blocked_contact_ids", "approved_scripts", "tags"):
            if list_field in updates:
                data[list_field] = self._clean_string_list(updates[list_field])

        data["updated_at"] = datetime.now(timezone.utc).isoformat()

        return CallConfigState(
            user_id=data["user_id"],
            workspace_id=data["workspace_id"],
            config_id=data["config_id"],
            enabled=bool(data["enabled"]),
            business_hours=self._construct_section(BusinessHours, data["business_hours"]),
            recording_policy=self._construct_section(RecordingPolicy, data["recording_policy"]),
            auto_answer_policy=self._construct_section(AutoAnswerPolicy, data["auto_answer_policy"]),
            legal_safety_policy=self._construct_section(LegalSafetyPolicy, data["legal_safety_policy"]),
            provider_policy=self._construct_section(CallProviderPolicy, data["provider_policy"]),
            approved_contact_ids=tuple(data["approved_contact_ids"]),
            blocked_contact_ids=tuple(data["blocked_contact_ids"]),
            approved_scripts=tuple(data["approved_scripts"]),
            tags=tuple(data["tags"]),
            created_at=data["created_at"],
            updated_at=data["updated_at"],
            version=data["version"],
        )

    def _construct_section(self, dataclass_type: Any, data: Dict[str, Any]) -> Any:
        """Construct config section with enum conversion."""
        cleaned = dict(data)

        if dataclass_type is RecordingPolicy:
            if "recording_mode" in cleaned:
                cleaned["recording_mode"] = self._coerce_enum(
                    RecordingMode,
                    cleaned["recording_mode"],
                    RecordingMode.CONSENT_REQUIRED,
                )
            if "consent_mode" in cleaned:
                cleaned["consent_mode"] = self._coerce_enum(
                    ConsentMode,
                    cleaned["consent_mode"],
                    ConsentMode.EXPLICIT_OPT_IN,
                )

        if dataclass_type is AutoAnswerPolicy:
            if "auto_answer_mode" in cleaned:
                cleaned["auto_answer_mode"] = self._coerce_enum(
                    AutoAnswerMode,
                    cleaned["auto_answer_mode"],
                    AutoAnswerMode.DISABLED,
                )
            if "human_handoff_keywords" in cleaned:
                cleaned["human_handoff_keywords"] = tuple(
                    self._clean_string_list(cleaned["human_handoff_keywords"])
                )

        if dataclass_type is LegalSafetyPolicy:
            if "opt_out_phrases" in cleaned:
                cleaned["opt_out_phrases"] = tuple(self._clean_string_list(cleaned["opt_out_phrases"]))
            if "blocked_topics" in cleaned:
                cleaned["blocked_topics"] = tuple(self._clean_string_list(cleaned["blocked_topics"]))

        if dataclass_type is CallProviderPolicy:
            if "allowed_provider_names" in cleaned:
                cleaned["allowed_provider_names"] = tuple(
                    self._clean_string_list(cleaned["allowed_provider_names"])
                )

        field_names = {field.name for field in dataclasses.fields(dataclass_type)}
        filtered = {key: value for key, value in cleaned.items() if key in field_names}
        return dataclass_type(**filtered)

    # ------------------------------------------------------------------
    # Legal/safety evaluation helpers
    # ------------------------------------------------------------------

    def _determine_required_consent_mode(
        self,
        configured_mode: ConsentMode,
        country_code: str,
        region_code: str,
        strictest: bool,
    ) -> ConsentMode:
        """
        Determine required consent mode.

        Uses safe conservative defaults:
            - US states commonly treated as all/two-party: two_party
            - Unknown strict mode: explicit_opt_in
            - Otherwise: configured mode
        """
        country_code = country_code.upper()
        region_code = region_code.upper()

        jurisdiction_mode = configured_mode

        if country_code == "US" and region_code in self.TWO_PARTY_US_REGIONS:
            jurisdiction_mode = ConsentMode.TWO_PARTY
        elif country_code not in {"US", "CA", "GB", "AU", "NZ"} and strictest:
            jurisdiction_mode = ConsentMode.EXPLICIT_OPT_IN

        if not strictest:
            return configured_mode

        rank = {
            ConsentMode.DISABLED: 0,
            ConsentMode.ONE_PARTY: 1,
            ConsentMode.TWO_PARTY: 2,
            ConsentMode.ALL_PARTY: 3,
            ConsentMode.EXPLICIT_OPT_IN: 4,
        }
        return configured_mode if rank[configured_mode] >= rank[jurisdiction_mode] else jurisdiction_mode

    def _evaluate_legal_text_safety(
        self,
        state: CallConfigState,
        text_signal: str,
    ) -> Dict[str, Any]:
        """Detect opt-out, blocked sensitive topics, and emergency signals."""
        legal_policy = state.legal_safety_policy
        recording_policy = state.recording_policy
        text = (text_signal or "").lower()

        reasons: List[str] = []
        warnings: List[str] = []
        blocked = False

        if not legal_policy.enabled:
            warnings.append("Legal safety policy is disabled; external review is recommended.")
            return {"blocked": False, "reasons": reasons, "warnings": warnings}

        for phrase in legal_policy.opt_out_phrases:
            if phrase.lower() in text:
                blocked = True
                reasons.append("Caller opt-out phrase detected.")
                break

        for topic in legal_policy.blocked_topics:
            if topic.lower() in text:
                blocked = True
                reasons.append(f"Blocked sensitive topic detected: {topic}")
                break

        if recording_policy.block_payment_card_capture:
            if any(item in text for item in ("cvv", "credit card", "card number", "debit card")):
                blocked = True
                reasons.append("Payment card capture is blocked by policy.")

        if recording_policy.block_government_id_capture:
            if any(item in text for item in ("ssn", "social security", "passport", "driver license")):
                blocked = True
                reasons.append("Government ID capture is blocked by policy.")

        if recording_policy.block_health_data_capture:
            if any(item in text for item in ("diagnosis", "medical record", "prescription", "health condition")):
                blocked = True
                reasons.append("Health data capture is blocked by policy.")

        if legal_policy.require_ai_identity_disclosure:
            warnings.append("AI identity disclosure is required.")

        if legal_policy.require_business_identity_disclosure:
            warnings.append("Business identity disclosure is required.")

        if legal_policy.require_opt_out_phrase:
            warnings.append("Opt-out instructions must be available where required.")

        if any(item in text for item in ("emergency", "heart attack", "fire", "police", "ambulance")):
            if not legal_policy.allow_emergency_handling:
                blocked = True
                reasons.append("Emergency-related signal detected; redirect to emergency services.")

        return {"blocked": blocked, "reasons": reasons, "warnings": warnings}

    def _detect_human_handoff_required(
        self,
        text_signal: str,
        keywords: Iterable[str],
    ) -> bool:
        """Return True when text signal indicates human handoff."""
        text = (text_signal or "").lower()
        return any(keyword.lower() in text for keyword in keywords)

    def _recommended_route(
        self,
        allowed: bool,
        risk: RiskLevel,
        auto_policy: AutoAnswerPolicy,
        caller_type: CallerType,
    ) -> str:
        """Recommend safe routing based on permission evaluation."""
        if risk == RiskLevel.BLOCKED:
            return "block_or_human_review"
        if not allowed and auto_policy.route_unknown_to_voicemail and caller_type == CallerType.UNKNOWN:
            return "voicemail"
        if not allowed:
            return "manual_review"
        if risk in {RiskLevel.MEDIUM, RiskLevel.HIGH}:
            return "human_handoff"
        return "call_agent"

    # ------------------------------------------------------------------
    # Generic helpers
    # ------------------------------------------------------------------

    def _resolve_scope(
        self,
        user_id: Optional[str],
        workspace_id: Optional[str],
    ) -> Tuple[str, str]:
        """Resolve user/workspace from explicit values or defaults."""
        resolved_user = str(user_id or self.default_user_id or "").strip()
        resolved_workspace = str(workspace_id or self.default_workspace_id or "").strip()
        return resolved_user, resolved_workspace

    def _base_metadata(
        self,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Standard metadata used in results."""
        return {
            "agent": self.AGENT_NAME,
            "module": self.AGENT_MODULE,
            "file_path": self.FILE_PATH,
            "version": self.VERSION,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "environment": os.getenv("WILLIAM_ENV", "development"),
        }

    def _new_config_id(self) -> str:
        """Generate config id."""
        return f"call_cfg_{uuid.uuid4().hex}"

    def _is_valid_identifier(self, value: Any) -> bool:
        """Validate user/workspace identifier without being overly restrictive."""
        if value is None:
            return False
        text = str(value).strip()
        if not text or len(text) > 128:
            return False
        return bool(re.fullmatch(r"[A-Za-z0-9_.:@\-]+", text))

    def _is_hhmm(self, value: str) -> bool:
        """Validate HH:MM 24-hour time."""
        if not re.fullmatch(r"\d{2}:\d{2}", value):
            return False
        hour, minute = value.split(":")
        return 0 <= int(hour) <= 23 and 0 <= int(minute) <= 59

    def _is_enum_value(self, enum_type: Any, value: Any) -> bool:
        """Return True if value is valid enum value."""
        try:
            enum_type(str(value))
            return True
        except Exception:
            return False

    def _coerce_enum(self, enum_type: Any, value: Any, default: Any) -> Any:
        """Safely coerce enum value."""
        try:
            if isinstance(value, enum_type):
                return value
            return enum_type(str(value))
        except Exception:
            return default

    def _clean_string_list(self, values: Iterable[Any]) -> List[str]:
        """Normalize list-like values to safe unique strings."""
        cleaned: List[str] = []
        for item in values:
            text = str(item).strip()
            if not text:
                continue
            if len(text) > 256:
                text = text[:256]
            if text not in cleaned:
                cleaned.append(text)
        return cleaned

    def _redact_for_logs(self, value: Any) -> Any:
        """Redact sensitive keys recursively for logs/events/payloads."""
        sensitive_keys = {
            "secret",
            "token",
            "api_key",
            "apikey",
            "password",
            "authorization",
            "auth",
            "credential",
            "private_key",
            "webhook_secret",
        }

        if isinstance(value, Mapping):
            redacted: Dict[str, Any] = {}
            for key, item in value.items():
                key_text = str(key)
                if any(secret_key in key_text.lower() for secret_key in sensitive_keys):
                    redacted[key_text] = "***REDACTED***"
                else:
                    redacted[key_text] = self._redact_for_logs(item)
            return redacted

        if isinstance(value, list):
            return [self._redact_for_logs(item) for item in value]

        if isinstance(value, tuple):
            return tuple(self._redact_for_logs(item) for item in value)

        return value


# ---------------------------------------------------------------------------
# Module-level safe defaults for dashboard/API import
# ---------------------------------------------------------------------------

DEFAULT_CALL_CONFIG = {
    "business_hours": BusinessHours().to_dict(),
    "recording_policy": RecordingPolicy().to_dict(),
    "auto_answer_policy": AutoAnswerPolicy().to_dict(),
    "legal_safety_policy": LegalSafetyPolicy().to_dict(),
    "provider_policy": CallProviderPolicy().to_dict(),
}

AGENT_REGISTRY_METADATA = {
    "agent_name": CallConfig.AGENT_NAME,
    "agent_module": CallConfig.AGENT_MODULE,
    "class_name": "CallConfig",
    "file_path": CallConfig.FILE_PATH,
    "version": CallConfig.VERSION,
    "safe_to_import": True,
    "requires_network": False,
    "performs_real_calls": False,
    "performs_recording": False,
}


__all__ = [
    "AutoAnswerMode",
    "AutoAnswerPolicy",
    "BusinessHours",
    "CallConfig",
    "CallConfigState",
    "CallDirection",
    "CallProviderPolicy",
    "CallerType",
    "ConsentMode",
    "DEFAULT_CALL_CONFIG",
    "AGENT_REGISTRY_METADATA",
    "LegalSafetyPolicy",
    "RecordingMode",
    "RecordingPolicy",
    "RiskLevel",
    "SecurityAction",
]