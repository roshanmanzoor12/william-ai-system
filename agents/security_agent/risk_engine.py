"""
agents/security_agent/risk_engine.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Score risks for financial, destructive, private, device, terminal, and
    account actions.

This module is intentionally policy-oriented and does not execute actions.
It evaluates proposed actions before execution and produces structured,
deterministic risk assessments that can be consumed by:

    - Security Agent
    - Master Agent
    - Agent Router
    - Permission Checker
    - Approval Manager
    - Biometric Gate
    - Verification Agent
    - Memory Agent
    - Dashboard / FastAPI endpoints
    - Audit Logger
    - Future policy, fraud, anomaly, and threat engines

Security priorities:
    1. Safety and permission enforcement
    2. SaaS user/workspace isolation
    3. BaseAgent compatibility
    4. Master Agent and Registry compatibility
    5. Risk-scoring functionality
    6. Future provider and policy upgrades

The engine never performs financial, destructive, terminal, account, device,
browser, message, file, or system operations. It only evaluates action risk.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence, Set, Tuple, Union


# =============================================================================
# Safe optional imports
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Import-safe fallback used until the real William BaseAgent exists.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get(
                "agent_id",
                self.agent_name.lower().replace(" ", "_"),
            )


try:
    from agents.security_agent.permission_checker import PermissionChecker  # type: ignore
except Exception:  # pragma: no cover
    PermissionChecker = None  # type: ignore


try:
    from agents.security_agent.biometric_gate import BiometricGate  # type: ignore
except Exception:  # pragma: no cover
    BiometricGate = None  # type: ignore


# =============================================================================
# Logging
# =============================================================================

LOGGER = logging.getLogger("william.security_agent.risk_engine")

if not LOGGER.handlers:
    LOGGER.addHandler(logging.NullHandler())


# =============================================================================
# Protocols
# =============================================================================

class EventEmitterProtocol(Protocol):
    """Interface for dashboard, registry, or message-bus event emitters."""

    def emit(self, event_name: str, payload: Dict[str, Any]) -> None:
        ...


class AuditLoggerProtocol(Protocol):
    """Interface for the future Security Agent audit logger."""

    def log(self, payload: Dict[str, Any]) -> None:
        ...


class PermissionCheckerProtocol(Protocol):
    """Minimal permission checker interface supported by this engine."""

    def check_permission(
        self,
        *,
        user_id: str,
        workspace_id: str,
        action: str,
        resource: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Any:
        ...


class PolicyProviderProtocol(Protocol):
    """
    Optional policy provider for workspace-specific risk overrides.

    The future policy engine may implement this protocol.
    """

    def get_risk_policy(
        self,
        *,
        user_id: str,
        workspace_id: str,
        action_type: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        ...


# =============================================================================
# Enums
# =============================================================================

class RiskCategory(str, Enum):
    """Supported action-risk categories."""

    GENERAL = "general"
    FINANCIAL = "financial"
    DESTRUCTIVE = "destructive"
    PRIVATE = "private"
    DEVICE = "device"
    TERMINAL = "terminal"
    ACCOUNT = "account"


class RiskLevel(str, Enum):
    """Normalized risk levels produced by the engine."""

    MINIMAL = "minimal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    BLOCKED = "blocked"


class RiskDecision(str, Enum):
    """Recommended handling decision."""

    ALLOW = "allow"
    ALLOW_WITH_LOGGING = "allow_with_logging"
    REQUIRE_CONFIRMATION = "require_confirmation"
    REQUIRE_APPROVAL = "require_approval"
    REQUIRE_BIOMETRIC = "require_biometric"
    REQUIRE_MULTI_APPROVAL = "require_multi_approval"
    DENY = "deny"


class ActionScope(str, Enum):
    """Approximate impact scope of an action."""

    SELF = "self"
    RESOURCE = "resource"
    PROJECT = "project"
    WORKSPACE = "workspace"
    ORGANIZATION = "organization"
    EXTERNAL = "external"
    GLOBAL = "global"


class Reversibility(str, Enum):
    """How easily an action can be reversed."""

    FULLY_REVERSIBLE = "fully_reversible"
    PARTIALLY_REVERSIBLE = "partially_reversible"
    DIFFICULT = "difficult"
    IRREVERSIBLE = "irreversible"
    UNKNOWN = "unknown"


# =============================================================================
# Configuration and data structures
# =============================================================================

@dataclass(frozen=True)
class RiskThresholds:
    """Score boundaries for normalized risk levels."""

    minimal_max: float = 14.99
    low_max: float = 29.99
    medium_max: float = 54.99
    high_max: float = 79.99
    critical_max: float = 100.0


@dataclass
class RiskEngineConfig:
    """Configuration for deterministic risk evaluation."""

    thresholds: RiskThresholds = field(default_factory=RiskThresholds)

    minimum_score: float = 0.0
    maximum_score: float = 100.0

    confirmation_threshold: float = 30.0
    approval_threshold: float = 55.0
    biometric_threshold: float = 70.0
    multi_approval_threshold: float = 85.0
    deny_threshold: float = 95.0

    enforce_user_workspace_context: bool = True
    default_deny_on_invalid_context: bool = True
    default_deny_on_permission_failure: bool = True

    audit_enabled: bool = True
    events_enabled: bool = True
    memory_payload_enabled: bool = True
    verification_payload_enabled: bool = True

    include_command_text_in_results: bool = False
    include_sensitive_values_in_results: bool = False

    max_action_length: int = 500
    max_description_length: int = 5_000
    max_command_length: int = 20_000
    max_metadata_depth: int = 6
    max_metadata_items: int = 500

    financial_amount_medium: float = 100.0
    financial_amount_high: float = 1_000.0
    financial_amount_critical: float = 10_000.0

    bulk_item_medium: int = 10
    bulk_item_high: int = 100
    bulk_item_critical: int = 1_000

    recent_auth_seconds: int = 300
    stale_auth_seconds: int = 1_800

    trusted_device_discount: float = 5.0
    recent_auth_discount: float = 5.0
    explicit_user_confirmation_discount: float = 4.0

    untrusted_device_penalty: float = 10.0
    unknown_device_penalty: float = 5.0
    stale_auth_penalty: float = 8.0
    external_destination_penalty: float = 8.0
    automation_penalty: float = 5.0
    elevated_privilege_penalty: float = 15.0
    bulk_action_penalty: float = 10.0
    irreversible_penalty: float = 18.0
    private_data_penalty: float = 15.0
    secret_exposure_penalty: float = 25.0
    cross_tenant_penalty: float = 100.0

    allow_policy_score_adjustment: bool = True
    maximum_policy_discount: float = 15.0
    maximum_policy_penalty: float = 30.0


@dataclass
class ActionContext:
    """
    Normalized description of a proposed action.

    Values are kept generic so every William agent can use the same risk engine.
    """

    action: str
    user_id: str
    workspace_id: str

    task_id: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None

    category: Optional[str] = None
    description: Optional[str] = None
    resource: Optional[str] = None
    target: Optional[str] = None

    command: Optional[str] = None
    arguments: List[str] = field(default_factory=list)

    amount: Optional[float] = None
    currency: Optional[str] = None

    item_count: int = 1
    action_scope: str = ActionScope.SELF.value
    reversibility: str = Reversibility.UNKNOWN.value

    contains_private_data: bool = False
    contains_secrets: bool = False
    contains_credentials: bool = False
    contains_payment_data: bool = False
    contains_health_data: bool = False
    contains_personal_identifiers: bool = False

    changes_permissions: bool = False
    changes_ownership: bool = False
    changes_billing: bool = False
    changes_security_settings: bool = False
    disables_security_controls: bool = False

    elevated_privileges: bool = False
    automated: bool = False
    scheduled: bool = False
    external_destination: bool = False
    third_party_integration: bool = False

    device_id: Optional[str] = None
    device_trusted: Optional[bool] = None
    device_new: bool = False

    authenticated: bool = True
    authentication_age_seconds: Optional[int] = None
    biometric_verified: bool = False
    user_confirmed: bool = False

    permission_granted: Optional[bool] = None
    actor_role: Optional[str] = None
    subscription_plan: Optional[str] = None

    source_agent: Optional[str] = None
    destination_agent: Optional[str] = None

    target_user_id: Optional[str] = None
    target_workspace_id: Optional[str] = None

    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RiskFactor:
    """A single scored or blocking factor."""

    code: str
    name: str
    category: str
    score: float
    reason: str
    blocking: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RiskAssessment:
    """Complete internal assessment before serialization."""

    assessment_id: str
    user_id: str
    workspace_id: str
    action: str
    category: str
    score: float
    level: str
    decision: str

    requires_security_check: bool
    requires_user_confirmation: bool
    requires_approval: bool
    requires_biometric: bool
    requires_multi_approval: bool
    blocked: bool

    factors: List[RiskFactor] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    required_controls: List[str] = field(default_factory=list)

    created_at: str = field(default_factory=lambda: _utc_now_iso())
    metadata: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# Constants and scoring rules
# =============================================================================

CATEGORY_BASE_SCORES: Dict[RiskCategory, float] = {
    RiskCategory.GENERAL: 5.0,
    RiskCategory.FINANCIAL: 35.0,
    RiskCategory.DESTRUCTIVE: 45.0,
    RiskCategory.PRIVATE: 30.0,
    RiskCategory.DEVICE: 25.0,
    RiskCategory.TERMINAL: 30.0,
    RiskCategory.ACCOUNT: 35.0,
}


FINANCIAL_KEYWORDS: Set[str] = {
    "pay",
    "payment",
    "purchase",
    "buy",
    "refund",
    "transfer",
    "withdraw",
    "deposit",
    "invoice",
    "charge",
    "billing",
    "subscription",
    "payout",
    "bank",
    "card",
    "credit",
    "debit",
    "wallet",
    "crypto",
    "wire",
    "transaction",
    "send money",
    "financial",
}


DESTRUCTIVE_KEYWORDS: Set[str] = {
    "delete",
    "remove",
    "destroy",
    "drop",
    "truncate",
    "erase",
    "wipe",
    "purge",
    "format",
    "reset",
    "terminate",
    "revoke",
    "disable",
    "uninstall",
    "overwrite",
    "rollback",
    "shutdown",
    "kill",
    "cancel",
    "archive permanently",
}


PRIVATE_KEYWORDS: Set[str] = {
    "private",
    "personal",
    "pii",
    "credential",
    "credentials",
    "password",
    "secret",
    "token",
    "api key",
    "access key",
    "cookie",
    "session",
    "medical",
    "health",
    "ssn",
    "passport",
    "identity",
    "email list",
    "phone list",
    "customer data",
    "client data",
    "export data",
}


DEVICE_KEYWORDS: Set[str] = {
    "device",
    "camera",
    "microphone",
    "location",
    "gps",
    "bluetooth",
    "wifi",
    "usb",
    "screen",
    "clipboard",
    "sensor",
    "accessibility",
    "notification",
    "contacts",
    "storage",
    "dialer",
    "sms",
    "android",
    "ios",
    "mobile",
}


TERMINAL_KEYWORDS: Set[str] = {
    "terminal",
    "shell",
    "command",
    "cmd",
    "powershell",
    "bash",
    "zsh",
    "sudo",
    "root",
    "administrator",
    "execute",
    "script",
    "docker",
    "kubectl",
    "ssh",
    "scp",
    "chmod",
    "chown",
    "systemctl",
    "registry",
    "apt",
    "pip",
    "npm",
}


ACCOUNT_KEYWORDS: Set[str] = {
    "account",
    "login",
    "logout",
    "password",
    "email",
    "username",
    "role",
    "permission",
    "owner",
    "ownership",
    "admin",
    "administrator",
    "member",
    "invite",
    "remove user",
    "suspend user",
    "disable user",
    "mfa",
    "2fa",
    "biometric",
    "security setting",
    "recovery",
}


CRITICAL_TERMINAL_PATTERNS: Tuple[Tuple[str, str, float], ...] = (
    (r"(^|\s)rm\s+-rf\s+/(?:\s|$)", "Recursive deletion of root filesystem", 100.0),
    (r"(^|\s)rm\s+-rf\s+~(?:/|\s|$)", "Recursive deletion of home directory", 95.0),
    (r"\bmkfs(?:\.[a-z0-9]+)?\b", "Filesystem formatting command", 100.0),
    (r"\bdd\s+if=.*\s+of=/dev/", "Raw disk overwrite command", 100.0),
    (r":\(\)\s*\{\s*:\|:&\s*\};:", "Fork bomb pattern", 100.0),
    (r"\bshutdown\b.*\b(now|-h|-r)\b", "System shutdown or reboot command", 75.0),
    (r"\bformat\s+[a-z]:", "Drive formatting command", 100.0),
    (r"\bdel\s+/[fsq].*\b(system32|windows)\b", "Windows system deletion command", 100.0),
    (r"\breg\s+delete\b", "Windows registry deletion", 75.0),
    (r"\bDROP\s+(DATABASE|SCHEMA)\b", "Database or schema deletion", 100.0),
    (r"\bTRUNCATE\s+TABLE\b", "Database table truncation", 90.0),
    (r"\bDELETE\s+FROM\b(?!.*\bWHERE\b)", "Unbounded database delete", 90.0),
    (r"\bchmod\s+-R\s+777\b", "Recursive globally writable permissions", 85.0),
    (r"\bchown\s+-R\b.*\s+/", "Recursive ownership change on root path", 90.0),
    (r"\bcurl\b.*\|\s*(bash|sh|zsh)\b", "Remote script piped into shell", 85.0),
    (r"\bwget\b.*\|\s*(bash|sh|zsh)\b", "Remote script piped into shell", 85.0),
    (r"\bbase64\s+-d\b.*\|\s*(bash|sh|zsh)\b", "Encoded payload executed by shell", 90.0),
)


SENSITIVE_COMMAND_PATTERNS: Tuple[Tuple[str, str, float], ...] = (
    (r"\bsudo\b", "Command requests elevated privileges", 15.0),
    (r"\bsu\s+-?\b", "Command switches user identity", 18.0),
    (r"\bssh\b", "Remote shell access", 12.0),
    (r"\bscp\b|\brsync\b", "File transfer to or from another host", 10.0),
    (r"\bkubectl\s+(delete|apply|patch|exec)\b", "Kubernetes state-changing command", 18.0),
    (r"\bdocker\s+(rm|rmi|system\s+prune|exec|run)\b", "Docker state-changing command", 14.0),
    (r"\bsystemctl\s+(stop|disable|mask|restart)\b", "Service state modification", 18.0),
    (r"\biptables\b|\bnft\b", "Firewall modification", 22.0),
    (r"\buserdel\b|\bdeluser\b", "Operating-system account deletion", 30.0),
    (r"\bpasswd\b", "Credential modification", 18.0),
    (r"\bchmod\b|\bchown\b", "File permission or ownership modification", 10.0),
    (r"\bgit\s+push\s+.*(--force|-f)\b", "Force push may overwrite shared history", 25.0),
    (r"\bgit\s+reset\s+--hard\b", "Hard reset discards local changes", 22.0),
    (r"\bterraform\s+destroy\b", "Infrastructure destruction", 90.0),
    (r"\bansible-playbook\b", "Remote infrastructure automation", 12.0),
)


SECRET_PATTERNS: Tuple[Tuple[str, str], ...] = (
    (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "private_key"),
    (r"\bsk-[A-Za-z0-9_-]{20,}\b", "api_secret"),
    (r"\bAKIA[0-9A-Z]{16}\b", "aws_access_key"),
    (r"\bgh[pousr]_[A-Za-z0-9]{20,}\b", "github_token"),
    (r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b", "slack_token"),
    (r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b", "bearer_token"),
    (r"\b(?:password|passwd|pwd)\s*[:=]\s*[^\s,;]{4,}", "password_assignment"),
    (r"\b(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*[^\s,;]{8,}", "secret_assignment"),
)


PRIVATE_DATA_PATTERNS: Tuple[Tuple[str, str], ...] = (
    (r"\b\d{3}-\d{2}-\d{4}\b", "us_ssn_pattern"),
    (r"\b(?:\d[ -]*?){13,19}\b", "possible_payment_card"),
    (r"\b[A-Z]{1,2}\d{6,9}\b", "possible_identity_document"),
    (r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b", "email_address"),
    (r"\b(?:\+?\d[\d\s().-]{7,}\d)\b", "phone_number"),
)


# =============================================================================
# Helper functions
# =============================================================================

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_uuid(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def _clean_string(value: Any, max_length: int) -> str:
    if value is None:
        return ""

    cleaned = str(value).replace("\x00", "").strip()
    return cleaned[:max_length]


def _normalize_identifier(value: Any) -> Optional[str]:
    if value is None:
        return None

    normalized = str(value).strip()
    return normalized or None


def _normalize_action(value: str) -> str:
    value = _clean_string(value, 500).lower()
    value = re.sub(r"[^a-z0-9._:/ -]+", " ", value)
    value = re.sub(r"\s+", " ", value)
    return value.strip()


def _tokenize(value: str) -> Set[str]:
    return set(re.findall(r"[a-z0-9_]+", value.lower()))


def _contains_phrase(text: str, phrases: Iterable[str]) -> bool:
    lowered = text.lower()
    tokens = _tokenize(lowered)

    for phrase in phrases:
        phrase = phrase.lower().strip()

        if " " in phrase:
            if phrase in lowered:
                return True
        elif phrase in tokens:
            return True

    return False


def _clamp(value: float, minimum: float, maximum: float) -> float:
    return max(minimum, min(maximum, value))


def _safe_float(value: Any, default: Optional[float] = None) -> Optional[float]:
    try:
        number = float(value)
        if math.isfinite(number):
            return number
    except (TypeError, ValueError):
        pass

    return default


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        number = int(value)
        return number
    except (TypeError, ValueError):
        return default


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()


def _sanitize_mapping(
    value: Any,
    *,
    max_depth: int,
    max_items: int,
    current_depth: int = 0,
) -> Any:
    """
    Convert arbitrary metadata into JSON-safe values while enforcing depth and
    item limits.
    """

    if current_depth >= max_depth:
        return "[MAX_DEPTH_REACHED]"

    if value is None or isinstance(value, (str, int, float, bool)):
        return value

    if isinstance(value, Enum):
        return value.value

    if isinstance(value, Mapping):
        output: Dict[str, Any] = {}

        for index, (key, item) in enumerate(value.items()):
            if index >= max_items:
                output["_truncated"] = True
                break

            output[str(key)] = _sanitize_mapping(
                item,
                max_depth=max_depth,
                max_items=max_items,
                current_depth=current_depth + 1,
            )

        return output

    if isinstance(value, (list, tuple, set)):
        output_list: List[Any] = []

        for index, item in enumerate(value):
            if index >= max_items:
                output_list.append("[TRUNCATED]")
                break

            output_list.append(
                _sanitize_mapping(
                    item,
                    max_depth=max_depth,
                    max_items=max_items,
                    current_depth=current_depth + 1,
                )
            )

        return output_list

    return str(value)


# =============================================================================
# Risk Engine
# =============================================================================

class RiskEngine(BaseAgent):
    """
    Central deterministic risk-scoring engine for William/Jarvis.

    Public responsibilities:
        - Validate SaaS task context.
        - Normalize proposed actions.
        - Classify actions into supported risk categories.
        - Score financial, destructive, private, device, terminal, and account
          risks.
        - Detect blocking tenant-isolation conflicts.
        - Recommend confirmation, approval, biometric, multi-approval, or denial.
        - Prepare audit, memory, verification, and event payloads.

    This class does not authorize or execute the requested action. Its decision
    is a recommendation for the Security Agent and Approval Manager. The final
    Security Agent may apply stricter policies.
    """

    AGENT_NAME = "RiskEngine"
    AGENT_ID = "security_risk_engine"
    MODULE_NAME = "Security Agent"
    VERSION = "1.0.0"

    def __init__(
        self,
        config: Optional[RiskEngineConfig] = None,
        *,
        permission_checker: Optional[PermissionCheckerProtocol] = None,
        policy_provider: Optional[PolicyProviderProtocol] = None,
        event_emitter: Optional[EventEmitterProtocol] = None,
        audit_logger: Optional[AuditLoggerProtocol] = None,
        logger: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            agent_name=kwargs.pop("agent_name", self.AGENT_NAME),
            agent_id=kwargs.pop("agent_id", self.AGENT_ID),
            **kwargs,
        )

        self.config = config or RiskEngineConfig()
        self.permission_checker = permission_checker
        self.policy_provider = policy_provider
        self.event_emitter = event_emitter
        self.audit_logger = audit_logger
        self.logger = logger or LOGGER

    # -------------------------------------------------------------------------
    # Structured result helpers
    # -------------------------------------------------------------------------

    def _safe_result(
        self,
        *,
        success: bool = True,
        message: str = "Operation completed successfully.",
        data: Optional[Dict[str, Any]] = None,
        error: Optional[Union[str, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return William-standard structured output."""

        return {
            "success": bool(success),
            "message": str(message),
            "data": data or {},
            "error": error,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        *,
        message: str,
        error: Optional[Union[str, Dict[str, Any], Exception]] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return William-standard structured error output."""

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
            data=data or {},
            error=error_payload,
            metadata=metadata or {},
        )

    # -------------------------------------------------------------------------
    # Required compatibility hooks
    # -------------------------------------------------------------------------

    def _validate_task_context(
        self,
        *,
        user_id: Optional[str],
        workspace_id: Optional[str],
        task_id: Optional[str] = None,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        target_user_id: Optional[str] = None,
        target_workspace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Validate required tenant context and detect cross-tenant requests.

        Cross-tenant target identifiers are not automatically permitted. They
        are marked as violations unless they exactly match the actor's tenant.
        A future Security Agent policy may explicitly support delegated
        cross-tenant administration, but this engine defaults to isolation.
        """

        errors: List[str] = []
        violations: List[str] = []

        normalized_user_id = _normalize_identifier(user_id)
        normalized_workspace_id = _normalize_identifier(workspace_id)
        normalized_task_id = _normalize_identifier(task_id)
        normalized_session_id = _normalize_identifier(session_id)
        normalized_request_id = _normalize_identifier(request_id)
        normalized_target_user_id = _normalize_identifier(target_user_id)
        normalized_target_workspace_id = _normalize_identifier(
            target_workspace_id
        )

        if self.config.enforce_user_workspace_context:
            if not normalized_user_id:
                errors.append("Missing or invalid user_id.")

            if not normalized_workspace_id:
                errors.append("Missing or invalid workspace_id.")

        if (
            normalized_target_workspace_id
            and normalized_workspace_id
            and normalized_target_workspace_id != normalized_workspace_id
        ):
            violations.append(
                "Target workspace differs from the authenticated workspace."
            )

        if (
            normalized_target_user_id
            and normalized_user_id
            and normalized_target_user_id != normalized_user_id
        ):
            violations.append(
                "Target user differs from the authenticated user."
            )

        valid = not errors and not violations

        if not valid:
            return self._error_result(
                message="Invalid or unsafe task context.",
                error={
                    "validation_errors": errors,
                    "isolation_violations": violations,
                },
                data={
                    "valid": False,
                    "user_id": normalized_user_id,
                    "workspace_id": normalized_workspace_id,
                    "task_id": normalized_task_id,
                    "session_id": normalized_session_id,
                    "request_id": normalized_request_id,
                },
                metadata={
                    "hook": "_validate_task_context",
                    "default_denied": self.config.default_deny_on_invalid_context,
                },
            )

        return self._safe_result(
            message="Task context validated.",
            data={
                "valid": True,
                "user_id": normalized_user_id,
                "workspace_id": normalized_workspace_id,
                "task_id": normalized_task_id,
                "session_id": normalized_session_id,
                "request_id": normalized_request_id,
                "target_user_id": normalized_target_user_id,
                "target_workspace_id": normalized_target_workspace_id,
            },
            metadata={"hook": "_validate_task_context"},
        )

    def _requires_security_check(
        self,
        *,
        action: str,
        category: Optional[str] = None,
        score: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Determine whether the proposal requires full Security Agent handling.

        Every sensitive category requires a check even when its calculated score
        is relatively low.
        """

        normalized_category = self._normalize_category(category)
        normalized_action = _normalize_action(action)
        metadata = metadata or {}

        sensitive_categories = {
            RiskCategory.FINANCIAL,
            RiskCategory.DESTRUCTIVE,
            RiskCategory.PRIVATE,
            RiskCategory.DEVICE,
            RiskCategory.TERMINAL,
            RiskCategory.ACCOUNT,
        }

        if normalized_category in sensitive_categories:
            return True

        if score is not None and score >= self.config.confirmation_threshold:
            return True

        if bool(metadata.get("sensitive")):
            return True

        if bool(metadata.get("requires_security_check")):
            return True

        combined = f"{normalized_action} {json.dumps(metadata, default=str)}"

        return any(
            (
                _contains_phrase(combined, FINANCIAL_KEYWORDS),
                _contains_phrase(combined, DESTRUCTIVE_KEYWORDS),
                _contains_phrase(combined, PRIVATE_KEYWORDS),
                _contains_phrase(combined, DEVICE_KEYWORDS),
                _contains_phrase(combined, TERMINAL_KEYWORDS),
                _contains_phrase(combined, ACCOUNT_KEYWORDS),
            )
        )

    def _request_security_approval(
        self,
        *,
        assessment: RiskAssessment,
        user_id: str,
        workspace_id: str,
        approval_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare a Security Agent approval request.

        Since RiskEngine is itself part of Security Agent, this method does not
        auto-approve sensitive actions. It returns an approval requirement for
        Approval Manager, Permission Checker, Biometric Gate, or the parent
        Security Agent.
        """

        approval_context = approval_context or {}

        provided_approval = bool(
            approval_context.get("security_approved", False)
        )
        biometric_verified = bool(
            approval_context.get("biometric_verified", False)
        )
        confirmation_provided = bool(
            approval_context.get("user_confirmed", False)
        )
        multi_approval_count = max(
            0,
            _safe_int(approval_context.get("multi_approval_count"), 0),
        )

        approved = True
        missing_controls: List[str] = []

        if assessment.blocked or assessment.decision == RiskDecision.DENY.value:
            approved = False
            missing_controls.append("action_must_be_denied")

        if assessment.requires_user_confirmation and not confirmation_provided:
            approved = False
            missing_controls.append("user_confirmation")

        if assessment.requires_approval and not provided_approval:
            approved = False
            missing_controls.append("security_approval")

        if assessment.requires_biometric and not biometric_verified:
            approved = False
            missing_controls.append("biometric_verification")

        if assessment.requires_multi_approval and multi_approval_count < 2:
            approved = False
            missing_controls.append("multi_approval")

        payload = {
            "approved": approved,
            "assessment_id": assessment.assessment_id,
            "risk_score": assessment.score,
            "risk_level": assessment.level,
            "decision": assessment.decision,
            "missing_controls": missing_controls,
            "required_controls": assessment.required_controls,
            "user_id": user_id,
            "workspace_id": workspace_id,
        }

        if not approved:
            return self._error_result(
                message="Security controls are required before execution.",
                error={
                    "code": "SECURITY_APPROVAL_REQUIRED",
                    "missing_controls": missing_controls,
                },
                data=payload,
                metadata={"hook": "_request_security_approval"},
            )

        return self._safe_result(
            message="Required security controls are satisfied.",
            data=payload,
            metadata={"hook": "_request_security_approval"},
        )

    def _prepare_verification_payload(
        self,
        *,
        assessment: RiskAssessment,
        operation: str = "risk_assessment",
        source_agent: Optional[str] = None,
        task_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Build a payload for Verification Agent.

        Verification Agent can confirm that:
            - tenant isolation was preserved,
            - the score was within configured boundaries,
            - required controls match the final decision,
            - no execution occurred inside RiskEngine.
        """

        return {
            "verification_type": "security_risk_assessment",
            "operation": operation,
            "agent": self.AGENT_NAME,
            "agent_id": self.AGENT_ID,
            "module": self.MODULE_NAME,
            "version": self.VERSION,
            "assessment_id": assessment.assessment_id,
            "user_id": assessment.user_id,
            "workspace_id": assessment.workspace_id,
            "task_id": task_id,
            "source_agent": source_agent,
            "risk_score": assessment.score,
            "risk_level": assessment.level,
            "decision": assessment.decision,
            "blocked": assessment.blocked,
            "requires_security_check": assessment.requires_security_check,
            "required_controls": assessment.required_controls,
            "factor_codes": [factor.code for factor in assessment.factors],
            "checks": {
                "score_within_range": (
                    self.config.minimum_score
                    <= assessment.score
                    <= self.config.maximum_score
                ),
                "tenant_context_present": bool(
                    assessment.user_id and assessment.workspace_id
                ),
                "execution_performed": False,
                "deterministic_rule_engine": True,
            },
            "created_at": _utc_now_iso(),
        }

    def _prepare_memory_payload(
        self,
        *,
        assessment: RiskAssessment,
        task_id: Optional[str] = None,
        source_agent: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Build a privacy-safe Memory Agent payload.

        Raw secrets, credentials, commands, and sensitive metadata are excluded.
        """

        return {
            "memory_type": "security_risk_context",
            "agent": self.AGENT_NAME,
            "module": self.MODULE_NAME,
            "user_id": assessment.user_id,
            "workspace_id": assessment.workspace_id,
            "task_id": task_id,
            "source_agent": source_agent,
            "content": (
                f"Action '{assessment.action}' received risk level "
                f"'{assessment.level}' with decision '{assessment.decision}'."
            ),
            "data": {
                "assessment_id": assessment.assessment_id,
                "category": assessment.category,
                "score": assessment.score,
                "level": assessment.level,
                "decision": assessment.decision,
                "blocked": assessment.blocked,
                "factor_codes": [factor.code for factor in assessment.factors],
                "required_controls": assessment.required_controls,
            },
            "metadata": {
                "sensitive_content_included": False,
                "created_at": assessment.created_at,
            },
        }

    def _emit_agent_event(
        self,
        *,
        event_name: str,
        payload: Dict[str, Any],
    ) -> None:
        """Emit a safe event for dashboard, registry, or message-bus consumers."""

        if not self.config.events_enabled:
            return

        try:
            if self.event_emitter is not None:
                self.event_emitter.emit(event_name, payload)
            else:
                self.logger.debug(
                    "RiskEngine event %s: %s",
                    event_name,
                    payload,
                )
        except Exception:
            self.logger.exception(
                "RiskEngine failed to emit event '%s'.",
                event_name,
            )

    def _log_audit_event(
        self,
        *,
        event_type: str,
        user_id: str,
        workspace_id: str,
        status: str,
        assessment_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log a tenant-scoped, privacy-safe audit event."""

        if not self.config.audit_enabled:
            return

        payload = {
            "event_type": event_type,
            "agent": self.AGENT_NAME,
            "agent_id": self.AGENT_ID,
            "module": self.MODULE_NAME,
            "version": self.VERSION,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "assessment_id": assessment_id,
            "status": status,
            "metadata": _sanitize_mapping(
                metadata or {},
                max_depth=self.config.max_metadata_depth,
                max_items=self.config.max_metadata_items,
            ),
            "created_at": _utc_now_iso(),
        }

        try:
            if self.audit_logger is not None:
                self.audit_logger.log(payload)
            else:
                self.logger.info("RiskEngine audit: %s", payload)
        except Exception:
            self.logger.exception("RiskEngine failed to write audit event.")

    # -------------------------------------------------------------------------
    # Main public API
    # -------------------------------------------------------------------------

    def assess_risk(
        self,
        action: Union[str, ActionContext, Dict[str, Any]],
        *,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        category: Optional[Union[str, RiskCategory]] = None,
        context: Optional[Dict[str, Any]] = None,
        check_permission: bool = True,
        prepare_approval_request: bool = True,
    ) -> Dict[str, Any]:
        """
        Assess the risk of a proposed action.

        Accepted input forms:
            - action string plus user_id/workspace_id
            - ActionContext instance
            - dictionary containing ActionContext-compatible fields

        The result is structured for FastAPI, dashboard, Master Agent routing,
        Security Agent processing, Verification Agent, and Memory Agent.
        """

        started_at = time.monotonic()

        try:
            normalized = self._build_action_context(
                action=action,
                user_id=user_id,
                workspace_id=workspace_id,
                category=category,
                extra_context=context,
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to normalize risk-assessment input.",
                error=exc,
                metadata={"operation": "assess_risk"},
            )

        validation = self._validate_task_context(
            user_id=normalized.user_id,
            workspace_id=normalized.workspace_id,
            task_id=normalized.task_id,
            session_id=normalized.session_id,
            request_id=normalized.request_id,
            target_user_id=normalized.target_user_id,
            target_workspace_id=normalized.target_workspace_id,
        )

        if not validation["success"]:
            blocked_assessment = self._build_context_failure_assessment(
                normalized,
                validation,
            )

            self._record_assessment(
                blocked_assessment,
                normalized,
                status="blocked",
                elapsed_ms=(time.monotonic() - started_at) * 1000,
            )

            return self._assessment_result(
                blocked_assessment,
                normalized,
                permission_result=None,
                approval_result=None,
                elapsed_ms=(time.monotonic() - started_at) * 1000,
            )

        permission_result: Optional[Dict[str, Any]] = None

        if check_permission:
            permission_result = self._evaluate_permission(normalized)

        factors = self._collect_risk_factors(
            normalized,
            permission_result=permission_result,
        )

        policy_data = self._load_policy(normalized)

        if policy_data:
            policy_factors = self._policy_factors(
                normalized,
                policy_data,
            )
            factors.extend(policy_factors)

        assessment = self._finalize_assessment(
            normalized,
            factors=factors,
            policy_data=policy_data,
        )

        approval_result: Optional[Dict[str, Any]] = None

        if prepare_approval_request:
            approval_result = self._request_security_approval(
                assessment=assessment,
                user_id=normalized.user_id,
                workspace_id=normalized.workspace_id,
                approval_context={
                    "security_approved": normalized.metadata.get(
                        "security_approved",
                        False,
                    ),
                    "biometric_verified": normalized.biometric_verified,
                    "user_confirmed": normalized.user_confirmed,
                    "multi_approval_count": normalized.metadata.get(
                        "multi_approval_count",
                        0,
                    ),
                },
            )

        elapsed_ms = (time.monotonic() - started_at) * 1000

        self._record_assessment(
            assessment,
            normalized,
            status="completed",
            elapsed_ms=elapsed_ms,
        )

        return self._assessment_result(
            assessment,
            normalized,
            permission_result=permission_result,
            approval_result=approval_result,
            elapsed_ms=elapsed_ms,
        )

    def score_action(
        self,
        action: Union[str, ActionContext, Dict[str, Any]],
        *,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        category: Optional[Union[str, RiskCategory]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Compatibility alias for assess_risk without preparing approval output.
        """

        return self.assess_risk(
            action,
            user_id=user_id,
            workspace_id=workspace_id,
            category=category,
            context=context,
            check_permission=True,
            prepare_approval_request=False,
        )

    def classify_action(
        self,
        action: str,
        *,
        description: Optional[str] = None,
        command: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Classify an action without requiring user/workspace context.

        This method performs classification only and must not be used as an
        authorization decision.
        """

        try:
            combined = self._combined_action_text(
                action=action,
                description=description,
                command=command,
                target=None,
                resource=None,
                metadata=metadata,
            )

            category, matches = self._classify_category(combined)

            return self._safe_result(
                message="Action classified successfully.",
                data={
                    "category": category.value,
                    "matches": matches,
                    "requires_security_check": self._requires_security_check(
                        action=action,
                        category=category.value,
                        metadata=metadata,
                    ),
                },
                metadata={
                    "operation": "classify_action",
                    "authorization_decision": False,
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to classify action.",
                error=exc,
                metadata={"operation": "classify_action"},
            )

    def assess_batch(
        self,
        actions: Sequence[Union[str, ActionContext, Dict[str, Any]]],
        *,
        user_id: str,
        workspace_id: str,
        fail_closed: bool = True,
    ) -> Dict[str, Any]:
        """
        Assess multiple actions for the same tenant.

        Each action is independently isolated and evaluated. The aggregate
        decision adopts the highest risk score and strictest decision.
        """

        validation = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
        )

        if not validation["success"]:
            return validation

        if not isinstance(actions, Sequence) or isinstance(actions, str):
            return self._error_result(
                message="actions must be a sequence of action definitions.",
                error="INVALID_BATCH_INPUT",
                metadata={"operation": "assess_batch"},
            )

        if not actions:
            return self._error_result(
                message="At least one action is required.",
                error="EMPTY_BATCH",
                metadata={"operation": "assess_batch"},
            )

        results: List[Dict[str, Any]] = []
        successful_assessments: List[Dict[str, Any]] = []
        failures: List[Dict[str, Any]] = []

        for index, action in enumerate(actions):
            result = self.assess_risk(
                action,
                user_id=user_id,
                workspace_id=workspace_id,
            )

            results.append(result)

            if result.get("success"):
                successful_assessments.append(result["data"])
            else:
                failures.append(
                    {
                        "index": index,
                        "message": result.get("message"),
                        "error": result.get("error"),
                    }
                )

                if fail_closed:
                    break

        aggregate_score = max(
            (
                _safe_float(item.get("score"), 0.0) or 0.0
                for item in successful_assessments
            ),
            default=0.0,
        )

        aggregate_level = self._score_to_level(aggregate_score)

        strictest_decision = self._strictest_decision(
            [
                str(item.get("decision", RiskDecision.ALLOW.value))
                for item in successful_assessments
            ]
        )

        if failures and fail_closed:
            aggregate_score = self.config.maximum_score
            aggregate_level = RiskLevel.BLOCKED
            strictest_decision = RiskDecision.DENY

        batch_data = {
            "total_requested": len(actions),
            "total_processed": len(results),
            "successful": len(successful_assessments),
            "failed": len(failures),
            "aggregate_score": round(aggregate_score, 2),
            "aggregate_level": aggregate_level.value,
            "aggregate_decision": strictest_decision.value,
            "blocked": strictest_decision == RiskDecision.DENY,
            "results": results,
            "failures": failures,
        }

        self._log_audit_event(
            event_type="security.risk.batch_assessed",
            user_id=user_id,
            workspace_id=workspace_id,
            status="completed" if not failures else "partial",
            metadata={
                "total_requested": len(actions),
                "total_processed": len(results),
                "failed": len(failures),
                "aggregate_score": aggregate_score,
                "aggregate_decision": strictest_decision.value,
            },
        )

        return self._safe_result(
            success=not failures or not fail_closed,
            message=(
                "Batch risk assessment completed."
                if not failures
                else "Batch risk assessment completed with failures."
            ),
            data=batch_data,
            error=(
                None
                if not failures
                else {
                    "code": "BATCH_ASSESSMENT_FAILURES",
                    "failure_count": len(failures),
                }
            ),
            metadata={"operation": "assess_batch"},
        )

    def get_risk_thresholds(self) -> Dict[str, Any]:
        """Return dashboard-safe risk threshold configuration."""

        return self._safe_result(
            message="Risk thresholds loaded.",
            data={
                "levels": {
                    "minimal": [
                        self.config.minimum_score,
                        self.config.thresholds.minimal_max,
                    ],
                    "low": [
                        self.config.thresholds.minimal_max,
                        self.config.thresholds.low_max,
                    ],
                    "medium": [
                        self.config.thresholds.low_max,
                        self.config.thresholds.medium_max,
                    ],
                    "high": [
                        self.config.thresholds.medium_max,
                        self.config.thresholds.high_max,
                    ],
                    "critical": [
                        self.config.thresholds.high_max,
                        self.config.thresholds.critical_max,
                    ],
                },
                "controls": {
                    "confirmation_threshold": self.config.confirmation_threshold,
                    "approval_threshold": self.config.approval_threshold,
                    "biometric_threshold": self.config.biometric_threshold,
                    "multi_approval_threshold": (
                        self.config.multi_approval_threshold
                    ),
                    "deny_threshold": self.config.deny_threshold,
                },
            },
            metadata={"operation": "get_risk_thresholds"},
        )

    def health_check(self) -> Dict[str, Any]:
        """Return import and integration readiness information."""

        return self._safe_result(
            message="RiskEngine is healthy.",
            data={
                "agent": self.AGENT_NAME,
                "agent_id": self.AGENT_ID,
                "module": self.MODULE_NAME,
                "version": self.VERSION,
                "ready": True,
                "permission_checker_connected": (
                    self.permission_checker is not None
                ),
                "policy_provider_connected": self.policy_provider is not None,
                "event_emitter_connected": self.event_emitter is not None,
                "audit_logger_connected": self.audit_logger is not None,
                "supported_categories": [
                    category.value for category in RiskCategory
                ],
            },
            metadata={"operation": "health_check"},
        )

    # -------------------------------------------------------------------------
    # Context normalization
    # -------------------------------------------------------------------------

    def _build_action_context(
        self,
        *,
        action: Union[str, ActionContext, Dict[str, Any]],
        user_id: Optional[str],
        workspace_id: Optional[str],
        category: Optional[Union[str, RiskCategory]],
        extra_context: Optional[Dict[str, Any]],
    ) -> ActionContext:
        extra_context = dict(extra_context or {})

        if isinstance(action, ActionContext):
            base = asdict(action)

        elif isinstance(action, dict):
            base = dict(action)

        elif isinstance(action, str):
            base = {"action": action}

        else:
            raise TypeError(
                "action must be a string, ActionContext, or dictionary."
            )

        base.update(extra_context)

        if user_id is not None:
            base["user_id"] = user_id

        if workspace_id is not None:
            base["workspace_id"] = workspace_id

        if category is not None:
            base["category"] = (
                category.value
                if isinstance(category, RiskCategory)
                else str(category)
            )

        normalized_user_id = _normalize_identifier(base.get("user_id")) or ""
        normalized_workspace_id = (
            _normalize_identifier(base.get("workspace_id")) or ""
        )

        action_value = _clean_string(
            base.get("action", ""),
            self.config.max_action_length,
        )

        if not action_value:
            raise ValueError("Action is required.")

        metadata = base.get("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {"raw_metadata": str(metadata)}

        sanitized_metadata = _sanitize_mapping(
            metadata,
            max_depth=self.config.max_metadata_depth,
            max_items=self.config.max_metadata_items,
        )

        amount = _safe_float(base.get("amount"), None)

        return ActionContext(
            action=action_value,
            user_id=normalized_user_id,
            workspace_id=normalized_workspace_id,
            task_id=_normalize_identifier(base.get("task_id")),
            session_id=_normalize_identifier(base.get("session_id")),
            request_id=_normalize_identifier(base.get("request_id")),
            category=_normalize_identifier(base.get("category")),
            description=_clean_string(
                base.get("description"),
                self.config.max_description_length,
            ) or None,
            resource=_normalize_identifier(base.get("resource")),
            target=_normalize_identifier(base.get("target")),
            command=_clean_string(
                base.get("command"),
                self.config.max_command_length,
            ) or None,
            arguments=[
                _clean_string(argument, 2_000)
                for argument in list(base.get("arguments") or [])
            ],
            amount=amount,
            currency=_normalize_identifier(base.get("currency")),
            item_count=max(1, _safe_int(base.get("item_count"), 1)),
            action_scope=self._normalize_scope(
                base.get("action_scope", ActionScope.SELF.value)
            ),
            reversibility=self._normalize_reversibility(
                base.get("reversibility", Reversibility.UNKNOWN.value)
            ),
            contains_private_data=bool(
                base.get("contains_private_data", False)
            ),
            contains_secrets=bool(base.get("contains_secrets", False)),
            contains_credentials=bool(
                base.get("contains_credentials", False)
            ),
            contains_payment_data=bool(
                base.get("contains_payment_data", False)
            ),
            contains_health_data=bool(
                base.get("contains_health_data", False)
            ),
            contains_personal_identifiers=bool(
                base.get("contains_personal_identifiers", False)
            ),
            changes_permissions=bool(
                base.get("changes_permissions", False)
            ),
            changes_ownership=bool(base.get("changes_ownership", False)),
            changes_billing=bool(base.get("changes_billing", False)),
            changes_security_settings=bool(
                base.get("changes_security_settings", False)
            ),
            disables_security_controls=bool(
                base.get("disables_security_controls", False)
            ),
            elevated_privileges=bool(
                base.get("elevated_privileges", False)
            ),
            automated=bool(base.get("automated", False)),
            scheduled=bool(base.get("scheduled", False)),
            external_destination=bool(
                base.get("external_destination", False)
            ),
            third_party_integration=bool(
                base.get("third_party_integration", False)
            ),
            device_id=_normalize_identifier(base.get("device_id")),
            device_trusted=(
                None
                if base.get("device_trusted") is None
                else bool(base.get("device_trusted"))
            ),
            device_new=bool(base.get("device_new", False)),
            authenticated=bool(base.get("authenticated", True)),
            authentication_age_seconds=(
                None
                if base.get("authentication_age_seconds") is None
                else max(
                    0,
                    _safe_int(base.get("authentication_age_seconds"), 0),
                )
            ),
            biometric_verified=bool(
                base.get("biometric_verified", False)
            ),
            user_confirmed=bool(base.get("user_confirmed", False)),
            permission_granted=(
                None
                if base.get("permission_granted") is None
                else bool(base.get("permission_granted"))
            ),
            actor_role=_normalize_identifier(base.get("actor_role")),
            subscription_plan=_normalize_identifier(
                base.get("subscription_plan")
            ),
            source_agent=_normalize_identifier(base.get("source_agent")),
            destination_agent=_normalize_identifier(
                base.get("destination_agent")
            ),
            target_user_id=_normalize_identifier(
                base.get("target_user_id")
            ),
            target_workspace_id=_normalize_identifier(
                base.get("target_workspace_id")
            ),
            metadata=(
                sanitized_metadata
                if isinstance(sanitized_metadata, dict)
                else {}
            ),
        )

    # -------------------------------------------------------------------------
    # Classification and factor collection
    # -------------------------------------------------------------------------

    def _collect_risk_factors(
        self,
        context: ActionContext,
        *,
        permission_result: Optional[Dict[str, Any]],
    ) -> List[RiskFactor]:
        factors: List[RiskFactor] = []

        combined_text = self._combined_context_text(context)
        category, category_matches = self._resolve_context_category(
            context,
            combined_text,
        )

        factors.append(
            RiskFactor(
                code="CATEGORY_BASE",
                name="Base category risk",
                category=category.value,
                score=CATEGORY_BASE_SCORES[category],
                reason=(
                    f"Action classified as {category.value}. "
                    f"Matches: {', '.join(category_matches) or 'explicit/default'}."
                ),
                metadata={"matches": category_matches},
            )
        )

        factors.extend(self._common_risk_factors(context, combined_text))

        if category == RiskCategory.FINANCIAL:
            factors.extend(self._financial_risk_factors(context, combined_text))

        elif category == RiskCategory.DESTRUCTIVE:
            factors.extend(
                self._destructive_risk_factors(context, combined_text)
            )

        elif category == RiskCategory.PRIVATE:
            factors.extend(self._private_risk_factors(context, combined_text))

        elif category == RiskCategory.DEVICE:
            factors.extend(self._device_risk_factors(context, combined_text))

        elif category == RiskCategory.TERMINAL:
            factors.extend(self._terminal_risk_factors(context, combined_text))

        elif category == RiskCategory.ACCOUNT:
            factors.extend(self._account_risk_factors(context, combined_text))

        # Actions may carry multiple risk dimensions even when one primary
        # category is selected.
        factors.extend(
            self._secondary_category_factors(
                context,
                combined_text,
                primary_category=category,
            )
        )

        if permission_result is not None:
            factors.extend(
                self._permission_risk_factors(
                    context,
                    permission_result,
                )
            )

        return self._deduplicate_factors(factors)

    def _common_risk_factors(
        self,
        context: ActionContext,
        combined_text: str,
    ) -> List[RiskFactor]:
        factors: List[RiskFactor] = []

        if not context.authenticated:
            factors.append(
                RiskFactor(
                    code="NOT_AUTHENTICATED",
                    name="Authentication missing",
                    category=RiskCategory.ACCOUNT.value,
                    score=100.0,
                    reason="The actor is not authenticated.",
                    blocking=True,
                )
            )

        if (
            context.target_workspace_id
            and context.target_workspace_id != context.workspace_id
        ):
            factors.append(
                RiskFactor(
                    code="CROSS_WORKSPACE_REQUEST",
                    name="Cross-workspace target",
                    category=RiskCategory.PRIVATE.value,
                    score=self.config.cross_tenant_penalty,
                    reason=(
                        "The requested target workspace does not match the "
                        "authenticated workspace."
                    ),
                    blocking=True,
                )
            )

        if (
            context.target_user_id
            and context.target_user_id != context.user_id
        ):
            factors.append(
                RiskFactor(
                    code="CROSS_USER_REQUEST",
                    name="Cross-user target",
                    category=RiskCategory.PRIVATE.value,
                    score=self.config.cross_tenant_penalty,
                    reason=(
                        "The requested target user does not match the "
                        "authenticated user."
                    ),
                    blocking=True,
                )
            )

        if context.elevated_privileges:
            factors.append(
                RiskFactor(
                    code="ELEVATED_PRIVILEGES",
                    name="Elevated privileges",
                    category=RiskCategory.TERMINAL.value,
                    score=self.config.elevated_privilege_penalty,
                    reason="The action requests elevated or administrative privileges.",
                )
            )

        if context.automated:
            factors.append(
                RiskFactor(
                    code="AUTOMATED_EXECUTION",
                    name="Automated execution",
                    category=RiskCategory.GENERAL.value,
                    score=self.config.automation_penalty,
                    reason=(
                        "The action is automated and may execute without an "
                        "immediate human review."
                    ),
                )
            )

        if context.scheduled:
            factors.append(
                RiskFactor(
                    code="SCHEDULED_EXECUTION",
                    name="Scheduled execution",
                    category=RiskCategory.GENERAL.value,
                    score=3.0,
                    reason=(
                        "The action may execute later when the original context "
                        "has changed."
                    ),
                )
            )

        if context.external_destination:
            factors.append(
                RiskFactor(
                    code="EXTERNAL_DESTINATION",
                    name="External destination",
                    category=RiskCategory.PRIVATE.value,
                    score=self.config.external_destination_penalty,
                    reason="The action sends data or value outside the workspace.",
                )
            )

        if context.third_party_integration:
            factors.append(
                RiskFactor(
                    code="THIRD_PARTY_INTEGRATION",
                    name="Third-party integration",
                    category=RiskCategory.PRIVATE.value,
                    score=5.0,
                    reason=(
                        "The action involves a third-party integration with "
                        "independent security and privacy controls."
                    ),
                )
            )

        if context.item_count >= self.config.bulk_item_critical:
            factors.append(
                RiskFactor(
                    code="MASS_BULK_ACTION",
                    name="Mass bulk action",
                    category=RiskCategory.DESTRUCTIVE.value,
                    score=25.0,
                    reason=(
                        f"The action affects {context.item_count} items, which "
                        "exceeds the critical bulk threshold."
                    ),
                )
            )

        elif context.item_count >= self.config.bulk_item_high:
            factors.append(
                RiskFactor(
                    code="HIGH_BULK_ACTION",
                    name="High-volume bulk action",
                    category=RiskCategory.DESTRUCTIVE.value,
                    score=18.0,
                    reason=f"The action affects {context.item_count} items.",
                )
            )

        elif context.item_count >= self.config.bulk_item_medium:
            factors.append(
                RiskFactor(
                    code="BULK_ACTION",
                    name="Bulk action",
                    category=RiskCategory.GENERAL.value,
                    score=self.config.bulk_action_penalty,
                    reason=f"The action affects {context.item_count} items.",
                )
            )

        if context.reversibility == Reversibility.IRREVERSIBLE.value:
            factors.append(
                RiskFactor(
                    code="IRREVERSIBLE_ACTION",
                    name="Irreversible action",
                    category=RiskCategory.DESTRUCTIVE.value,
                    score=self.config.irreversible_penalty,
                    reason="The action is marked as irreversible.",
                )
            )

        elif context.reversibility == Reversibility.DIFFICULT.value:
            factors.append(
                RiskFactor(
                    code="DIFFICULT_TO_REVERSE",
                    name="Difficult rollback",
                    category=RiskCategory.DESTRUCTIVE.value,
                    score=10.0,
                    reason="The action is difficult to reverse.",
                )
            )

        elif context.reversibility == Reversibility.UNKNOWN.value:
            factors.append(
                RiskFactor(
                    code="UNKNOWN_REVERSIBILITY",
                    name="Unknown rollback capability",
                    category=RiskCategory.GENERAL.value,
                    score=4.0,
                    reason="The action's reversibility is unknown.",
                )
            )

        scope_scores = {
            ActionScope.SELF.value: 0.0,
            ActionScope.RESOURCE.value: 2.0,
            ActionScope.PROJECT.value: 6.0,
            ActionScope.WORKSPACE.value: 12.0,
            ActionScope.ORGANIZATION.value: 18.0,
            ActionScope.EXTERNAL.value: 12.0,
            ActionScope.GLOBAL.value: 30.0,
        }

        scope_score = scope_scores.get(context.action_scope, 5.0)

        if scope_score > 0:
            factors.append(
                RiskFactor(
                    code="ACTION_SCOPE",
                    name="Action impact scope",
                    category=RiskCategory.GENERAL.value,
                    score=scope_score,
                    reason=(
                        f"The action scope is '{context.action_scope}'."
                    ),
                )
            )

        if context.device_trusted is False:
            factors.append(
                RiskFactor(
                    code="UNTRUSTED_DEVICE",
                    name="Untrusted device",
                    category=RiskCategory.DEVICE.value,
                    score=self.config.untrusted_device_penalty,
                    reason="The action originates from an untrusted device.",
                )
            )

        elif context.device_trusted is None and context.device_id:
            factors.append(
                RiskFactor(
                    code="UNKNOWN_DEVICE_TRUST",
                    name="Unknown device trust",
                    category=RiskCategory.DEVICE.value,
                    score=self.config.unknown_device_penalty,
                    reason="Device identity exists but its trust state is unknown.",
                )
            )

        elif context.device_trusted is True:
            factors.append(
                RiskFactor(
                    code="TRUSTED_DEVICE_DISCOUNT",
                    name="Trusted device",
                    category=RiskCategory.DEVICE.value,
                    score=-abs(self.config.trusted_device_discount),
                    reason="A trusted device slightly reduces contextual risk.",
                )
            )

        if context.device_new:
            factors.append(
                RiskFactor(
                    code="NEW_DEVICE",
                    name="New device",
                    category=RiskCategory.DEVICE.value,
                    score=8.0,
                    reason="The action originates from a newly observed device.",
                )
            )

        if context.authentication_age_seconds is not None:
            if (
                context.authentication_age_seconds
                > self.config.stale_auth_seconds
            ):
                factors.append(
                    RiskFactor(
                        code="STALE_AUTHENTICATION",
                        name="Stale authentication",
                        category=RiskCategory.ACCOUNT.value,
                        score=self.config.stale_auth_penalty,
                        reason=(
                            "The authentication event is older than the "
                            "configured stale-authentication limit."
                        ),
                    )
                )

            elif (
                context.authentication_age_seconds
                <= self.config.recent_auth_seconds
            ):
                factors.append(
                    RiskFactor(
                        code="RECENT_AUTH_DISCOUNT",
                        name="Recent authentication",
                        category=RiskCategory.ACCOUNT.value,
                        score=-abs(self.config.recent_auth_discount),
                        reason="The actor authenticated recently.",
                    )
                )

        if context.user_confirmed:
            factors.append(
                RiskFactor(
                    code="USER_CONFIRMATION_DISCOUNT",
                    name="Explicit user confirmation",
                    category=RiskCategory.GENERAL.value,
                    score=-abs(
                        self.config.explicit_user_confirmation_discount
                    ),
                    reason="The user explicitly confirmed the proposed action.",
                )
            )

        secret_matches = self._find_pattern_matches(
            combined_text,
            SECRET_PATTERNS,
        )

        if secret_matches or context.contains_secrets:
            factors.append(
                RiskFactor(
                    code="SECRET_CONTENT",
                    name="Secret or token content",
                    category=RiskCategory.PRIVATE.value,
                    score=self.config.secret_exposure_penalty,
                    reason=(
                        "The action context contains or is marked as containing "
                        "secret material."
                    ),
                    metadata={"detected_types": secret_matches},
                )
            )

        private_matches = self._find_pattern_matches(
            combined_text,
            PRIVATE_DATA_PATTERNS,
        )

        if private_matches or context.contains_private_data:
            factors.append(
                RiskFactor(
                    code="PRIVATE_DATA",
                    name="Private data involved",
                    category=RiskCategory.PRIVATE.value,
                    score=self.config.private_data_penalty,
                    reason=(
                        "The action context contains or is marked as containing "
                        "private data."
                    ),
                    metadata={"detected_types": private_matches},
                )
            )

        return factors

    def _financial_risk_factors(
        self,
        context: ActionContext,
        combined_text: str,
    ) -> List[RiskFactor]:
        factors: List[RiskFactor] = []

        amount = abs(context.amount or 0.0)

        if amount >= self.config.financial_amount_critical:
            factors.append(
                RiskFactor(
                    code="CRITICAL_FINANCIAL_AMOUNT",
                    name="Critical financial amount",
                    category=RiskCategory.FINANCIAL.value,
                    score=35.0,
                    reason=(
                        f"The transaction amount reaches the critical threshold "
                        f"of {self.config.financial_amount_critical:g}."
                    ),
                    metadata={
                        "amount": amount,
                        "currency": context.currency,
                    },
                )
            )

        elif amount >= self.config.financial_amount_high:
            factors.append(
                RiskFactor(
                    code="HIGH_FINANCIAL_AMOUNT",
                    name="High financial amount",
                    category=RiskCategory.FINANCIAL.value,
                    score=25.0,
                    reason=(
                        f"The transaction amount reaches the high threshold of "
                        f"{self.config.financial_amount_high:g}."
                    ),
                    metadata={
                        "amount": amount,
                        "currency": context.currency,
                    },
                )
            )

        elif amount >= self.config.financial_amount_medium:
            factors.append(
                RiskFactor(
                    code="MEDIUM_FINANCIAL_AMOUNT",
                    name="Moderate financial amount",
                    category=RiskCategory.FINANCIAL.value,
                    score=14.0,
                    reason=(
                        f"The transaction amount reaches the medium threshold "
                        f"of {self.config.financial_amount_medium:g}."
                    ),
                    metadata={
                        "amount": amount,
                        "currency": context.currency,
                    },
                )
            )

        elif amount > 0:
            factors.append(
                RiskFactor(
                    code="FINANCIAL_VALUE_TRANSFER",
                    name="Financial value transfer",
                    category=RiskCategory.FINANCIAL.value,
                    score=5.0,
                    reason="The action transfers or changes financial value.",
                    metadata={
                        "amount": amount,
                        "currency": context.currency,
                    },
                )
            )

        if context.changes_billing:
            factors.append(
                RiskFactor(
                    code="BILLING_CHANGE",
                    name="Billing configuration change",
                    category=RiskCategory.FINANCIAL.value,
                    score=18.0,
                    reason="The action changes billing or subscription settings.",
                )
            )

        if context.contains_payment_data:
            factors.append(
                RiskFactor(
                    code="PAYMENT_DATA",
                    name="Payment data involved",
                    category=RiskCategory.PRIVATE.value,
                    score=20.0,
                    reason="Payment-card or financial account data is involved.",
                )
            )

        if _contains_phrase(
            combined_text,
            {"refund", "withdraw", "transfer", "payout", "wire"},
        ):
            factors.append(
                RiskFactor(
                    code="FUNDS_MOVEMENT",
                    name="Funds movement",
                    category=RiskCategory.FINANCIAL.value,
                    score=14.0,
                    reason="The action moves, withdraws, refunds, or pays out funds.",
                )
            )

        if context.external_destination:
            factors.append(
                RiskFactor(
                    code="EXTERNAL_FINANCIAL_DESTINATION",
                    name="External financial destination",
                    category=RiskCategory.FINANCIAL.value,
                    score=12.0,
                    reason="The financial destination is outside the workspace.",
                )
            )

        return factors

    def _destructive_risk_factors(
        self,
        context: ActionContext,
        combined_text: str,
    ) -> List[RiskFactor]:
        factors: List[RiskFactor] = []

        destructive_terms = [
            term
            for term in DESTRUCTIVE_KEYWORDS
            if _contains_phrase(combined_text, {term})
        ]

        if destructive_terms:
            factors.append(
                RiskFactor(
                    code="DESTRUCTIVE_OPERATION",
                    name="Destructive operation",
                    category=RiskCategory.DESTRUCTIVE.value,
                    score=15.0,
                    reason=(
                        "The action includes destructive operation terms."
                    ),
                    metadata={"matched_terms": sorted(destructive_terms)},
                )
            )

        if context.item_count > 1:
            factors.append(
                RiskFactor(
                    code="MULTI_RESOURCE_DESTRUCTION",
                    name="Multiple resources affected",
                    category=RiskCategory.DESTRUCTIVE.value,
                    score=min(20.0, math.log10(context.item_count + 1) * 8.0),
                    reason=(
                        f"The destructive action may affect "
                        f"{context.item_count} resources."
                    ),
                )
            )

        if context.action_scope in {
            ActionScope.WORKSPACE.value,
            ActionScope.ORGANIZATION.value,
            ActionScope.GLOBAL.value,
        }:
            factors.append(
                RiskFactor(
                    code="WIDE_DESTRUCTIVE_SCOPE",
                    name="Wide destructive scope",
                    category=RiskCategory.DESTRUCTIVE.value,
                    score=18.0,
                    reason=(
                        "The destructive action has workspace-wide or broader "
                        "impact."
                    ),
                )
            )

        return factors

    def _private_risk_factors(
        self,
        context: ActionContext,
        combined_text: str,
    ) -> List[RiskFactor]:
        factors: List[RiskFactor] = []

        if context.contains_credentials:
            factors.append(
                RiskFactor(
                    code="CREDENTIAL_DATA",
                    name="Credential data involved",
                    category=RiskCategory.PRIVATE.value,
                    score=25.0,
                    reason="Credentials are involved in the proposed action.",
                )
            )

        if context.contains_health_data:
            factors.append(
                RiskFactor(
                    code="HEALTH_DATA",
                    name="Sensitive health data",
                    category=RiskCategory.PRIVATE.value,
                    score=22.0,
                    reason="The proposed action involves sensitive health data.",
                )
            )

        if context.contains_personal_identifiers:
            factors.append(
                RiskFactor(
                    code="PERSONAL_IDENTIFIERS",
                    name="Personal identifiers",
                    category=RiskCategory.PRIVATE.value,
                    score=18.0,
                    reason="The action involves personally identifying information.",
                )
            )

        if _contains_phrase(
            combined_text,
            {"export", "download", "share", "send", "upload", "sync"},
        ):
            factors.append(
                RiskFactor(
                    code="DATA_MOVEMENT",
                    name="Private data movement",
                    category=RiskCategory.PRIVATE.value,
                    score=12.0,
                    reason="The action may move or disclose data.",
                )
            )

        if context.external_destination:
            factors.append(
                RiskFactor(
                    code="PRIVATE_DATA_EXTERNAL_DESTINATION",
                    name="Private data leaves workspace",
                    category=RiskCategory.PRIVATE.value,
                    score=20.0,
                    reason="Private data may be sent outside the workspace.",
                )
            )

        return factors

    def _device_risk_factors(
        self,
        context: ActionContext,
        combined_text: str,
    ) -> List[RiskFactor]:
        factors: List[RiskFactor] = []

        sensitive_device_capabilities = {
            "camera": 8.0,
            "microphone": 12.0,
            "location": 10.0,
            "gps": 10.0,
            "contacts": 12.0,
            "sms": 15.0,
            "dialer": 15.0,
            "accessibility": 20.0,
            "clipboard": 8.0,
            "screen": 8.0,
            "storage": 8.0,
        }

        for capability, score in sensitive_device_capabilities.items():
            if _contains_phrase(combined_text, {capability}):
                factors.append(
                    RiskFactor(
                        code=f"DEVICE_{capability.upper()}",
                        name=f"Device capability: {capability}",
                        category=RiskCategory.DEVICE.value,
                        score=score,
                        reason=(
                            f"The action accesses or controls device "
                            f"capability '{capability}'."
                        ),
                    )
                )

        if context.device_id is None:
            factors.append(
                RiskFactor(
                    code="DEVICE_ID_MISSING",
                    name="Device identity missing",
                    category=RiskCategory.DEVICE.value,
                    score=6.0,
                    reason=(
                        "A device-related action does not include a device "
                        "identifier."
                    ),
                )
            )

        return factors

    def _terminal_risk_factors(
        self,
        context: ActionContext,
        combined_text: str,
    ) -> List[RiskFactor]:
        factors: List[RiskFactor] = []

        command_text = context.command or combined_text

        for pattern, description, score in CRITICAL_TERMINAL_PATTERNS:
            if re.search(pattern, command_text, flags=re.IGNORECASE):
                factors.append(
                    RiskFactor(
                        code="CRITICAL_COMMAND_PATTERN",
                        name="Critical terminal command",
                        category=RiskCategory.TERMINAL.value,
                        score=score,
                        reason=description,
                        blocking=score >= self.config.deny_threshold,
                        metadata={"pattern_hash": _hash_text(pattern)[:12]},
                    )
                )

        for pattern, description, score in SENSITIVE_COMMAND_PATTERNS:
            if re.search(pattern, command_text, flags=re.IGNORECASE):
                factors.append(
                    RiskFactor(
                        code="SENSITIVE_COMMAND_PATTERN",
                        name="Sensitive terminal command",
                        category=RiskCategory.TERMINAL.value,
                        score=score,
                        reason=description,
                        metadata={"pattern_hash": _hash_text(pattern)[:12]},
                    )
                )

        shell_operators = re.findall(
            r"(?:&&|\|\||;|\||>|>>|<|\$\(|`)",
            command_text,
        )

        if len(shell_operators) >= 3:
            factors.append(
                RiskFactor(
                    code="COMPLEX_SHELL_CHAIN",
                    name="Complex shell command chain",
                    category=RiskCategory.TERMINAL.value,
                    score=10.0,
                    reason=(
                        "The terminal command chains multiple shell operations, "
                        "making its behavior harder to verify."
                    ),
                    metadata={"operator_count": len(shell_operators)},
                )
            )

        if context.elevated_privileges or re.search(
            r"\b(sudo|root|administrator)\b",
            command_text,
            flags=re.IGNORECASE,
        ):
            factors.append(
                RiskFactor(
                    code="TERMINAL_ELEVATION",
                    name="Terminal privilege elevation",
                    category=RiskCategory.TERMINAL.value,
                    score=15.0,
                    reason="The terminal action requests elevated privileges.",
                )
            )

        return factors

    def _account_risk_factors(
        self,
        context: ActionContext,
        combined_text: str,
    ) -> List[RiskFactor]:
        factors: List[RiskFactor] = []

        if context.changes_permissions:
            factors.append(
                RiskFactor(
                    code="PERMISSION_CHANGE",
                    name="Permission modification",
                    category=RiskCategory.ACCOUNT.value,
                    score=25.0,
                    reason="The action changes account or workspace permissions.",
                )
            )

        if context.changes_ownership:
            factors.append(
                RiskFactor(
                    code="OWNERSHIP_CHANGE",
                    name="Ownership transfer",
                    category=RiskCategory.ACCOUNT.value,
                    score=35.0,
                    reason="The action transfers or changes ownership.",
                )
            )

        if context.changes_security_settings:
            factors.append(
                RiskFactor(
                    code="SECURITY_SETTINGS_CHANGE",
                    name="Security settings modification",
                    category=RiskCategory.ACCOUNT.value,
                    score=25.0,
                    reason="The action changes security settings.",
                )
            )

        if context.disables_security_controls:
            factors.append(
                RiskFactor(
                    code="SECURITY_CONTROL_DISABLE",
                    name="Security controls disabled",
                    category=RiskCategory.ACCOUNT.value,
                    score=45.0,
                    reason="The action disables or weakens security controls.",
                )
            )

        if _contains_phrase(
            combined_text,
            {
                "change password",
                "reset password",
                "disable mfa",
                "remove 2fa",
                "change recovery",
            },
        ):
            factors.append(
                RiskFactor(
                    code="AUTHENTICATION_CHANGE",
                    name="Authentication configuration change",
                    category=RiskCategory.ACCOUNT.value,
                    score=20.0,
                    reason="The action changes account authentication controls.",
                )
            )

        if _contains_phrase(
            combined_text,
            {"delete account", "remove owner", "suspend user"},
        ):
            factors.append(
                RiskFactor(
                    code="ACCOUNT_AVAILABILITY_CHANGE",
                    name="Account availability change",
                    category=RiskCategory.ACCOUNT.value,
                    score=25.0,
                    reason="The action may remove or suspend account access.",
                )
            )

        return factors

    def _secondary_category_factors(
        self,
        context: ActionContext,
        combined_text: str,
        *,
        primary_category: RiskCategory,
    ) -> List[RiskFactor]:
        factors: List[RiskFactor] = []

        mappings = (
            (
                RiskCategory.FINANCIAL,
                FINANCIAL_KEYWORDS,
                8.0,
                "Secondary financial impact detected.",
            ),
            (
                RiskCategory.DESTRUCTIVE,
                DESTRUCTIVE_KEYWORDS,
                10.0,
                "Secondary destructive impact detected.",
            ),
            (
                RiskCategory.PRIVATE,
                PRIVATE_KEYWORDS,
                8.0,
                "Secondary private-data impact detected.",
            ),
            (
                RiskCategory.DEVICE,
                DEVICE_KEYWORDS,
                6.0,
                "Secondary device-access impact detected.",
            ),
            (
                RiskCategory.TERMINAL,
                TERMINAL_KEYWORDS,
                8.0,
                "Secondary terminal-execution impact detected.",
            ),
            (
                RiskCategory.ACCOUNT,
                ACCOUNT_KEYWORDS,
                8.0,
                "Secondary account impact detected.",
            ),
        )

        for category, keywords, score, reason in mappings:
            if category == primary_category:
                continue

            if _contains_phrase(combined_text, keywords):
                factors.append(
                    RiskFactor(
                        code=f"SECONDARY_{category.value.upper()}",
                        name=f"Secondary {category.value} risk",
                        category=category.value,
                        score=score,
                        reason=reason,
                    )
                )

        return factors

    # -------------------------------------------------------------------------
    # Permission and policy integration
    # -------------------------------------------------------------------------

    def _evaluate_permission(
        self,
        context: ActionContext,
    ) -> Dict[str, Any]:
        if context.permission_granted is not None:
            return self._safe_result(
                success=context.permission_granted,
                message=(
                    "Permission was pre-validated."
                    if context.permission_granted
                    else "Permission was pre-denied."
                ),
                data={
                    "allowed": context.permission_granted,
                    "source": "action_context",
                },
                error=(
                    None
                    if context.permission_granted
                    else {"code": "PERMISSION_DENIED"}
                ),
                metadata={"operation": "permission_check"},
            )

        if self.permission_checker is None:
            return self._safe_result(
                success=not self.config.default_deny_on_permission_failure,
                message=(
                    "Permission checker is not connected."
                    if self.config.default_deny_on_permission_failure
                    else "Permission checker unavailable; policy allows fallback."
                ),
                data={
                    "allowed": not self.config.default_deny_on_permission_failure,
                    "source": "fallback",
                    "checker_available": False,
                },
                error=(
                    {"code": "PERMISSION_CHECKER_UNAVAILABLE"}
                    if self.config.default_deny_on_permission_failure
                    else None
                ),
                metadata={"operation": "permission_check"},
            )

        try:
            raw_result = self.permission_checker.check_permission(
                user_id=context.user_id,
                workspace_id=context.workspace_id,
                action=context.action,
                resource=context.resource,
                context={
                    "task_id": context.task_id,
                    "actor_role": context.actor_role,
                    "source_agent": context.source_agent,
                    "category": context.category,
                },
            )

            if isinstance(raw_result, bool):
                allowed = raw_result
                return self._safe_result(
                    success=allowed,
                    message=(
                        "Permission granted."
                        if allowed
                        else "Permission denied."
                    ),
                    data={
                        "allowed": allowed,
                        "source": "permission_checker",
                    },
                    error=(
                        None
                        if allowed
                        else {"code": "PERMISSION_DENIED"}
                    ),
                    metadata={"operation": "permission_check"},
                )

            if isinstance(raw_result, dict):
                allowed = bool(
                    raw_result.get(
                        "allowed",
                        raw_result.get("success", False),
                    )
                )

                return self._safe_result(
                    success=allowed,
                    message=str(
                        raw_result.get(
                            "message",
                            "Permission granted."
                            if allowed
                            else "Permission denied.",
                        )
                    ),
                    data={
                        **raw_result.get("data", {}),
                        "allowed": allowed,
                        "source": "permission_checker",
                    },
                    error=raw_result.get("error"),
                    metadata={
                        "operation": "permission_check",
                        **raw_result.get("metadata", {}),
                    },
                )

            return self._error_result(
                message="Permission checker returned an unsupported response.",
                error={"code": "INVALID_PERMISSION_RESPONSE"},
                data={"allowed": False},
                metadata={"operation": "permission_check"},
            )

        except Exception as exc:
            self.logger.exception("Permission evaluation failed.")

            return self._error_result(
                message="Permission evaluation failed.",
                error=exc,
                data={
                    "allowed": not self.config.default_deny_on_permission_failure,
                    "source": "permission_checker_exception",
                },
                metadata={"operation": "permission_check"},
            )

    def _permission_risk_factors(
        self,
        context: ActionContext,
        permission_result: Dict[str, Any],
    ) -> List[RiskFactor]:
        allowed = bool(
            permission_result.get("data", {}).get(
                "allowed",
                permission_result.get("success", False),
            )
        )

        if allowed:
            return []

        return [
            RiskFactor(
                code="PERMISSION_NOT_GRANTED",
                name="Permission not granted",
                category=RiskCategory.ACCOUNT.value,
                score=100.0,
                reason=(
                    "The actor does not have verified permission to perform "
                    "the proposed action."
                ),
                blocking=True,
                metadata={
                    "permission_error": permission_result.get("error"),
                },
            )
        ]

    def _load_policy(
        self,
        context: ActionContext,
    ) -> Dict[str, Any]:
        if self.policy_provider is None:
            return {}

        try:
            policy = self.policy_provider.get_risk_policy(
                user_id=context.user_id,
                workspace_id=context.workspace_id,
                action_type=context.category or "auto",
                context={
                    "action": context.action,
                    "actor_role": context.actor_role,
                    "subscription_plan": context.subscription_plan,
                    "source_agent": context.source_agent,
                },
            )

            return policy if isinstance(policy, dict) else {}

        except Exception:
            self.logger.exception("Workspace risk policy loading failed.")
            return {
                "policy_error": True,
                "score_adjustment": 5.0,
                "reason": "Risk policy could not be loaded.",
            }

    def _policy_factors(
        self,
        context: ActionContext,
        policy_data: Dict[str, Any],
    ) -> List[RiskFactor]:
        factors: List[RiskFactor] = []

        if policy_data.get("deny") is True:
            factors.append(
                RiskFactor(
                    code="POLICY_DENY",
                    name="Workspace policy denial",
                    category=RiskCategory.ACCOUNT.value,
                    score=100.0,
                    reason=str(
                        policy_data.get(
                            "reason",
                            "Workspace policy denies this action.",
                        )
                    ),
                    blocking=True,
                )
            )

        if policy_data.get("require_biometric") is True:
            factors.append(
                RiskFactor(
                    code="POLICY_BIOMETRIC",
                    name="Workspace biometric policy",
                    category=RiskCategory.ACCOUNT.value,
                    score=5.0,
                    reason="Workspace policy requires biometric verification.",
                    metadata={"force_biometric": True},
                )
            )

        if policy_data.get("require_multi_approval") is True:
            factors.append(
                RiskFactor(
                    code="POLICY_MULTI_APPROVAL",
                    name="Workspace multi-approval policy",
                    category=RiskCategory.ACCOUNT.value,
                    score=10.0,
                    reason="Workspace policy requires multiple approvers.",
                    metadata={"force_multi_approval": True},
                )
            )

        adjustment = _safe_float(
            policy_data.get("score_adjustment"),
            0.0,
        ) or 0.0

        if adjustment != 0 and self.config.allow_policy_score_adjustment:
            adjustment = _clamp(
                adjustment,
                -abs(self.config.maximum_policy_discount),
                abs(self.config.maximum_policy_penalty),
            )

            factors.append(
                RiskFactor(
                    code="POLICY_SCORE_ADJUSTMENT",
                    name="Workspace policy adjustment",
                    category=RiskCategory.GENERAL.value,
                    score=adjustment,
                    reason=str(
                        policy_data.get(
                            "reason",
                            "Workspace policy adjusted the risk score.",
                        )
                    ),
                )
            )

        return factors

    # -------------------------------------------------------------------------
    # Assessment finalization
    # -------------------------------------------------------------------------

    def _finalize_assessment(
        self,
        context: ActionContext,
        *,
        factors: List[RiskFactor],
        policy_data: Dict[str, Any],
    ) -> RiskAssessment:
        combined_text = self._combined_context_text(context)
        category, _ = self._resolve_context_category(
            context,
            combined_text,
        )

        blocked = any(factor.blocking for factor in factors)

        raw_score = sum(factor.score for factor in factors)

        if blocked:
            score = self.config.maximum_score
            level = RiskLevel.BLOCKED
            decision = RiskDecision.DENY

        else:
            score = _clamp(
                raw_score,
                self.config.minimum_score,
                self.config.maximum_score,
            )
            level = self._score_to_level(score)
            decision = self._score_to_decision(score)

        force_biometric = any(
            bool(factor.metadata.get("force_biometric"))
            for factor in factors
        )

        force_multi_approval = any(
            bool(factor.metadata.get("force_multi_approval"))
            for factor in factors
        )

        requires_confirmation = (
            score >= self.config.confirmation_threshold
            or decision
            in {
                RiskDecision.REQUIRE_CONFIRMATION,
                RiskDecision.REQUIRE_APPROVAL,
                RiskDecision.REQUIRE_BIOMETRIC,
                RiskDecision.REQUIRE_MULTI_APPROVAL,
                RiskDecision.DENY,
            }
        )

        requires_approval = (
            score >= self.config.approval_threshold
            or decision
            in {
                RiskDecision.REQUIRE_APPROVAL,
                RiskDecision.REQUIRE_BIOMETRIC,
                RiskDecision.REQUIRE_MULTI_APPROVAL,
                RiskDecision.DENY,
            }
        )

        requires_biometric = (
            score >= self.config.biometric_threshold
            or force_biometric
            or decision
            in {
                RiskDecision.REQUIRE_BIOMETRIC,
                RiskDecision.REQUIRE_MULTI_APPROVAL,
                RiskDecision.DENY,
            }
        )

        requires_multi_approval = (
            score >= self.config.multi_approval_threshold
            or force_multi_approval
            or decision
            in {
                RiskDecision.REQUIRE_MULTI_APPROVAL,
                RiskDecision.DENY,
            }
        )

        requires_security_check = self._requires_security_check(
            action=context.action,
            category=category.value,
            score=score,
            metadata=context.metadata,
        )

        controls = self._required_controls(
            blocked=blocked,
            requires_security_check=requires_security_check,
            requires_confirmation=requires_confirmation,
            requires_approval=requires_approval,
            requires_biometric=requires_biometric,
            requires_multi_approval=requires_multi_approval,
        )

        recommendations = self._build_recommendations(
            context,
            score=score,
            level=level,
            decision=decision,
            factors=factors,
            controls=controls,
        )

        return RiskAssessment(
            assessment_id=_safe_uuid("risk"),
            user_id=context.user_id,
            workspace_id=context.workspace_id,
            action=_normalize_action(context.action),
            category=category.value,
            score=round(score, 2),
            level=level.value,
            decision=decision.value,
            requires_security_check=requires_security_check,
            requires_user_confirmation=requires_confirmation,
            requires_approval=requires_approval,
            requires_biometric=requires_biometric,
            requires_multi_approval=requires_multi_approval,
            blocked=blocked,
            factors=factors,
            recommendations=recommendations,
            required_controls=controls,
            metadata={
                "version": self.VERSION,
                "factor_count": len(factors),
                "policy_applied": bool(policy_data),
                "raw_score": round(raw_score, 2),
                "score_clamped": raw_score != score,
            },
        )

    def _build_context_failure_assessment(
        self,
        context: ActionContext,
        validation: Dict[str, Any],
    ) -> RiskAssessment:
        factor = RiskFactor(
            code="INVALID_TASK_CONTEXT",
            name="Invalid task context",
            category=RiskCategory.PRIVATE.value,
            score=100.0,
            reason=(
                "The action lacks valid tenant context or violates SaaS "
                "user/workspace isolation."
            ),
            blocking=True,
            metadata={
                "validation_error": validation.get("error"),
            },
        )

        return RiskAssessment(
            assessment_id=_safe_uuid("risk"),
            user_id=context.user_id,
            workspace_id=context.workspace_id,
            action=_normalize_action(context.action),
            category=RiskCategory.PRIVATE.value,
            score=100.0,
            level=RiskLevel.BLOCKED.value,
            decision=RiskDecision.DENY.value,
            requires_security_check=True,
            requires_user_confirmation=False,
            requires_approval=False,
            requires_biometric=False,
            requires_multi_approval=False,
            blocked=True,
            factors=[factor],
            recommendations=[
                "Reject the action.",
                "Restore valid user_id and workspace_id context.",
                "Do not permit cross-tenant execution without an explicit secure delegation policy.",
            ],
            required_controls=["deny_execution", "tenant_context_validation"],
            metadata={
                "version": self.VERSION,
                "context_validation_failed": True,
            },
        )

    def _assessment_result(
        self,
        assessment: RiskAssessment,
        context: ActionContext,
        *,
        permission_result: Optional[Dict[str, Any]],
        approval_result: Optional[Dict[str, Any]],
        elapsed_ms: float,
    ) -> Dict[str, Any]:
        assessment_data = asdict(assessment)

        if not self.config.include_command_text_in_results:
            assessment_data["command"] = None

        assessment_data["safe_context"] = self._safe_context_snapshot(context)

        verification_payload = (
            self._prepare_verification_payload(
                assessment=assessment,
                source_agent=context.source_agent,
                task_id=context.task_id,
            )
            if self.config.verification_payload_enabled
            else None
        )

        memory_payload = (
            self._prepare_memory_payload(
                assessment=assessment,
                task_id=context.task_id,
                source_agent=context.source_agent,
            )
            if self.config.memory_payload_enabled
            else None
        )

        metadata = {
            "operation": "assess_risk",
            "agent": self.AGENT_NAME,
            "agent_id": self.AGENT_ID,
            "module": self.MODULE_NAME,
            "version": self.VERSION,
            "processing_ms": round(elapsed_ms, 3),
            "verification_payload": verification_payload,
            "memory_payload": memory_payload,
            "permission_result": permission_result,
            "approval_result": approval_result,
        }

        return self._safe_result(
            success=True,
            message=(
                "Risk assessment completed. Execution is denied."
                if assessment.blocked
                else "Risk assessment completed successfully."
            ),
            data=assessment_data,
            metadata=metadata,
        )

    def _record_assessment(
        self,
        assessment: RiskAssessment,
        context: ActionContext,
        *,
        status: str,
        elapsed_ms: float,
    ) -> None:
        event_payload = {
            "assessment_id": assessment.assessment_id,
            "user_id": assessment.user_id,
            "workspace_id": assessment.workspace_id,
            "task_id": context.task_id,
            "source_agent": context.source_agent,
            "action_hash": _hash_text(assessment.action)[:16],
            "category": assessment.category,
            "score": assessment.score,
            "level": assessment.level,
            "decision": assessment.decision,
            "blocked": assessment.blocked,
            "required_controls": assessment.required_controls,
            "processing_ms": round(elapsed_ms, 3),
            "created_at": assessment.created_at,
        }

        self._emit_agent_event(
            event_name="security.risk.assessed",
            payload=event_payload,
        )

        self._log_audit_event(
            event_type="security.risk.assessed",
            user_id=assessment.user_id,
            workspace_id=assessment.workspace_id,
            status=status,
            assessment_id=assessment.assessment_id,
            metadata=event_payload,
        )

    # -------------------------------------------------------------------------
    # Decision helpers
    # -------------------------------------------------------------------------

    def _score_to_level(self, score: float) -> RiskLevel:
        score = _clamp(
            score,
            self.config.minimum_score,
            self.config.maximum_score,
        )

        thresholds = self.config.thresholds

        if score <= thresholds.minimal_max:
            return RiskLevel.MINIMAL

        if score <= thresholds.low_max:
            return RiskLevel.LOW

        if score <= thresholds.medium_max:
            return RiskLevel.MEDIUM

        if score <= thresholds.high_max:
            return RiskLevel.HIGH

        return RiskLevel.CRITICAL

    def _score_to_decision(self, score: float) -> RiskDecision:
        if score >= self.config.deny_threshold:
            return RiskDecision.DENY

        if score >= self.config.multi_approval_threshold:
            return RiskDecision.REQUIRE_MULTI_APPROVAL

        if score >= self.config.biometric_threshold:
            return RiskDecision.REQUIRE_BIOMETRIC

        if score >= self.config.approval_threshold:
            return RiskDecision.REQUIRE_APPROVAL

        if score >= self.config.confirmation_threshold:
            return RiskDecision.REQUIRE_CONFIRMATION

        if score > self.config.thresholds.minimal_max:
            return RiskDecision.ALLOW_WITH_LOGGING

        return RiskDecision.ALLOW

    def _required_controls(
        self,
        *,
        blocked: bool,
        requires_security_check: bool,
        requires_confirmation: bool,
        requires_approval: bool,
        requires_biometric: bool,
        requires_multi_approval: bool,
    ) -> List[str]:
        controls: List[str] = []

        if blocked:
            controls.append("deny_execution")

        if requires_security_check:
            controls.append("security_agent_review")

        if requires_confirmation:
            controls.append("explicit_user_confirmation")

        if requires_approval:
            controls.append("security_approval")

        if requires_biometric:
            controls.append("biometric_verification")

        if requires_multi_approval:
            controls.append("multi_party_approval")

        controls.extend(
            [
                "audit_logging",
                "verification_payload",
                "tenant_isolation",
            ]
        )

        return list(dict.fromkeys(controls))

    def _build_recommendations(
        self,
        context: ActionContext,
        *,
        score: float,
        level: RiskLevel,
        decision: RiskDecision,
        factors: List[RiskFactor],
        controls: List[str],
    ) -> List[str]:
        recommendations: List[str] = []

        if decision == RiskDecision.DENY:
            recommendations.append(
                "Do not execute the action in its current form."
            )

        elif decision == RiskDecision.REQUIRE_MULTI_APPROVAL:
            recommendations.append(
                "Require approval from at least two authorized reviewers."
            )

        elif decision == RiskDecision.REQUIRE_BIOMETRIC:
            recommendations.append(
                "Require fresh biometric or equivalent step-up authentication."
            )

        elif decision == RiskDecision.REQUIRE_APPROVAL:
            recommendations.append(
                "Require explicit Security Agent approval before execution."
            )

        elif decision == RiskDecision.REQUIRE_CONFIRMATION:
            recommendations.append(
                "Show the exact action impact and request explicit user confirmation."
            )

        elif decision == RiskDecision.ALLOW_WITH_LOGGING:
            recommendations.append(
                "Execution may proceed only after permission validation and audit logging."
            )

        else:
            recommendations.append(
                "Execution may proceed after normal permission validation."
            )

        factor_codes = {factor.code for factor in factors}

        if "IRREVERSIBLE_ACTION" in factor_codes:
            recommendations.append(
                "Create a backup or recovery point before execution."
            )

        if "HIGH_BULK_ACTION" in factor_codes or "MASS_BULK_ACTION" in factor_codes:
            recommendations.append(
                "Provide a preview and sample before applying the action to all items."
            )

        if "SECRET_CONTENT" in factor_codes:
            recommendations.append(
                "Redact secrets and prevent them from entering logs, memory, or analytics."
            )

        if "PRIVATE_DATA" in factor_codes:
            recommendations.append(
                "Apply minimum-data handling and verify destination authorization."
            )

        if context.external_destination:
            recommendations.append(
                "Verify the external recipient, destination, and data-sharing policy."
            )

        if context.action_scope in {
            ActionScope.WORKSPACE.value,
            ActionScope.ORGANIZATION.value,
            ActionScope.GLOBAL.value,
        }:
            recommendations.append(
                "Display the workspace-wide impact before requesting approval."
            )

        if score >= self.config.approval_threshold:
            recommendations.append(
                "Send the completed result to Verification Agent before marking the task complete."
            )

        recommendations.append(
            f"Required controls: {', '.join(controls)}."
        )

        return list(dict.fromkeys(recommendations))

    # -------------------------------------------------------------------------
    # Classification helpers
    # -------------------------------------------------------------------------

    def _resolve_context_category(
        self,
        context: ActionContext,
        combined_text: str,
    ) -> Tuple[RiskCategory, List[str]]:
        explicit = self._normalize_category(context.category)

        if explicit != RiskCategory.GENERAL or (
            context.category
            and str(context.category).lower() == RiskCategory.GENERAL.value
        ):
            return explicit, ["explicit_category"]

        return self._classify_category(combined_text)

    def _classify_category(
        self,
        combined_text: str,
    ) -> Tuple[RiskCategory, List[str]]:
        category_scores: Dict[RiskCategory, int] = {
            RiskCategory.FINANCIAL: self._keyword_match_count(
                combined_text,
                FINANCIAL_KEYWORDS,
            ),
            RiskCategory.DESTRUCTIVE: self._keyword_match_count(
                combined_text,
                DESTRUCTIVE_KEYWORDS,
            ),
            RiskCategory.PRIVATE: self._keyword_match_count(
                combined_text,
                PRIVATE_KEYWORDS,
            ),
            RiskCategory.DEVICE: self._keyword_match_count(
                combined_text,
                DEVICE_KEYWORDS,
            ),
            RiskCategory.TERMINAL: self._keyword_match_count(
                combined_text,
                TERMINAL_KEYWORDS,
            ),
            RiskCategory.ACCOUNT: self._keyword_match_count(
                combined_text,
                ACCOUNT_KEYWORDS,
            ),
        }

        priority = {
            RiskCategory.DESTRUCTIVE: 6,
            RiskCategory.FINANCIAL: 5,
            RiskCategory.ACCOUNT: 4,
            RiskCategory.TERMINAL: 3,
            RiskCategory.PRIVATE: 2,
            RiskCategory.DEVICE: 1,
        }

        best_category = max(
            category_scores,
            key=lambda item: (
                category_scores[item],
                priority.get(item, 0),
            ),
        )

        if category_scores[best_category] <= 0:
            return RiskCategory.GENERAL, []

        keyword_map = {
            RiskCategory.FINANCIAL: FINANCIAL_KEYWORDS,
            RiskCategory.DESTRUCTIVE: DESTRUCTIVE_KEYWORDS,
            RiskCategory.PRIVATE: PRIVATE_KEYWORDS,
            RiskCategory.DEVICE: DEVICE_KEYWORDS,
            RiskCategory.TERMINAL: TERMINAL_KEYWORDS,
            RiskCategory.ACCOUNT: ACCOUNT_KEYWORDS,
        }

        matches = sorted(
            phrase
            for phrase in keyword_map[best_category]
            if _contains_phrase(combined_text, {phrase})
        )

        return best_category, matches

    def _normalize_category(
        self,
        category: Optional[Union[str, RiskCategory]],
    ) -> RiskCategory:
        if isinstance(category, RiskCategory):
            return category

        normalized = str(category or "").strip().lower()

        aliases = {
            "finance": RiskCategory.FINANCIAL,
            "money": RiskCategory.FINANCIAL,
            "payment": RiskCategory.FINANCIAL,
            "delete": RiskCategory.DESTRUCTIVE,
            "destruction": RiskCategory.DESTRUCTIVE,
            "privacy": RiskCategory.PRIVATE,
            "personal_data": RiskCategory.PRIVATE,
            "pii": RiskCategory.PRIVATE,
            "hardware": RiskCategory.DEVICE,
            "mobile": RiskCategory.DEVICE,
            "shell": RiskCategory.TERMINAL,
            "command": RiskCategory.TERMINAL,
            "system": RiskCategory.TERMINAL,
            "identity": RiskCategory.ACCOUNT,
            "auth": RiskCategory.ACCOUNT,
            "authentication": RiskCategory.ACCOUNT,
        }

        if normalized in aliases:
            return aliases[normalized]

        try:
            return RiskCategory(normalized)
        except ValueError:
            return RiskCategory.GENERAL

    def _normalize_scope(self, scope: Any) -> str:
        normalized = str(scope or "").strip().lower()

        try:
            return ActionScope(normalized).value
        except ValueError:
            return ActionScope.SELF.value

    def _normalize_reversibility(self, reversibility: Any) -> str:
        normalized = str(reversibility or "").strip().lower()

        aliases = {
            "reversible": Reversibility.FULLY_REVERSIBLE.value,
            "partial": Reversibility.PARTIALLY_REVERSIBLE.value,
            "hard": Reversibility.DIFFICULT.value,
            "not_reversible": Reversibility.IRREVERSIBLE.value,
        }

        if normalized in aliases:
            return aliases[normalized]

        try:
            return Reversibility(normalized).value
        except ValueError:
            return Reversibility.UNKNOWN.value

    def _keyword_match_count(
        self,
        text: str,
        keywords: Set[str],
    ) -> int:
        return sum(
            1
            for keyword in keywords
            if _contains_phrase(text, {keyword})
        )

    # -------------------------------------------------------------------------
    # Safe text and metadata helpers
    # -------------------------------------------------------------------------

    def _combined_context_text(self, context: ActionContext) -> str:
        return self._combined_action_text(
            action=context.action,
            description=context.description,
            command=context.command,
            target=context.target,
            resource=context.resource,
            metadata=context.metadata,
            arguments=context.arguments,
        )

    def _combined_action_text(
        self,
        *,
        action: Optional[str],
        description: Optional[str],
        command: Optional[str],
        target: Optional[str],
        resource: Optional[str],
        metadata: Optional[Dict[str, Any]],
        arguments: Optional[List[str]] = None,
    ) -> str:
        metadata_text = ""

        try:
            metadata_text = json.dumps(
                metadata or {},
                sort_keys=True,
                default=str,
            )
        except Exception:
            metadata_text = str(metadata or {})

        return " ".join(
            part
            for part in [
                action or "",
                description or "",
                command or "",
                target or "",
                resource or "",
                " ".join(arguments or []),
                metadata_text,
            ]
            if part
        ).lower()

    def _safe_context_snapshot(
        self,
        context: ActionContext,
    ) -> Dict[str, Any]:
        snapshot = {
            "action": _normalize_action(context.action),
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "task_id": context.task_id,
            "session_id": context.session_id,
            "request_id": context.request_id,
            "category": context.category,
            "resource": context.resource,
            "target": context.target,
            "amount": context.amount,
            "currency": context.currency,
            "item_count": context.item_count,
            "action_scope": context.action_scope,
            "reversibility": context.reversibility,
            "source_agent": context.source_agent,
            "destination_agent": context.destination_agent,
            "device_id": context.device_id,
            "device_trusted": context.device_trusted,
            "authenticated": context.authenticated,
            "actor_role": context.actor_role,
            "contains_private_data": context.contains_private_data,
            "contains_secrets": context.contains_secrets,
            "contains_credentials": context.contains_credentials,
            "external_destination": context.external_destination,
            "automated": context.automated,
            "scheduled": context.scheduled,
        }

        if self.config.include_command_text_in_results:
            snapshot["command"] = context.command
        elif context.command:
            snapshot["command_hash"] = _hash_text(context.command)

        return snapshot

    def _find_pattern_matches(
        self,
        text: str,
        patterns: Iterable[Tuple[str, str]],
    ) -> List[str]:
        matches: List[str] = []

        for pattern, label in patterns:
            if re.search(pattern, text, flags=re.IGNORECASE):
                matches.append(label)

        return sorted(set(matches))

    def _deduplicate_factors(
        self,
        factors: List[RiskFactor],
    ) -> List[RiskFactor]:
        """
        Deduplicate identical factors without losing distinct pattern matches.

        Factors with the same code, reason, and score are considered duplicates.
        """

        output: List[RiskFactor] = []
        seen: Set[Tuple[str, str, float]] = set()

        for factor in factors:
            key = (
                factor.code,
                factor.reason,
                round(factor.score, 4),
            )

            if key in seen:
                continue

            seen.add(key)
            output.append(factor)

        return output

    def _strictest_decision(
        self,
        decisions: Sequence[str],
    ) -> RiskDecision:
        ranking = {
            RiskDecision.ALLOW.value: 0,
            RiskDecision.ALLOW_WITH_LOGGING.value: 1,
            RiskDecision.REQUIRE_CONFIRMATION.value: 2,
            RiskDecision.REQUIRE_APPROVAL.value: 3,
            RiskDecision.REQUIRE_BIOMETRIC.value: 4,
            RiskDecision.REQUIRE_MULTI_APPROVAL.value: 5,
            RiskDecision.DENY.value: 6,
        }

        if not decisions:
            return RiskDecision.ALLOW

        strictest = max(
            decisions,
            key=lambda item: ranking.get(item, 6),
        )

        try:
            return RiskDecision(strictest)
        except ValueError:
            return RiskDecision.DENY


# =============================================================================
# Factory and registry compatibility
# =============================================================================

def create_risk_engine(
    *,
    config: Optional[RiskEngineConfig] = None,
    permission_checker: Optional[PermissionCheckerProtocol] = None,
    policy_provider: Optional[PolicyProviderProtocol] = None,
    event_emitter: Optional[EventEmitterProtocol] = None,
    audit_logger: Optional[AuditLoggerProtocol] = None,
    logger: Optional[logging.Logger] = None,
    **kwargs: Any,
) -> RiskEngine:
    """
    Factory for Agent Loader, Agent Registry, FastAPI dependency injection, and
    unit tests.
    """

    return RiskEngine(
        config=config,
        permission_checker=permission_checker,
        policy_provider=policy_provider,
        event_emitter=event_emitter,
        audit_logger=audit_logger,
        logger=logger,
        **kwargs,
    )


def get_agent_manifest() -> Dict[str, Any]:
    """
    Import-safe manifest for William's future Agent Registry and Agent Loader.
    """

    return {
        "agent_name": RiskEngine.AGENT_NAME,
        "agent_id": RiskEngine.AGENT_ID,
        "module": RiskEngine.MODULE_NAME,
        "class_name": "RiskEngine",
        "factory": "create_risk_engine",
        "version": RiskEngine.VERSION,
        "file": "agents/security_agent/risk_engine.py",
        "capabilities": [
            "risk_scoring",
            "action_classification",
            "financial_risk",
            "destructive_risk",
            "private_data_risk",
            "device_risk",
            "terminal_risk",
            "account_risk",
            "approval_recommendation",
            "verification_payload",
            "memory_payload",
            "audit_event",
        ],
        "executes_actions": False,
        "requires_user_workspace_context": True,
        "structured_results": True,
    }


__all__ = [
    "RiskCategory",
    "RiskLevel",
    "RiskDecision",
    "ActionScope",
    "Reversibility",
    "RiskThresholds",
    "RiskEngineConfig",
    "ActionContext",
    "RiskFactor",
    "RiskAssessment",
    "RiskEngine",
    "create_risk_engine",
    "get_agent_manifest",
]