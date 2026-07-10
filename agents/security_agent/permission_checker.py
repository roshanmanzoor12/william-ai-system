"""
agents/security_agent/permission_checker.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Central permission decision engine for determining whether an action is:

        1. allowed
        2. confirm_required
        3. biometric_required
        4. blocked

This module is designed for use by:
    - Master Agent
    - Security Agent
    - Agent Router
    - Agent Registry
    - Agent Loader
    - Approval Manager
    - Biometric Gate
    - Risk Engine
    - Policy Engine
    - Session Guard
    - Payment Guard
    - Dashboard/API
    - Verification Agent
    - Memory Agent

Core security priorities:
    1. Safety and explicit denial rules.
    2. SaaS user/workspace isolation.
    3. User, role, subscription, and agent permissions.
    4. Confirmation and biometric requirements.
    5. Master Agent and Registry compatibility.
    6. Future extensibility.

Important:
    - This module does not execute actions.
    - This module does not verify real biometrics.
    - This module does not charge payments.
    - This module does not access devices, browsers, files, or operating systems.
    - It only evaluates permission and returns structured decisions.
    - Biometric verification must be performed by biometric_gate.py.
    - Final approvals can later be managed by approval_manager.py.
    - Advanced risk scoring can later be delegated to risk_engine.py.
    - Policy persistence can later be delegated to policy_engine.py.

All user-specific operations require:
    - user_id
    - workspace_id

All permission decisions are isolated by:
    - user_id
    - workspace_id
    - optional session_id
    - optional task_id

No external dependencies are required.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import re
import threading
import time
import uuid
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import (
    Any,
    Callable,
    Deque,
    Dict,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
)


# =============================================================================
# Optional William imports
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Import-safe fallback BaseAgent.

        The real William BaseAgent will automatically replace this fallback
        once agents/base_agent.py is available.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_version = kwargs.get("agent_version", "1.0.0")
            self.logger = logging.getLogger(self.agent_name)

        def health_check(self) -> Dict[str, Any]:
            return {
                "success": True,
                "message": "Fallback BaseAgent is active.",
                "data": {
                    "agent_name": self.agent_name,
                    "agent_version": self.agent_version,
                },
                "error": None,
                "metadata": {
                    "fallback_base_agent": True,
                    "timestamp": _utc_now_iso(),
                },
            }


# =============================================================================
# Constants
# =============================================================================

DEFAULT_AUDIT_LIMIT = 5000
DEFAULT_EVENT_LIMIT = 5000
DEFAULT_DECISION_CACHE_LIMIT = 5000
DEFAULT_APPROVAL_TTL_SECONDS = 300
DEFAULT_BIOMETRIC_TTL_SECONDS = 180
DEFAULT_CONFIRMATION_TTL_SECONDS = 300
DEFAULT_MAX_PAYLOAD_DEPTH = 8
DEFAULT_MAX_STRING_LENGTH = 5000
DEFAULT_MAX_PERMISSION_RULES = 10000
DEFAULT_MAX_SCOPE_OVERRIDES = 2000

SUPPORTED_POLICY_EFFECTS = {
    "allow",
    "confirm",
    "biometric",
    "block",
}

SAFE_SUBSCRIPTION_STATES = {
    "active",
    "trialing",
    "past_due",
    "paused",
    "cancelled",
    "expired",
    "suspended",
    "unknown",
}

ACTIVE_SUBSCRIPTION_STATES = {
    "active",
    "trialing",
}

DEFAULT_ROLE_HIERARCHY = {
    "viewer": 10,
    "member": 20,
    "operator": 30,
    "manager": 40,
    "admin": 50,
    "workspace_owner": 60,
    "system_admin": 70,
}

DEFAULT_RISK_LEVEL_ORDER = {
    "minimal": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

KNOWN_SENSITIVE_ACTION_PATTERNS = (
    r"\bdelete\b",
    r"\bremove\b",
    r"\bdestroy\b",
    r"\btruncate\b",
    r"\bdrop\b",
    r"\bformat\b",
    r"\boverwrite\b",
    r"\bdeploy\b",
    r"\bpublish\b",
    r"\bsend\b",
    r"\bemail\b",
    r"\bmessage\b",
    r"\bcall\b",
    r"\bpayment\b",
    r"\bcharge\b",
    r"\brefund\b",
    r"\btransfer\b",
    r"\bwithdraw\b",
    r"\bbank\b",
    r"\bfinancial\b",
    r"\bcredential\b",
    r"\bpassword\b",
    r"\bsecret\b",
    r"\btoken\b",
    r"\bpermission\b",
    r"\brole\b",
    r"\bsubscription\b",
    r"\bbilling\b",
    r"\bbiometric\b",
    r"\bemergency\b",
    r"\bshutdown\b",
    r"\brestart\b",
    r"\breboot\b",
    r"\bsystem\b",
    r"\bshell\b",
    r"\bterminal\b",
    r"\bcommand\b",
    r"\bexecute\b",
    r"\bbrowser\b",
    r"\bdevice\b",
    r"\bfile\b",
)

CRITICAL_ACTION_PATTERNS = (
    r"\bdelete[_\s-]*workspace\b",
    r"\bdelete[_\s-]*account\b",
    r"\bdelete[_\s-]*user\b",
    r"\bdelete[_\s-]*database\b",
    r"\bdrop[_\s-]*database\b",
    r"\bpayment[_\s-]*transfer\b",
    r"\bbank[_\s-]*transfer\b",
    r"\bwithdraw\b",
    r"\bchange[_\s-]*owner\b",
    r"\bgrant[_\s-]*admin\b",
    r"\brevoke[_\s-]*admin\b",
    r"\bdisable[_\s-]*security\b",
    r"\bdisable[_\s-]*audit\b",
    r"\bexport[_\s-]*all[_\s-]*data\b",
    r"\bproduction[_\s-]*deploy\b",
    r"\bemergency[_\s-]*unlock\b",
)

BLOCKED_BY_DEFAULT_ACTION_PATTERNS = (
    r"\bbypass[_\s-]*security\b",
    r"\bdisable[_\s-]*security[_\s-]*agent\b",
    r"\bdisable[_\s-]*permission[_\s-]*check\b",
    r"\bsteal[_\s-]*credential\b",
    r"\bexfiltrate\b",
    r"\bdump[_\s-]*password\b",
    r"\bcredential[_\s-]*harvest\b",
    r"\bmalware\b",
    r"\bransomware\b",
    r"\bkeylogger\b",
    r"\bunauthorized[_\s-]*access\b",
)

SENSITIVE_METADATA_KEYS = {
    "password",
    "passwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "authorization",
    "private_key",
    "client_secret",
    "cookie",
    "session_cookie",
    "biometric_template",
    "fingerprint",
    "face_template",
    "voiceprint",
}

DEFAULT_AGENT_ACTION_POLICIES = {
    "Voice": {
        "voice.listen": "allow",
        "voice.transcribe": "allow",
        "voice.respond": "allow",
        "voice.call": "confirm",
        "voice.record": "confirm",
        "voice.impersonate": "block",
    },
    "System": {
        "system.read": "allow",
        "system.inspect": "allow",
        "system.settings_change": "confirm",
        "system.install": "biometric",
        "system.uninstall": "biometric",
        "system.shutdown": "biometric",
        "system.reboot": "biometric",
        "system.execute_command": "biometric",
    },
    "Browser": {
        "browser.search": "allow",
        "browser.read": "allow",
        "browser.navigate": "allow",
        "browser.login": "confirm",
        "browser.submit_form": "confirm",
        "browser.purchase": "biometric",
        "browser.download_executable": "biometric",
    },
    "Code": {
        "code.read": "allow",
        "code.analyze": "allow",
        "code.generate": "allow",
        "code.write": "confirm",
        "code.delete": "biometric",
        "code.execute": "confirm",
        "code.deploy": "biometric",
        "code.production_deploy": "biometric",
    },
    "Memory": {
        "memory.read_short_term": "allow",
        "memory.write_short_term": "allow",
        "memory.read_long_term": "allow",
        "memory.write_long_term": "confirm",
        "memory.delete": "biometric",
        "memory.export": "biometric",
    },
    "Security": {
        "security.inspect": "allow",
        "security.evaluate": "allow",
        "security.policy_change": "biometric",
        "security.disable": "block",
        "security.emergency_unlock": "biometric",
    },
    "Verification": {
        "verification.inspect": "allow",
        "verification.verify": "allow",
        "verification.override": "biometric",
    },
    "Visual": {
        "visual.analyze": "allow",
        "visual.generate": "allow",
        "visual.capture_screen": "confirm",
        "visual.capture_camera": "biometric",
    },
    "Workflow": {
        "workflow.read": "allow",
        "workflow.create": "allow",
        "workflow.run": "confirm",
        "workflow.schedule": "confirm",
        "workflow.delete": "biometric",
    },
    "Hologram": {
        "hologram.render": "allow",
        "hologram.display": "allow",
        "hologram.capture_environment": "confirm",
    },
    "Call": {
        "call.prepare": "allow",
        "call.place": "confirm",
        "call.record": "biometric",
        "call.emergency": "biometric",
    },
    "Business": {
        "business.analyze": "allow",
        "business.generate_report": "allow",
        "business.contact_lead": "confirm",
        "business.sign_contract": "biometric",
    },
    "Finance": {
        "finance.read": "allow",
        "finance.analyze": "allow",
        "finance.create_invoice": "confirm",
        "finance.send_invoice": "confirm",
        "finance.refund": "biometric",
        "finance.transfer": "biometric",
        "finance.withdraw": "biometric",
    },
    "Creator": {
        "creator.generate": "allow",
        "creator.edit": "allow",
        "creator.publish": "confirm",
        "creator.delete_published": "biometric",
    },
}


# =============================================================================
# Utility functions
# =============================================================================

def _utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _unix_now() -> float:
    """Return the current Unix timestamp."""
    return time.time()


def _safe_uuid(prefix: str = "permission") -> str:
    """Generate a safe prefixed UUID."""
    clean_prefix = re.sub(r"[^a-zA-Z0-9_-]", "", str(prefix))[:32] or "permission"
    return f"{clean_prefix}_{uuid.uuid4().hex}"


def _deepcopy_safe(value: Any) -> Any:
    """Return a best-effort deep copy."""
    try:
        return copy.deepcopy(value)
    except Exception:
        try:
            return json.loads(json.dumps(value, default=str))
        except Exception:
            return str(value)


def _safe_json(value: Any) -> str:
    """Serialize a value safely for hashing or logs."""
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
    except Exception:
        return str(value)


def _normalize_identifier(value: Any, field_name: str) -> str:
    """
    Normalize a SaaS identifier.

    Raises:
        ValueError: if the identifier is missing or unsafe.
    """
    if value is None:
        raise ValueError(f"{field_name} is required.")

    normalized = str(value).strip()

    if not normalized:
        raise ValueError(f"{field_name} cannot be empty.")

    if len(normalized) > 256:
        raise ValueError(f"{field_name} cannot exceed 256 characters.")

    if not re.fullmatch(r"[A-Za-z0-9_.:@\-]+", normalized):
        raise ValueError(
            f"{field_name} contains invalid characters. "
            "Allowed: letters, numbers, underscore, dash, dot, colon, and @."
        )

    return normalized


def _normalize_action(action: Any) -> str:
    """Normalize an action name."""
    if action is None:
        raise ValueError("action is required.")

    normalized = str(action).strip().lower()
    normalized = re.sub(r"\s+", "_", normalized)
    normalized = re.sub(r"[^a-z0-9_.:\-]", "_", normalized)
    normalized = re.sub(r"_+", "_", normalized).strip("_")

    if not normalized:
        raise ValueError("action cannot be empty.")

    if len(normalized) > 256:
        raise ValueError("action cannot exceed 256 characters.")

    return normalized


def _normalize_agent_name(agent_name: Optional[Any]) -> Optional[str]:
    """Normalize agent name while preserving readable capitalization."""
    if agent_name is None:
        return None

    clean = str(agent_name).strip()
    if not clean:
        return None

    if len(clean) > 128:
        raise ValueError("agent_name cannot exceed 128 characters.")

    return clean


def _normalize_role(role: Any) -> str:
    """Normalize a role name."""
    normalized = str(role or "").strip().lower()
    normalized = re.sub(r"[\s\-]+", "_", normalized)

    if not normalized:
        raise ValueError("role cannot be empty.")

    if len(normalized) > 128:
        raise ValueError("role cannot exceed 128 characters.")

    return normalized


def _truncate_string(value: str, maximum: int = DEFAULT_MAX_STRING_LENGTH) -> str:
    """Truncate long strings."""
    if len(value) <= maximum:
        return value
    return f"{value[:maximum]}...[truncated]"


def _is_mapping(value: Any) -> bool:
    return isinstance(value, Mapping)


def _coerce_mapping(
    value: Optional[Mapping[str, Any]],
    field_name: str,
) -> Dict[str, Any]:
    """Coerce an optional mapping into a normal dictionary."""
    if value is None:
        return {}

    if not isinstance(value, Mapping):
        raise ValueError(f"{field_name} must be a mapping/dictionary.")

    return dict(value)


def _stable_hash(value: Any) -> str:
    """Return a stable SHA-256 hash for a JSON-safe value."""
    return hashlib.sha256(_safe_json(value).encode("utf-8")).hexdigest()


def _action_matches(action: str, pattern: str) -> bool:
    """
    Match action against wildcard or exact pattern.

    Supported:
        *
        finance.*
        *.delete
        exact.action
    """
    normalized_pattern = _normalize_action(pattern)

    escaped = re.escape(normalized_pattern)
    regex = "^" + escaped.replace(r"\*", ".*") + "$"
    return re.match(regex, action, flags=re.IGNORECASE) is not None


# =============================================================================
# Enums
# =============================================================================

class PermissionDecision(str, Enum):
    """Final permission decision returned by PermissionChecker."""

    ALLOWED = "allowed"
    CONFIRM_REQUIRED = "confirm_required"
    BIOMETRIC_REQUIRED = "biometric_required"
    BLOCKED = "blocked"


class PolicyEffect(str, Enum):
    """Effect assigned by a permission policy."""

    ALLOW = "allow"
    CONFIRM = "confirm"
    BIOMETRIC = "biometric"
    BLOCK = "block"


class RuleSource(str, Enum):
    """Source that produced a permission decision."""

    EMERGENCY_LOCK = "emergency_lock"
    EXPLICIT_DENY = "explicit_deny"
    EXPLICIT_ALLOW = "explicit_allow"
    USER_OVERRIDE = "user_override"
    WORKSPACE_POLICY = "workspace_policy"
    ROLE_POLICY = "role_policy"
    AGENT_POLICY = "agent_policy"
    SUBSCRIPTION_POLICY = "subscription_policy"
    RISK_POLICY = "risk_policy"
    DEFAULT_POLICY = "default_policy"
    APPROVAL = "approval"
    BIOMETRIC = "biometric"
    CONFIRMATION = "confirmation"


# =============================================================================
# Data models
# =============================================================================

@dataclass
class PermissionCheckerConfig:
    """Runtime configuration for PermissionChecker."""

    default_decision: str = PermissionDecision.CONFIRM_REQUIRED.value

    fail_closed: bool = True
    require_active_subscription: bool = False
    require_known_role: bool = False
    require_registered_agent: bool = False
    allow_system_admin_cross_workspace: bool = False

    medium_risk_requires_confirmation: bool = True
    high_risk_requires_biometric: bool = True
    critical_risk_block_without_explicit_allow: bool = True

    confirmation_ttl_seconds: int = DEFAULT_CONFIRMATION_TTL_SECONDS
    biometric_ttl_seconds: int = DEFAULT_BIOMETRIC_TTL_SECONDS
    approval_ttl_seconds: int = DEFAULT_APPROVAL_TTL_SECONDS

    audit_limit: int = DEFAULT_AUDIT_LIMIT
    event_limit: int = DEFAULT_EVENT_LIMIT
    decision_cache_limit: int = DEFAULT_DECISION_CACHE_LIMIT
    max_permission_rules: int = DEFAULT_MAX_PERMISSION_RULES
    max_scope_overrides: int = DEFAULT_MAX_SCOPE_OVERRIDES

    max_payload_depth: int = DEFAULT_MAX_PAYLOAD_DEPTH
    max_string_length: int = DEFAULT_MAX_STRING_LENGTH
    redact_sensitive_values: bool = True

    role_hierarchy: Dict[str, int] = field(
        default_factory=lambda: dict(DEFAULT_ROLE_HIERARCHY)
    )

    agent_action_policies: Dict[str, Dict[str, str]] = field(
        default_factory=lambda: copy.deepcopy(DEFAULT_AGENT_ACTION_POLICIES)
    )

    allowed_subscription_states: Set[str] = field(
        default_factory=lambda: set(ACTIVE_SUBSCRIPTION_STATES)
    )


@dataclass
class PermissionContext:
    """Validated context used to evaluate a permission request."""

    user_id: str
    workspace_id: str
    action: str

    session_id: Optional[str] = None
    task_id: Optional[str] = None
    request_id: Optional[str] = None

    agent_name: Optional[str] = None
    agent_id: Optional[str] = None

    roles: List[str] = field(default_factory=list)
    subscription_status: str = "unknown"
    subscription_plan: Optional[str] = None

    user_permissions: List[str] = field(default_factory=list)
    denied_permissions: List[str] = field(default_factory=list)
    agent_permissions: List[str] = field(default_factory=list)

    risk_level: str = "low"
    risk_score: float = 0.0

    confirmed: bool = False
    confirmation_id: Optional[str] = None
    confirmation_timestamp: Optional[float] = None

    biometric_verified: bool = False
    biometric_verification_id: Optional[str] = None
    biometric_timestamp: Optional[float] = None

    approval_granted: bool = False
    approval_id: Optional[str] = None
    approval_timestamp: Optional[float] = None

    device_id: Optional[str] = None
    ip_address: Optional[str] = None
    source: str = "unknown"

    resource_owner_user_id: Optional[str] = None
    resource_workspace_id: Optional[str] = None

    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PermissionRule:
    """One explicit permission policy rule."""

    rule_id: str
    name: str
    action_pattern: str
    effect: str

    enabled: bool = True
    priority: int = 100

    user_id: Optional[str] = None
    workspace_id: Optional[str] = None
    agent_name: Optional[str] = None
    role: Optional[str] = None
    subscription_plan: Optional[str] = None

    minimum_risk_level: Optional[str] = None
    maximum_risk_level: Optional[str] = None

    require_confirmation: bool = False
    require_biometric: bool = False

    conditions: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    created_at: str = field(default_factory=_utc_now_iso)
    updated_at: str = field(default_factory=_utc_now_iso)


@dataclass
class PermissionEvaluation:
    """Internal permission evaluation state."""

    decision: str
    reason: str
    source: str

    matched_rule_id: Optional[str] = None
    matched_rule_name: Optional[str] = None

    requires_confirmation: bool = False
    requires_biometric: bool = False
    requires_approval: bool = False

    confirmation_satisfied: bool = False
    biometric_satisfied: bool = False
    approval_satisfied: bool = False

    risk_level: str = "low"
    risk_score: float = 0.0

    policy_trace: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


# =============================================================================
# PermissionChecker
# =============================================================================

class PermissionChecker(BaseAgent):
    """
    Central permission decision engine for William/Jarvis.

    This class evaluates whether an action should be:

        - allowed
        - confirm_required
        - biometric_required
        - blocked

    Evaluation order:
        1. Validate SaaS context.
        2. Enforce workspace/user resource isolation.
        3. Enforce emergency locks.
        4. Enforce blocked-by-default malicious actions.
        5. Evaluate explicit deny rules.
        6. Evaluate subscription restrictions.
        7. Evaluate role and user permissions.
        8. Evaluate agent-specific permissions.
        9. Evaluate explicit allow/confirm/biometric rules.
        10. Apply risk escalation.
        11. Validate confirmation, approval, and biometric evidence.
        12. Return structured decision with audit and integration payloads.

    The class is thread-safe and import-safe.
    """

    def __init__(
        self,
        config: Optional[
            Union[PermissionCheckerConfig, Mapping[str, Any]]
        ] = None,
        logger: Optional[logging.Logger] = None,
        agent_name: str = "PermissionChecker",
        agent_version: str = "1.0.0",
    ) -> None:
        """Initialize PermissionChecker."""
        try:
            super().__init__(
                agent_name=agent_name,
                agent_version=agent_version,
            )
        except TypeError:
            super().__init__()

        self.agent_name = agent_name
        self.agent_version = agent_version
        self.logger = logger or logging.getLogger(
            "william.security_agent.permission_checker"
        )

        if isinstance(config, PermissionCheckerConfig):
            self.config = config
        elif isinstance(config, Mapping):
            raw_config = dict(config)

            if "allowed_subscription_states" in raw_config:
                raw_config["allowed_subscription_states"] = set(
                    raw_config["allowed_subscription_states"]
                )

            self.config = PermissionCheckerConfig(**raw_config)
        else:
            self.config = PermissionCheckerConfig()

        self._validate_config()

        self._lock = threading.RLock()

        self._rules: Dict[str, PermissionRule] = {}

        self._workspace_locks: Dict[str, Dict[str, Any]] = {}
        self._user_locks: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self._session_locks: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

        self._temporary_approvals: Dict[str, Dict[str, Any]] = {}
        self._confirmations: Dict[str, Dict[str, Any]] = {}
        self._biometric_verifications: Dict[str, Dict[str, Any]] = {}

        self._workspace_role_permissions: Dict[
            Tuple[str, str], Dict[str, Set[str]]
        ] = {}

        self._user_permission_overrides: Dict[
            Tuple[str, str], Dict[str, Set[str]]
        ] = {}

        self._agent_permission_overrides: Dict[
            Tuple[str, str], Dict[str, Set[str]]
        ] = {}

        self._audit_events: Deque[Dict[str, Any]] = deque(
            maxlen=self.config.audit_limit
        )
        self._agent_events: Deque[Dict[str, Any]] = deque(
            maxlen=self.config.event_limit
        )
        self._decision_cache: Deque[Dict[str, Any]] = deque(
            maxlen=self.config.decision_cache_limit
        )

        self._emit_agent_event(
            event_type="permission_checker_initialized",
            user_id=None,
            workspace_id=None,
            session_id=None,
            data={
                "agent_name": self.agent_name,
                "agent_version": self.agent_version,
                "default_decision": self.config.default_decision,
                "fail_closed": self.config.fail_closed,
            },
        )

    # =========================================================================
    # Configuration
    # =========================================================================

    def _validate_config(self) -> None:
        """Validate configuration values."""
        valid_decisions = {item.value for item in PermissionDecision}

        if self.config.default_decision not in valid_decisions:
            raise ValueError(
                f"default_decision must be one of {sorted(valid_decisions)}."
            )

        if self.config.confirmation_ttl_seconds < 1:
            raise ValueError("confirmation_ttl_seconds must be >= 1.")

        if self.config.biometric_ttl_seconds < 1:
            raise ValueError("biometric_ttl_seconds must be >= 1.")

        if self.config.approval_ttl_seconds < 1:
            raise ValueError("approval_ttl_seconds must be >= 1.")

        if self.config.audit_limit < 10:
            raise ValueError("audit_limit must be >= 10.")

        if self.config.event_limit < 10:
            raise ValueError("event_limit must be >= 10.")

        if self.config.decision_cache_limit < 10:
            raise ValueError("decision_cache_limit must be >= 10.")

        if self.config.max_permission_rules < 1:
            raise ValueError("max_permission_rules must be >= 1.")

        if self.config.max_scope_overrides < 1:
            raise ValueError("max_scope_overrides must be >= 1.")

        if self.config.max_payload_depth < 1:
            raise ValueError("max_payload_depth must be >= 1.")

        if self.config.max_string_length < 100:
            raise ValueError("max_string_length must be >= 100.")

        for role, level in self.config.role_hierarchy.items():
            _normalize_role(role)

            if not isinstance(level, int) or level < 0:
                raise ValueError(
                    f"Role hierarchy level for '{role}' must be a positive integer."
                )

        for state in self.config.allowed_subscription_states:
            if state not in SAFE_SUBSCRIPTION_STATES:
                raise ValueError(
                    f"Unsupported subscription state in allowed states: {state}"
                )

    # =========================================================================
    # Validation and sanitization
    # =========================================================================

    def _validate_task_context(
        self,
        user_id: Any,
        workspace_id: Any,
        action: Any,
        session_id: Optional[Any] = None,
        task_id: Optional[Any] = None,
    ) -> Dict[str, Optional[str]]:
        """
        Validate and normalize a permission task context.

        Required compatibility hook.
        """
        normalized_user_id = _normalize_identifier(user_id, "user_id")
        normalized_workspace_id = _normalize_identifier(
            workspace_id,
            "workspace_id",
        )
        normalized_action = _normalize_action(action)

        normalized_session_id = (
            _normalize_identifier(session_id, "session_id")
            if session_id is not None
            else None
        )

        normalized_task_id = (
            _normalize_identifier(task_id, "task_id")
            if task_id is not None
            else None
        )

        return {
            "user_id": normalized_user_id,
            "workspace_id": normalized_workspace_id,
            "action": normalized_action,
            "session_id": normalized_session_id,
            "task_id": normalized_task_id,
        }

    def _sanitize_payload(
        self,
        payload: Any,
        depth: int = 0,
        parent_key: str = "",
    ) -> Any:
        """Sanitize payloads before logs, events, or storage."""
        if depth > self.config.max_payload_depth:
            return "[max_depth_reached]"

        if (
            self.config.redact_sensitive_values
            and parent_key.lower() in SENSITIVE_METADATA_KEYS
        ):
            return "[redacted]"

        if payload is None or isinstance(payload, (bool, int, float)):
            return payload

        if isinstance(payload, str):
            if self._looks_like_secret(payload):
                return "[redacted]"

            return _truncate_string(
                payload,
                self.config.max_string_length,
            )

        if isinstance(payload, Mapping):
            output: Dict[str, Any] = {}

            for raw_key, raw_value in payload.items():
                key = _truncate_string(str(raw_key), 256)

                if (
                    self.config.redact_sensitive_values
                    and key.lower() in SENSITIVE_METADATA_KEYS
                ):
                    output[key] = "[redacted]"
                else:
                    output[key] = self._sanitize_payload(
                        raw_value,
                        depth + 1,
                        key,
                    )

            return output

        if isinstance(payload, (list, tuple, set)):
            return [
                self._sanitize_payload(item, depth + 1, parent_key)
                for item in list(payload)[:1000]
            ]

        return _truncate_string(
            str(payload),
            self.config.max_string_length,
        )

    def _looks_like_secret(self, value: str) -> bool:
        """Detect obvious secret-like strings."""
        secret_patterns = (
            r"sk-[A-Za-z0-9_\-]{20,}",
            r"AKIA[0-9A-Z]{16}",
            r"AIza[0-9A-Za-z_\-]{20,}",
            r"(?i)bearer\s+[A-Za-z0-9._\-]{16,}",
            r"(?i)(password|secret|token|api[_-]?key)\s*[:=]\s*\S+",
        )

        return any(re.search(pattern, value) for pattern in secret_patterns)

    def _build_permission_context(
        self,
        *,
        user_id: Any,
        workspace_id: Any,
        action: Any,
        session_id: Optional[Any] = None,
        task_id: Optional[Any] = None,
        request_id: Optional[Any] = None,
        agent_name: Optional[Any] = None,
        agent_id: Optional[Any] = None,
        roles: Optional[Iterable[Any]] = None,
        subscription_status: str = "unknown",
        subscription_plan: Optional[str] = None,
        user_permissions: Optional[Iterable[str]] = None,
        denied_permissions: Optional[Iterable[str]] = None,
        agent_permissions: Optional[Iterable[str]] = None,
        risk_level: str = "low",
        risk_score: float = 0.0,
        confirmed: bool = False,
        confirmation_id: Optional[str] = None,
        confirmation_timestamp: Optional[float] = None,
        biometric_verified: bool = False,
        biometric_verification_id: Optional[str] = None,
        biometric_timestamp: Optional[float] = None,
        approval_granted: bool = False,
        approval_id: Optional[str] = None,
        approval_timestamp: Optional[float] = None,
        device_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        source: str = "unknown",
        resource_owner_user_id: Optional[Any] = None,
        resource_workspace_id: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> PermissionContext:
        """Create a fully validated PermissionContext."""
        validated = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            action=action,
            session_id=session_id,
            task_id=task_id,
        )

        normalized_roles = sorted(
            {
                _normalize_role(role)
                for role in list(roles or [])
                if str(role).strip()
            }
        )

        normalized_subscription = str(
            subscription_status or "unknown"
        ).strip().lower()

        if normalized_subscription not in SAFE_SUBSCRIPTION_STATES:
            normalized_subscription = "unknown"

        normalized_risk_level = str(risk_level or "low").strip().lower()

        if normalized_risk_level not in DEFAULT_RISK_LEVEL_ORDER:
            raise ValueError(
                f"Unsupported risk_level '{normalized_risk_level}'. "
                f"Allowed: {sorted(DEFAULT_RISK_LEVEL_ORDER)}"
            )

        normalized_risk_score = max(
            0.0,
            min(100.0, float(risk_score)),
        )

        return PermissionContext(
            user_id=str(validated["user_id"]),
            workspace_id=str(validated["workspace_id"]),
            action=str(validated["action"]),
            session_id=validated["session_id"],
            task_id=validated["task_id"],
            request_id=(
                _normalize_identifier(request_id, "request_id")
                if request_id is not None
                else _safe_uuid("permission_request")
            ),
            agent_name=_normalize_agent_name(agent_name),
            agent_id=(
                _normalize_identifier(agent_id, "agent_id")
                if agent_id is not None
                else None
            ),
            roles=normalized_roles,
            subscription_status=normalized_subscription,
            subscription_plan=(
                str(subscription_plan).strip()
                if subscription_plan is not None
                else None
            ),
            user_permissions=self._normalize_permission_list(
                user_permissions or []
            ),
            denied_permissions=self._normalize_permission_list(
                denied_permissions or []
            ),
            agent_permissions=self._normalize_permission_list(
                agent_permissions or []
            ),
            risk_level=normalized_risk_level,
            risk_score=normalized_risk_score,
            confirmed=bool(confirmed),
            confirmation_id=confirmation_id,
            confirmation_timestamp=confirmation_timestamp,
            biometric_verified=bool(biometric_verified),
            biometric_verification_id=biometric_verification_id,
            biometric_timestamp=biometric_timestamp,
            approval_granted=bool(approval_granted),
            approval_id=approval_id,
            approval_timestamp=approval_timestamp,
            device_id=(
                _normalize_identifier(device_id, "device_id")
                if device_id is not None
                else None
            ),
            ip_address=(
                _truncate_string(str(ip_address), 128)
                if ip_address is not None
                else None
            ),
            source=_truncate_string(str(source or "unknown"), 128),
            resource_owner_user_id=(
                _normalize_identifier(
                    resource_owner_user_id,
                    "resource_owner_user_id",
                )
                if resource_owner_user_id is not None
                else None
            ),
            resource_workspace_id=(
                _normalize_identifier(
                    resource_workspace_id,
                    "resource_workspace_id",
                )
                if resource_workspace_id is not None
                else None
            ),
            metadata=self._sanitize_payload(
                _coerce_mapping(metadata, "metadata")
            ),
        )

    def _normalize_permission_list(
        self,
        permissions: Iterable[Any],
    ) -> List[str]:
        """Normalize permission or action patterns."""
        output: Set[str] = set()

        for permission in permissions:
            if permission is None:
                continue

            raw = str(permission).strip().lower()

            if not raw:
                continue

            if raw == "*":
                output.add("*")
                continue

            normalized = re.sub(r"\s+", "_", raw)
            normalized = re.sub(r"[^a-z0-9_.*:\-]", "_", normalized)
            normalized = re.sub(r"_+", "_", normalized)

            if normalized:
                output.add(normalized)

        return sorted(output)

    # =========================================================================
    # Structured results
    # =========================================================================

    def _safe_result(
        self,
        message: str,
        data: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return a standard successful William result."""
        return {
            "success": True,
            "message": message,
            "data": data if data is not None else {},
            "error": None,
            "metadata": {
                "agent": self.agent_name,
                "agent_version": self.agent_version,
                "timestamp": _utc_now_iso(),
                **dict(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Union[str, Exception]] = None,
        data: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return a standard failed William result."""
        return {
            "success": False,
            "message": message,
            "data": data if data is not None else {},
            "error": str(error) if error is not None else message,
            "metadata": {
                "agent": self.agent_name,
                "agent_version": self.agent_version,
                "timestamp": _utc_now_iso(),
                **dict(metadata or {}),
            },
        }

    # =========================================================================
    # Integration hooks
    # =========================================================================

    def _requires_security_check(
        self,
        action: str,
        risk_level: str = "low",
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Return whether an action must pass through Security Agent.

        PermissionChecker itself is part of the Security Agent, so this method
        identifies whether an action is sensitive enough to require formal
        permission evaluation.
        """
        normalized_action = _normalize_action(action)
        normalized_risk = str(risk_level).lower()

        if normalized_risk in {"medium", "high", "critical"}:
            return True

        if any(
            re.search(pattern, normalized_action, re.IGNORECASE)
            for pattern in KNOWN_SENSITIVE_ACTION_PATTERNS
        ):
            return True

        if metadata:
            serialized = _safe_json(metadata)

            if any(
                re.search(pattern, serialized, re.IGNORECASE)
                for pattern in KNOWN_SENSITIVE_ACTION_PATTERNS
            ):
                return True

        return False

    def _request_security_approval(
        self,
        user_id: str,
        workspace_id: str,
        action: str,
        reason: str,
        session_id: Optional[str] = None,
        task_id: Optional[str] = None,
        required_method: str = "confirmation",
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Prepare an approval request for Approval Manager or Biometric Gate."""
        request = {
            "approval_request_id": _safe_uuid("security_approval"),
            "requested_by_agent": self.agent_name,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "session_id": session_id,
            "task_id": task_id,
            "action": action,
            "reason": reason,
            "required_method": required_method,
            "status": "pending",
            "metadata": self._sanitize_payload(metadata or {}),
            "created_at": _utc_now_iso(),
        }

        self._log_audit_event(
            action="security_approval_requested",
            user_id=user_id,
            workspace_id=workspace_id,
            session_id=session_id,
            details=request,
        )

        self._emit_agent_event(
            event_type="security_approval_requested",
            user_id=user_id,
            workspace_id=workspace_id,
            session_id=session_id,
            data=request,
        )

        return request

    def _prepare_verification_payload(
        self,
        context: PermissionContext,
        evaluation: PermissionEvaluation,
    ) -> Dict[str, Any]:
        """Prepare Verification Agent payload."""
        return {
            "verification_id": _safe_uuid("permission_verify"),
            "source_agent": self.agent_name,
            "verification_type": "permission_decision",
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "session_id": context.session_id,
            "task_id": context.task_id,
            "request_id": context.request_id,
            "action": context.action,
            "decision": evaluation.decision,
            "reason": evaluation.reason,
            "source": evaluation.source,
            "matched_rule_id": evaluation.matched_rule_id,
            "risk_level": evaluation.risk_level,
            "risk_score": evaluation.risk_score,
            "confirmation_satisfied": evaluation.confirmation_satisfied,
            "biometric_satisfied": evaluation.biometric_satisfied,
            "approval_satisfied": evaluation.approval_satisfied,
            "policy_trace_hash": _stable_hash(evaluation.policy_trace),
            "created_at": _utc_now_iso(),
        }

    def _prepare_memory_payload(
        self,
        context: PermissionContext,
        evaluation: PermissionEvaluation,
    ) -> Dict[str, Any]:
        """Prepare privacy-safe Memory Agent payload."""
        return {
            "memory_id": _safe_uuid("permission_memory"),
            "source_agent": self.agent_name,
            "memory_type": "security_permission_decision",
            "importance": (
                "critical"
                if evaluation.decision == PermissionDecision.BLOCKED.value
                else "security"
            ),
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "session_id": context.session_id,
            "task_id": context.task_id,
            "content": {
                "request_id": context.request_id,
                "action": context.action,
                "agent_name": context.agent_name,
                "decision": evaluation.decision,
                "reason": evaluation.reason,
                "source": evaluation.source,
                "risk_level": evaluation.risk_level,
                "risk_score": evaluation.risk_score,
                "matched_rule_id": evaluation.matched_rule_id,
                "requires_confirmation": evaluation.requires_confirmation,
                "requires_biometric": evaluation.requires_biometric,
                "requires_approval": evaluation.requires_approval,
            },
            "created_at": _utc_now_iso(),
        }

    def _emit_agent_event(
        self,
        event_type: str,
        user_id: Optional[str],
        workspace_id: Optional[str],
        session_id: Optional[str],
        data: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Emit an internal event for Dashboard/API or future event bus."""
        event = {
            "event_id": _safe_uuid("security_event"),
            "event_type": str(event_type),
            "source_agent": self.agent_name,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "session_id": session_id,
            "data": self._sanitize_payload(data or {}),
            "created_at": _utc_now_iso(),
        }

        with self._lock:
            self._agent_events.append(event)

        return event

    def _log_audit_event(
        self,
        action: str,
        user_id: Optional[str],
        workspace_id: Optional[str],
        session_id: Optional[str],
        details: Optional[Mapping[str, Any]] = None,
        level: str = "info",
    ) -> Dict[str, Any]:
        """Create an in-memory audit event."""
        event = {
            "audit_id": _safe_uuid("security_audit"),
            "action": str(action),
            "level": str(level),
            "source_agent": self.agent_name,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "session_id": session_id,
            "details": self._sanitize_payload(details or {}),
            "created_at": _utc_now_iso(),
        }

        with self._lock:
            self._audit_events.append(event)

        if level.lower() in {"warning", "error", "critical"}:
            self.logger.warning(
                "Permission audit: %s",
                _safe_json(event),
            )
        else:
            self.logger.debug(
                "Permission audit: %s",
                _safe_json(event),
            )

        return event

    # =========================================================================
    # Primary public permission API
    # =========================================================================

    def check_permission(
        self,
        *,
        user_id: Any,
        workspace_id: Any,
        action: Any,
        session_id: Optional[Any] = None,
        task_id: Optional[Any] = None,
        request_id: Optional[Any] = None,
        agent_name: Optional[Any] = None,
        agent_id: Optional[Any] = None,
        roles: Optional[Iterable[Any]] = None,
        subscription_status: str = "unknown",
        subscription_plan: Optional[str] = None,
        user_permissions: Optional[Iterable[str]] = None,
        denied_permissions: Optional[Iterable[str]] = None,
        agent_permissions: Optional[Iterable[str]] = None,
        risk_level: str = "low",
        risk_score: float = 0.0,
        confirmed: bool = False,
        confirmation_id: Optional[str] = None,
        confirmation_timestamp: Optional[float] = None,
        biometric_verified: bool = False,
        biometric_verification_id: Optional[str] = None,
        biometric_timestamp: Optional[float] = None,
        approval_granted: bool = False,
        approval_id: Optional[str] = None,
        approval_timestamp: Optional[float] = None,
        device_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        source: str = "unknown",
        resource_owner_user_id: Optional[Any] = None,
        resource_workspace_id: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Check whether an action is permitted.

        Returns a structured result containing one of:
            - allowed
            - confirm_required
            - biometric_required
            - blocked
        """
        try:
            self._cleanup_expired_evidence()

            context = self._build_permission_context(
                user_id=user_id,
                workspace_id=workspace_id,
                action=action,
                session_id=session_id,
                task_id=task_id,
                request_id=request_id,
                agent_name=agent_name,
                agent_id=agent_id,
                roles=roles,
                subscription_status=subscription_status,
                subscription_plan=subscription_plan,
                user_permissions=user_permissions,
                denied_permissions=denied_permissions,
                agent_permissions=agent_permissions,
                risk_level=risk_level,
                risk_score=risk_score,
                confirmed=confirmed,
                confirmation_id=confirmation_id,
                confirmation_timestamp=confirmation_timestamp,
                biometric_verified=biometric_verified,
                biometric_verification_id=biometric_verification_id,
                biometric_timestamp=biometric_timestamp,
                approval_granted=approval_granted,
                approval_id=approval_id,
                approval_timestamp=approval_timestamp,
                device_id=device_id,
                ip_address=ip_address,
                source=source,
                resource_owner_user_id=resource_owner_user_id,
                resource_workspace_id=resource_workspace_id,
                metadata=metadata,
            )

            evaluation = self._evaluate_permission(context)

            approval_request = None

            if evaluation.decision == PermissionDecision.CONFIRM_REQUIRED.value:
                approval_request = self._request_security_approval(
                    user_id=context.user_id,
                    workspace_id=context.workspace_id,
                    session_id=context.session_id,
                    task_id=context.task_id,
                    action=context.action,
                    reason=evaluation.reason,
                    required_method="confirmation",
                    metadata={
                        "request_id": context.request_id,
                        "risk_level": context.risk_level,
                        "agent_name": context.agent_name,
                    },
                )

            elif evaluation.decision == PermissionDecision.BIOMETRIC_REQUIRED.value:
                approval_request = self._request_security_approval(
                    user_id=context.user_id,
                    workspace_id=context.workspace_id,
                    session_id=context.session_id,
                    task_id=context.task_id,
                    action=context.action,
                    reason=evaluation.reason,
                    required_method="biometric",
                    metadata={
                        "request_id": context.request_id,
                        "risk_level": context.risk_level,
                        "agent_name": context.agent_name,
                    },
                )

            decision_id = _safe_uuid("permission_decision")

            decision_payload = {
                "decision_id": decision_id,
                "request_id": context.request_id,
                "decision": evaluation.decision,
                "allowed": evaluation.decision == PermissionDecision.ALLOWED.value,
                "blocked": evaluation.decision == PermissionDecision.BLOCKED.value,
                "confirm_required": (
                    evaluation.decision
                    == PermissionDecision.CONFIRM_REQUIRED.value
                ),
                "biometric_required": (
                    evaluation.decision
                    == PermissionDecision.BIOMETRIC_REQUIRED.value
                ),
                "reason": evaluation.reason,
                "source": evaluation.source,
                "matched_rule_id": evaluation.matched_rule_id,
                "matched_rule_name": evaluation.matched_rule_name,
                "requires_confirmation": evaluation.requires_confirmation,
                "requires_biometric": evaluation.requires_biometric,
                "requires_approval": evaluation.requires_approval,
                "confirmation_satisfied": evaluation.confirmation_satisfied,
                "biometric_satisfied": evaluation.biometric_satisfied,
                "approval_satisfied": evaluation.approval_satisfied,
                "risk_level": evaluation.risk_level,
                "risk_score": evaluation.risk_score,
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
                "session_id": context.session_id,
                "task_id": context.task_id,
                "action": context.action,
                "agent_name": context.agent_name,
                "roles": list(context.roles),
                "subscription_status": context.subscription_status,
                "subscription_plan": context.subscription_plan,
                "approval_request": approval_request,
                "warnings": list(evaluation.warnings),
                "policy_trace": _deepcopy_safe(evaluation.policy_trace),
                "verification_payload": self._prepare_verification_payload(
                    context,
                    evaluation,
                ),
                "memory_payload": self._prepare_memory_payload(
                    context,
                    evaluation,
                ),
                "created_at": _utc_now_iso(),
            }

            self._cache_decision(decision_payload)

            audit_level = (
                "warning"
                if evaluation.decision == PermissionDecision.BLOCKED.value
                else "info"
            )

            self._log_audit_event(
                action="permission_checked",
                user_id=context.user_id,
                workspace_id=context.workspace_id,
                session_id=context.session_id,
                details={
                    "decision_id": decision_id,
                    "request_id": context.request_id,
                    "action": context.action,
                    "agent_name": context.agent_name,
                    "decision": evaluation.decision,
                    "reason": evaluation.reason,
                    "source": evaluation.source,
                    "risk_level": evaluation.risk_level,
                    "matched_rule_id": evaluation.matched_rule_id,
                },
                level=audit_level,
            )

            self._emit_agent_event(
                event_type="permission_decision_created",
                user_id=context.user_id,
                workspace_id=context.workspace_id,
                session_id=context.session_id,
                data={
                    "decision_id": decision_id,
                    "request_id": context.request_id,
                    "action": context.action,
                    "decision": evaluation.decision,
                    "agent_name": context.agent_name,
                    "risk_level": evaluation.risk_level,
                },
            )

            return self._safe_result(
                message=f"Permission decision: {evaluation.decision}.",
                data=decision_payload,
                metadata={
                    "decision": evaluation.decision,
                    "request_id": context.request_id,
                },
            )

        except Exception as exc:
            self.logger.exception("Permission check failed.")

            if self.config.fail_closed:
                return self._safe_result(
                    message="Permission check failed closed; action blocked.",
                    data={
                        "decision": PermissionDecision.BLOCKED.value,
                        "allowed": False,
                        "blocked": True,
                        "confirm_required": False,
                        "biometric_required": False,
                        "reason": "Permission evaluation failed and fail-closed is enabled.",
                        "source": RuleSource.DEFAULT_POLICY.value,
                        "internal_error": str(exc),
                    },
                    metadata={
                        "fail_closed": True,
                    },
                )

            return self._error_result(
                "Permission check failed.",
                exc,
            )

    def is_allowed(self, **kwargs: Any) -> bool:
        """Convenience method returning only whether an action is allowed."""
        result = self.check_permission(**kwargs)

        return bool(
            result.get("success")
            and result.get("data", {}).get("decision")
            == PermissionDecision.ALLOWED.value
        )

    def require_permission(self, **kwargs: Any) -> Dict[str, Any]:
        """
        Check permission and return a callable-friendly structured result.

        This method does not raise by default because William uses structured
        dict/JSON results between agents.
        """
        return self.check_permission(**kwargs)

    # =========================================================================
    # Permission evaluation pipeline
    # =========================================================================

    def _evaluate_permission(
        self,
        context: PermissionContext,
    ) -> PermissionEvaluation:
        """Execute the complete permission evaluation pipeline."""
        trace: List[Dict[str, Any]] = []
        warnings: List[str] = []

        isolation_result = self._evaluate_resource_isolation(context)

        if isolation_result is not None:
            isolation_result.policy_trace = trace + isolation_result.policy_trace
            return isolation_result

        lock_result = self._evaluate_locks(context)

        if lock_result is not None:
            lock_result.policy_trace = trace + lock_result.policy_trace
            return lock_result

        malicious_result = self._evaluate_blocked_by_default(context)

        if malicious_result is not None:
            malicious_result.policy_trace = trace + malicious_result.policy_trace
            return malicious_result

        explicit_deny = self._evaluate_explicit_denials(context)

        if explicit_deny is not None:
            explicit_deny.policy_trace = trace + explicit_deny.policy_trace
            return explicit_deny

        subscription_result = self._evaluate_subscription(context)

        if subscription_result is not None:
            subscription_result.policy_trace = trace + subscription_result.policy_trace
            return subscription_result

        role_result = self._evaluate_role_requirements(context)

        if role_result is not None:
            role_result.policy_trace = trace + role_result.policy_trace
            return role_result

        agent_registration_result = self._evaluate_agent_registration(context)

        if agent_registration_result is not None:
            agent_registration_result.policy_trace = (
                trace + agent_registration_result.policy_trace
            )
            return agent_registration_result

        explicit_rule = self._find_best_matching_rule(context)

        if explicit_rule is not None:
            trace.append({
                "step": "explicit_rule",
                "rule_id": explicit_rule.rule_id,
                "rule_name": explicit_rule.name,
                "effect": explicit_rule.effect,
                "priority": explicit_rule.priority,
            })

            evaluation = self._evaluation_from_rule(
                context,
                explicit_rule,
                trace,
            )

            return self._apply_evidence(
                context,
                evaluation,
            )

        user_permission_effect = self._evaluate_user_permissions(context)

        if user_permission_effect is not None:
            trace.append({
                "step": "user_permissions",
                "effect": user_permission_effect,
            })

            evaluation = self._evaluation_from_effect(
                context=context,
                effect=user_permission_effect,
                source=RuleSource.USER_OVERRIDE.value,
                reason="User-specific permission policy matched.",
                trace=trace,
            )

            return self._apply_risk_and_evidence(
                context,
                evaluation,
            )

        agent_permission_effect = self._evaluate_agent_permissions(context)

        if agent_permission_effect is not None:
            trace.append({
                "step": "agent_permissions",
                "effect": agent_permission_effect,
            })

            evaluation = self._evaluation_from_effect(
                context=context,
                effect=agent_permission_effect,
                source=RuleSource.AGENT_POLICY.value,
                reason="Agent-specific permission policy matched.",
                trace=trace,
            )

            return self._apply_risk_and_evidence(
                context,
                evaluation,
            )

        default_agent_effect = self._evaluate_default_agent_policy(context)

        if default_agent_effect is not None:
            trace.append({
                "step": "default_agent_policy",
                "effect": default_agent_effect,
                "agent_name": context.agent_name,
            })

            evaluation = self._evaluation_from_effect(
                context=context,
                effect=default_agent_effect,
                source=RuleSource.AGENT_POLICY.value,
                reason="Default agent action policy matched.",
                trace=trace,
            )

            return self._apply_risk_and_evidence(
                context,
                evaluation,
            )

        inferred_effect = self._infer_action_effect(context)

        if inferred_effect is not None:
            trace.append({
                "step": "action_inference",
                "effect": inferred_effect,
            })

            evaluation = self._evaluation_from_effect(
                context=context,
                effect=inferred_effect,
                source=RuleSource.RISK_POLICY.value,
                reason="Action sensitivity and risk policy determined the decision.",
                trace=trace,
            )

            return self._apply_risk_and_evidence(
                context,
                evaluation,
            )

        trace.append({
            "step": "default_policy",
            "effect": self.config.default_decision,
        })

        default_effect = self._decision_to_effect(
            self.config.default_decision
        )

        evaluation = self._evaluation_from_effect(
            context=context,
            effect=default_effect,
            source=RuleSource.DEFAULT_POLICY.value,
            reason="No explicit permission policy matched; default policy applied.",
            trace=trace,
        )

        evaluation.warnings.extend(warnings)

        return self._apply_risk_and_evidence(
            context,
            evaluation,
        )

    def _evaluate_resource_isolation(
        self,
        context: PermissionContext,
    ) -> Optional[PermissionEvaluation]:
        """Block cross-user or cross-workspace resource access."""
        if (
            context.resource_workspace_id is not None
            and context.resource_workspace_id != context.workspace_id
        ):
            if not (
                self.config.allow_system_admin_cross_workspace
                and "system_admin" in context.roles
            ):
                return PermissionEvaluation(
                    decision=PermissionDecision.BLOCKED.value,
                    reason=(
                        "Resource workspace does not match the requesting workspace."
                    ),
                    source=RuleSource.EXPLICIT_DENY.value,
                    risk_level="critical",
                    risk_score=max(context.risk_score, 100.0),
                    policy_trace=[{
                        "step": "workspace_isolation",
                        "request_workspace_id": context.workspace_id,
                        "resource_workspace_id": context.resource_workspace_id,
                        "matched": False,
                    }],
                )

        if (
            context.resource_owner_user_id is not None
            and context.resource_owner_user_id != context.user_id
        ):
            elevated_roles = {
                "manager",
                "admin",
                "workspace_owner",
                "system_admin",
            }

            if not elevated_roles.intersection(context.roles):
                return PermissionEvaluation(
                    decision=PermissionDecision.BLOCKED.value,
                    reason=(
                        "Resource owner does not match the requesting user "
                        "and no elevated role is present."
                    ),
                    source=RuleSource.EXPLICIT_DENY.value,
                    risk_level="high",
                    risk_score=max(context.risk_score, 90.0),
                    policy_trace=[{
                        "step": "user_isolation",
                        "request_user_id": context.user_id,
                        "resource_owner_user_id": context.resource_owner_user_id,
                        "elevated_role_present": False,
                    }],
                )

        return None

    def _evaluate_locks(
        self,
        context: PermissionContext,
    ) -> Optional[PermissionEvaluation]:
        """Evaluate workspace, user, and session emergency locks."""
        with self._lock:
            workspace_lock = self._workspace_locks.get(context.workspace_id)
            user_lock = self._user_locks.get(
                (context.user_id, context.workspace_id)
            )

            session_lock = None

            if context.session_id:
                session_lock = self._session_locks.get(
                    (
                        context.user_id,
                        context.workspace_id,
                        context.session_id,
                    )
                )

        matched_lock = session_lock or user_lock or workspace_lock

        if not matched_lock:
            return None

        allow_patterns = matched_lock.get("allowed_action_patterns", [])

        if any(
            _action_matches(context.action, pattern)
            for pattern in allow_patterns
        ):
            return None

        return PermissionEvaluation(
            decision=PermissionDecision.BLOCKED.value,
            reason=matched_lock.get(
                "reason",
                "Security emergency lock is active.",
            ),
            source=RuleSource.EMERGENCY_LOCK.value,
            risk_level="critical",
            risk_score=max(context.risk_score, 100.0),
            policy_trace=[{
                "step": "emergency_lock",
                "lock_id": matched_lock.get("lock_id"),
                "lock_scope": matched_lock.get("scope"),
                "active": True,
            }],
        )

    def _evaluate_blocked_by_default(
        self,
        context: PermissionContext,
    ) -> Optional[PermissionEvaluation]:
        """Block known security bypass and malicious actions."""
        if any(
            re.search(pattern, context.action, re.IGNORECASE)
            for pattern in BLOCKED_BY_DEFAULT_ACTION_PATTERNS
        ):
            return PermissionEvaluation(
                decision=PermissionDecision.BLOCKED.value,
                reason="Action is blocked by the core security safety policy.",
                source=RuleSource.EXPLICIT_DENY.value,
                risk_level="critical",
                risk_score=100.0,
                policy_trace=[{
                    "step": "blocked_by_default",
                    "action": context.action,
                    "matched": True,
                }],
            )

        return None

    def _evaluate_explicit_denials(
        self,
        context: PermissionContext,
    ) -> Optional[PermissionEvaluation]:
        """Evaluate explicit denied permissions and deny rules."""
        combined_denials = set(context.denied_permissions)

        with self._lock:
            override = self._user_permission_overrides.get(
                (context.user_id, context.workspace_id),
                {},
            )

            combined_denials.update(override.get("deny", set()))

        if self._matches_any_permission(
            context.action,
            combined_denials,
        ):
            return PermissionEvaluation(
                decision=PermissionDecision.BLOCKED.value,
                reason="Action matched an explicit denied permission.",
                source=RuleSource.EXPLICIT_DENY.value,
                risk_level=context.risk_level,
                risk_score=context.risk_score,
                policy_trace=[{
                    "step": "explicit_permission_deny",
                    "matched": True,
                }],
            )

        matching_rules = self._find_matching_rules(context)

        deny_rules = [
            rule
            for rule in matching_rules
            if rule.effect == PolicyEffect.BLOCK.value
        ]

        if deny_rules:
            best = sorted(
                deny_rules,
                key=lambda item: item.priority,
                reverse=True,
            )[0]

            return PermissionEvaluation(
                decision=PermissionDecision.BLOCKED.value,
                reason=f"Blocked by policy rule: {best.name}",
                source=RuleSource.EXPLICIT_DENY.value,
                matched_rule_id=best.rule_id,
                matched_rule_name=best.name,
                risk_level=context.risk_level,
                risk_score=context.risk_score,
                policy_trace=[{
                    "step": "explicit_deny_rule",
                    "rule_id": best.rule_id,
                    "rule_name": best.name,
                    "priority": best.priority,
                }],
            )

        return None

    def _evaluate_subscription(
        self,
        context: PermissionContext,
    ) -> Optional[PermissionEvaluation]:
        """Apply subscription-state access restrictions."""
        if not self.config.require_active_subscription:
            return None

        if (
            context.subscription_status
            not in self.config.allowed_subscription_states
        ):
            return PermissionEvaluation(
                decision=PermissionDecision.BLOCKED.value,
                reason=(
                    "An active or trial subscription is required for this action."
                ),
                source=RuleSource.SUBSCRIPTION_POLICY.value,
                risk_level=context.risk_level,
                risk_score=context.risk_score,
                policy_trace=[{
                    "step": "subscription_check",
                    "subscription_status": context.subscription_status,
                    "allowed_states": sorted(
                        self.config.allowed_subscription_states
                    ),
                    "passed": False,
                }],
            )

        return None

    def _evaluate_role_requirements(
        self,
        context: PermissionContext,
    ) -> Optional[PermissionEvaluation]:
        """Apply optional known-role requirement."""
        if not self.config.require_known_role:
            return None

        known_roles = set(self.config.role_hierarchy)
        matched_roles = known_roles.intersection(context.roles)

        if not matched_roles:
            return PermissionEvaluation(
                decision=PermissionDecision.BLOCKED.value,
                reason="No recognized workspace role was provided.",
                source=RuleSource.ROLE_POLICY.value,
                risk_level=context.risk_level,
                risk_score=context.risk_score,
                policy_trace=[{
                    "step": "known_role_check",
                    "roles": context.roles,
                    "passed": False,
                }],
            )

        return None

    def _evaluate_agent_registration(
        self,
        context: PermissionContext,
    ) -> Optional[PermissionEvaluation]:
        """Optionally require a known registered agent name."""
        if not self.config.require_registered_agent:
            return None

        if not context.agent_name:
            return PermissionEvaluation(
                decision=PermissionDecision.BLOCKED.value,
                reason="Registered agent identity is required.",
                source=RuleSource.AGENT_POLICY.value,
                risk_level=context.risk_level,
                risk_score=context.risk_score,
                policy_trace=[{
                    "step": "registered_agent_check",
                    "agent_name": None,
                    "passed": False,
                }],
            )

        known_agents = {
            name.lower()
            for name in self.config.agent_action_policies
        }

        if context.agent_name.lower() not in known_agents:
            return PermissionEvaluation(
                decision=PermissionDecision.BLOCKED.value,
                reason="Agent is not registered in the permission policy.",
                source=RuleSource.AGENT_POLICY.value,
                risk_level=context.risk_level,
                risk_score=context.risk_score,
                policy_trace=[{
                    "step": "registered_agent_check",
                    "agent_name": context.agent_name,
                    "passed": False,
                }],
            )

        return None

    def _evaluate_user_permissions(
        self,
        context: PermissionContext,
    ) -> Optional[str]:
        """Evaluate user permission allow/confirm/biometric overrides."""
        with self._lock:
            overrides = self._user_permission_overrides.get(
                (context.user_id, context.workspace_id),
                {},
            )

        allow_permissions = set(context.user_permissions)
        allow_permissions.update(overrides.get("allow", set()))

        confirm_permissions = overrides.get("confirm", set())
        biometric_permissions = overrides.get("biometric", set())

        role_permissions = self._collect_role_permissions(context)
        allow_permissions.update(role_permissions.get("allow", set()))
        confirm_permissions = set(confirm_permissions).union(
            role_permissions.get("confirm", set())
        )
        biometric_permissions = set(biometric_permissions).union(
            role_permissions.get("biometric", set())
        )

        if self._matches_any_permission(
            context.action,
            biometric_permissions,
        ):
            return PolicyEffect.BIOMETRIC.value

        if self._matches_any_permission(
            context.action,
            confirm_permissions,
        ):
            return PolicyEffect.CONFIRM.value

        if self._matches_any_permission(
            context.action,
            allow_permissions,
        ):
            return PolicyEffect.ALLOW.value

        return None

    def _evaluate_agent_permissions(
        self,
        context: PermissionContext,
    ) -> Optional[str]:
        """Evaluate provided and stored agent permissions."""
        if not context.agent_name:
            return None

        with self._lock:
            overrides = self._agent_permission_overrides.get(
                (context.workspace_id, context.agent_name.lower()),
                {},
            )

        deny_permissions = overrides.get("deny", set())

        if self._matches_any_permission(
            context.action,
            deny_permissions,
        ):
            return PolicyEffect.BLOCK.value

        biometric_permissions = overrides.get("biometric", set())

        if self._matches_any_permission(
            context.action,
            biometric_permissions,
        ):
            return PolicyEffect.BIOMETRIC.value

        confirm_permissions = overrides.get("confirm", set())

        if self._matches_any_permission(
            context.action,
            confirm_permissions,
        ):
            return PolicyEffect.CONFIRM.value

        allow_permissions = set(context.agent_permissions)
        allow_permissions.update(overrides.get("allow", set()))

        if self._matches_any_permission(
            context.action,
            allow_permissions,
        ):
            return PolicyEffect.ALLOW.value

        return None

    def _evaluate_default_agent_policy(
        self,
        context: PermissionContext,
    ) -> Optional[str]:
        """Evaluate built-in action policy for the routed agent."""
        if not context.agent_name:
            return None

        policy = None

        for registered_name, registered_policy in (
            self.config.agent_action_policies.items()
        ):
            if registered_name.lower() == context.agent_name.lower():
                policy = registered_policy
                break

        if not policy:
            return None

        matched_effects: List[Tuple[int, str]] = []

        for pattern, effect in policy.items():
            if _action_matches(context.action, pattern):
                specificity = len(pattern.replace("*", ""))
                matched_effects.append((specificity, effect))

        if not matched_effects:
            return None

        matched_effects.sort(
            key=lambda item: item[0],
            reverse=True,
        )

        return matched_effects[0][1]

    def _infer_action_effect(
        self,
        context: PermissionContext,
    ) -> Optional[str]:
        """Infer a policy effect from action sensitivity and risk."""
        if any(
            re.search(pattern, context.action, re.IGNORECASE)
            for pattern in CRITICAL_ACTION_PATTERNS
        ):
            if (
                self.config.critical_risk_block_without_explicit_allow
                and not self._has_explicit_allow(context)
            ):
                return PolicyEffect.BLOCK.value

            return PolicyEffect.BIOMETRIC.value

        sensitive = any(
            re.search(pattern, context.action, re.IGNORECASE)
            for pattern in KNOWN_SENSITIVE_ACTION_PATTERNS
        )

        if context.risk_level == "critical":
            if self.config.critical_risk_block_without_explicit_allow:
                return PolicyEffect.BLOCK.value

            return PolicyEffect.BIOMETRIC.value

        if context.risk_level == "high":
            if self.config.high_risk_requires_biometric:
                return PolicyEffect.BIOMETRIC.value

            return PolicyEffect.CONFIRM.value

        if context.risk_level == "medium":
            if self.config.medium_risk_requires_confirmation:
                return PolicyEffect.CONFIRM.value

        if sensitive:
            return PolicyEffect.CONFIRM.value

        if context.risk_level in {"minimal", "low"}:
            return PolicyEffect.ALLOW.value

        return None

    # =========================================================================
    # Rule matching
    # =========================================================================

    def _find_matching_rules(
        self,
        context: PermissionContext,
    ) -> List[PermissionRule]:
        """Return all enabled permission rules matching the context."""
        with self._lock:
            rules = list(self._rules.values())

        matched: List[PermissionRule] = []

        for rule in rules:
            if not rule.enabled:
                continue

            if not _action_matches(
                context.action,
                rule.action_pattern,
            ):
                continue

            if rule.user_id and rule.user_id != context.user_id:
                continue

            if (
                rule.workspace_id
                and rule.workspace_id != context.workspace_id
            ):
                continue

            if (
                rule.agent_name
                and (
                    not context.agent_name
                    or rule.agent_name.lower()
                    != context.agent_name.lower()
                )
            ):
                continue

            if rule.role and rule.role not in context.roles:
                continue

            if (
                rule.subscription_plan
                and rule.subscription_plan != context.subscription_plan
            ):
                continue

            if rule.minimum_risk_level:
                current_level = DEFAULT_RISK_LEVEL_ORDER[
                    context.risk_level
                ]
                minimum_level = DEFAULT_RISK_LEVEL_ORDER[
                    rule.minimum_risk_level
                ]

                if current_level < minimum_level:
                    continue

            if rule.maximum_risk_level:
                current_level = DEFAULT_RISK_LEVEL_ORDER[
                    context.risk_level
                ]
                maximum_level = DEFAULT_RISK_LEVEL_ORDER[
                    rule.maximum_risk_level
                ]

                if current_level > maximum_level:
                    continue

            if not self._conditions_match(
                rule.conditions,
                context,
            ):
                continue

            matched.append(rule)

        matched.sort(
            key=lambda item: (
                item.priority,
                len(item.action_pattern.replace("*", "")),
            ),
            reverse=True,
        )

        return matched

    def _find_best_matching_rule(
        self,
        context: PermissionContext,
    ) -> Optional[PermissionRule]:
        """Return the highest-priority non-block rule."""
        rules = self._find_matching_rules(context)

        for rule in rules:
            if rule.effect != PolicyEffect.BLOCK.value:
                return rule

        return None

    def _conditions_match(
        self,
        conditions: Mapping[str, Any],
        context: PermissionContext,
    ) -> bool:
        """Evaluate supported rule conditions."""
        if not conditions:
            return True

        supported_values = {
            "source": context.source,
            "device_id": context.device_id,
            "ip_address": context.ip_address,
            "subscription_status": context.subscription_status,
            "subscription_plan": context.subscription_plan,
            "agent_name": context.agent_name,
            "risk_level": context.risk_level,
        }

        for key, expected in conditions.items():
            if key.startswith("metadata."):
                metadata_key = key.split(".", 1)[1]
                actual = context.metadata.get(metadata_key)
            else:
                if key not in supported_values:
                    return False

                actual = supported_values[key]

            if isinstance(expected, list):
                if actual not in expected:
                    return False
            elif actual != expected:
                return False

        return True

    def _evaluation_from_rule(
        self,
        context: PermissionContext,
        rule: PermissionRule,
        trace: List[Dict[str, Any]],
    ) -> PermissionEvaluation:
        """Convert a PermissionRule into an evaluation."""
        effect = rule.effect

        if rule.require_biometric:
            effect = PolicyEffect.BIOMETRIC.value
        elif rule.require_confirmation and effect == PolicyEffect.ALLOW.value:
            effect = PolicyEffect.CONFIRM.value

        return self._evaluation_from_effect(
            context=context,
            effect=effect,
            source=RuleSource.WORKSPACE_POLICY.value,
            reason=f"Permission policy matched: {rule.name}",
            trace=trace,
            matched_rule_id=rule.rule_id,
            matched_rule_name=rule.name,
        )

    def _evaluation_from_effect(
        self,
        *,
        context: PermissionContext,
        effect: str,
        source: str,
        reason: str,
        trace: List[Dict[str, Any]],
        matched_rule_id: Optional[str] = None,
        matched_rule_name: Optional[str] = None,
    ) -> PermissionEvaluation:
        """Convert a policy effect into PermissionEvaluation."""
        if effect == PolicyEffect.ALLOW.value:
            decision = PermissionDecision.ALLOWED.value
        elif effect == PolicyEffect.CONFIRM.value:
            decision = PermissionDecision.CONFIRM_REQUIRED.value
        elif effect == PolicyEffect.BIOMETRIC.value:
            decision = PermissionDecision.BIOMETRIC_REQUIRED.value
        elif effect == PolicyEffect.BLOCK.value:
            decision = PermissionDecision.BLOCKED.value
        else:
            decision = (
                PermissionDecision.BLOCKED.value
                if self.config.fail_closed
                else self.config.default_decision
            )

        return PermissionEvaluation(
            decision=decision,
            reason=reason,
            source=source,
            matched_rule_id=matched_rule_id,
            matched_rule_name=matched_rule_name,
            requires_confirmation=(
                decision
                == PermissionDecision.CONFIRM_REQUIRED.value
            ),
            requires_biometric=(
                decision
                == PermissionDecision.BIOMETRIC_REQUIRED.value
            ),
            requires_approval=(
                decision
                in {
                    PermissionDecision.CONFIRM_REQUIRED.value,
                    PermissionDecision.BIOMETRIC_REQUIRED.value,
                }
            ),
            risk_level=context.risk_level,
            risk_score=context.risk_score,
            policy_trace=_deepcopy_safe(trace),
        )

    # =========================================================================
    # Risk and evidence
    # =========================================================================

    def _apply_risk_and_evidence(
        self,
        context: PermissionContext,
        evaluation: PermissionEvaluation,
    ) -> PermissionEvaluation:
        """Escalate policy using risk and then validate evidence."""
        evaluation = self._apply_risk_escalation(
            context,
            evaluation,
        )

        return self._apply_evidence(
            context,
            evaluation,
        )

    def _apply_risk_escalation(
        self,
        context: PermissionContext,
        evaluation: PermissionEvaluation,
    ) -> PermissionEvaluation:
        """Escalate lower permission decisions based on risk."""
        if evaluation.decision == PermissionDecision.BLOCKED.value:
            return evaluation

        if context.risk_level == "critical":
            if (
                self.config.critical_risk_block_without_explicit_allow
                and evaluation.source
                not in {
                    RuleSource.EXPLICIT_ALLOW.value,
                    RuleSource.WORKSPACE_POLICY.value,
                }
            ):
                evaluation.decision = PermissionDecision.BLOCKED.value
                evaluation.reason = (
                    "Critical-risk action blocked because no explicit allow "
                    "policy matched."
                )
                evaluation.source = RuleSource.RISK_POLICY.value
                evaluation.requires_confirmation = False
                evaluation.requires_biometric = False
                evaluation.requires_approval = False

            elif evaluation.decision != PermissionDecision.BLOCKED.value:
                evaluation.decision = (
                    PermissionDecision.BIOMETRIC_REQUIRED.value
                )
                evaluation.reason = (
                    "Critical-risk action requires biometric verification."
                )
                evaluation.source = RuleSource.RISK_POLICY.value
                evaluation.requires_confirmation = False
                evaluation.requires_biometric = True
                evaluation.requires_approval = True

        elif (
            context.risk_level == "high"
            and self.config.high_risk_requires_biometric
            and evaluation.decision
            in {
                PermissionDecision.ALLOWED.value,
                PermissionDecision.CONFIRM_REQUIRED.value,
            }
        ):
            evaluation.decision = (
                PermissionDecision.BIOMETRIC_REQUIRED.value
            )
            evaluation.reason = (
                "High-risk action requires biometric verification."
            )
            evaluation.source = RuleSource.RISK_POLICY.value
            evaluation.requires_confirmation = False
            evaluation.requires_biometric = True
            evaluation.requires_approval = True

        elif (
            context.risk_level == "medium"
            and self.config.medium_risk_requires_confirmation
            and evaluation.decision == PermissionDecision.ALLOWED.value
        ):
            evaluation.decision = (
                PermissionDecision.CONFIRM_REQUIRED.value
            )
            evaluation.reason = (
                "Medium-risk action requires explicit confirmation."
            )
            evaluation.source = RuleSource.RISK_POLICY.value
            evaluation.requires_confirmation = True
            evaluation.requires_biometric = False
            evaluation.requires_approval = True

        evaluation.policy_trace.append({
            "step": "risk_escalation",
            "risk_level": context.risk_level,
            "risk_score": context.risk_score,
            "resulting_decision": evaluation.decision,
        })

        return evaluation

    def _apply_evidence(
        self,
        context: PermissionContext,
        evaluation: PermissionEvaluation,
    ) -> PermissionEvaluation:
        """Apply confirmation, approval, and biometric evidence."""
        confirmation_valid = self._is_confirmation_valid(context)
        biometric_valid = self._is_biometric_valid(context)
        approval_valid = self._is_approval_valid(context)

        evaluation.confirmation_satisfied = confirmation_valid
        evaluation.biometric_satisfied = biometric_valid
        evaluation.approval_satisfied = approval_valid

        if evaluation.decision == PermissionDecision.BLOCKED.value:
            return evaluation

        if evaluation.decision == PermissionDecision.BIOMETRIC_REQUIRED.value:
            if biometric_valid:
                evaluation.decision = PermissionDecision.ALLOWED.value
                evaluation.reason = (
                    "Biometric requirement satisfied; action allowed."
                )
                evaluation.source = RuleSource.BIOMETRIC.value
                evaluation.requires_biometric = False
                evaluation.requires_approval = False

        elif evaluation.decision == PermissionDecision.CONFIRM_REQUIRED.value:
            if confirmation_valid or approval_valid:
                evaluation.decision = PermissionDecision.ALLOWED.value
                evaluation.reason = (
                    "Confirmation or approval requirement satisfied; "
                    "action allowed."
                )
                evaluation.source = (
                    RuleSource.CONFIRMATION.value
                    if confirmation_valid
                    else RuleSource.APPROVAL.value
                )
                evaluation.requires_confirmation = False
                evaluation.requires_approval = False

        evaluation.policy_trace.append({
            "step": "evidence_validation",
            "confirmation_valid": confirmation_valid,
            "biometric_valid": biometric_valid,
            "approval_valid": approval_valid,
            "resulting_decision": evaluation.decision,
        })

        return evaluation

    def _is_confirmation_valid(
        self,
        context: PermissionContext,
    ) -> bool:
        """Validate confirmation evidence."""
        if context.confirmation_id:
            with self._lock:
                stored = self._confirmations.get(
                    context.confirmation_id
                )

            if stored and self._stored_evidence_matches(
                stored,
                context,
                self.config.confirmation_ttl_seconds,
            ):
                return True

        if not context.confirmed:
            return False

        if context.confirmation_timestamp is None:
            return False

        return (
            _unix_now() - float(context.confirmation_timestamp)
            <= self.config.confirmation_ttl_seconds
        )

    def _is_biometric_valid(
        self,
        context: PermissionContext,
    ) -> bool:
        """Validate biometric evidence."""
        if context.biometric_verification_id:
            with self._lock:
                stored = self._biometric_verifications.get(
                    context.biometric_verification_id
                )

            if stored and self._stored_evidence_matches(
                stored,
                context,
                self.config.biometric_ttl_seconds,
            ):
                return True

        if not context.biometric_verified:
            return False

        if context.biometric_timestamp is None:
            return False

        return (
            _unix_now() - float(context.biometric_timestamp)
            <= self.config.biometric_ttl_seconds
        )

    def _is_approval_valid(
        self,
        context: PermissionContext,
    ) -> bool:
        """Validate temporary approval evidence."""
        if context.approval_id:
            with self._lock:
                stored = self._temporary_approvals.get(
                    context.approval_id
                )

            if stored and self._stored_evidence_matches(
                stored,
                context,
                self.config.approval_ttl_seconds,
            ):
                return True

        if not context.approval_granted:
            return False

        if context.approval_timestamp is None:
            return False

        return (
            _unix_now() - float(context.approval_timestamp)
            <= self.config.approval_ttl_seconds
        )

    def _stored_evidence_matches(
        self,
        evidence: Mapping[str, Any],
        context: PermissionContext,
        ttl_seconds: int,
    ) -> bool:
        """Validate scope, action, status, and expiry of stored evidence."""
        if evidence.get("status") != "valid":
            return False

        if evidence.get("user_id") != context.user_id:
            return False

        if evidence.get("workspace_id") != context.workspace_id:
            return False

        if evidence.get("action") != context.action:
            return False

        evidence_session = evidence.get("session_id")

        if (
            evidence_session is not None
            and evidence_session != context.session_id
        ):
            return False

        created_at_unix = float(
            evidence.get("created_at_unix", 0.0)
        )

        if _unix_now() - created_at_unix > ttl_seconds:
            return False

        if evidence.get("one_time", True):
            evidence_id = str(evidence.get("evidence_id", ""))

            with self._lock:
                mutable_evidence: Optional[MutableMapping[str, Any]] = None

                if evidence_id in self._confirmations:
                    mutable_evidence = self._confirmations[evidence_id]
                elif evidence_id in self._biometric_verifications:
                    mutable_evidence = self._biometric_verifications[evidence_id]
                elif evidence_id in self._temporary_approvals:
                    mutable_evidence = self._temporary_approvals[evidence_id]

                if mutable_evidence is not None:
                    if mutable_evidence.get("consumed"):
                        return False

                    mutable_evidence["consumed"] = True
                    mutable_evidence["consumed_at"] = _utc_now_iso()

        return True

    # =========================================================================
    # Permission helpers
    # =========================================================================

    def _matches_any_permission(
        self,
        action: str,
        permissions: Iterable[str],
    ) -> bool:
        """Return whether an action matches any permission pattern."""
        for permission in permissions:
            if permission == "*":
                return True

            if _action_matches(action, permission):
                return True

        return False

    def _collect_role_permissions(
        self,
        context: PermissionContext,
    ) -> Dict[str, Set[str]]:
        """Collect permissions for all current workspace roles."""
        output: Dict[str, Set[str]] = {
            "allow": set(),
            "deny": set(),
            "confirm": set(),
            "biometric": set(),
        }

        with self._lock:
            for role in context.roles:
                permissions = self._workspace_role_permissions.get(
                    (context.workspace_id, role),
                    {},
                )

                for effect in output:
                    output[effect].update(
                        permissions.get(effect, set())
                    )

        return output

    def _has_explicit_allow(
        self,
        context: PermissionContext,
    ) -> bool:
        """Return whether a strong explicit allow policy matches."""
        if self._matches_any_permission(
            context.action,
            context.user_permissions,
        ):
            return True

        with self._lock:
            override = self._user_permission_overrides.get(
                (context.user_id, context.workspace_id),
                {},
            )

        if self._matches_any_permission(
            context.action,
            override.get("allow", set()),
        ):
            return True

        matching_rules = self._find_matching_rules(context)

        return any(
            rule.effect == PolicyEffect.ALLOW.value
            for rule in matching_rules
        )

    def _decision_to_effect(self, decision: str) -> str:
        """Convert final decision string to policy effect."""
        mapping = {
            PermissionDecision.ALLOWED.value: PolicyEffect.ALLOW.value,
            PermissionDecision.CONFIRM_REQUIRED.value: (
                PolicyEffect.CONFIRM.value
            ),
            PermissionDecision.BIOMETRIC_REQUIRED.value: (
                PolicyEffect.BIOMETRIC.value
            ),
            PermissionDecision.BLOCKED.value: PolicyEffect.BLOCK.value,
        }

        return mapping.get(
            decision,
            PolicyEffect.BLOCK.value,
        )

    # =========================================================================
    # Rule management
    # =========================================================================

    def add_rule(
        self,
        *,
        name: str,
        action_pattern: str,
        effect: str,
        rule_id: Optional[str] = None,
        enabled: bool = True,
        priority: int = 100,
        user_id: Optional[Any] = None,
        workspace_id: Optional[Any] = None,
        agent_name: Optional[str] = None,
        role: Optional[str] = None,
        subscription_plan: Optional[str] = None,
        minimum_risk_level: Optional[str] = None,
        maximum_risk_level: Optional[str] = None,
        require_confirmation: bool = False,
        require_biometric: bool = False,
        conditions: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Add an explicit permission rule."""
        try:
            clean_effect = str(effect).strip().lower()

            if clean_effect not in SUPPORTED_POLICY_EFFECTS:
                raise ValueError(
                    f"effect must be one of {sorted(SUPPORTED_POLICY_EFFECTS)}."
                )

            clean_name = str(name).strip()

            if not clean_name:
                raise ValueError("name is required.")

            clean_action_pattern = str(action_pattern).strip().lower()

            if not clean_action_pattern:
                raise ValueError("action_pattern is required.")

            normalized_rule_id = (
                _normalize_identifier(rule_id, "rule_id")
                if rule_id
                else _safe_uuid("permission_rule")
            )

            normalized_user_id = (
                _normalize_identifier(user_id, "user_id")
                if user_id is not None
                else None
            )

            normalized_workspace_id = (
                _normalize_identifier(workspace_id, "workspace_id")
                if workspace_id is not None
                else None
            )

            normalized_role = (
                _normalize_role(role)
                if role is not None
                else None
            )

            if (
                minimum_risk_level
                and minimum_risk_level not in DEFAULT_RISK_LEVEL_ORDER
            ):
                raise ValueError("Invalid minimum_risk_level.")

            if (
                maximum_risk_level
                and maximum_risk_level not in DEFAULT_RISK_LEVEL_ORDER
            ):
                raise ValueError("Invalid maximum_risk_level.")

            rule = PermissionRule(
                rule_id=normalized_rule_id,
                name=_truncate_string(clean_name, 256),
                action_pattern=clean_action_pattern,
                effect=clean_effect,
                enabled=bool(enabled),
                priority=int(priority),
                user_id=normalized_user_id,
                workspace_id=normalized_workspace_id,
                agent_name=_normalize_agent_name(agent_name),
                role=normalized_role,
                subscription_plan=subscription_plan,
                minimum_risk_level=minimum_risk_level,
                maximum_risk_level=maximum_risk_level,
                require_confirmation=bool(require_confirmation),
                require_biometric=bool(require_biometric),
                conditions=self._sanitize_payload(
                    _coerce_mapping(conditions, "conditions")
                ),
                metadata=self._sanitize_payload(
                    _coerce_mapping(metadata, "metadata")
                ),
            )

            with self._lock:
                if (
                    len(self._rules) >= self.config.max_permission_rules
                    and normalized_rule_id not in self._rules
                ):
                    raise RuntimeError(
                        "Maximum permission rule limit reached."
                    )

                if normalized_rule_id in self._rules:
                    raise ValueError(
                        f"Permission rule '{normalized_rule_id}' already exists."
                    )

                self._rules[normalized_rule_id] = rule

            self._log_audit_event(
                action="permission_rule_added",
                user_id=normalized_user_id,
                workspace_id=normalized_workspace_id,
                session_id=None,
                details={
                    "rule_id": normalized_rule_id,
                    "name": rule.name,
                    "effect": rule.effect,
                    "action_pattern": rule.action_pattern,
                    "priority": rule.priority,
                },
            )

            return self._safe_result(
                message="Permission rule added.",
                data={
                    "rule": asdict(rule),
                },
            )

        except Exception as exc:
            return self._error_result(
                "Failed to add permission rule.",
                exc,
            )

    def update_rule(
        self,
        rule_id: Any,
        **updates: Any,
    ) -> Dict[str, Any]:
        """Update an existing permission rule."""
        try:
            normalized_rule_id = _normalize_identifier(
                rule_id,
                "rule_id",
            )

            allowed_fields = {
                "name",
                "action_pattern",
                "effect",
                "enabled",
                "priority",
                "user_id",
                "workspace_id",
                "agent_name",
                "role",
                "subscription_plan",
                "minimum_risk_level",
                "maximum_risk_level",
                "require_confirmation",
                "require_biometric",
                "conditions",
                "metadata",
            }

            unknown_fields = set(updates) - allowed_fields

            if unknown_fields:
                raise ValueError(
                    f"Unsupported update fields: {sorted(unknown_fields)}"
                )

            with self._lock:
                rule = self._rules.get(normalized_rule_id)

                if rule is None:
                    return self._safe_result(
                        message="Permission rule not found.",
                        data={
                            "updated": False,
                            "rule_id": normalized_rule_id,
                        },
                    )

                if "effect" in updates:
                    effect = str(updates["effect"]).strip().lower()

                    if effect not in SUPPORTED_POLICY_EFFECTS:
                        raise ValueError(
                            f"effect must be one of "
                            f"{sorted(SUPPORTED_POLICY_EFFECTS)}."
                        )

                    rule.effect = effect

                if "name" in updates:
                    clean_name = str(updates["name"]).strip()

                    if not clean_name:
                        raise ValueError("name cannot be empty.")

                    rule.name = _truncate_string(
                        clean_name,
                        256,
                    )

                if "action_pattern" in updates:
                    clean_pattern = str(
                        updates["action_pattern"]
                    ).strip().lower()

                    if not clean_pattern:
                        raise ValueError(
                            "action_pattern cannot be empty."
                        )

                    rule.action_pattern = clean_pattern

                if "enabled" in updates:
                    rule.enabled = bool(updates["enabled"])

                if "priority" in updates:
                    rule.priority = int(updates["priority"])

                if "user_id" in updates:
                    rule.user_id = (
                        _normalize_identifier(
                            updates["user_id"],
                            "user_id",
                        )
                        if updates["user_id"] is not None
                        else None
                    )

                if "workspace_id" in updates:
                    rule.workspace_id = (
                        _normalize_identifier(
                            updates["workspace_id"],
                            "workspace_id",
                        )
                        if updates["workspace_id"] is not None
                        else None
                    )

                if "agent_name" in updates:
                    rule.agent_name = _normalize_agent_name(
                        updates["agent_name"]
                    )

                if "role" in updates:
                    rule.role = (
                        _normalize_role(updates["role"])
                        if updates["role"] is not None
                        else None
                    )

                if "subscription_plan" in updates:
                    rule.subscription_plan = updates[
                        "subscription_plan"
                    ]

                if "minimum_risk_level" in updates:
                    value = updates["minimum_risk_level"]

                    if (
                        value is not None
                        and value not in DEFAULT_RISK_LEVEL_ORDER
                    ):
                        raise ValueError(
                            "Invalid minimum_risk_level."
                        )

                    rule.minimum_risk_level = value

                if "maximum_risk_level" in updates:
                    value = updates["maximum_risk_level"]

                    if (
                        value is not None
                        and value not in DEFAULT_RISK_LEVEL_ORDER
                    ):
                        raise ValueError(
                            "Invalid maximum_risk_level."
                        )

                    rule.maximum_risk_level = value

                if "require_confirmation" in updates:
                    rule.require_confirmation = bool(
                        updates["require_confirmation"]
                    )

                if "require_biometric" in updates:
                    rule.require_biometric = bool(
                        updates["require_biometric"]
                    )

                if "conditions" in updates:
                    rule.conditions = self._sanitize_payload(
                        _coerce_mapping(
                            updates["conditions"],
                            "conditions",
                        )
                    )

                if "metadata" in updates:
                    rule.metadata = self._sanitize_payload(
                        _coerce_mapping(
                            updates["metadata"],
                            "metadata",
                        )
                    )

                rule.updated_at = _utc_now_iso()
                updated_rule = asdict(rule)

            self._log_audit_event(
                action="permission_rule_updated",
                user_id=rule.user_id,
                workspace_id=rule.workspace_id,
                session_id=None,
                details={
                    "rule_id": normalized_rule_id,
                    "updated_fields": sorted(updates.keys()),
                },
            )

            return self._safe_result(
                message="Permission rule updated.",
                data={
                    "updated": True,
                    "rule": updated_rule,
                },
            )

        except Exception as exc:
            return self._error_result(
                "Failed to update permission rule.",
                exc,
            )

    def remove_rule(
        self,
        rule_id: Any,
        security_approved: bool = False,
    ) -> Dict[str, Any]:
        """Remove a permission rule."""
        try:
            normalized_rule_id = _normalize_identifier(
                rule_id,
                "rule_id",
            )

            if not security_approved:
                return self._safe_result(
                    message=(
                        "Security approval is required before removing "
                        "a permission rule."
                    ),
                    data={
                        "removed": False,
                        "decision": (
                            PermissionDecision.CONFIRM_REQUIRED.value
                        ),
                        "approval_request": {
                            "approval_request_id": _safe_uuid(
                                "rule_remove_approval"
                            ),
                            "rule_id": normalized_rule_id,
                            "required_method": "confirmation",
                            "status": "pending",
                        },
                    },
                )

            with self._lock:
                removed = self._rules.pop(
                    normalized_rule_id,
                    None,
                )

            self._log_audit_event(
                action="permission_rule_removed",
                user_id=removed.user_id if removed else None,
                workspace_id=(
                    removed.workspace_id if removed else None
                ),
                session_id=None,
                details={
                    "rule_id": normalized_rule_id,
                    "removed": removed is not None,
                },
                level="warning",
            )

            return self._safe_result(
                message=(
                    "Permission rule removed."
                    if removed
                    else "Permission rule not found."
                ),
                data={
                    "removed": removed is not None,
                    "rule": asdict(removed) if removed else None,
                },
            )

        except Exception as exc:
            return self._error_result(
                "Failed to remove permission rule.",
                exc,
            )

    def list_rules(
        self,
        *,
        workspace_id: Optional[Any] = None,
        user_id: Optional[Any] = None,
        agent_name: Optional[str] = None,
        effect: Optional[str] = None,
        enabled_only: bool = False,
        limit: int = 500,
    ) -> Dict[str, Any]:
        """List permission rules with safe filtering."""
        try:
            normalized_workspace_id = (
                _normalize_identifier(
                    workspace_id,
                    "workspace_id",
                )
                if workspace_id is not None
                else None
            )

            normalized_user_id = (
                _normalize_identifier(user_id, "user_id")
                if user_id is not None
                else None
            )

            normalized_agent_name = _normalize_agent_name(
                agent_name
            )

            normalized_effect = (
                str(effect).strip().lower()
                if effect is not None
                else None
            )

            if (
                normalized_effect is not None
                and normalized_effect not in SUPPORTED_POLICY_EFFECTS
            ):
                raise ValueError("Invalid effect filter.")

            safe_limit = max(
                1,
                min(int(limit), self.config.max_permission_rules),
            )

            with self._lock:
                rules = list(self._rules.values())

            if normalized_workspace_id:
                rules = [
                    rule
                    for rule in rules
                    if rule.workspace_id == normalized_workspace_id
                ]

            if normalized_user_id:
                rules = [
                    rule
                    for rule in rules
                    if rule.user_id == normalized_user_id
                ]

            if normalized_agent_name:
                rules = [
                    rule
                    for rule in rules
                    if rule.agent_name
                    and rule.agent_name.lower()
                    == normalized_agent_name.lower()
                ]

            if normalized_effect:
                rules = [
                    rule
                    for rule in rules
                    if rule.effect == normalized_effect
                ]

            if enabled_only:
                rules = [
                    rule
                    for rule in rules
                    if rule.enabled
                ]

            rules.sort(
                key=lambda item: (
                    item.priority,
                    item.updated_at,
                ),
                reverse=True,
            )

            payload = [
                asdict(rule)
                for rule in rules[:safe_limit]
            ]

            return self._safe_result(
                message="Permission rules retrieved.",
                data={
                    "rules": payload,
                    "count": len(payload),
                },
            )

        except Exception as exc:
            return self._error_result(
                "Failed to list permission rules.",
                exc,
            )

    # =========================================================================
    # Role and user permission management
    # =========================================================================

    def set_role_permissions(
        self,
        *,
        workspace_id: Any,
        role: Any,
        allow: Optional[Iterable[str]] = None,
        deny: Optional[Iterable[str]] = None,
        confirm: Optional[Iterable[str]] = None,
        biometric: Optional[Iterable[str]] = None,
    ) -> Dict[str, Any]:
        """Set permission patterns for a workspace role."""
        try:
            normalized_workspace_id = _normalize_identifier(
                workspace_id,
                "workspace_id",
            )
            normalized_role = _normalize_role(role)

            permission_set = {
                "allow": set(
                    self._normalize_permission_list(allow or [])
                ),
                "deny": set(
                    self._normalize_permission_list(deny or [])
                ),
                "confirm": set(
                    self._normalize_permission_list(confirm or [])
                ),
                "biometric": set(
                    self._normalize_permission_list(
                        biometric or []
                    )
                ),
            }

            with self._lock:
                self._workspace_role_permissions[
                    (
                        normalized_workspace_id,
                        normalized_role,
                    )
                ] = permission_set

            self._log_audit_event(
                action="role_permissions_updated",
                user_id=None,
                workspace_id=normalized_workspace_id,
                session_id=None,
                details={
                    "role": normalized_role,
                    "counts": {
                        key: len(value)
                        for key, value in permission_set.items()
                    },
                },
            )

            return self._safe_result(
                message="Role permissions updated.",
                data={
                    "workspace_id": normalized_workspace_id,
                    "role": normalized_role,
                    "permissions": {
                        key: sorted(value)
                        for key, value in permission_set.items()
                    },
                },
            )

        except Exception as exc:
            return self._error_result(
                "Failed to set role permissions.",
                exc,
            )

    def set_user_permission_override(
        self,
        *,
        user_id: Any,
        workspace_id: Any,
        allow: Optional[Iterable[str]] = None,
        deny: Optional[Iterable[str]] = None,
        confirm: Optional[Iterable[str]] = None,
        biometric: Optional[Iterable[str]] = None,
    ) -> Dict[str, Any]:
        """Set user-specific permission overrides."""
        try:
            normalized_user_id = _normalize_identifier(
                user_id,
                "user_id",
            )
            normalized_workspace_id = _normalize_identifier(
                workspace_id,
                "workspace_id",
            )

            permission_set = {
                "allow": set(
                    self._normalize_permission_list(allow or [])
                ),
                "deny": set(
                    self._normalize_permission_list(deny or [])
                ),
                "confirm": set(
                    self._normalize_permission_list(confirm or [])
                ),
                "biometric": set(
                    self._normalize_permission_list(
                        biometric or []
                    )
                ),
            }

            with self._lock:
                if (
                    len(self._user_permission_overrides)
                    >= self.config.max_scope_overrides
                    and (
                        normalized_user_id,
                        normalized_workspace_id,
                    )
                    not in self._user_permission_overrides
                ):
                    raise RuntimeError(
                        "Maximum user permission override limit reached."
                    )

                self._user_permission_overrides[
                    (
                        normalized_user_id,
                        normalized_workspace_id,
                    )
                ] = permission_set

            self._log_audit_event(
                action="user_permission_override_updated",
                user_id=normalized_user_id,
                workspace_id=normalized_workspace_id,
                session_id=None,
                details={
                    "counts": {
                        key: len(value)
                        for key, value in permission_set.items()
                    },
                },
            )

            return self._safe_result(
                message="User permission override updated.",
                data={
                    "user_id": normalized_user_id,
                    "workspace_id": normalized_workspace_id,
                    "permissions": {
                        key: sorted(value)
                        for key, value in permission_set.items()
                    },
                },
            )

        except Exception as exc:
            return self._error_result(
                "Failed to set user permission override.",
                exc,
            )

    def set_agent_permission_override(
        self,
        *,
        workspace_id: Any,
        agent_name: Any,
        allow: Optional[Iterable[str]] = None,
        deny: Optional[Iterable[str]] = None,
        confirm: Optional[Iterable[str]] = None,
        biometric: Optional[Iterable[str]] = None,
    ) -> Dict[str, Any]:
        """Set workspace-specific agent permission overrides."""
        try:
            normalized_workspace_id = _normalize_identifier(
                workspace_id,
                "workspace_id",
            )
            normalized_agent_name = _normalize_agent_name(
                agent_name
            )

            if normalized_agent_name is None:
                raise ValueError("agent_name is required.")

            permission_set = {
                "allow": set(
                    self._normalize_permission_list(allow or [])
                ),
                "deny": set(
                    self._normalize_permission_list(deny or [])
                ),
                "confirm": set(
                    self._normalize_permission_list(confirm or [])
                ),
                "biometric": set(
                    self._normalize_permission_list(
                        biometric or []
                    )
                ),
            }

            with self._lock:
                self._agent_permission_overrides[
                    (
                        normalized_workspace_id,
                        normalized_agent_name.lower(),
                    )
                ] = permission_set

            self._log_audit_event(
                action="agent_permission_override_updated",
                user_id=None,
                workspace_id=normalized_workspace_id,
                session_id=None,
                details={
                    "agent_name": normalized_agent_name,
                    "counts": {
                        key: len(value)
                        for key, value in permission_set.items()
                    },
                },
            )

            return self._safe_result(
                message="Agent permission override updated.",
                data={
                    "workspace_id": normalized_workspace_id,
                    "agent_name": normalized_agent_name,
                    "permissions": {
                        key: sorted(value)
                        for key, value in permission_set.items()
                    },
                },
            )

        except Exception as exc:
            return self._error_result(
                "Failed to set agent permission override.",
                exc,
            )

    # =========================================================================
    # Confirmation, biometric, and approval evidence
    # =========================================================================

    def register_confirmation(
        self,
        *,
        user_id: Any,
        workspace_id: Any,
        action: Any,
        session_id: Optional[Any] = None,
        confirmation_id: Optional[str] = None,
        one_time: bool = True,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Register a valid user confirmation."""
        return self._register_evidence(
            evidence_type="confirmation",
            store=self._confirmations,
            user_id=user_id,
            workspace_id=workspace_id,
            action=action,
            session_id=session_id,
            evidence_id=confirmation_id,
            one_time=one_time,
            metadata=metadata,
        )

    def register_biometric_verification(
        self,
        *,
        user_id: Any,
        workspace_id: Any,
        action: Any,
        session_id: Optional[Any] = None,
        verification_id: Optional[str] = None,
        one_time: bool = True,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Register biometric verification produced by biometric_gate.py.

        This method stores only verification evidence, never biometric templates.
        """
        return self._register_evidence(
            evidence_type="biometric",
            store=self._biometric_verifications,
            user_id=user_id,
            workspace_id=workspace_id,
            action=action,
            session_id=session_id,
            evidence_id=verification_id,
            one_time=one_time,
            metadata=metadata,
        )

    def register_temporary_approval(
        self,
        *,
        user_id: Any,
        workspace_id: Any,
        action: Any,
        session_id: Optional[Any] = None,
        approval_id: Optional[str] = None,
        one_time: bool = True,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Register temporary Approval Manager evidence."""
        return self._register_evidence(
            evidence_type="approval",
            store=self._temporary_approvals,
            user_id=user_id,
            workspace_id=workspace_id,
            action=action,
            session_id=session_id,
            evidence_id=approval_id,
            one_time=one_time,
            metadata=metadata,
        )

    def _register_evidence(
        self,
        *,
        evidence_type: str,
        store: MutableMapping[str, Dict[str, Any]],
        user_id: Any,
        workspace_id: Any,
        action: Any,
        session_id: Optional[Any],
        evidence_id: Optional[str],
        one_time: bool,
        metadata: Optional[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """Register permission evidence safely."""
        try:
            validated = self._validate_task_context(
                user_id=user_id,
                workspace_id=workspace_id,
                action=action,
                session_id=session_id,
            )

            prefix = {
                "confirmation": "confirmation",
                "biometric": "biometric_verification",
                "approval": "temporary_approval",
            }.get(evidence_type, "permission_evidence")

            normalized_evidence_id = (
                _normalize_identifier(
                    evidence_id,
                    f"{evidence_type}_id",
                )
                if evidence_id
                else _safe_uuid(prefix)
            )

            record = {
                "evidence_id": normalized_evidence_id,
                "evidence_type": evidence_type,
                "status": "valid",
                "user_id": validated["user_id"],
                "workspace_id": validated["workspace_id"],
                "session_id": validated["session_id"],
                "action": validated["action"],
                "one_time": bool(one_time),
                "consumed": False,
                "metadata": self._sanitize_payload(
                    _coerce_mapping(metadata, "metadata")
                ),
                "created_at": _utc_now_iso(),
                "created_at_unix": _unix_now(),
            }

            with self._lock:
                store[normalized_evidence_id] = record

            self._log_audit_event(
                action=f"{evidence_type}_registered",
                user_id=str(validated["user_id"]),
                workspace_id=str(validated["workspace_id"]),
                session_id=validated["session_id"],
                details={
                    "evidence_id": normalized_evidence_id,
                    "action": validated["action"],
                    "one_time": bool(one_time),
                },
            )

            return self._safe_result(
                message=f"{evidence_type.capitalize()} evidence registered.",
                data={
                    "evidence": _deepcopy_safe(record),
                },
            )

        except Exception as exc:
            return self._error_result(
                f"Failed to register {evidence_type} evidence.",
                exc,
            )

    def revoke_evidence(
        self,
        evidence_id: Any,
    ) -> Dict[str, Any]:
        """Revoke confirmation, biometric, or approval evidence."""
        try:
            normalized_evidence_id = _normalize_identifier(
                evidence_id,
                "evidence_id",
            )

            revoked = None

            with self._lock:
                for store in (
                    self._confirmations,
                    self._biometric_verifications,
                    self._temporary_approvals,
                ):
                    if normalized_evidence_id in store:
                        revoked = store[normalized_evidence_id]
                        revoked["status"] = "revoked"
                        revoked["revoked_at"] = _utc_now_iso()
                        break

            return self._safe_result(
                message=(
                    "Permission evidence revoked."
                    if revoked
                    else "Permission evidence not found."
                ),
                data={
                    "revoked": revoked is not None,
                    "evidence_id": normalized_evidence_id,
                },
            )

        except Exception as exc:
            return self._error_result(
                "Failed to revoke permission evidence.",
                exc,
            )

    # =========================================================================
    # Emergency lock management
    # =========================================================================

    def set_workspace_lock(
        self,
        *,
        workspace_id: Any,
        reason: str,
        allowed_action_patterns: Optional[Iterable[str]] = None,
    ) -> Dict[str, Any]:
        """Activate an emergency workspace security lock."""
        try:
            normalized_workspace_id = _normalize_identifier(
                workspace_id,
                "workspace_id",
            )

            lock_record = self._create_lock_record(
                scope="workspace",
                reason=reason,
                allowed_action_patterns=allowed_action_patterns,
            )

            with self._lock:
                self._workspace_locks[
                    normalized_workspace_id
                ] = lock_record

            self._log_audit_event(
                action="workspace_security_lock_enabled",
                user_id=None,
                workspace_id=normalized_workspace_id,
                session_id=None,
                details=lock_record,
                level="critical",
            )

            return self._safe_result(
                message="Workspace security lock enabled.",
                data={
                    "workspace_id": normalized_workspace_id,
                    "lock": lock_record,
                },
            )

        except Exception as exc:
            return self._error_result(
                "Failed to enable workspace security lock.",
                exc,
            )

    def set_user_lock(
        self,
        *,
        user_id: Any,
        workspace_id: Any,
        reason: str,
        allowed_action_patterns: Optional[Iterable[str]] = None,
    ) -> Dict[str, Any]:
        """Activate an emergency user lock."""
        try:
            normalized_user_id = _normalize_identifier(
                user_id,
                "user_id",
            )
            normalized_workspace_id = _normalize_identifier(
                workspace_id,
                "workspace_id",
            )

            lock_record = self._create_lock_record(
                scope="user",
                reason=reason,
                allowed_action_patterns=allowed_action_patterns,
            )

            with self._lock:
                self._user_locks[
                    (
                        normalized_user_id,
                        normalized_workspace_id,
                    )
                ] = lock_record

            self._log_audit_event(
                action="user_security_lock_enabled",
                user_id=normalized_user_id,
                workspace_id=normalized_workspace_id,
                session_id=None,
                details=lock_record,
                level="critical",
            )

            return self._safe_result(
                message="User security lock enabled.",
                data={
                    "user_id": normalized_user_id,
                    "workspace_id": normalized_workspace_id,
                    "lock": lock_record,
                },
            )

        except Exception as exc:
            return self._error_result(
                "Failed to enable user security lock.",
                exc,
            )

    def set_session_lock(
        self,
        *,
        user_id: Any,
        workspace_id: Any,
        session_id: Any,
        reason: str,
        allowed_action_patterns: Optional[Iterable[str]] = None,
    ) -> Dict[str, Any]:
        """Activate an emergency session lock."""
        try:
            validated = self._validate_task_context(
                user_id=user_id,
                workspace_id=workspace_id,
                session_id=session_id,
                action="security.session_lock",
            )

            lock_record = self._create_lock_record(
                scope="session",
                reason=reason,
                allowed_action_patterns=allowed_action_patterns,
            )

            key = (
                str(validated["user_id"]),
                str(validated["workspace_id"]),
                str(validated["session_id"]),
            )

            with self._lock:
                self._session_locks[key] = lock_record

            self._log_audit_event(
                action="session_security_lock_enabled",
                user_id=key[0],
                workspace_id=key[1],
                session_id=key[2],
                details=lock_record,
                level="critical",
            )

            return self._safe_result(
                message="Session security lock enabled.",
                data={
                    "user_id": key[0],
                    "workspace_id": key[1],
                    "session_id": key[2],
                    "lock": lock_record,
                },
            )

        except Exception as exc:
            return self._error_result(
                "Failed to enable session security lock.",
                exc,
            )

    def _create_lock_record(
        self,
        *,
        scope: str,
        reason: str,
        allowed_action_patterns: Optional[Iterable[str]],
    ) -> Dict[str, Any]:
        """Create a lock record."""
        clean_reason = str(reason).strip()

        if not clean_reason:
            raise ValueError("reason is required.")

        return {
            "lock_id": _safe_uuid("security_lock"),
            "scope": scope,
            "reason": _truncate_string(clean_reason, 1000),
            "allowed_action_patterns": (
                self._normalize_permission_list(
                    allowed_action_patterns
                    or [
                        "security.inspect",
                        "security.unlock_request",
                        "security.audit.read",
                    ]
                )
            ),
            "active": True,
            "created_at": _utc_now_iso(),
        }

    def clear_workspace_lock(
        self,
        *,
        workspace_id: Any,
        biometric_verified: bool = False,
    ) -> Dict[str, Any]:
        """Clear workspace lock only after biometric authorization."""
        normalized_workspace_id = _normalize_identifier(
            workspace_id,
            "workspace_id",
        )

        if not biometric_verified:
            return self._safe_result(
                message=(
                    "Biometric verification is required to clear "
                    "the workspace lock."
                ),
                data={
                    "cleared": False,
                    "decision": (
                        PermissionDecision.BIOMETRIC_REQUIRED.value
                    ),
                },
            )

        with self._lock:
            removed = self._workspace_locks.pop(
                normalized_workspace_id,
                None,
            )

        self._log_audit_event(
            action="workspace_security_lock_cleared",
            user_id=None,
            workspace_id=normalized_workspace_id,
            session_id=None,
            details={
                "cleared": removed is not None,
                "lock_id": (
                    removed.get("lock_id")
                    if removed
                    else None
                ),
            },
            level="warning",
        )

        return self._safe_result(
            message=(
                "Workspace security lock cleared."
                if removed
                else "Workspace lock was not active."
            ),
            data={
                "cleared": removed is not None,
            },
        )

    def clear_user_lock(
        self,
        *,
        user_id: Any,
        workspace_id: Any,
        biometric_verified: bool = False,
    ) -> Dict[str, Any]:
        """Clear user lock only after biometric authorization."""
        normalized_user_id = _normalize_identifier(
            user_id,
            "user_id",
        )
        normalized_workspace_id = _normalize_identifier(
            workspace_id,
            "workspace_id",
        )

        if not biometric_verified:
            return self._safe_result(
                message=(
                    "Biometric verification is required to clear "
                    "the user lock."
                ),
                data={
                    "cleared": False,
                    "decision": (
                        PermissionDecision.BIOMETRIC_REQUIRED.value
                    ),
                },
            )

        with self._lock:
            removed = self._user_locks.pop(
                (
                    normalized_user_id,
                    normalized_workspace_id,
                ),
                None,
            )

        return self._safe_result(
            message=(
                "User security lock cleared."
                if removed
                else "User lock was not active."
            ),
            data={
                "cleared": removed is not None,
            },
        )

    def clear_session_lock(
        self,
        *,
        user_id: Any,
        workspace_id: Any,
        session_id: Any,
        biometric_verified: bool = False,
    ) -> Dict[str, Any]:
        """Clear session lock only after biometric authorization."""
        validated = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            session_id=session_id,
            action="security.session_unlock",
        )

        if not biometric_verified:
            return self._safe_result(
                message=(
                    "Biometric verification is required to clear "
                    "the session lock."
                ),
                data={
                    "cleared": False,
                    "decision": (
                        PermissionDecision.BIOMETRIC_REQUIRED.value
                    ),
                },
            )

        key = (
            str(validated["user_id"]),
            str(validated["workspace_id"]),
            str(validated["session_id"]),
        )

        with self._lock:
            removed = self._session_locks.pop(
                key,
                None,
            )

        return self._safe_result(
            message=(
                "Session security lock cleared."
                if removed
                else "Session lock was not active."
            ),
            data={
                "cleared": removed is not None,
            },
        )

    # =========================================================================
    # Cleanup and cache
    # =========================================================================

    def _cleanup_expired_evidence(self) -> int:
        """Remove expired confirmation, biometric, and approval evidence."""
        now = _unix_now()
        removed = 0

        stores_with_ttl = (
            (
                self._confirmations,
                self.config.confirmation_ttl_seconds,
            ),
            (
                self._biometric_verifications,
                self.config.biometric_ttl_seconds,
            ),
            (
                self._temporary_approvals,
                self.config.approval_ttl_seconds,
            ),
        )

        with self._lock:
            for store, ttl in stores_with_ttl:
                expired_ids = [
                    evidence_id
                    for evidence_id, evidence in store.items()
                    if (
                        now
                        - float(
                            evidence.get(
                                "created_at_unix",
                                0.0,
                            )
                        )
                        > ttl
                    )
                ]

                for evidence_id in expired_ids:
                    store.pop(evidence_id, None)
                    removed += 1

        return removed

    def cleanup_expired_evidence(self) -> Dict[str, Any]:
        """Public evidence cleanup method."""
        try:
            removed = self._cleanup_expired_evidence()

            return self._safe_result(
                message="Expired permission evidence cleaned.",
                data={
                    "removed_count": removed,
                },
            )

        except Exception as exc:
            return self._error_result(
                "Failed to clean expired permission evidence.",
                exc,
            )

    def _cache_decision(
        self,
        decision_payload: Mapping[str, Any],
    ) -> None:
        """Store a privacy-safe recent decision."""
        cached = {
            "decision_id": decision_payload.get("decision_id"),
            "request_id": decision_payload.get("request_id"),
            "user_id": decision_payload.get("user_id"),
            "workspace_id": decision_payload.get("workspace_id"),
            "session_id": decision_payload.get("session_id"),
            "action": decision_payload.get("action"),
            "agent_name": decision_payload.get("agent_name"),
            "decision": decision_payload.get("decision"),
            "reason": decision_payload.get("reason"),
            "source": decision_payload.get("source"),
            "risk_level": decision_payload.get("risk_level"),
            "created_at": decision_payload.get("created_at"),
        }

        with self._lock:
            self._decision_cache.append(cached)

    # =========================================================================
    # Dashboard/API and diagnostics
    # =========================================================================

    def get_recent_decisions(
        self,
        *,
        user_id: Optional[Any] = None,
        workspace_id: Optional[Any] = None,
        decision: Optional[str] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """Get recent permission decisions."""
        try:
            normalized_user_id = (
                _normalize_identifier(user_id, "user_id")
                if user_id is not None
                else None
            )
            normalized_workspace_id = (
                _normalize_identifier(
                    workspace_id,
                    "workspace_id",
                )
                if workspace_id is not None
                else None
            )

            valid_decisions = {
                item.value
                for item in PermissionDecision
            }

            if (
                decision is not None
                and decision not in valid_decisions
            ):
                raise ValueError("Invalid decision filter.")

            safe_limit = max(
                1,
                min(
                    int(limit),
                    self.config.decision_cache_limit,
                ),
            )

            with self._lock:
                records = list(self._decision_cache)

            if normalized_user_id:
                records = [
                    item
                    for item in records
                    if item.get("user_id")
                    == normalized_user_id
                ]

            if normalized_workspace_id:
                records = [
                    item
                    for item in records
                    if item.get("workspace_id")
                    == normalized_workspace_id
                ]

            if decision:
                records = [
                    item
                    for item in records
                    if item.get("decision") == decision
                ]

            records = list(reversed(records))[:safe_limit]

            return self._safe_result(
                message="Recent permission decisions retrieved.",
                data={
                    "decisions": records,
                    "count": len(records),
                },
            )

        except Exception as exc:
            return self._error_result(
                "Failed to get recent permission decisions.",
                exc,
            )

    def get_audit_events(
        self,
        *,
        user_id: Optional[Any] = None,
        workspace_id: Optional[Any] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """Get permission audit events."""
        try:
            normalized_user_id = (
                _normalize_identifier(user_id, "user_id")
                if user_id is not None
                else None
            )
            normalized_workspace_id = (
                _normalize_identifier(
                    workspace_id,
                    "workspace_id",
                )
                if workspace_id is not None
                else None
            )

            safe_limit = max(
                1,
                min(int(limit), self.config.audit_limit),
            )

            with self._lock:
                events = list(self._audit_events)

            if normalized_user_id:
                events = [
                    event
                    for event in events
                    if event.get("user_id")
                    == normalized_user_id
                ]

            if normalized_workspace_id:
                events = [
                    event
                    for event in events
                    if event.get("workspace_id")
                    == normalized_workspace_id
                ]

            events = list(reversed(events))[:safe_limit]

            return self._safe_result(
                message="Permission audit events retrieved.",
                data={
                    "events": events,
                    "count": len(events),
                },
            )

        except Exception as exc:
            return self._error_result(
                "Failed to get permission audit events.",
                exc,
            )

    def get_agent_events(
        self,
        *,
        user_id: Optional[Any] = None,
        workspace_id: Optional[Any] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """Get permission-related agent events."""
        try:
            normalized_user_id = (
                _normalize_identifier(user_id, "user_id")
                if user_id is not None
                else None
            )
            normalized_workspace_id = (
                _normalize_identifier(
                    workspace_id,
                    "workspace_id",
                )
                if workspace_id is not None
                else None
            )

            safe_limit = max(
                1,
                min(int(limit), self.config.event_limit),
            )

            with self._lock:
                events = list(self._agent_events)

            if normalized_user_id:
                events = [
                    event
                    for event in events
                    if event.get("user_id")
                    == normalized_user_id
                ]

            if normalized_workspace_id:
                events = [
                    event
                    for event in events
                    if event.get("workspace_id")
                    == normalized_workspace_id
                ]

            events = list(reversed(events))[:safe_limit]

            return self._safe_result(
                message="Permission agent events retrieved.",
                data={
                    "events": events,
                    "count": len(events),
                },
            )

        except Exception as exc:
            return self._error_result(
                "Failed to get permission agent events.",
                exc,
            )

    def get_stats(self) -> Dict[str, Any]:
        """Return PermissionChecker statistics."""
        try:
            with self._lock:
                decision_counts = {
                    item.value: 0
                    for item in PermissionDecision
                }

                for decision in self._decision_cache:
                    value = decision.get("decision")

                    if value in decision_counts:
                        decision_counts[value] += 1

                data = {
                    "rule_count": len(self._rules),
                    "workspace_lock_count": len(
                        self._workspace_locks
                    ),
                    "user_lock_count": len(
                        self._user_locks
                    ),
                    "session_lock_count": len(
                        self._session_locks
                    ),
                    "confirmation_count": len(
                        self._confirmations
                    ),
                    "biometric_verification_count": len(
                        self._biometric_verifications
                    ),
                    "temporary_approval_count": len(
                        self._temporary_approvals
                    ),
                    "role_permission_scope_count": len(
                        self._workspace_role_permissions
                    ),
                    "user_override_count": len(
                        self._user_permission_overrides
                    ),
                    "agent_override_count": len(
                        self._agent_permission_overrides
                    ),
                    "audit_event_count": len(
                        self._audit_events
                    ),
                    "agent_event_count": len(
                        self._agent_events
                    ),
                    "decision_count": len(
                        self._decision_cache
                    ),
                    "decision_counts": decision_counts,
                }

            return self._safe_result(
                message="PermissionChecker statistics retrieved.",
                data=data,
            )

        except Exception as exc:
            return self._error_result(
                "Failed to get PermissionChecker statistics.",
                exc,
            )

    def get_capabilities(self) -> List[str]:
        """Return capabilities for Agent Registry and Master Agent."""
        return [
            "permission_checking",
            "allowed_decision",
            "confirmation_required_decision",
            "biometric_required_decision",
            "blocked_decision",
            "saas_user_workspace_isolation",
            "role_permission_evaluation",
            "subscription_permission_evaluation",
            "agent_permission_evaluation",
            "explicit_permission_rules",
            "risk_based_permission_escalation",
            "confirmation_evidence_validation",
            "biometric_evidence_validation",
            "temporary_approval_validation",
            "emergency_workspace_lock",
            "emergency_user_lock",
            "emergency_session_lock",
            "permission_audit_logging",
            "verification_payload_preparation",
            "memory_payload_preparation",
            "dashboard_permission_analytics",
        ]

    def health_check(self) -> Dict[str, Any]:
        """Health check for Agent Registry and Agent Loader."""
        stats = self.get_stats()

        return self._safe_result(
            message="PermissionChecker is healthy.",
            data={
                "healthy": True,
                "agent_name": self.agent_name,
                "agent_version": self.agent_version,
                "capabilities": self.get_capabilities(),
                "stats": stats.get("data", {}),
                "configuration": {
                    "default_decision": (
                        self.config.default_decision
                    ),
                    "fail_closed": self.config.fail_closed,
                    "require_active_subscription": (
                        self.config.require_active_subscription
                    ),
                    "require_known_role": (
                        self.config.require_known_role
                    ),
                    "require_registered_agent": (
                        self.config.require_registered_agent
                    ),
                },
            },
            metadata={
                "component": (
                    "security_agent.permission_checker"
                ),
            },
        )


# =============================================================================
# Factory
# =============================================================================

def create_permission_checker(
    config: Optional[
        Union[PermissionCheckerConfig, Mapping[str, Any]]
    ] = None,
    logger: Optional[logging.Logger] = None,
) -> PermissionChecker:
    """
    Factory for Agent Loader, Agent Registry, or dependency injection.
    """
    return PermissionChecker(
        config=config,
        logger=logger,
    )


# =============================================================================
# Manual smoke tests
# =============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    checker = PermissionChecker()

    print("\n1. Safe read action")
    print(
        json.dumps(
            checker.check_permission(
                user_id="user_1",
                workspace_id="workspace_1",
                session_id="session_1",
                action="code.read",
                agent_name="Code",
                roles=["member"],
                subscription_status="active",
                risk_level="low",
            ),
            indent=2,
            default=str,
        )
    )

    print("\n2. Code write requiring confirmation")
    confirmation_result = checker.check_permission(
        user_id="user_1",
        workspace_id="workspace_1",
        session_id="session_1",
        action="code.write",
        agent_name="Code",
        roles=["member"],
        subscription_status="active",
        risk_level="low",
    )

    print(
        json.dumps(
            confirmation_result,
            indent=2,
            default=str,
        )
    )

    print("\n3. Register confirmation")
    registered_confirmation = checker.register_confirmation(
        user_id="user_1",
        workspace_id="workspace_1",
        session_id="session_1",
        action="code.write",
    )

    print(
        json.dumps(
            registered_confirmation,
            indent=2,
            default=str,
        )
    )

    confirmation_id = registered_confirmation[
        "data"
    ]["evidence"]["evidence_id"]

    print("\n4. Code write with valid confirmation")
    print(
        json.dumps(
            checker.check_permission(
                user_id="user_1",
                workspace_id="workspace_1",
                session_id="session_1",
                action="code.write",
                agent_name="Code",
                roles=["member"],
                subscription_status="active",
                confirmation_id=confirmation_id,
            ),
            indent=2,
            default=str,
        )
    )

    print("\n5. Finance transfer requiring biometric")
    print(
        json.dumps(
            checker.check_permission(
                user_id="user_1",
                workspace_id="workspace_1",
                session_id="session_1",
                action="finance.transfer",
                agent_name="Finance",
                roles=["workspace_owner"],
                subscription_status="active",
                risk_level="high",
            ),
            indent=2,
            default=str,
        )
    )

    print("\n6. Register biometric verification")
    biometric_result = checker.register_biometric_verification(
        user_id="user_1",
        workspace_id="workspace_1",
        session_id="session_1",
        action="finance.transfer",
        metadata={
            "provider": "biometric_gate",
            "verification_method": "device_biometric",
        },
    )

    print(
        json.dumps(
            biometric_result,
            indent=2,
            default=str,
        )
    )

    biometric_id = biometric_result[
        "data"
    ]["evidence"]["evidence_id"]

    print("\n7. Finance transfer with biometric evidence")
    print(
        json.dumps(
            checker.check_permission(
                user_id="user_1",
                workspace_id="workspace_1",
                session_id="session_1",
                action="finance.transfer",
                agent_name="Finance",
                roles=["workspace_owner"],
                subscription_status="active",
                risk_level="high",
                biometric_verification_id=biometric_id,
            ),
            indent=2,
            default=str,
        )
    )

    print("\n8. Cross-workspace resource access")
    print(
        json.dumps(
            checker.check_permission(
                user_id="user_1",
                workspace_id="workspace_1",
                resource_workspace_id="workspace_2",
                action="memory.read_long_term",
                agent_name="Memory",
                roles=["member"],
                subscription_status="active",
            ),
            indent=2,
            default=str,
        )
    )

    print("\n9. Security bypass attempt")
    print(
        json.dumps(
            checker.check_permission(
                user_id="user_1",
                workspace_id="workspace_1",
                action="disable_security_agent",
                agent_name="System",
                roles=["system_admin"],
                subscription_status="active",
            ),
            indent=2,
            default=str,
        )
    )

    print("\n10. Health check")
    print(
        json.dumps(
            checker.health_check(),
            indent=2,
            default=str,
        )
    )